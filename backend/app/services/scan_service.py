"""
Scan service — two-model pipeline.

Model 1 (Detection): runs on every upload, uses chunk-level max-pooling.
Model 2 (Fix):       runs only when user clicks "Generate Fix".

Architecture decision — rule-vs-ML (Gap B):
─────────────────────────────────────────────
This file implements an ML-primary verdict with a deterministic rule layer
as an auxiliary explainability + safety-net component. In short:

  - The trained CNN+BiLSTM model is the primary classifier.
  - Rule signals (FSTRING_SQL, SQL_CONCAT, etc.) are emitted by the
    preprocessing step and feed BOTH the model (as input tokens) AND a
    parallel deterministic score, so the user sees *why* a chunk was flagged.
  - Fusion (`_fuse_scores`) lets ML override rules when ML is very confident,
    and lets rules win on patterns where the model is uncertain.
  - When the ML model is unavailable, the rule layer alone produces a
    degraded but functional verdict.

Every chunk in the response includes a `verdictSource` field exposing which
layer drove the decision. See backend/docs/ARCHITECTURE.md for full details,
worked examples, and the academic-defense framing.
"""
from pathlib import Path
import json
import re

from bson import ObjectId
from fastapi import HTTPException, UploadFile

from app.core.constants import ALLOWED_EXTENSIONS
from app.db.database import get_audit_logs_collection
from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.preprocessing.normalizer import (
    normalize_tokens,
    extract_safe_returning_funcs,
    extract_numeric_returning_funcs,
    extract_db_returning_funcs,
)
from app.preprocessing.chunker import split_into_chunks
from app.schemas.scan import (
    CleanCodePayload,
    GenerateFixResponse,
    NormalizedCodePayload,
    RawCodePayload,
    ScanDetectionInfo,
    ScanFileInfo,
    ScanHistoryItemResponse,
    ScanHistoryListResponse,
    ScanPreprocessingInfo,
    ScanResponse,
    ScanVectorizationInfo,
    SuspiciousPattern,
    TokenizedCodePayload,
)
from app.services.audit_log_service import log_audit_event
from app.vectorization.vocabulary import build_fixed_vocabulary
from app.vectorization.vectorizer import vectorize_tokens
from app.model.inference import run_inference, model_is_loaded
from app.model.fix_model_inference import run_fix_inference
from app.fix_engine.fix_generator import generate_fix

VOCABULARY = build_fixed_vocabulary()

_DETECTION_METADATA_PATH = Path(__file__).resolve().parents[1] / "model" / "weights" / "sqli_detection_metadata.json"
_DETECTION_METADATA_CACHE: dict | None = None


def _detection_metadata() -> dict:
    """Best-effort model metadata for API/audit reports."""
    global _DETECTION_METADATA_CACHE
    if _DETECTION_METADATA_CACHE is not None:
        return _DETECTION_METADATA_CACHE
    try:
        _DETECTION_METADATA_CACHE = json.loads(_DETECTION_METADATA_PATH.read_text(encoding="utf-8"))
    except Exception:
        _DETECTION_METADATA_CACHE = {}
    return _DETECTION_METADATA_CACHE


def _model_version() -> str | None:
    return _detection_metadata().get("model_version")


def _model_sequence_length() -> int | None:
    value = _detection_metadata().get("sequence_length")
    try:
        return int(value) if value is not None else None
    except Exception:
        return None


def _label_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 0.70:
        return "VULNERABLE"
    if score >= 0.45:
        return "SUSPICIOUS"
    return "SAFE"


def _decision_source_bucket(source: str, ml_executed: bool) -> str:
    """Coarse audit category while preserving the exact verdictSource separately."""
    s = (source or "").lower()
    if s.startswith("raw_"):
        return "raw_evidence_override"
    if s == "ml":
        return "ml_primary"
    if s in {"ml+rule", "ml_overrides_rule"}:
        return "ml_supported_by_evidence"
    if s == "semantic_safe_guard":
        return "semantic_safe_guard"
    if s == "rule_safety_net":
        return "rule_safety_net_no_model" if not ml_executed else "rule_safety_net"
    if s == "rule":
        return "rule_primary"
    return s or ("ml_primary" if ml_executed else "unknown")

# ── Signal severity weights ───────────────────────────────────────────────────

# HIGH signals that alone (or in combination) prove a vulnerability
HIGH_SIGNALS = {"FSTRING_SQL", "SQL_CONCAT", "FSTRING_SQL_RAW", "SECOND_ORDER_FLOW"}

# Signals that are dangerous when combined with a SQL context
MEDIUM_SIGNALS = {"UNSAFE_EXEC"}

# Signals that indicate parameterized / safe usage
SAFE_SIGNALS = {"SAFE_EXEC", "SAFE_PLACEHOLDER_LIST", "SAFE_NUMERIC_VAR"}

# These combos are ALWAYS vulnerable — hard override ignores the ML score
ALWAYS_VULNERABLE_COMBOS = [
    {"SQL_CONCAT", "UNSAFE_EXEC"},        # concat + unsafe exec
    {"FSTRING_SQL", "UNSAFE_EXEC"},       # f-string injection + unsafe exec
    {"FSTRING_SQL"},                      # f-string SQL alone is enough
    {"FSTRING_SQL_RAW"},                  # f-string with RAW interpolated var (always)
    {"SQL_CONCAT"},                       # concat alone is enough
    {"SECOND_ORDER_FLOW"},                # DB-loaded value reused as SQL text
]




# ── Raw-code evidence layer ───────────────────────────────────────────────────
# This is deliberately kept inside scan_service.py (no extra service file).  It is
# not a filename/test patch: it recognizes source/sink principles that the token
# normalizer and ML model can miss, especially in compact one-function examples.
# It is conservative: SAFE overrides require strong exact safe structure; unsafe
# overrides require an actual raw-execution or SQL-syntax data-flow pattern.

def _strip_comments(code: str, language: str) -> str:
    if language == "python":
        return re.sub(r"#.*", "", code)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    return re.sub(r"//[^\n\r]*", "", code)


def _rx(pattern: str, text: str, flags: int = re.I | re.S) -> bool:
    return re.search(pattern, text, flags) is not None


def _raw_php_has_bound_execute(c: str) -> bool:
    """PHP PDO execute() with separately passed bound params.

    This deliberately accepts array literals that contain nested access such as
    [$q["tenant"]]. A simple `r"\[[^\]]*\]"` regex stops too early on the
    inner `]`, which caused safe PDO query-builder code to be misread as a
    raw sink.
    """
    return _rx(
        r"->\s*execute\s*\(\s*(?:\[[\s\S]*?\]|\$\w+)\s*\)",
        c,
    )


def _raw_safe_sqlite_param_js(code: str) -> bool:
    """SQLite-style JS parameter binding: const sql='... ? ...'; db.all(sql,[x])."""
    c = _strip_comments(code, "javascript")
    # SQL variable with ? placeholders, assigned from a static quoted/template string.
    sql_vars = set()
    for m in re.finditer(r"\b(?:const|let|var)\s+(\w+)\s*=\s*(['\"`])(?=[\s\S]*?\?)(?:[\s\S]*?(?:SELECT|INSERT|UPDATE|DELETE))[\s\S]*?\2\s*;", c, re.I):
        val = m.group(0)
        if "${" not in val:
            sql_vars.add(m.group(1))
    if not sql_vars:
        return False
    param_vars = {m.group(1) for m in re.finditer(r"\b(?:const|let|var)\s+(\w+)\s*=\s*\[[^\]]*\]\s*;", c)}
    for v in sql_vars:
        call_array = rf"\b\w+\s*\.\s*(?:all|get|run|each)\s*\(\s*{re.escape(v)}\s*,\s*\[[^\]]*\]"
        call_var = rf"\b\w+\s*\.\s*(?:all|get|run|each)\s*\(\s*{re.escape(v)}\s*,\s*(?:{'|'.join(map(re.escape, param_vars))})\b" if param_vars else r"a^"
        if _rx(call_array, c) or _rx(call_var, c):
            dyn = rf"\b{re.escape(v)}\s*(?:\+=|=\s*`[^`]*\$\{{|=\s*[^;]*\+|=\s*[^;]*\.join\s*\()"
            if not _rx(dyn, c):
                return True
    return False


def _raw_safe_numeric_limit_offset(code: str, language: str) -> bool:
    c = _strip_comments(code, language)
    if language == "python":
        # Covers helper forms: limit = clamp(parse_int(...)); offset = clamp(parse_int(...))
        # and inline max/min/int forms. Safe only if executed with params or numeric formatting.
        has_limit = _rx(r"\blimit\s*=\s*(?:clamp\s*\(\s*parse_int\s*\(|max\s*\([^\n;]*min\s*\([^\n;]*int\s*\()", c)
        has_offset = _rx(r"\boffset\s*=\s*(?:clamp\s*\(\s*parse_int\s*\(|max\s*\([^\n;]*min\s*\([^\n;]*int\s*\()", c)
        safe_use = _rx(r"LIMIT\s+(?:%d|\{\s*limit\s*\}|\{limit\})\s+OFFSET\s+(?:%d|\{\s*offset\s*\}|\{offset\})", c)
        if has_limit and has_offset and safe_use:
            return True
    if language == "javascript":
        # Track numeric-safe variables, not only variables literally named
        # limit/offset. Real code often uses names such as safeSize, pageSize,
        # safeLimit, offset, etc. A variable is considered numeric-safe if it is
        # derived from Number()/parseInt()/Math.min()/Math.max()/clamp(), or from
        # arithmetic over already-safe numeric variables. This keeps single-arg
        # db.all(sql) safe when the only interpolation is bounded numeric
        # LIMIT/OFFSET syntax.
        safe_numeric: set[str] = set()
        assign_re = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*([^;]+);", re.I | re.S)
        for _ in range(3):
            changed = False
            for m in assign_re.finditer(c):
                name, rhs = m.group(1), m.group(2)
                if name in safe_numeric:
                    continue
                rhs_names = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", rhs))
                has_numeric_wrapper = re.search(r"\b(?:Number|parseInt|parseFloat|Math\.min|Math\.max|clamp)\s*\(", rhs, re.I) is not None
                arithmetic_only = bool(re.fullmatch(r"[\s\w()+\-*/%.,]+", rhs)) and bool(rhs_names) and rhs_names <= (safe_numeric | {"Math", "Number", "parseInt", "parseFloat"})
                if has_numeric_wrapper or arithmetic_only:
                    safe_numeric.add(name)
                    changed = True
            if not changed:
                break
        if len(safe_numeric) >= 2:
            # Template SQL: `... LIMIT ${safeSize} OFFSET ${offset} ...`
            for m in re.finditer(r"`(?=[\s\S]*?\b(?:SELECT|INSERT|UPDATE|DELETE)\b)[\s\S]*?\bLIMIT\s+\$\{\s*(\w+)\s*\}\s+OFFSET\s+\$\{\s*(\w+)\s*\}[\s\S]*?`", c, re.I):
                if m.group(1) in safe_numeric and m.group(2) in safe_numeric:
                    return True
            # Concatenated/static SQL forms using safe numeric vars.
            if _rx(r"LIMIT\s+\$?\{?\s*(?:" + "|".join(map(re.escape, safe_numeric)) + r")\s*\}?\s+OFFSET\s+\$?\{?\s*(?:" + "|".join(map(re.escape, safe_numeric)) + r")\s*\}?", c):
                return True
        has_limit = _rx(r"\blimit\s*=\s*(?:clamp\s*\(|Math\.max\s*\([^;]*Math\.min\s*\([^;]*(?:Number|parseInt)\s*\()", c)
        has_offset = _rx(r"\boffset\s*=\s*(?:clamp\s*\(|Math\.max\s*\([^;]*Math\.min\s*\([^;]*(?:Number|parseInt)\s*\()", c)
        safe_template = _rx(r"LIMIT\s+\$\{\s*limit\s*\}\s+OFFSET\s+\$\{\s*offset\s*\}", c)
        if has_limit and has_offset and safe_template:
            return True
    if language == "php":
        has_limit = _rx(r"\$limit\s*=\s*(?:clamp_int\s*\(|max\s*\([^;]*min\s*\([^;]*\(\s*int\s*\)\s*\$)", c)
        has_offset = _rx(r"\$offset\s*=\s*(?:clamp_int\s*\(|max\s*\([^;]*min\s*\([^;]*\(\s*int\s*\)\s*\$)", c)
        safe_query = _rx(r"LIMIT\s+(?:\{\$limit\}|\$limit)\s+OFFSET\s+(?:\{\$offset\}|\$offset)", c)
        if has_limit and has_offset and safe_query:
            return True
    return False


def _raw_safe_allowlisted_identifier_sql(code: str, language: str) -> bool:
    """Strict safe dynamic SQL identifier proof.

    This covers the common, valid pattern where SQL syntax positions such as
    ORDER BY columns/directions or table names are dynamic, but the selected
    identifier is taken only from a closed allowlist/map before execution.

    It is intentionally strict: every interpolation inside the executed SQL
    template must reference a proven safe identifier variable. If the SQL uses
    the raw request variable (sort_by, direction, req.query.sort, etc.) the
    function returns False and the detector can still flag it.
    """
    c = _strip_comments(code, language)
    if _raw_second_order_stored_sql(code, language):
        return False

    safe_vars: set[str] = set()

    if language == "python":
        # safe_col = sort_by if sort_by in ALLOWED_COLUMNS else "created_at"
        # safe_dir = direction.upper() if direction.upper() in ALLOWED_DIRECTIONS else "DESC"
        for m in re.finditer(
            r"\b(\w+)\s*=\s*[^\n;]+\s+if\s+[^\n;]+\s+in\s+\w+\s+else\s+['\"][\w.]+['\"]",
            c,
            re.I,
        ):
            safe_vars.add(m.group(1))
        # table = TABLE_MAP.get(requested_table, "users")
        for m in re.finditer(
            r"\b(\w+)\s*=\s*\w+\s*\.\s*get\s*\([^,]+,\s*['\"][\w.]+['\"]\s*\)",
            c,
            re.I,
        ):
            safe_vars.add(m.group(1))

        # safe_col = pick_allowed(sort_by, ALLOWED_COLUMNS, "created_at")
        # safe_dir = pick_allowed(direction.upper(), ALLOWED_DIRECTIONS, "DESC")
        # Covers a closed helper that returns value only when it is in the
        # provided allowlist, otherwise a constant default. This is still strict:
        # only the helper output variable becomes safe. If SQL interpolates the
        # original raw variable (sort_by/direction), it will NOT be considered safe.
        has_closed_pick_helper = bool(
            re.search(
                r"def\s+\w+\s*\([^)]*\ballowed\b[^)]*\bdefault\b[^)]*\)\s*:[\s\S]{0,240}"
                r"return\s+\w+\s+if\s+\w+\s+in\s+allowed\s+else\s+default",
                c,
                re.I,
            )
        )
        if has_closed_pick_helper:
            for m in re.finditer(
                r"\b(\w+)\s*=\s*\w+\s*\([^\n;]*\bALLOWED_[A-Z0-9_]+\b[^\n;]*,\s*['\"][\w.]+['\"]\s*\)",
                c,
                re.I,
            ):
                safe_vars.add(m.group(1))
            # safe_col, safe_dir = normalize_sort(...)
            # def normalize_sort(...): ... return col, dir_
            for m in re.finditer(
                r"\b([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*=\s*\w+\s*\([^\n;]*\)",
                c,
                re.I,
            ):
                # Accept only when the same file contains a normalizer/helper that
                # returns two variables created through pick_allowed(... ALLOWED_* ...).
                if re.search(
                    r"def\s+\w+\s*\([^)]*\)\s*:[\s\S]{0,500}"
                    r"\w+\s*=\s*\w+\s*\([^\n;]*\bALLOWED_[A-Z0-9_]+\b[^\n;]*\)[\s\S]{0,240}"
                    r"\w+\s*=\s*\w+\s*\([^\n;]*\bALLOWED_[A-Z0-9_]+\b[^\n;]*\)[\s\S]{0,160}"
                    r"return\s+\w+\s*,\s*\w+",
                    c,
                    re.I,
                ):
                    safe_vars.add(m.group(1))
                    safe_vars.add(m.group(2))
        if not safe_vars:
            return False

        sql_templates: list[str] = []
        for m in re.finditer(
            r"\b(?:sql|query)\s*=\s*f([\"'])(?=[\s\S]{0,80}\b(?:SELECT|INSERT|UPDATE|DELETE)\b)([\s\S]*?)\1",
            c,
            re.I,
        ):
            sql_templates.append(m.group(2))
        if not sql_templates:
            return False

        has_sink = _rx(r"\.execute\s*\(\s*(?:sql|query)\s*\)", c) or _rx(r"\.execute\s*\(\s*(?:sql|query)\s*,", c)
        if not has_sink:
            return False

        for tmpl in sql_templates:
            # Only identifier syntax positions are allowed for this safe proof.
            # Values must still be parameterized elsewhere.
            if not re.search(r"\b(?:ORDER\s+BY|FROM)\b", tmpl, re.I):
                continue
            placeholders = set(re.findall(r"\{\s*([A-Za-z_]\w*)\s*\}", tmpl))
            if placeholders and placeholders.issubset(safe_vars):
                return True
        return False

    if language == "javascript":
        # const safeCol = ALLOWED_COLUMNS.has(sortBy) ? sortBy : "created_at";
        # const safeDir = ALLOWED_DIRECTIONS.has(String(direction).toUpperCase()) ? ... : "DESC";
        for m in re.finditer(
            r"\b(?:const|let|var)\s+(\w+)\s*=\s*[^;?]+\.has\s*\([^;?]+\)\s*\?\s*[^:;]+:\s*['\"][\w.]+['\"]",
            c,
            re.I | re.S,
        ):
            safe_vars.add(m.group(1))
        # const table = TABLE_MAP.get(requested) || "users" / ?? "users"
        for m in re.finditer(
            r"\b(?:const|let|var)\s+(\w+)\s*=\s*\w+\s*\.\s*get\s*\([^)]*\)\s*(?:\?\?|\|\|)\s*['\"][\w.]+['\"]",
            c,
            re.I | re.S,
        ):
            safe_vars.add(m.group(1))
        if not safe_vars:
            return False

        sql_templates: list[str] = []
        for m in re.finditer(
            r"\b(?:const|let|var)\s+(?:sql|query)\s*=\s*`(?=[\s\S]{0,80}\b(?:SELECT|INSERT|UPDATE|DELETE)\b)([\s\S]*?)`\s*;",
            c,
            re.I,
        ):
            sql_templates.append(m.group(1))
        if not sql_templates:
            return False

        has_sink = _rx(r"\.\s*(?:all|get|run|each|query|execute)\s*\(\s*(?:sql|query)\s*\)", c) or _rx(r"\.\s*(?:all|get|run|each|query|execute)\s*\(\s*(?:sql|query)\s*,", c)
        if not has_sink:
            return False

        for tmpl in sql_templates:
            if not re.search(r"\b(?:ORDER\s+BY|FROM)\b", tmpl, re.I):
                continue
            placeholders = set(re.findall(r"\$\{\s*([A-Za-z_]\w*)\s*\}", tmpl))
            if placeholders and placeholders.issubset(safe_vars):
                return True
        return False

    return False


def _raw_safe_query_builder(code: str, language: str) -> bool:
    """Recognize a complete safe dynamic query-builder sink, not isolated SAFE_EXEC."""
    c = _strip_comments(code, language)
    if _raw_second_order_stored_sql(code, language):
        return False
    if _raw_safe_allowlisted_identifier_sql(code, language):
        return True
    if language == "python":
        # Values are bound through params; identifiers are selected from dict/map or fixed direction; numeric paging is bounded.
        has_param_exec = _rx(r"\.execute\s*\(\s*\w+\s*,", c)
        has_allowlist = _rx(r"\b\w+\s*=\s*(?:self\.)?\w+\.get\s*\([^,]+,\s*['\"][\w\.]+['\"]\s*\)", c) or _rx(r"\bSORTS\s*=\s*\{", c)
        has_order = _rx(r"ORDER\s+BY\s+\{\s*\w+\s*\}", c) or _rx(r"ORDER\s+BY\s*[\"\']?\s*\+\s*\w+", c) or _rx(r"ORDER\s+BY\s+created_at", c)
        raw_value_concat = _rx(r"\bsql\s*\+=\s*[\s\S]{0,220}?(?:LIKE|=)[\s\S]{0,160}?\+\s*\w+\s*\+", c)
        raw_used = (
            _rx(r"ORDER\s+BY\s+\{\s*(?:raw_|requested_|args\.|request\.)", c)
            or _rx(r"\+\s*(?:raw_where|debug_sql|args\[|args\.get\([^)]*where)", c)
            or raw_value_concat
        )
        if has_param_exec and (has_allowlist or _raw_safe_numeric_limit_offset(code, language)) and has_order and not raw_used:
            return True
        # Safe decoy-style parameterized WHERE builder with allowlisted ORDER.
        if has_param_exec and (has_allowlist or _rx(r"\.join\s*\(\s*parts\s*\)", c) or _rx(r"ORDER\s+BY\s+created_at", c)) and _rx(r"params\.(?:append|extend)\s*\(|\[[^\]]+\]", c) and not raw_used:
            return True
    elif language == "javascript":
        if _raw_js_safe_sequelize_replacements(code):
            return True
        has_param_exec = _rx(r"\.\s*(?:all|get|run|each)\s*\(\s*\w+\s*,\s*(?:params|\[[^\]]*\]|\w+)\s*\)", c)
        has_allowlist = _rx(r"\.sorts\.get\s*\(", c) or _rx(r"new\s+Map\s*\(\s*\[", c) or _rx(r"Set\s*\(", c)
        has_numeric = _raw_safe_numeric_limit_offset(code, language) or _rx(r"\b(?:limit|offset)\s*=\s*clamp\s*\(", c)
        raw_used = _rx(r"ORDER\s+BY\s+\$\{\s*(?:query\.|req\.|raw)", c) or _rx(r"\+\s*(?:query\.|req\.|raw)", c)
        if has_param_exec and (has_allowlist or has_numeric) and not raw_used:
            return True
    elif language == "java":
        has_prepared = _rx(r"prepareStatement\s*\(\s*sql\s*\)", c) and _rx(r"\.set(?:String|Int|Long|Object|Double|Boolean)\s*\(", c) and _rx(r"\.execute(?:Query|Update)\s*\(\s*\)", c)
        has_allowlist = _rx(r"\.contains\s*\(\s*\w+\s*\)\s*\?\s*\w+\s*:", c) or _rx(r"Set\s*<\s*String\s*>|Set\.of|Arrays\.asList", c)
        raw_order = _rx(r"ORDER\s+BY\s*\"\s*\+\s*(?:sort|orderBy|raw)", c)
        if has_prepared and has_allowlist and not raw_order:
            return True
    elif language == "php":
        if _raw_php_danger(code):
            return False
        # Safe PDO query-builder pattern: SQL may contain allowlisted identifier
        # interpolation and bounded numeric LIMIT, but values are still bound via
        # stmt->execute([...]) or stmt->execute($params).
        has_pdo = _rx(r"->\s*prepare\s*\(\s*\$\w+\s*\)", c) and _raw_php_has_bound_execute(c)
        has_allowlist = (
            _rx(r"\$\w+\s*=\s*\$this->\w+\s*\[", c)
            or _rx(r"\$\w+\s*=\s*\$\w+\s*\[\s*\$\w+\s*\]\s*\?\?", c)
            or _rx(r"private\s+array\s+\$\w+\s*=\s*\[", c)
        )
        has_numeric = _raw_safe_numeric_limit_offset(code, language) or _rx(r"\$\w+\s*=\s*clamp_int\s*\(", c)
        raw_syntax = _rx(r"ORDER\s+BY[\s\S]{0,120}\$raw\b|WHERE[\s\S]{0,120}\$unused\b|LIKE[\s\S]{0,120}\$unused\b", c)
        if has_pdo and (has_allowlist or has_numeric) and not raw_syntax:
            return True
    return False



def _raw_time_based_delay_sql(code: str, language: str) -> bool:
    """Attack-type evidence for time-based blind SQLi in executed SQL."""
    c = _strip_comments(code, language)
    time_expr = (
        _rx(r"\bSLEEP\s*\(", c)
        or _rx(r"\bpg_sleep\s*\(", c)
        or _rx(r"\bWAITFOR\s+DELAY\b", c)
        or _rx(r"\bBENCHMARK\s*\(", c)
        or _rx(r"\bDBMS_LOCK\s*\.\s*SLEEP\s*\(", c)
        or _rx(r"\bIF\s*\([\s\S]{0,240}\bSLEEP\s*\(", c)
        or _rx(r"\bCASE\s+WHEN[\s\S]{0,300}\bSLEEP\s*\(", c)
    )
    return bool(time_expr and _raw_has_valid_execution_sink(code, language))


def _raw_js_safe_sequelize_replacements(code: str) -> bool:
    """Safe Sequelize named replacements: query string has :params, no ${} or concatenation."""
    c = _strip_comments(code, "javascript")
    if not (_rx(r"\.\s*query\s*\(", c) and _rx(r"\breplacements\s*:", c)):
        return False
    safe_named = _rx(
        r"\.\s*query\s*\(\s*(['\"])\s*[\s\S]{0,80}\b(?:SELECT|UPDATE|DELETE|INSERT)\b[\s\S]{0,600}:[A-Za-z_]\w*[\s\S]{0,600}\1\s*,\s*\{\s*replacements\s*:",
        c,
    )
    unsafe_interpolation = _rx(r"\.\s*query\s*\(\s*`[\s\S]{0,600}\$\{", c)
    unsafe_concat = _rx(r"\.\s*query\s*\(\s*(['\"])[\s\S]{0,600}\1\s*\+", c)
    return bool(safe_named and not unsafe_interpolation and not unsafe_concat)


def _raw_php_callable_query_alias(code: str) -> bool:
    """PHP callable-array alias to a known DB execution method, then invoked."""
    c = _strip_comments(code, "php")
    aliases = set()
    for m in re.finditer(
        r"\$(\w+)\s*=\s*\[\s*(?:\$this->\w+|\$\w+)\s*,\s*['\"](?:query|exec)['\"]\s*\]",
        c,
        re.I,
    ):
        aliases.add(m.group(1))
    if not aliases:
        return False
    for alias in aliases:
        call_pat = rf"\${re.escape(alias)}\s*\(\s*(\$\w+|['\"][\s\S]{{0,400}}?['\"])\s*\)"
        for cm in re.finditer(call_pat, c, re.I):
            arg = cm.group(1)
            if arg.startswith(("'", '"')):
                if re.search(r"\b(?:SELECT|UPDATE|DELETE|INSERT)\b", arg, re.I):
                    return True
                continue
            var = re.escape(arg[1:])
            if re.search(rf"\${var}\s*=\s*[^;]{{0,900}}\b(?:SELECT|UPDATE|DELETE|INSERT)\b[^;]*;", c, re.I):
                return True
    return False


def _raw_safe_db_loaded_as_bound_param(code: str, language: str) -> bool:
    """DB-loaded value is safe when it is only passed as a bound parameter to another static SQL statement."""
    c = _strip_comments(code, language)
    if language == "python":
        # Load value with parameterized SELECT, return row[field], then execute a static placeholder query with that value in params.
        loads_value = _rx(r"SELECT[^\n;]+FROM[^\n;]+WHERE[^\n;]+\?", c) and _rx(r"return\s+row\s*\[\s*['\"]\w+['\"]\s*\]", c)
        bound_later = _rx(r"\.execute\s*\(\s*sql\s*,\s*\[[^\]]*\w+[^\]]*\]\s*\)", c) and _rx(r"\?", c)
        no_sql_syntax_use = not _rx(r"\+\s*\w+\s*(?:\+|$)|\{\s*\w+\s*\}", c)
        return loads_value and bound_later and no_sql_syntax_use
    if language == "javascript":
        return _rx(r"SELECT[^;]+\?", c) and _rx(r"db\.(?:all|get|run)\s*\(\s*sql\s*,\s*\[[^\]]*\w+[^\]]*\]", c) and not _rx(r"\+\s*\w+|\$\{\s*\w+\s*\}", c)
    if language == "java":
        return _rx(r"prepareStatement\s*\([^)]*\?", c) and _rx(r"\.set(?:String|Int|Long|Object)\s*\([^,]+,\s*\w+\s*\)", c) and not _rx(r"\+\s*\w+|createStatement\s*\(\s*\)\.execute", c)
    if language == "php":
        if _raw_second_order_stored_sql(code, language) or _raw_php_danger(code) or _rx(r"->\s*query\s*\(", c):
            return False
    return False


def _raw_second_order_stored_sql(code: str, language: str) -> bool:
    c = _strip_comments(code, language)
    sqlish = r"(?:sql_body|sql_text|sql_script|saved_sql|stored_sql|admin_query|query_sql|query_text|where_clause|where_fragment|filter|predicate|fragment|order_expression|order_clause|condition|clause|config)"
    if language == "python":
        # Helper loads SQL-ish DB/config/cache field and caller executes or concatenates it.
        if _rx(rf"SELECT[\s\S]*?(?:{sqlish}|sort_expression|filter_sql)[\s\S]*?(?:fetchone|fetchall)", c) and _rx(r"(?:executescript|execute)\s*\(\s*\w+\s*\)|\+\s*\w+(?:\s|\+|\})", c):
            return True
        if _rx(rf"(?:cache|config|settings|widget|filter|row)\.get\s*\([^)]*(?:{sqlish})[^)]*\)|\w+\s*=\s*\w+\[\s*['\"](?:{sqlish})['\"]\s*\]", c) and _rx(r"ORDER\s+BY\s*\"?\s*\+\s*\w+|AND\s*\"?\s*\+\s*\w+|executescript\s*\(\s*\w+\s*\)", c):
            return True
        if _rx(r"def\s+load\w*sql[\s\S]*?SELECT[\s\S]*?sql_", c) and _rx(r"executescript\s*\(\s*\w+\s*\)", c):
            return True
    elif language == "javascript":
        if _rx(rf"SELECT[\s\S]*?(?:{sqlish})[\s\S]*?db\.(?:get|all)", c) and _rx(r"const\s+\w+\s*=\s*\w+\.(?:query_sql|sql_body|sql_text|where_clause|where_fragment|order_clause|filter|condition)", c) and _rx(r"db\.(?:exec|all|get|run)\s*\(\s*\w+\s*\)", c):
            return True
        if _rx(rf"\b(?:const|let|var)\s+\w+\s*=\s*await\s+\w+\.get\s*\(\s*['\"][^'\"]*(?:{sqlish})[^'\"]*['\"]", c) and (_rx(r"db\.(?:all|get|run|exec)\s*\(\s*\w+\.(?:sql_text|sql_body|query_sql|where_clause|filter|condition|fragment|order_clause)\s*\)", c) or _rx(r"\+\s*\w+\.(?:filter|where_clause|condition|fragment|order_clause|sql_text|sql_body)", c)):
            return True
        if _rx(rf"load\w*\s*\([^)]*\)[\s\S]*?(?:{sqlish})", c) and _rx(r"db\.(?:exec|all|get|run)\s*\(\s*\w+\s*\)", c):
            return True
    elif language == "java":
        if _rx(rf"SELECT[\s\S]*?(?:{sqlish})[\s\S]*?getString\s*\(\s*['\"](?:{sqlish})['\"]\s*\)", c) and _rx(r"\+\s*\w+|execute(?:Query|Update)?\s*\(\s*\w+\s*\)", c):
            return True
        if _rx(r"String\s+\w+\s*=\s*load\w*\s*\(", c) and _rx(r"createStatement\s*\(\s*\)\.execute(?:Query|Update)?\s*\(\s*\w+\s*\)", c):
            return True
        if _rx(r"tenant_config[\s\S]*?getString\s*\(\s*['\"]value['\"]\s*\)", c) and _rx(r"String\s+\w+\s*=\s*\w+\s*\([^)]*\)\s*;[\s\S]*?\+\s*\w+\s*;[\s\S]*?createStatement\s*\(\s*\)\.executeQuery\s*\(\s*sql\s*\)", c):
            return True
        if _rx(r"executeQuery\s*\(\s*rs\.getString\s*\(\s*['\"](?:sql_text|sql_body|query_sql|where_clause|fragment)['\"]\s*\)\s*\)", c):
            return True
        if _rx(r"cache\.put\s*\([^;]*rs\.getString", c) and _rx(r"\+\s*cache\.get\s*\(", c):
            return True
    elif language == "php":
        if _rx(rf"SELECT[\s\S]*?(?:{sqlish})[\s\S]*?fetch", c) and _rx(r"\$\w+\s*=\s*\$\w+\[\s*['\"](?:sql_body|sql_text|query_sql|where_clause|where_fragment|order_clause|filter|condition)['\"]\s*\]", c) and _rx(r"->\s*(?:query|exec|prepare)\s*\(\s*\$\w+\s*\)|\.\s*\$\w+", c):
            return True
        if _rx(r"function\s+load\w*Sql[\s\S]*?SELECT[\s\S]*?sql_", c, re.I) and _rx(r"->\s*query\s*\(\s*\$\w+\s*\)", c):
            return True
        if _rx(r"loadFilter[\s\S]*?where_clause", c) and _rx(r"\.\s*\$where\s*\.", c):
            return True
        # Direct use of fetched SQL-ish column as SQL syntax.
        if _rx(r"fetch\s*\(\s*PDO::FETCH_ASSOC\s*\)|fetch_assoc\s*\(\s*\)", c) and _rx(r'''\$sql\s*=\s*[^;]*\.\s*\$\w+\s*\[\s*['\"](?:where_clause|where_fragment|filter|predicate|condition|order_clause|sql_text|sql_body|query_sql)['\"]\s*\]''', c) and _rx(r"->\s*query\s*\(\s*\$sql\s*\)", c):
            return True
        if _rx(r"fetchColumn\s*\(\s*\)", c) and _rx(r"\$\w+\s*=\s*\$stmt->fetchColumn\s*\(\s*\)", c) and (_rx(r"\$sql\s*=\s*[^;]*\.\s*\$\w+", c) or _rx(r"->\s*query\s*\([^;]*\.\s*\$\w+", c)) and _rx(r"->\s*query\s*\(", c):
            return True
        if _rx(r"\$\w+\s*=\s*\$\w+->query\s*\([^;]*(?:config|saved|filter|report|tenant)[^;]*\)->fetchColumn\s*\(\s*\)", c) and _rx(r"->\s*query\s*\([^;]*\.\s*\$\w+", c):
            return True
        if _rx(r"SELECT[^;]*(?:sql_text|sql_body|query_sql)[^;]*", c) and _rx(r"\$sql\s*=\s*\$stmt->fetchColumn\s*\(\s*\)", c) and _rx(r"->\s*query\s*\(\s*\$sql\s*\)", c):
            return True
        # Generic second-order PHP: value fetched from DB row/assoc result and reused as SQL syntax.
        if _rx(r"fetch_assoc\s*\(\s*\)", c) and _rx(r'''\$\w+\s*=\s*\$\w+\s*\[\s*['\"]\w+['\"]\s*\]''', c) and _rx(r"\$sql\s*=\s*[^;]*\.\s*\$\w+\s*\.[^;]*;[\s\S]*(?:mysqli_query\s*\([^;]*\$sql|->\s*query\s*\(\s*\$sql\s*\))", c):
            return True
        if _rx(r'''function\s+\w*(?:Clause|Filter|Sql|Condition|Order)\w*\s*\([^)]*\)[\s\S]*?SELECT[\s\S]*?(?:tenant_config|config|saved|filter|report|widget)[\s\S]*?fetch\s*\([^)]*\)[\s\S]*?return\s+\$\w+\s*\[\s*['\"](?:value|where_clause|where_fragment|order_clause|filter|condition|sql_text|sql_body|query_sql)['\"]\s*\]''', c) and _rx(r"\$\w+\s*=\s*\$this->\w+\s*\([\s\S]*?\)\s*;[\s\S]*?(?:ORDER\s+BY|WHERE|AND|HAVING|GROUP\s+BY)[^;]*\.\s*\$\w+", c):
            return True
        # Generic loader-helper second-order pattern. Keep this deliberately
        # cheap and bounded for huge PHP repositories: first check that a helper
        # returns a SQL-ish DB field, then check that a SQL-ish variable is
        # concatenated into $sql and executed.
        if (
            re.search(r"return\s+\$\w+\s*\[\s*['\"](?:where_clause|where_fragment|order_clause|filter|condition|sql_text|sql_body|query_sql)['\"]\s*\]", c, re.I)
            and re.search(r"\$(?:where|filter|clause|fragment|condition|sql|query)\w*\s*=\s*\w+\s*\(", c, re.I)
            and re.search(r"\$sql\s*=\s*[^;]{0,500}\.\s*\$(?:where|filter|clause|fragment|condition|sql|query)\w*", c, re.I)
            and re.search(r"->\s*query\s*\(\s*\$sql\s*\)", c, re.I)
        ):
            return True
    return False


def _raw_blind_boolean_sink(code: str, language: str) -> bool:
    c = _strip_comments(code, language)
    if _raw_time_based_delay_sql(code, language):
        return True
    if language == "python":
        # Avoid treating ordinary list-returning repository methods as blind.
        if _rx(r"return\s+\[\s*dict\s*\(\s*row\s*\)\s+for\s+row\s+in", c):
            return False
        return (
            _rx(r"return\s+bool\s*\([^)]*(?:execute|fetchone)", c)
            or _rx(r"return\s+.*fetchone\s*\(\s*\)\s+is\s+not\s+None", c)
            or _rx(r"return\s+\w+\s*\[\s*0\s*\]\s*(?:>|<|==|!=|>=|<=)", c)
            or _rx(r"return\s+\w+\s+is\s+not\s+None(?:\s*(?:$|#|;|\n)|\s+and)", c)
            or (_rx(r"fetchone\s*\(\s*\)", c) and _rx(r"return\s+\w+\s*(?:>|<|==|!=|>=|<=)\s*", c))
            or (_rx(r"fetchone\s*\(\s*\)", c) and _rx(r"return\s+\w+\s*\(\s*\w+\s*\)", c))
            or _rx(r"if\s+.*(?:fetchone\s*\(\s*\)|count\s*[>!=])", c)
        )
    if language == "javascript":
        return (
            _rx(r"return\s+!!\s*(?:\(|\w|await).*db\.(?:get|all|run)", c)
            or (_rx(r"\b(?:const|let|var)\s+(\w+)\s*=\s*await\s+\w+\.(?:get|all)\s*\(", c) and _rx(r"return\s+(?:!!\s*\w+|Boolean\s*\(\s*\w+\s*\)|\w+\s*!==?\s*null|\w+\s*!==?\s*undefined)", c))
            or _rx(r"return\s+Boolean\s*\(\s*\w+\s*\)", c)
            or _rx(r"return\s+.*\.length\s*>\s*0", c)
            or (_rx(r"\b(?:login|authenticate|permission|feature|token|session|isAdmin|valid|allowed)", c) and _rx(r"return\s+(?:!!|Boolean|row|rows|result)", c))
        )
    if language == "java":
        return (
            _rx(r"\.executeQuery\s*\([^;]+\)\.next\s*\(\s*\)", c)
            or _rx(r"return\s+\w+\.next\s*\(\s*\)", c)
            or (_rx(r"\b(?:login|authenticate|permission|token|session|isAdmin|allowed|valid)\b", c) and _rx(r"\.next\s*\(\s*\)", c))
        )
    if language == "php":
        return (
            _rx(r"return\s*\(\s*bool\s*\)\s*\$?\w*->\s*query\s*\([^;]+\)->\s*fetch", c)
            or _rx(r"return\s*\$?\w*->\s*query\s*\([^;]+\)->\s*fetch(?:Column)?\s*\([^)]*\)\s*(?:>|!==|!=|==)", c)
            or _rx(r"return\s*\$\w+\s*&&\s*\$\w+->\s*(?:num_rows|fetch_assoc\s*\(\s*\))\s*(?:>|!==|!=|==)", c)
            or _rx(r"return\s*\$\w+->\s*num_rows\s*>\s*0", c)
            or _rx(r"return\s*mysqli_num_rows\s*\(\s*\$\w+\s*\)\s*>\s*0", c)
            or _rx(r"return\s*\$\w+\s*&&\s*\$\w+->fetch_assoc\s*\(\s*\)\s*!==\s*null", c)
            or _rx(r"return\s*\$\w+\s*\[[^\]]+\]\s*(?:>|<|==|!=|>=|<=)", c)
            or (_rx(r"(?:num_rows|fetch\s*\(|fetch_assoc\s*\(|mysqli_fetch_assoc\s*\(|fetchColumn\s*\()", c) and _rx(r"\b(?:login|authenticate|permission|feature|token|session|allowed|valid|canDelete|canAccess|canEdit|enabled|registered)\b", c))
        )
    return False


def _raw_php_danger(code: str) -> bool:
    c = _strip_comments(code, "php")
    if _rx(r"\$allowed\s*=\s*\[", c) and _rx(r"\$(?:safe\w*|sort)\s*=\s*\$allowed\s*\[", c) and _rx(r"ORDER\s+BY[\s\S]{0,100}\.\s*\$(?:safe\w*|sort)\b", c) and not _rx(r"ORDER\s+BY[\s\S]{0,100}\.\s*\$raw\b", c):
        return False
    return (
        _rx(r"->\s*query\s*\(\s*['\"][\s\S]*?(?:SELECT|UPDATE|DELETE|INSERT)[\s\S]*?['\"]\s*\.", c)
        or _rx(r"->\s*query\s*\([\s\S]*?(?:SELECT|UPDATE|DELETE|INSERT)[\s\S]*?\.\s*(?:norm|trim|strtolower|filter_input)\s*\(", c)
        or _rx(r"->\s*query\s*\(\s*\$\w+\s*\)", c)
        or _rx(r"->\s*query\s*\(\s*\"[^\"]*(?:SELECT|UPDATE|DELETE|INSERT)[^\"]*\$\w+", c)
        or _rx(r"mysqli_query\s*\([^,]+,\s*\"[^\"]*\$\w+", c)
        or _rx(r"\bDB::select\s*\([\s\S]*?(?:SELECT|UPDATE|DELETE|INSERT)[\s\S]*?\.\s*\$\w+", c)
        or _rx(r"->\s*prepare\s*\([\s\S]*?(?:ORDER\s+BY|WHERE|AND|IN\s*\()[\s\S]*?\.\s*\$(?:raw|q|term|email|id|ids|sort|order)", c)
        or _rx(r"\$\w+\s*=\s*\"[^\"]*(?:SELECT|UPDATE|DELETE|INSERT)[^\"]*\$\w+[^\"]*\"\s*;[\s\S]*->\s*query\s*\(\s*\$\w+\s*\)", c)
        or _rx(r"\$\w+\s*=\s*[^;]*(?:SELECT|UPDATE|DELETE|INSERT)[^;]*\.\s*\$\w+[^;]*;[\s\S]*(?:->\s*query|mysqli_query)\s*\([^;]*\$\w+", c)
        or (_rx(r"implode\s*\(\s*['\"][^'\"]*['\"]\s*,\s*\$\w+\s*\)", c) and _rx(r"IN\s*\(\s*\$\w+\s*\)", c))
    )



def _raw_has_valid_execution_sink(code: str, language: str) -> bool:
    c = _strip_comments(code, language)
    if language == "python":
        return _rx(r"\.execute(?:many|script)?\s*\(", c) or _rx(r"\b\w+\s*=\s*[\w.]+\.execute\b[\s\S]*\b\w+\s*\(", c)
    if language == "javascript":
        return _rx(r"\.(?:all|get|run|each|exec|query|execute|raw)\s*\(", c) or _rx(r"\b\w+\s*=\s*[\w.]+\.(?:all|get|run|each|exec|query)\.bind\s*\([^)]*\)[\s\S]*?\b\w+\s*\(", c)
    if language == "java":
        return _rx(r"\.(?:executeQuery|executeUpdate|execute|queryForList|query|update)\s*\(", c) or _rx(r"\bprepareStatement\s*\(", c) or _rx(r"\bcreateNativeQuery\s*\(", c)
    if language == "php":
        return _rx(r"->\s*(?:query|exec|execute|prepare)\s*\(", c) or _rx(r"\bmysqli_(?:query|execute)\s*\(", c) or _rx(r"\bDB::(?:select|statement|raw)\s*\(", c) or _raw_php_callable_query_alias(code)
    return False


def _raw_python_alias_execute_unsafe(code: str) -> bool:
    c = _strip_comments(code, "python")
    aliases = [m.group(1) for m in re.finditer(r"\b(\w+)\s*=\s*[\w.]+\.execute\b", c)]
    if not aliases:
        return False
    raw_source = _rx(r"\b\w+\s*=\s*norm\s*\(|request\.|\.GET\b|\.POST\b|args?\.get\(|\[[\s]*['\"][\w-]+['\"][\s]*\]", c)
    raw_concat = _rx(r"\b\w+\s*=\s*['\"][^'\"]*(?:WHERE|AND|OR|=)[^'\"]*['\"]\s*\+\s*\w+|\+\s*\w+\s*\+\s*['\"]", c)
    return any(_rx(rf"\b{re.escape(a)}\s*\([^)]*\+[^)]*\)", c) for a in aliases) and (raw_source or raw_concat)


def _raw_python_raw_concat_executed(code: str) -> bool:
    c = _strip_comments(code, "python")
    if _rx(r"\bsql\s*=\s*[^\n;]*(?:SELECT|UPDATE|DELETE|INSERT)[^\n;]*\+\s*norm\s*\(", c) and _rx(r"\.execute\s*\(\s*sql\s*,", c):
        return True
    # Query builder with bound params can still be vulnerable if a raw search
    # value is concatenated into SQL text, e.g. LIKE '%" + term + "%'.
    if _rx(r"\bsql\s*\+=\s*[\s\S]{0,220}?(?:LIKE|=)[\s\S]{0,160}?\+\s*\w+\s*\+", c) and _rx(r"\.execute\s*\(\s*sql\s*,", c):
        return True
    if _raw_python_alias_execute_unsafe(code):
        return True
    for m in re.finditer(r"\b(\w+)\s*=\s*[^\n;]*(?:SELECT|UPDATE|DELETE|INSERT)[^\n;]*\+[^\n;]*", c, re.I):
        v = m.group(1)
        if _rx(rf"\.execute\s*\(\s*{re.escape(v)}\s*\)", c):
            return True
        if _rx(rf"\.execute\s*\(\s*{re.escape(v)}\s*,\s*\[[^\]]*\]\s*\)", c) and _rx(r"['\"]\s*\+\s*(?:norm\s*\(|\w+)\s*\+\s*['\"]", m.group(0)):
            return True
    return False


def _raw_js_inband_danger(code: str) -> bool:
    c = _strip_comments(code, "javascript")
    has_knex_raw_concat = _rx(r"\.raw\s*\(", c) and _rx(r"(?:SELECT|UPDATE|DELETE|INSERT)", c) and _rx(r"\+\s*(?:raw|sort|email|q|term|req|query)\b", c)
    has_bound_template_alias = _rx(r"`[\s\S]*?(?:SELECT|UPDATE|DELETE|INSERT)[\s\S]*?\$\{", c) and _rx(r"\.bind\s*\(", c) and _rx(r"return\s+\w+\s*\(\s*\w+\s*\)", c)
    has_direct_template_exec = _rx(r"\.(?:exec|query|execute)\s*\(\s*`[\s\S]*?(?:SELECT|UPDATE|DELETE|INSERT)[\s\S]*?\$\{", c)
    return bool(has_knex_raw_concat or has_bound_template_alias or has_direct_template_exec)


def _raw_java_inband_danger(code: str) -> bool:
    c = _strip_comments(code, "java")
    return (
        _rx(r'''String\s+(\w+)\s*=\s*['"][^'"]*(?:SELECT|UPDATE|DELETE|INSERT)[^'"]*['"]\s*\+\s*\w+[\s\S]*?\.queryForList\s*\(\s*\1\s*\)''', c)
        or _rx(r'''String\s+(\w+)\s*=\s*['"][^'"]*(?:SELECT|UPDATE|DELETE|INSERT)[^'"]*['"]\s*\+\s*\w+[\s\S]*?\.query\s*\(\s*\1\s*[,)]''', c)
    )


def _raw_java_safe_allowlist_order(code: str) -> bool:
    c = _strip_comments(code, "java")
    safe_vars: list[str] = []

    # Generic allowlist ternary forms:
    #   String sort = allowed.contains(sortRaw) ? sortRaw : "created_at";
    #   String sort = allowed.contains(req.getParameter("sort")) ? req.getParameter("sort") : "created_at";
    for m in re.finditer(
        r"String\s+(\w+)\s*=\s*\w+\.contains\s*\([^;?]+\)\s*\?\s*[^:;]+:\s*['\"]\w+['\"]",
        c,
        re.I | re.S,
    ):
        safe_vars.append(m.group(1))

    # Map/get style allowlists can also produce safe identifiers.
    for m in re.finditer(
        r"String\s+(\w+)\s*=\s*\w+\.getOrDefault\s*\([^;]+,\s*['\"]\w+['\"]\s*\)",
        c,
        re.I | re.S,
    ):
        safe_vars.append(m.group(1))

    if not safe_vars:
        return False

    for safe in set(safe_vars):
        uses_safe_order = _rx(rf"ORDER\s+BY[\s\S]{{0,160}}\+\s*{re.escape(safe)}\b", c)
        if uses_safe_order:
            return True
    return False

def _raw_java_safe_jpa_native_params(code: str) -> bool:
    """Safe JPA native query with named parameters bound via setParameter.

    Conservative: createNativeQuery must receive a static SQL string with named
    placeholders, and every placeholder must be bound with setParameter.
    """
    c = _strip_comments(code, "java")
    m = re.search(
        r'(?:javax\.persistence\.)?Query\s+(\w+)\s*=\s*\w+\.createNativeQuery\s*\(\s*(["\'])([\s\S]*?)\2\s*\)',
        c,
        re.I,
    )
    if not m:
        return False
    qvar, sql = m.group(1), m.group(3)
    if "+" in sql or "${" in sql:
        return False
    placeholders = set(re.findall(r":([A-Za-z_]\w*)", sql))
    if not placeholders:
        return False
    bound = set(re.findall(rf'\b{re.escape(qvar)}\.setParameter\s*\(\s*["\']([A-Za-z_]\w*)["\']\s*,', c))
    if not placeholders.issubset(bound):
        return False
    if _rx(r"createStatement\s*\(\s*\)\.execute(?:Query|Update)?\s*\(", c):
        return False
    if _rx(r"createNativeQuery\s*\([^)]*\+", c):
        return False
    return True


def _raw_php_safe_prepared_only(code: str) -> bool:
    c = _strip_comments(code, "php")
    if _raw_second_order_stored_sql(code, "php"):
        return False
    has_prepare = _rx(r"->\s*prepare\s*\(", c) or _rx(r"mysqli_prepare\s*\(", c) or _rx(r"\$\w+\s*=\s*\$\w+->prepare\s*\(", c)
    has_binding = _raw_php_has_bound_execute(c) or _rx(r"->\s*bind_param\s*\(", c) or _rx(r"mysqli_stmt_bind_param\s*\(", c)
    has_raw_query = _rx(r"->\s*(?:query|exec)\s*\(", c) or _rx(r"mysqli_query\s*\(", c)
    has_raw_prepare_syntax = (
        _rx(r"->\s*prepare\s*\([\s\S]*?(?:ORDER\s+BY|GROUP\s+BY|HAVING|WHERE|AND|OR|IN\s*\()[\s\S]*?\.\s*\$", c)
        or _rx(r"\$\w+\s*=\s*[^;]*(?:SELECT|UPDATE|DELETE|INSERT)[^;]*\.\s*\$\w+[^;]*;[\s\S]*->\s*prepare\s*\(\s*\$\w+\s*\)", c)
    )
    # Prepared execution is safe only when dynamic values are placeholders or
    # bound parameters. It must not suppress raw SQL syntax interpolation such as
    # ORDER BY " . $raw.
    return bool(has_prepare and has_binding and not has_raw_query and not has_raw_prepare_syntax)

def _apply_raw_evidence_override(raw_code: str, language: str, label: str, attack_type: str, score: float, source: str, all_signals: set[str], ml_score: float | None = None, ml_attack_type: str | None = None) -> tuple[str, str, float, str, set[str]]:
    """Final evidence-aware correction layer. Conservative and source/sink based."""
    signals = set(all_signals)

    # V11 model-first correction:
    # If the CNN+BiLSTM model is very confident that a file is vulnerable,
    # do not let a broad raw fallback erase the model's decision simply because
    # the exact sink syntax is uncommon (for example PHP callable-array aliases).
    # This is not a new filename or pattern rule; it preserves the primary ML
    # decision and keeps raw rules as a safety/explanation layer.
    ml_specific = (ml_attack_type or attack_type or "NONE")
    confident_ml_vuln = (
        ml_score is not None
        and ml_score >= 0.95
        and label == "VULNERABLE"
        and ml_specific in {"IN_BAND", "BLIND", "SECOND_ORDER"}
    )

    if not _raw_has_valid_execution_sink(raw_code, language):
        # Option B / ML-first but evidence-aware:
        # A very confident model may drive the vulnerability verdict, but it must
        # not turn documentation, comments, or standalone SQL-looking strings into
        # an executed SQLi finding when no DB sink exists.  This keeps the model
        # central while preserving the source→sink requirement of SAST.
        return "SAFE", "NONE", min(score, 0.25), "raw_no_valid_sql_sink", signals

    # Source provenance wins over boolean sink. Stored/config/DB SQL syntax is SECOND_ORDER even if a result is checked.
    if _raw_second_order_stored_sql(raw_code, language):
        signals.add("SECOND_ORDER_FLOW")
        return "VULNERABLE", "SECOND_ORDER", max(score, 0.90), "raw_second_order_flow", signals

    if _raw_time_based_delay_sql(raw_code, language) and label in ("VULNERABLE", "SUSPICIOUS"):
        signals.add("BOOLEAN_SINK")
        return "VULNERABLE", "BLIND", max(score, 0.90, float(ml_score or 0.0)), "raw_time_based_blind", signals

    # Strong safe identifier proof must run BEFORE raw concat/template danger.
    # Safe ORDER BY / FROM syntax may be executed as one SQL string, so the ML
    # and UNSAFE_EXEC token can overreact unless we prove that every dynamic
    # identifier came from an allowlist/map.
    if _raw_safe_allowlisted_identifier_sql(raw_code, language):
        signals.add("WHITELIST_VAR")
        signals.add("SAFE_EXEC")
        return "SAFE", "NONE", min(score, 0.08), "raw_safe_allowlisted_identifier", signals

    if language == "python" and _raw_python_raw_concat_executed(raw_code):
        signals.add("SQL_CONCAT")
        signals.add("UNSAFE_EXEC")
        py_clean = _strip_comments(raw_code, language)
        data_returning = _rx(r"fetchall\s*\(\s*\)|return\s+.*\.execute\s*\([^\n]+\)\.fetchall", py_clean)
        if _raw_blind_boolean_sink(raw_code, language) and not data_returning:
            signals.add("BOOLEAN_SINK")
            return "VULNERABLE", "BLIND", max(score, 0.90), "raw_python_blind_concat", signals
        return "VULNERABLE", "IN_BAND", max(score, 0.90), "raw_python_inband_concat", signals

    # DB-loaded scalar values are safe when they are only passed as bound parameters.
    if _raw_safe_db_loaded_as_bound_param(raw_code, language):
        signals.add("SAFE_EXEC")
        return "SAFE", "NONE", min(score, 0.08), "raw_safe_db_loaded_bound_param", signals

    # Strong safe overrides: tied to an executed sink, and only when no stored SQL execution evidence exists.
    if language == "java" and _raw_java_safe_jpa_native_params(raw_code):
        signals.add("SAFE_EXEC")
        return "SAFE", "NONE", min(score, 0.08), "raw_java_jpa_native_params", signals
    if language == "java" and _raw_java_safe_allowlist_order(raw_code):
        signals.add("WHITELIST_VAR")
        return "SAFE", "NONE", min(score, 0.08), "raw_java_allowlist_order", signals
    if language == "php" and _raw_php_safe_prepared_only(raw_code):
        signals.add("SAFE_EXEC")
        return "SAFE", "NONE", min(score, 0.08), "raw_php_prepared_params", signals
    if _raw_safe_sqlite_param_js(raw_code):
        danger = signals & {"SQL_CONCAT", "FSTRING_SQL", "FSTRING_SQL_RAW", "UNSAFE_EXEC", "SECOND_ORDER_FLOW"}
        if not danger:
            signals.add("SAFE_EXEC")
            return "SAFE", "NONE", min(score, 0.08), "raw_safe_sqlite_params", signals
    if _raw_safe_query_builder(raw_code, language):
        signals.add("SAFE_EXEC")
        return "SAFE", "NONE", min(score, 0.08), "raw_safe_query_builder", signals
    if _raw_safe_numeric_limit_offset(raw_code, language):
        signals.add("SAFE_NUMERIC_VAR")
        return "SAFE", "NONE", min(score, 0.08), "raw_safe_numeric_limit_offset", signals

    if _raw_safe_numeric_limit_offset(raw_code, language):
        signals.add("SAFE_NUMERIC_VAR")
        return "SAFE", "NONE", min(score, 0.08), "raw_safe_numeric_limit_offset", signals

    # From this point onward, ML confidence may keep the file VULNERABLE,
    # but attack-type selection is evidence-aware.  In previous V11/V12 runs,
    # accepting ml_specific blindly caused regressions such as IN_BAND being
    # reported as SECOND_ORDER when no stored/config/DB-loaded SQL fragment
    # existed.  Therefore the type is chosen by concrete flow evidence first:
    # SECOND_ORDER only with stored/config/DB-loaded SQL syntax, BLIND only with
    # boolean/time-decision evidence, otherwise direct unsafe SQL is IN_BAND.

    # Dangerous PHP raw SQL, with BLIND type when the raw query controls a boolean/security decision.
    if language == "php" and _raw_php_danger(raw_code):
        signals.add("SQL_CONCAT")
        if _raw_blind_boolean_sink(raw_code, language):
            signals.add("BOOLEAN_SINK")
            return "VULNERABLE", "BLIND", max(score, 0.90), "raw_php_blind_sqli", signals
        return "VULNERABLE", "IN_BAND", max(score, 0.90), "raw_php_sqli", signals
    if label in ("VULNERABLE", "SUSPICIOUS") and _raw_blind_boolean_sink(raw_code, language):
        signals.add("BOOLEAN_SINK")
        return "VULNERABLE", "BLIND", max(score, 0.90), "raw_blind_boolean_sink", signals

    if confident_ml_vuln:
        # Preserve the model as the primary vulnerability engine without letting
        # an unsupported attack-type argmax override stronger semantic evidence.
        if "SECOND_ORDER_FLOW" in signals or _raw_second_order_stored_sql(raw_code, language):
            signals.add("SECOND_ORDER_FLOW")
            return "VULNERABLE", "SECOND_ORDER", max(score, float(ml_score)), "ml_confident_with_second_order_evidence", signals
        if "BOOLEAN_SINK" in signals or _raw_blind_boolean_sink(raw_code, language):
            signals.add("BOOLEAN_SINK")
            return "VULNERABLE", "BLIND", max(score, float(ml_score)), "ml_confident_with_blind_evidence", signals
        if signals & {"SQL_CONCAT", "FSTRING_SQL", "FSTRING_SQL_RAW", "UNSAFE_EXEC"}:
            return "VULNERABLE", "IN_BAND", max(score, float(ml_score)), "ml_confident_vulnerable_evidence_typed", signals
        return "VULNERABLE", ("IN_BAND" if ml_specific == "SECOND_ORDER" else ml_specific), max(score, float(ml_score)), "ml_confident_vulnerable", signals

    return label, attack_type, score, source, signals


# ── Language detection ────────────────────────────────────────────────────────

def detect_language(filename: str) -> str:
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix}'. Allowed: .py, .js, .php, .java",
        )
    return ALLOWED_EXTENSIONS[suffix]


# ── File reading ──────────────────────────────────────────────────────────────

async def read_uploaded_code(file: UploadFile) -> RawCodePayload:
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing file name")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    try:
        raw_code = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded text")
    return RawCodePayload(
        originalName=file.filename,
        language=detect_language(file.filename),
        size=len(content),
        rawCode=raw_code,
    )


# ── Hard override check ───────────────────────────────────────────────────────

def _is_hard_vulnerable(signals: set[str]) -> bool:
    """
    Return True if the signal combination ALWAYS means vulnerable,
    regardless of what the ML model scored.

    This prevents a high concentration of SAFE_EXEC tokens in a long
    file from diluting the score of a single deeply buried vulnerable
    function.
    """
    for combo in ALWAYS_VULNERABLE_COMBOS:
        if combo.issubset(signals):
            return True
    return False


def _rule_score(signals: set[str]) -> float:
    """
    Compute a rule-based risk score from detected signals.
    Used when the ML model is not loaded, and also as a floor
    when the ML score disagrees with strong rule signals.
    """
    # ── Gap-A v2 safe-overrides (ordered: most specific first) ──────────────
    # FSTRING_SQL_RAW is non-negotiable — always vulnerable, even if other
    # safe signals are present in the same chunk.
    if "FSTRING_SQL_RAW" in signals:
        return 0.90

    # SAFE_NUMERIC_VAR + FSTRING_SQL (no concat) → safe LIMIT/OFFSET pattern
    if (
        "SAFE_NUMERIC_VAR" in signals
        and "FSTRING_SQL" in signals
        and "SQL_CONCAT" not in signals
    ):
        return 0.08

    # SAFE_PLACEHOLDER_LIST + SAFE_EXEC → safe IN(?,?,?) pattern
    if (
        "SAFE_PLACEHOLDER_LIST" in signals
        and "SAFE_EXEC" in signals
        and "SQL_CONCAT" not in signals
    ):
        return 0.08

    # WHITELIST_VAR marks a strict-allowlist-validated identifier. When NO
    # SQL_CONCAT (raw-input concat is real injection) AND NO FSTRING_SQL_RAW
    # (raw var interpolated despite whitelist context — already handled
    # above), the f-string is safe by construction.
    if "WHITELIST_VAR" in signals and "SQL_CONCAT" not in signals:
        return 0.10

    # Numeric-only interpolation into SQL syntax (LIMIT/OFFSET) is safe even
    # when the DB API call has a single SQL argument. The normalizer emits
    # SAFE_NUMERIC_VAR for values derived from Number/int/min/max/clamp. Treat
    # this as a safe deterministic guard only when no raw SQL-construction signal
    # exists.
    if (
        "SAFE_NUMERIC_VAR" in signals
        and not (signals & {"SQL_CONCAT", "FSTRING_SQL", "FSTRING_SQL_RAW", "SECOND_ORDER_FLOW", "DB_LOADED_VAR"})
    ):
        return 0.08

    if _is_hard_vulnerable(signals):
        return 0.90

    n_high = sum(1 for s in signals if s in HIGH_SIGNALS)
    has_unsafe = "UNSAFE_EXEC" in signals
    has_sql    = "SQL_STRING" in signals
    has_safe   = "SAFE_EXEC"  in signals

    if n_high >= 2:
        return 0.88
    if n_high == 1:
        return 0.75 if has_unsafe else 0.72
    if has_unsafe and has_sql:
        return 0.62
    if has_safe and not has_sql:
        return 0.08
    return 0.25


def _fuse_scores(
    ml_score: float | None,
    rule_score: float,
    signals: set[str],
) -> tuple[float, str]:
    """
    Combine ML score and rule-based score.

    Returns (fused_score, source_tag). The source_tag is exposed in the API
    response as `verdictSource` so the frontend can show which layer drove
    the verdict. Possible values:

        "rule_safety_net"     — ML model unavailable; rule layer is the verdict.
        "ml_overrides_rule"   — ML strongly disagreed with rule and won
                                (whitelist-validated f-string pattern).
        "ml"                  — ML score won and rule was neutral or agreed.
        "ml+rule"             — ML and rule both flagged the chunk; max(ml, rule).
        "rule"                — Rule beat ML (e.g. ML was confused on a
                                builder-pattern chunk that the rule clearly
                                marked dangerous via SQL_CONCAT).

    Policy (ML-primary, rule = soft prior, with calibrated escape clauses):

    1. If ML model is NOT loaded → fall back to deterministic rule score
       → source = "rule_safety_net".

    2. ML loaded:

       a. CONFIDENT-SAFE ESCAPE: ml_score < 0.05 AND no high-confidence rule
          signals → trust ML. Obvious-safe cases (parameterised, ORM, no SQL).
          → source = "ml".

       b. VALIDATED F-STRING OVERRIDE: ml_score < 0.05 AND FSTRING_SQL is
          present BUT SQL_CONCAT is NOT → trust ML. The "validated dynamic
          SQL" pattern: f-string built from whitelist-validated values.
          → source = "ml_overrides_rule".

          We require the absence of SQL_CONCAT because string concatenation
          (`"SELECT ... " + var`) is almost always genuine injection.

       c. OTHERWISE → max(ml_score, rule_score). Conservative default.
          - If the winner is rule and rule >= ml + 0.10 → source = "rule".
          - If both are roughly aligned (within 0.10) → source = "ml+rule".
          - If ml is the winner by a clear margin → source = "ml".

    The hard-override list (ALWAYS_VULNERABLE_COMBOS) is kept ONLY as a
    failsafe path when ML is unavailable.
    """
    if ml_score is None:
        if _is_hard_vulnerable(signals):
            return max(0.90, rule_score), "rule_safety_net"
        return rule_score, "rule_safety_net"

    has_fstring = "FSTRING_SQL" in signals
    has_fstring_raw = "FSTRING_SQL_RAW" in signals
    has_concat  = "SQL_CONCAT"  in signals
    has_unsafe_exec = "UNSAFE_EXEC" in signals
    has_safe_exec = "SAFE_EXEC" in signals
    has_whitelist = "WHITELIST_VAR" in signals

    # 0. FSTRING_SQL_RAW is non-negotiable — raw var interpolated despite
    # whitelist context. Real injection. Rule wins regardless of ML.
    if has_fstring_raw:
        return max(rule_score, 0.90), "rule"

    # 2a. Chunks with no SQL/security semantic signal at all are boilerplate
    # (class shell, constructor, imports, DTOs).  The ML model can have a
    # noise floor on these short chunks; do not let them dominate file-level
    # max-pooling.
    sql_semantic_signals = (
        HIGH_SIGNALS | MEDIUM_SIGNALS | SAFE_SIGNALS |
        {"WHITELIST_VAR", "DB_LOADED_VAR", "BOOLEAN_SINK", "SQL_STRING"}
    )
    if not (signals & sql_semantic_signals):
        return min(ml_score, rule_score), "rule"

    # 2b. Confident-safe, no dangerous rule signal at all → ML wins outright
    if ml_score < 0.05 and not has_fstring and not has_concat:
        return ml_score, "ml"

    # 2b. Whitelist-validated f-string: ML strongly says safe AND a strict
    # allowlist marker is present AND no concat. Without WHITELIST_VAR we
    # never trust ML over rule on FSTRING_SQL — raw f-string is real injection.
    if (ml_score < 0.05 and has_fstring and has_whitelist and not has_concat):
        return ml_score, "ml_overrides_rule"

    # 2b-bis. Strong-whitelist override: WHITELIST_VAR / SAFE_PLACEHOLDER_LIST
    # / SAFE_NUMERIC_VAR present AND no real injection signals (FSTRING_SQL_RAW,
    # SQL_CONCAT) → trust the rule layer's safe verdict regardless of ML score.
    # ML weights trained before flow signals existed cannot reason about them;
    # the rule layer's deterministic flow analysis is more reliable here.
    has_safe_flow = (
        has_whitelist
        or has_safe_exec
        or "SAFE_PLACEHOLDER_LIST" in signals
        or "SAFE_NUMERIC_VAR" in signals
    )
    # SAFE_NUMERIC_VAR is special: many APIs execute safe LIMIT/OFFSET SQL as a
    # single SQL string, so UNSAFE_EXEC can be present even though the value flow
    # is numeric-only and bounded. Do not let that single-arg sink alone block
    # the safe guard. For all other flows, UNSAFE_EXEC remains dangerous.
    if (
        "SAFE_NUMERIC_VAR" in signals
        and not (signals & {"FSTRING_SQL_RAW", "FSTRING_SQL", "SQL_CONCAT", "SECOND_ORDER_FLOW", "DB_LOADED_VAR"})
        and rule_score < 0.30
    ):
        return rule_score, "semantic_safe_guard"
    has_dangerous_flow = (
        has_fstring_raw
        or has_fstring
        or has_concat
        or has_unsafe_exec
        or "SECOND_ORDER_FLOW" in signals
    )
    if has_safe_flow and not has_dangerous_flow and rule_score < 0.30:
        return rule_score, "semantic_safe_guard"

    # 2c. Default: either side can raise the alarm. Tag depends on which won.
    fused = max(ml_score, rule_score)
    diff  = ml_score - rule_score
    if diff >= 0.10:
        source = "ml"
    elif diff <= -0.10:
        source = "rule"
    else:
        source = "ml+rule"
    return fused, source


# ── Chunk-level analysis ──────────────────────────────────────────────────────

def _analyse_chunk(
    code: str,
    chunk_name: str,
    extra_safe_funcs: set[str] | None = None,
    extra_numeric_funcs: set[str] | None = None,
    extra_db_loaded_funcs: set[str] | None = None,
) -> dict:
    """
    Run preprocessing + ML inference on a single code chunk.
    Returns a dict with signals, rule_score, ml_score, fused_score.
    """
    cleaned  = clean_code(code)
    tokens   = tokenize_code(cleaned)
    norm     = normalize_tokens(
        tokens,
        extra_safe_funcs=extra_safe_funcs,
        extra_numeric_funcs=extra_numeric_funcs,
        extra_db_loaded_funcs=extra_db_loaded_funcs,
    )
    vec      = vectorize_tokens(norm, VOCABULARY)
    signals  = set(norm)

    # Tiny chunks (e.g. empty class bodies, decorator-only stubs, single-line
    # passthrough methods) tokenise to <8 meaningful tokens. The model has a
    # noise floor on such inputs (~0.1–0.3 score range) because the embedding
    # average is ill-defined on so few tokens. Skip ML on these and use the
    # rule score alone — if there are no signals, the rule score will be a low
    # baseline (~0.25), which then can't push the file-level verdict up.
    SKIP_ML_BELOW = 8
    if len(norm) < SKIP_ML_BELOW:
        ml_score             = None
        ml_attack_type       = "NONE"
        ml_attack_type_id    = 0
        ml_attack_conf       = 0.0
        ml_attack_probs      = {}
        ml_type_head_available = False
    else:
        ml_result = run_inference(vec["tokenIds"])
        if ml_result is None:
            ml_score             = None
            ml_attack_type       = "NONE"
            ml_attack_type_id    = 0
            ml_attack_conf       = 0.0
            ml_attack_probs      = {}
            ml_type_head_available = False
        else:
            ml_score             = ml_result["riskScore"]
            ml_attack_type       = ml_result.get("attackType", "NONE")
            ml_attack_type_id    = ml_result.get("attackTypeId", 0)
            ml_attack_conf       = ml_result.get("attackTypeConfidence", 0.0)
            ml_attack_probs      = ml_result.get("attackTypeProbs", {})
            ml_type_head_available = ml_result.get("attackTypeAvailable", False)

    r_score = _rule_score(signals)
    f_score, f_source = _fuse_scores(ml_score, r_score, signals)

    return {
        "chunkName":            chunk_name,
        "signals":              signals,
        "norm":                 norm,
        "tokenIds":             vec["tokenIds"],
        "mlScore":              ml_score,
        "ruleScore":            r_score,
        "fusedScore":           f_score,
        "verdictSource":        f_source,
        "seqLen":               len(norm),
        # Gap A — attack-type prediction (per-chunk)
        "attackType":           ml_attack_type,
        "attackTypeId":         ml_attack_type_id,
        "attackTypeConfidence": ml_attack_conf,
        "attackTypeProbs":      ml_attack_probs,
        "attackTypeAvailable":  ml_type_head_available,
    }


# ── Pattern builder ───────────────────────────────────────────────────────────

def _build_patterns(signals: set[str], worst_chunk: str) -> list[SuspiciousPattern]:
    patterns: list[SuspiciousPattern] = []

    if "FSTRING_SQL" in signals:
        patterns.append(SuspiciousPattern(
            pattern="FSTRING_SQL",
            description=(
                f"F-string SQL injection in '{worst_chunk}': "
                "user variable embedded directly in SQL via f\"...{{var}}...\""
            ),
            severity="HIGH",
        ))
    if "SQL_CONCAT" in signals:
        patterns.append(SuspiciousPattern(
            pattern="SQL_CONCAT",
            description=(
                f"SQL string concatenation in '{worst_chunk}': "
                "SQL_STRING + variable — user input merged into query via + operator"
            ),
            severity="HIGH",
        ))
    if "UNSAFE_EXEC" in signals:
        patterns.append(SuspiciousPattern(
            pattern="UNSAFE_EXEC",
            description=(
                f"Unsafe execute() in '{worst_chunk}': "
                "cursor.execute(query) called with a single argument — no parameter tuple"
            ),
            severity="HIGH" if patterns else "MEDIUM",
        ))

    return patterns



def _raw_fast_detection(raw_code: str, language: str) -> ScanDetectionInfo | None:
    """Fast whole-file source/sink proof before expensive chunk+ML pass.

    Used for huge generated repositories and broken-syntax samples.  It only
    returns when evidence is strong and sink-specific; otherwise the normal
    ML/chunk pipeline runs.
    """
    def make(label: str, attack_type: str, score: float, source: str, explanation: str) -> ScanDetectionInfo:
        probs = {
            "NONE": 1.0 if label == "SAFE" else 0.0,
            "IN_BAND": 1.0 if attack_type == "IN_BAND" else 0.0,
            "BLIND": 1.0 if attack_type == "BLIND" else 0.0,
            "SECOND_ORDER": 1.0 if attack_type == "SECOND_ORDER" else 0.0,
        }
        # This fast path intentionally does NOT execute the neural model.  The
        # audit fields make that explicit so we never mistake raw source/sink
        # evidence for an ML decision.
        loaded = model_is_loaded()
        return ScanDetectionInfo(
            riskScore=round(score, 4),
            label=label,
            confidence=round(score, 4),
            vulnerabilityType="SQL Injection" if label == "VULNERABLE" else None,
            explanation=explanation,
            suspiciousPatterns=[],
            modelLoaded=loaded,
            verdictSource=source,
            attackType=attack_type,
            attackTypeConfidence=1.0 if label == "VULNERABLE" else 0.0,
            attackTypeProbs=probs,
            attackTypeAvailable=True,
            mlExecuted=False,
            mlRiskScore=None,
            mlPredictedVerdict=None,
            mlPredictedAttackType=None,
            mlAttackTypeConfidence=0.0,
            mlAttackTypeProbabilities={},
            ruleScore=round(score, 4),
            finalRiskScore=round(score, 4),
            finalVerdict=label,
            fusionReason=source,
            decisionSource="raw_evidence_fast_path",
            rawEvidenceOverrideApplied=True,
            preOverrideVerdict=None,
            preOverrideAttackType=None,
            preOverrideRiskScore=None,
            worstChunk="__raw_fast__",
            chunkCount=0,
            modelVersion=_model_version(),
            modelSequenceLength=_model_sequence_length(),
        )

    if _raw_second_order_stored_sql(raw_code, language):
        return make("VULNERABLE", "SECOND_ORDER", 0.90, "raw_second_order_flow", "Stored/config/DB-loaded SQL fragment reaches SQL syntax or direct execution.")

    if _raw_safe_allowlisted_identifier_sql(raw_code, language):
        return make("SAFE", "NONE", 0.08, "raw_safe_allowlisted_identifier", "Dynamic SQL identifier is selected only from a strict allowlist/map before execution.")

    if language == "javascript" and _raw_js_inband_danger(raw_code):
        return make("VULNERABLE", "IN_BAND", 0.90, "raw_js_sqli", "Raw JavaScript SQL reaches a framework/alias execution sink.")
    if language == "java" and _raw_java_inband_danger(raw_code):
        return make("VULNERABLE", "IN_BAND", 0.90, "raw_java_sqli", "Raw Java SQL reaches JdbcTemplate/query execution.")

    if _raw_safe_numeric_limit_offset(raw_code, language):
        return make("SAFE", "NONE", 0.08, "raw_safe_numeric_limit_offset", "LIMIT/OFFSET values are numeric and bounded before SQL execution.")

    if _raw_time_based_delay_sql(raw_code, language):
        return make("VULNERABLE", "BLIND", 0.90, "raw_time_based_blind", "Unsafe SQL contains a time-delay expression, which is blind SQL injection evidence.")

    if language == "php" and _raw_php_danger(raw_code):
        if _raw_blind_boolean_sink(raw_code, language):
            return make("VULNERABLE", "BLIND", 0.90, "raw_php_blind_sqli", "Raw PHP SQL controls a boolean/security decision.")
        return make("VULNERABLE", "IN_BAND", 0.90, "raw_php_sqli", "Raw PHP input is concatenated/interpolated into executed SQL.")

    if not _raw_has_valid_execution_sink(raw_code, language):
        return make("SAFE", "NONE", 0.25, "raw_no_valid_sql_sink", "No valid SQL execution sink detected; SQL-looking text alone is not SQL injection.")

    if language == "python" and _raw_python_raw_concat_executed(raw_code):
        py_clean = _strip_comments(raw_code, language)
        data_returning = _rx(r"fetchall\s*\(\s*\)|return\s+.*\.execute\s*\([^\n]+\)\.fetchall", py_clean)
        if _raw_blind_boolean_sink(raw_code, language) and not data_returning:
            return make("VULNERABLE", "BLIND", 0.90, "raw_python_blind_concat", "Unsafe SQL result controls a boolean/security decision.")
        return make("VULNERABLE", "IN_BAND", 0.90, "raw_python_inband_concat", "Raw input is concatenated into executed SQL text.")


    if language == "java" and _raw_java_safe_allowlist_order(raw_code):
        return make("SAFE", "NONE", 0.08, "raw_java_allowlist_order", "ORDER BY value is selected by exact Set.contains allowlist before execution.")
    if language == "java" and _raw_java_safe_jpa_native_params(raw_code):
        return make("SAFE", "NONE", 0.08, "raw_java_jpa_named_params", "JPA native query uses named placeholders and binds all parameters with setParameter.")

    if language == "php" and _raw_php_safe_prepared_only(raw_code):
        return make("SAFE", "NONE", 0.08, "raw_php_prepared_params", "Only prepared statements with bound parameters are executed.")

    if _raw_safe_sqlite_param_js(raw_code):
        return make("SAFE", "NONE", 0.08, "raw_safe_sqlite_params", "SQLite-style ? placeholders with separately passed params.")

    if _raw_safe_query_builder(raw_code, language):
        return make("SAFE", "NONE", 0.08, "raw_safe_query_builder", "Dynamic query builder uses allowlisted identifiers/bounded numeric values and bound params.")

    return None

# ── Model 1: Detection ────────────────────────────────────────────────────────

def _build_detection(
    raw_code: str,
    language: str,
    # These are the file-level norm/vec passed in from process_uploaded_code
    # for backward compat with history items that don't store chunk data
    file_norm: list[str] | None = None,
    file_token_ids: list[int] | None = None,
    force_ml: bool = False,
) -> ScanDetectionInfo:
    """
    Chunk-level detection with max-pool aggregation.

    Steps:
    1. Split code into function/method chunks
    2. Analyse each chunk independently (preprocessing + ML)
    3. Take the chunk with the highest fused score (max-pool)
    4. Apply hard override: if ANY chunk has HARD_VULNERABLE signals → VULNERABLE
    5. Build the final verdict from the worst chunk's score
    """
    # V9 final policy: ML-first runtime.
    #
    # The old raw fast path returned a final verdict before neural inference.
    # It was useful for speed, but audit showed that regular execution became
    # rule/raw-heavy even though V9 is strong enough to run on almost every file.
    # Therefore, normal detection always goes through chunk preprocessing + ML.
    # Raw evidence is still applied later by _apply_raw_evidence_override() as an
    # evidence-aware safety/correction layer, not as a model bypass.
    #
    # Keep _raw_fast_detection() defined for historical debugging only; do not
    # call it from the default production/test path.

    chunks = split_into_chunks(raw_code, language)

    # Compute file-level "safe-returning helper" set BEFORE chunking each
    # function. This lets a chunk recognize that its assignment
    # `safe_col, safe_dir = normalize_sort(...)` is whitelist-validated even
    # though `normalize_sort` is defined in a different chunk.
    full_tokens = tokenize_code(clean_code(raw_code))
    file_safe_funcs = extract_safe_returning_funcs(full_tokens)
    file_numeric_funcs = extract_numeric_returning_funcs(full_tokens)
    file_db_loaded_funcs = extract_db_returning_funcs(full_tokens)

    # Analyse every chunk
    results = []
    for chunk_name, chunk_code in chunks:
        r = _analyse_chunk(
            chunk_code,
            chunk_name,
            extra_safe_funcs=file_safe_funcs,
            extra_numeric_funcs=file_numeric_funcs,
            extra_db_loaded_funcs=file_db_loaded_funcs,
        )
        results.append(r)

    # Max-pool: pick the chunk with the highest fused score
    worst = max(results, key=lambda r: r["fusedScore"])

    # Aggregate all signals across all chunks (union)
    all_signals: set[str] = set()
    for r in results:
        all_signals |= r["signals"]

    ml_chunks = [r for r in results if r["mlScore"] is not None]
    model_loaded = bool(ml_chunks)
    ml_worst = max(ml_chunks, key=lambda r: r["mlScore"]) if ml_chunks else None
    ml_file_score = ml_worst["mlScore"] if ml_worst is not None else None
    ml_file_verdict = _label_from_score(ml_file_score)
    ml_file_attack_type = (
        ml_worst["attackType"]
        if ml_worst is not None and ml_file_verdict != "SAFE"
        else "NONE"
    )
    ml_file_attack_conf = ml_worst["attackTypeConfidence"] if ml_worst is not None else 0.0
    ml_file_attack_probs = ml_worst["attackTypeProbs"] if ml_worst is not None else {}
    file_rule_score = max((r["ruleScore"] for r in results), default=None)

    # Hard-override floor is now a FAILSAFE for the no-ML path only.
    # When the ML model is loaded, _fuse_scores() has already let ML decide,
    # including for whitelist-guarded patterns where FSTRING_SQL appears in
    # safe context. Re-applying the rule floor here would re-introduce the
    # false positives the new fusion policy is designed to eliminate.
    final_score   = worst["fusedScore"]
    verdict_source = worst["verdictSource"]
    if not model_loaded and _is_hard_vulnerable(all_signals):
        final_score = max(final_score, 0.90)
        verdict_source = "rule_safety_net"

    # Determine label
    if final_score >= 0.70:
        label = "VULNERABLE"
    elif final_score >= 0.45:
        label = "SUSPICIOUS"
    else:
        label = "SAFE"

    # Build patterns from the worst chunk's signals
    worst_signals = worst["signals"]
    patterns = _build_patterns(worst_signals, worst["chunkName"])

    # Build explanation
    vuln_type = None
    if label == "VULNERABLE":
        vuln_type = "SQL Injection"
        if patterns:
            pnames = " + ".join(p.pattern for p in patterns)
            chunk_info = (
                f" (found in function '{worst['chunkName']}')"
                if worst["chunkName"] != "__file__"
                else ""
            )
            explanation = (
                f"SQL injection pattern detected{chunk_info}: {pnames}. "
                f"Risk score: {final_score:.0%}. "
                f"File analysed in {len(results)} chunk(s) — worst chunk scored {worst['fusedScore']:.0%}."
            )
        else:
            explanation = f"High risk score ({final_score:.0%}) from ML model."

    elif label == "SUSPICIOUS":
        vuln_type = "Possible SQL Injection"
        explanation = (
            f"Suspicious patterns detected (score {final_score:.0%}). "
            f"Manual review recommended."
        )
    else:
        if "SAFE_EXEC" in all_signals:
            explanation = (
                f"Parameterized queries detected throughout the file (SAFE_EXEC signals). "
                f"Risk score: {final_score:.0%}."
            )
        else:
            explanation = f"No SQL injection patterns detected. Risk score: {final_score:.0%}."

    # ── Gap A — File-level attack-type aggregation ──────────────────────────────
    # Rule: among chunks classified as vulnerable (fusedScore >= 0.45), take
    # the most common predicted attack type (mode). If multiple types are tied,
    # the priority order is SECOND_ORDER > BLIND > IN_BAND (rarest-most-specific
    # first — proposal pages 4-5 highlight these as the harder cases).
    # If NO chunks are flagged vulnerable: attackType is NONE.
    #
    # In addition to ML aggregation, a deterministic rule layer based on
    # flow signals (BOOLEAN_SINK, DB_LOADED_VAR) provides a strong override
    # when ML type-head is untrained or uncertain. This fills the gap when
    # the type head's argmax is wrong but the flow signals are present.
    type_head_available = any(r["attackTypeAvailable"] for r in results)

    vuln_chunks = [r for r in results if r["fusedScore"] >= 0.45]
    if not vuln_chunks or not type_head_available:
        file_attack_type       = "NONE"
        file_attack_type_id    = 0
        file_attack_confidence = 0.0
        file_attack_probs      = {"NONE": 1.0, "IN_BAND": 0.0, "BLIND": 0.0, "SECOND_ORDER": 0.0}
    else:
        # Mode with priority tiebreak (most-specific class wins on ties)
        type_priority = {"SECOND_ORDER": 3, "BLIND": 2, "IN_BAND": 1, "NONE": 0}
        type_votes: dict[str, int] = {}
        for r in vuln_chunks:
            t = r["attackType"]
            type_votes[t] = type_votes.get(t, 0) + 1

        winner = max(
            type_votes.items(),
            key=lambda kv: (kv[1], type_priority.get(kv[0], 0)),
        )[0]
        file_attack_type    = winner
        file_attack_type_id = {"NONE": 0, "IN_BAND": 1, "BLIND": 2, "SECOND_ORDER": 3}[winner]

        winning_chunks = [r for r in vuln_chunks if r["attackType"] == winner]
        file_attack_confidence = round(
            sum(r["attackTypeConfidence"] for r in winning_chunks) / len(winning_chunks), 4
        )

        all_classes = ("NONE", "IN_BAND", "BLIND", "SECOND_ORDER")
        file_attack_probs = {}
        for cls in all_classes:
            vals = [
                r["attackTypeProbs"].get(cls, 0.0)
                for r in vuln_chunks
                if r["attackTypeProbs"]
            ]
            file_attack_probs[cls] = (
                round(sum(vals) / len(vals), 4) if vals else 0.0
            )

    # ── ML-specific type preservation ──────────────────────────────────────────
    # V11 learned several attack-type distinctions that do not always emit a
    # simple BOOLEAN_SINK token (for example time-based BLIND SQLi).  If the
    # most risky ML chunk is extremely confident and predicts a specific type,
    # keep that type as the primary type unless a stronger semantic rule below
    # has explicit SECOND_ORDER/BOOLEAN evidence.
    ml_strong_specific_type = (
        ml_file_score is not None
        and ml_file_score >= 0.95
        and ml_file_attack_type in {"BLIND", "SECOND_ORDER"}
        and label in ("VULNERABLE", "SUSPICIOUS")
    )
    # Option B: keep ML as the main verdict engine, but do not let a
    # high-confidence attack-type argmax override concrete flow evidence.
    # SECOND_ORDER requires stored/config/DB-loaded SQL fragment evidence;
    # BLIND requires boolean/time-decision evidence.  Otherwise the rule layer
    # below is allowed to type direct unsafe SQL as IN_BAND.
    raw_second_order_evidence = _raw_second_order_stored_sql(raw_code, language)
    raw_blind_evidence = "BOOLEAN_SINK" in all_signals or _raw_time_based_delay_sql(raw_code, language) or _raw_blind_boolean_sink(raw_code, language)
    ml_specific_type_supported = (
        (ml_file_attack_type == "SECOND_ORDER" and raw_second_order_evidence)
        or (ml_file_attack_type == "BLIND" and raw_blind_evidence)
    )
    if ml_strong_specific_type and ml_specific_type_supported:
        file_attack_type = ml_file_attack_type
        file_attack_type_id = {"NONE": 0, "IN_BAND": 1, "BLIND": 2, "SECOND_ORDER": 3}[file_attack_type]

    # ── Rule-based attack-type override using flow signals ─────────────────────
    # When type-head argmax is uncertain (often the case until model fully
    # trains on flow signals), use deterministic flow-signal logic:
    #   BOOLEAN_SINK + dangerous SQL signal → BLIND
    #   SECOND_ORDER_FLOW → SECOND_ORDER
    #   Other dangerous SQL → IN_BAND
    # The override applies whenever the file is VULNERABLE/SUSPICIOUS — file
    # is unsafe by ML, and we just need to label the kind of unsafe.
    if label in ("VULNERABLE", "SUSPICIOUS"):
        has_bool_sink = "BOOLEAN_SINK" in all_signals or _raw_time_based_delay_sql(raw_code, language) or _raw_blind_boolean_sink(raw_code, language)
        has_second_order_flow = _raw_second_order_stored_sql(raw_code, language)
        has_dangerous = bool(all_signals & {"FSTRING_SQL", "FSTRING_SQL_RAW", "SQL_CONCAT", "UNSAFE_EXEC", "SECOND_ORDER_FLOW"})
        rule_attack_type = None
        if has_second_order_flow:
            rule_attack_type = "SECOND_ORDER"
        elif has_bool_sink and has_dangerous:
            rule_attack_type = "BLIND"
        elif has_dangerous:
            rule_attack_type = "IN_BAND"
        if rule_attack_type is not None:
            # Evidence-aware attack typing: a confident ML verdict is important,
            # but the attack-type head can still confuse IN_BAND/BLIND/SECOND_ORDER.
            # Let concrete flow evidence choose the type whenever present.
            if (not ml_strong_specific_type) or (not ml_specific_type_supported) or rule_attack_type == ml_file_attack_type:
                file_attack_type = rule_attack_type
                file_attack_type_id = {"NONE": 0, "IN_BAND": 1, "BLIND": 2, "SECOND_ORDER": 3}[rule_attack_type]

    # Sanity: if VULNERABLE label but attack type came back NONE, default IN_BAND
    if label == "VULNERABLE" and file_attack_type == "NONE":
        file_attack_type    = "IN_BAND"
        file_attack_type_id = 1

    # Final raw-code evidence correction.  This layer fixes cases where the ML
    # score or semantic token stream loses exact source/sink context.  It never
    # relies on filenames; it recognizes parameter binding, numeric-only SQL
    # syntax, second-order stored SQL execution, PHP interpolation, and boolean
    # decision sinks.
    pre_override_label = label
    pre_override_attack_type = file_attack_type
    pre_override_score = final_score
    pre_override_source = verdict_source
    label, file_attack_type, final_score, verdict_source, all_signals = _apply_raw_evidence_override(
        raw_code=raw_code,
        language=language,
        label=label,
        attack_type=file_attack_type,
        score=final_score,
        source=verdict_source,
        all_signals=all_signals,
        ml_score=ml_file_score,
        ml_attack_type=ml_file_attack_type,
    )
    # For audit purposes, an override means the raw-evidence layer changed the
    # actual decision (verdict or attack type).  If it only adjusted the score or
    # explanation while keeping the same decision, we keep the earlier ML/fusion
    # source as the decision owner.
    raw_override_applied = (
        label != pre_override_label
        or file_attack_type != pre_override_attack_type
    )
    decision_owner_source = verdict_source if raw_override_applied else pre_override_source
    file_attack_type_id = {"NONE": 0, "IN_BAND": 1, "BLIND": 2, "SECOND_ORDER": 3}.get(file_attack_type, 0)
    if label == "SAFE":
        vuln_type = None
        patterns = []
        file_attack_confidence = 0.0
        file_attack_probs = {"NONE": 1.0, "IN_BAND": 0.0, "BLIND": 0.0, "SECOND_ORDER": 0.0}
        explanation = f"No SQL injection patterns detected. Risk score: {final_score:.0%}."
    elif label == "VULNERABLE" and not patterns:
        vuln_type = "SQL Injection"
        explanation = f"SQL injection evidence detected by source/sink analysis. Risk score: {final_score:.0%}."

    return ScanDetectionInfo(
        riskScore=round(final_score, 4),
        label=label,
        confidence=round(final_score, 4),
        vulnerabilityType=vuln_type,
        explanation=explanation,
        suspiciousPatterns=patterns,
        modelLoaded=model_loaded,
        verdictSource=verdict_source,
        # Gap A — attack-type fields
        attackType=file_attack_type,
        attackTypeConfidence=file_attack_confidence,
        attackTypeProbs=file_attack_probs,
        attackTypeAvailable=type_head_available,
        # ML-vs-fusion audit fields
        mlExecuted=model_loaded,
        mlRiskScore=round(ml_file_score, 4) if ml_file_score is not None else None,
        mlPredictedVerdict=ml_file_verdict,
        mlPredictedAttackType=ml_file_attack_type,
        mlAttackTypeConfidence=round(float(ml_file_attack_conf), 4),
        mlAttackTypeProbabilities=ml_file_attack_probs or {},
        ruleScore=round(file_rule_score, 4) if file_rule_score is not None else None,
        finalRiskScore=round(final_score, 4),
        finalVerdict=label,
        fusionReason=verdict_source,
        decisionSource=_decision_source_bucket(decision_owner_source, model_loaded),
        rawEvidenceOverrideApplied=raw_override_applied,
        preOverrideVerdict=pre_override_label,
        preOverrideAttackType=pre_override_attack_type,
        preOverrideRiskScore=round(pre_override_score, 4),
        worstChunk=worst["chunkName"],
        chunkCount=len(results),
        modelVersion=_model_version(),
        modelSequenceLength=_model_sequence_length(),
    )


# ── Main scan pipeline ────────────────────────────────────────────────────────

async def process_uploaded_code(file: UploadFile, current_user: dict) -> ScanResponse:
    """
    Model 1 pipeline:
      Upload → file-level preprocessing (for display) + chunk-level detection
    Fix is NOT generated here — only when user explicitly requests it.
    """
    raw_payload = await read_uploaded_code(file)

    # File-level preprocessing (for display in frontend)
    cleaned_code      = clean_code(raw_payload.rawCode)
    tokens            = tokenize_code(cleaned_code)
    normalized_tokens = normalize_tokens(tokens)
    vectorized_result = vectorize_tokens(normalized_tokens, VOCABULARY)

    # Chunk-level detection (the actual verdict)
    detection = _build_detection(
        raw_code=raw_payload.rawCode,
        language=raw_payload.language,
    )

    # Audit log
    scan_id = await log_audit_event(
        action="code_scanned",
        actor_user_id=current_user["id"],
        details={
            "originalName":    raw_payload.originalName,
            "language":        raw_payload.language,
            "size":            raw_payload.size,
            "sequenceLength":  len(normalized_tokens),
            "rawCode":         raw_payload.rawCode,
            "cleanedCode":     cleaned_code,
            "tokens":          tokens,
            "normalizedTokens": normalized_tokens,
            "detection":       detection.model_dump(),
        },
    )

    return ScanResponse(
        scanId=scan_id,
        file=ScanFileInfo(
            originalName=raw_payload.originalName,
            language=raw_payload.language,
            size=raw_payload.size,
        ),
        preprocessing=ScanPreprocessingInfo(
            cleanedCode=cleaned_code,
            tokens=tokens,
            normalizedTokens=normalized_tokens,
            sequenceLength=len(normalized_tokens),
        ),
        vectorization=ScanVectorizationInfo(
            tokenIds=vectorized_result["tokenIds"],
            paddedLength=vectorized_result["paddedLength"],
            truncated=vectorized_result["truncated"],
        ),
        detection=detection,
    )


# ── Model 2: Generate fix (user-triggered only) ───────────────────────────────

async def generate_fix_for_scan(
    scan_id: str,
    current_user: dict,
) -> GenerateFixResponse:
    """Model 2 — runs only after explicit Generate Fix and never changes Model 1 verdict."""
    audit_logs = get_audit_logs_collection()
    try:
        doc = await audit_logs.find_one({"_id": ObjectId(scan_id), "action": "code_scanned", "actorUserId": current_user["id"]})
    except Exception:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found")
    details = doc.get("details", {})
    raw_code = details.get("rawCode", "")
    language = details.get("language", "python")
    normalized_tokens = details.get("normalizedTokens", [])
    saved_detection = details.get("detection", {}) or {}
    if not raw_code:
        raise HTTPException(status_code=422, detail="Cannot generate fix: original code not stored for this scan.")
    if str(saved_detection.get("label", "")).upper() == "SAFE":
        raise HTTPException(status_code=422, detail="No fix generated: Model 1 classified this scan as SAFE. The saved detection did not find an executable SQL injection sink. Generate Fix is only available for VULNERABLE or SUSPICIOUS scans.")
    attack_type = saved_detection.get("attackType", "NONE")
    chunks = split_into_chunks(raw_code, language)
    best_fix = None
    best_model_prediction = None
    for chunk_name, chunk_code in chunks:
        norm = normalize_tokens(tokenize_code(clean_code(chunk_code)))
        vec = vectorize_tokens(norm, VOCABULARY)
        model_prediction = run_fix_inference(vec["tokenIds"], language=language, attack_type=attack_type, normalized_tokens=norm, raw_code=chunk_code)
        fix_result = generate_fix(chunk_code, language, norm, preferred_fix_type=(model_prediction or {}).get("fixType"), model_prediction=model_prediction)
        if fix_result is not None:
            best_fix = fix_result; best_model_prediction = model_prediction; break
    if best_fix is None:
        vec = vectorize_tokens(normalized_tokens, VOCABULARY)
        best_model_prediction = run_fix_inference(vec["tokenIds"], language=language, attack_type=attack_type, normalized_tokens=normalized_tokens, raw_code=raw_code)
        best_fix = generate_fix(raw_code, language, normalized_tokens, preferred_fix_type=(best_model_prediction or {}).get("fixType"), model_prediction=best_model_prediction)
    if best_fix is None:
        raise HTTPException(status_code=422, detail="No SQL injection pattern detected — no fix can be generated.")
    raw_model_type = (best_model_prediction or {}).get("fixType")
    final_source = "rule_fallback" if best_model_prediction is None else ("model2+template" if raw_model_type == best_fix.fix_type else "model2+semantic_guard")
    return GenerateFixResponse(
        vulnerabilityType=best_fix.vulnerability_type, fixType=best_fix.fix_type, fixStrategy=best_fix.fix_strategy, explanation=best_fix.explanation, fixedCode=best_fix.fixed_code,
        fixSource=final_source, modelFixType=raw_model_type, modelFixStrategy=(best_model_prediction or {}).get("fixStrategy"), modelConfidence=(best_model_prediction or {}).get("confidence"), modelProbabilities=(best_model_prediction or {}).get("allProbabilities"),
    )

# ── History ───────────────────────────────────────────────────────────────────

async def get_user_scan_history(
    current_user: dict,
    limit: int = 50,
) -> ScanHistoryListResponse:
    audit_logs = get_audit_logs_collection()
    docs = (
        await audit_logs.find(
            {"action": "code_scanned", "actorUserId": current_user["id"]}
        )
        .sort("timestamp", -1)
        .limit(limit)
        .to_list(length=limit)
    )

    history = []
    for doc in docs:
        details = doc.get("details", {})
        saved_detection = details.get("detection", {})
        detection_label = saved_detection.get("label") if saved_detection else None
        history.append(
            ScanHistoryItemResponse(
                id=str(doc["_id"]),
                originalName=details.get("originalName", "unknown"),
                language=details.get("language", "unknown"),
                size=details.get("size", 0),
                sequenceLength=details.get("sequenceLength", 0),
                timestamp=doc.get("timestamp"),
                detectionLabel=detection_label,
            )
        )
    return ScanHistoryListResponse(history=history, count=len(history))


async def get_scan_history_item(
    history_id: str,
    current_user: dict,
) -> ScanResponse:
    audit_logs = get_audit_logs_collection()

    try:
        doc = await audit_logs.find_one(
            {
                "_id": ObjectId(history_id),
                "action": "code_scanned",
                "actorUserId": current_user["id"],
            }
        )
    except Exception:
        raise HTTPException(status_code=404, detail="History item not found")

    if not doc:
        raise HTTPException(status_code=404, detail="History item not found")

    details           = doc.get("details", {})
    normalized_tokens = details.get("normalizedTokens", [])
    raw_code          = details.get("rawCode", "")
    language          = details.get("language", "python")

    vectorized_result = vectorize_tokens(normalized_tokens, VOCABULARY)

    # Restore saved detection; re-run only if missing
    saved_detection = details.get("detection")
    if saved_detection:
        detection = ScanDetectionInfo(**saved_detection)
    else:
        detection = _build_detection(raw_code=raw_code, language=language)

    return ScanResponse(
        scanId=history_id,
        file=ScanFileInfo(
            originalName=details.get("originalName", "unknown"),
            language=details.get("language", "unknown"),
            size=details.get("size", 0),
        ),
        preprocessing=ScanPreprocessingInfo(
            cleanedCode=details.get("cleanedCode", ""),
            tokens=details.get("tokens", []),
            normalizedTokens=normalized_tokens,
            sequenceLength=details.get("sequenceLength", 0),
        ),
        vectorization=ScanVectorizationInfo(
            tokenIds=vectorized_result["tokenIds"],
            paddedLength=vectorized_result["paddedLength"],
            truncated=vectorized_result["truncated"],
        ),
        detection=detection,
    )
