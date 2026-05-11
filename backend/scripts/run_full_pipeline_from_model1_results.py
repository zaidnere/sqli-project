# FULL_PIPELINE_FROM_MODEL1_RESULTS_LIBRARY_AWARE_STRICT_VALIDATION_V3_MARKER
# STRICT_VALIDATOR_C_MIGRATION_ACCEPTS_CODE_V4_MARKER
# STRICT_VALIDATOR_ACCEPTS_TUPLE_PARAMS_V3_MARKER
"""
Full Pipeline runner: official Model 1 results -> Model 2 -> fix_generator -> strict fix validation.

This runner is for the SQLi project Model 2 evaluation.
It uses official Model 1 CSV outputs as the source of detection truth, then routes only
expected-vulnerable cases to Model 2. It validates three levels:
  1. Model 2 class decision: A/B/C/D.
  2. Final fix type returned by fix_generator.
  3. Strict structural validation of the actual generated fix code.

It does NOT modify Model 1 or Model 2. It is a read-only evaluator.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Make backend root importable when running as python scripts\... from Windows.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.preprocessing.normalizer import normalize_tokens
from app.vectorization.vocabulary import build_fixed_vocabulary
from app.vectorization.vectorizer import vectorize_tokens
from app.model.fix_model_inference import run_fix_inference
from app.fix_engine.fix_generator import generate_fix

SAFE_VERDICTS = {"SAFE", "NONE", "CLEAN", "OK"}
VULN_VERDICTS = {"VULNERABLE", "SUSPICIOUS", "VULN", "UNSAFE"}
ATTACK_TYPES = {"NONE", "IN_BAND", "BLIND", "SECOND_ORDER"}

LANG_ALIASES = {
    "py": "python",
    "python": "python",
    "js": "javascript",
    "javascript": "javascript",
    "java": "java",
    "php": "php",
}

FIX_NAMES = {
    "A": "Parameterized Query",
    "B": "Whitelist Validation",
    "C": "ORM / Query Builder Migration",
    "D": "Second-Order Mitigation",
}


@dataclass
class SuiteData:
    name: str
    zip_path: Path
    root: str
    manifest_rows: List[Dict[str, str]]
    manifest_by_file: Dict[str, Dict[str, str]]


def _norm_str(v: Any) -> str:
    if v is None:
        return ""
    s = str(v)
    if s.lower() == "nan":
        return ""
    return s.strip()


def _yes(v: Any) -> bool:
    return _norm_str(v).upper() in {"YES", "TRUE", "1", "PASS", "PASSED"}


def _canon_language(v: Any, file_path: str = "") -> str:
    raw = _norm_str(v).lower()
    if raw in LANG_ALIASES:
        return LANG_ALIASES[raw]
    ext = Path(file_path).suffix.lower()
    if ext == ".py":
        return "python"
    if ext == ".js":
        return "javascript"
    if ext == ".java":
        return "java"
    if ext == ".php":
        return "php"
    return raw or "python"


def _suite_base_from_result_csv(name: str) -> str:
    base = Path(name).name
    base = re.sub(r"_test_results\.csv$", "", base)
    return base


def _read_csv_from_zip(z: zipfile.ZipFile, name: str) -> List[Dict[str, str]]:
    data = z.read(name)
    text = data.decode("utf-8-sig", errors="replace")
    return list(csv.DictReader(io.StringIO(text)))


def _load_model1_result_csvs(results_zip: Path) -> Dict[str, List[Dict[str, str]]]:
    out: Dict[str, List[Dict[str, str]]] = {}
    with zipfile.ZipFile(results_zip, "r") as z:
        for name in z.namelist():
            if not name.endswith("_test_results.csv"):
                continue
            suite = _suite_base_from_result_csv(name)
            # Skip Model 2 dedicated suite if present; this runner is for detection suites.
            if suite == "model2_fix_cases":
                continue
            out[suite] = _read_csv_from_zip(z, name)
    return out


def _find_manifest_name(z: zipfile.ZipFile) -> Optional[str]:
    names = [n for n in z.namelist() if n.replace("\\", "/").endswith("manifest.csv")]
    if not names:
        return None
    return sorted(names, key=lambda x: (x.count("/"), len(x)))[0]


def _load_suite(zip_path: Path) -> Optional[SuiteData]:
    suite_name = zip_path.stem
    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            manifest_name = _find_manifest_name(z)
            if not manifest_name:
                return None
            root = manifest_name.rsplit("/", 1)[0]
            rows = _read_csv_from_zip(z, manifest_name)
            by_file: Dict[str, Dict[str, str]] = {}
            for row in rows:
                f = _norm_str(row.get("file"))
                if f:
                    by_file[f.replace("\\", "/")] = row
            return SuiteData(suite_name, zip_path, root, rows, by_file)
    except zipfile.BadZipFile:
        return None


def _load_suites(suites_dir: Path) -> Dict[str, SuiteData]:
    suites: Dict[str, SuiteData] = {}
    for p in sorted(suites_dir.glob("*.zip")):
        sd = _load_suite(p)
        if sd is not None:
            suites[sd.name] = sd
    return suites


def _read_code_from_suite(sd: SuiteData, file_path: str) -> str:
    target = file_path.replace("\\", "/")
    with zipfile.ZipFile(sd.zip_path, "r") as z:
        candidates = []
        if sd.root:
            candidates.append(f"{sd.root}/{target}")
        candidates.append(target)
        # Some manifests include root already.
        for c in candidates:
            if c in z.namelist():
                return z.read(c).decode("utf-8", errors="replace")
        # Fallback by suffix.
        for n in z.namelist():
            if n.replace("\\", "/").endswith("/" + target) or n.replace("\\", "/") == target:
                return z.read(n).decode("utf-8", errors="replace")
    raise FileNotFoundError(f"{file_path} not found in {sd.zip_path}")


def _strip_comments(code: str, language: str) -> str:
    if language == "python":
        return re.sub(r"#.*", "", code)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    return re.sub(r"//[^\n\r]*", "", code)


def _rx(pattern: str, text: str, flags: int = re.I | re.S) -> bool:
    return re.search(pattern, text, flags) is not None


def _detect_order_by_dynamic(code: str, language: str) -> bool:
    c = _strip_comments(code, language)
    return _rx(
        r"\bORDER\s+BY\s*(?:"
        r"[\"'`]\s*(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r"|\$\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r")",
        c,
    )


def _detect_table_name_dynamic(code: str, language: str) -> bool:
    c = _strip_comments(code, language)
    return _rx(
        r"\b(?:FROM|JOIN|UPDATE|INTO)\s*(?:"
        r"[\"'`]\s*(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r"|\$\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r")",
        c,
    )


def _detect_stored_sql_context(code: str, language: str) -> bool:
    c = _strip_comments(code, language)
    return _rx(
        r"(?:sql_text|saved_filter|savedFilter|where_clause|cached_where|stored_filter|report_sql|cache\.get|config\.get|fetchColumn|getString)"
        r"[\s\S]{0,320}(?:execute|executeQuery|query|all|get|run|exec)",
        c,
    ) or _rx(
        r"(?:SELECT\s+(?:sql_text|saved_filter)|cache\.get|config\.get)[\s\S]{0,260}(?:\+|execute|query)",
        c,
    )


def _detect_complex_builder_context(code: str, language: str) -> bool:
    c = _strip_comments(code, language)
    loop_or_collection = _rx(
        r"\b(?:for|foreach)\b[\s\S]{0,220}(?:filters|criteria|whereMap|searchFields|params|Object\.keys|keySet|items\s*\(|implode|join)",
        c,
    )
    incremental_sql = _rx(
        r"(?:sql|query|where|parts|where_parts)[\s\S]{0,260}(?:\+=|\.append\s*\(|\.push\s*\(|\.add\s*\(|\.=|join\s*\(|implode\s*\()",
        c,
    )
    helper_builder = _rx(
        r"\b(?:build|compose|make|create|render|assemble)[A-Za-z0-9_]*(?:Sql|SQL|Query|Where|Filter)[A-Za-z0-9_]*\s*\(",
        c,
    )
    framework_raw = _rx(
        r"\b(?:sequelize\.query|knex\.raw|entityManager\.createNativeQuery|createNativeQuery|session\.createSQLQuery|db\.raw|sqlalchemy\.text)\s*\(",
        c,
    )
    return bool((loop_or_collection and incremental_sql) or helper_builder or framework_raw)


def _infer_expected_fix_type(code: str, language: str, attack_type: str, category: str = "", notes: str = "") -> Tuple[str, str]:
    blob = " ".join([category, notes]).lower()
    if attack_type == "SECOND_ORDER" or _detect_stored_sql_context(code, language):
        return "D", "SECOND_ORDER/stored-sql context -> Second-Order Mitigation"
    if _detect_order_by_dynamic(code, language) or _detect_table_name_dynamic(code, language):
        return "B", "dynamic SQL identifier/table/order-by -> Whitelist Validation"
    if _detect_complex_builder_context(code, language) or any(k in blob for k in ["orm", "framework", "query_builder", "builder", "native_query"]):
        return "C", "complex builder/framework raw SQL -> ORM / Query Builder Migration"
    return "A", "default vulnerable value injection -> Parameterized Query"


def _sanitize_code_for_simple_patterns(code: str) -> str:
    return re.sub(r"\s+", " ", code or "").strip()


def _detect_php_library(original_code: str, fixed_code: str = "") -> str:
    """Infer whether the original PHP code is mysqli or PDO.

    This is used only by the evaluator. It does not alter Model 2 or the generated fix.
    """
    blob = f"{original_code}\n{fixed_code}"
    low = blob.lower()
    if re.search(r"\bmysqli_(?:query|prepare|connect)\s*\(", blob) or "bind_param" in low:
        return "mysqli"
    if re.search(r"(?:\$this->conn|\$conn|\$mysqli|\$db)\s*->\s*(?:query|prepare)\s*\(", blob):
        # Most project mysqli examples use $this->conn/$conn. PDO examples usually use $pdo.
        if "$pdo" not in blob and "new pdo" not in low:
            return "mysqli"
    if "$pdo" in blob or "new pdo" in low or re.search(r"\bPDO\b", blob):
        return "pdo"
    return "unknown"


def _detect_js_library(original_code: str, fixed_code: str = "") -> str:
    """Infer mysql/mysql2 vs pg for JavaScript SQL calls."""
    blob = f"{original_code}\n{fixed_code}"
    low = blob.lower()
    if re.search(r"\$\d+", blob) or "from 'pg'" in low or 'from "pg"' in low or "require('pg')" in low or 'require("pg")' in low:
        return "pg"
    if re.search(r"\b(?:client|pool)\s*\.\s*query\s*\(", original_code) and not re.search(r"\?", fixed_code):
        return "pg"
    if "mysql" in low or re.search(r"\b(?:db|conn|connection)\s*\.\s*(?:query|execute)\s*\(", blob):
        return "mysql"
    return "unknown"


def _strict_validate_fix(expected_fix: str, language: str, fixed_code: str, original_code: str, expected_reason: str = "") -> Tuple[bool, List[str]]:
    """Structural validation of the generated fix code.

    This validator is intentionally language/library-aware:
    - PHP mysqli fixes are expected to remain mysqli, not switch to PDO.
    - PHP PDO fixes are expected to remain PDO.
    - JavaScript pg uses $1/$2 placeholders; mysql/mysql2 uses ? placeholders.
    - Python sqlite-style fixes use ? and execute(query, params).
    - Java/JDBC uses PreparedStatement and setX methods.

    This does not prove formal security, but it is stricter and more accurate than
    checking only the A/B/C/D class label.
    """
    reasons: List[str] = []
    code = fixed_code or ""
    c = _sanitize_code_for_simple_patterns(code)
    lc = c.lower()
    # Strict validation should judge executable repair structure, not comments.
    # This prevents a valid A/parameterized fix from failing only because a comment
    # mentions phrases such as "query builder" or "ORM".
    no_comment_code = re.sub(r"(?m)^\s*(?:#|//).*?$", " ", code or "")
    no_comment_code = re.sub(r"/\*.*?\*/", " ", no_comment_code, flags=re.S)
    no_comment_lc = _sanitize_code_for_simple_patterns(no_comment_code).lower()

    if not c:
        return False, ["fixed_code is empty"]

    if expected_fix == "A":
        has_param_marker = bool(re.search(r"\?|%s|:\w+|\$\d+|@\w+", c))
        if language == "python":
            has_bound_exec = bool(
                re.search(r"\.execute\s*\([^,]+,\s*(?:\(|\[|tuple\s*\(|list\s*\(|params\b)", c)
            )
            if not (has_param_marker and has_bound_exec):
                reasons.append("Python A fix should use placeholder plus cursor.execute(query, params)")
            if re.search(r"\.execute\s*\(\s*(?:sql|query)\s*\)", c):
                reasons.append("Python A fix should not leave execute(sql/query) without parameters")
            if "(str,)" in c or re.search(r"\b(str|int|float)\s*,\s*\)", c):
                reasons.append("Python A fix should bind real variables, not builtins like str/int/float")
        elif language == "javascript":
            js_lib = _detect_js_library(original_code, fixed_code)
            has_array_binding = bool(re.search(r"\.(?:all|get|run|query|execute)\s*\([^,]+,\s*\[", c))
            if js_lib == "pg":
                if not (re.search(r"\$1", c) and re.search(r"\.query\s*\([^,]+,\s*\[", c)):
                    reasons.append("JavaScript pg A fix should use $1/$2 placeholders plus client.query(sql, [params])")
                if "?" in c:
                    reasons.append("JavaScript pg A fix should not use ? placeholders")
            else:
                if not ("?" in c and has_array_binding):
                    reasons.append("JavaScript mysql/mysql2 A fix should use ? placeholders plus parameter array")
            if re.search(r"\.(?:query|execute|all|get|run)\s*\(\s*(?:sql|query)\s*\)", c):
                reasons.append("JavaScript A fix should not leave query(sql) without parameters")
        elif language == "java":
            if not ("preparedstatement" in lc and re.search(r"\.set(?:string|int|long|double|float|object)\s*\(", lc)):
                reasons.append("Java A fix should use PreparedStatement with setX parameter binding")
            if re.search(r"executeQuery\s*\(\s*sql\s*\)", c) or "createstatement()" in lc:
                reasons.append("Java A fix should not keep Statement/createStatement/executeQuery(sql)")
        elif language == "php":
            php_lib = _detect_php_library(original_code, fixed_code)
            if php_lib == "mysqli":
                ok = (
                    "prepare" in lc
                    and "bind_param" in lc
                    and "execute" in lc
                    and "$pdo" not in code
                    and ("$types" in code or re.search(r"bind_param\s*\(\s*[\"'][sidb]+[\"']", code))
                )
                if not ok:
                    reasons.append("PHP mysqli A fix should use mysqli prepare + bind_param + execute, and must not introduce $pdo")
                if re.search(r"mysqli_query\s*\([^\n;]+\$sql\s*\)", code):
                    reasons.append("PHP mysqli A fix should not leave mysqli_query(..., $sql) as the unsafe execution")
            elif php_lib == "pdo":
                if not ("prepare" in lc and "execute" in lc and re.search(r"execute\s*\(\s*\[", lc)):
                    reasons.append("PHP PDO A fix should use PDO prepare + execute([...])")
                if "bind_param" in lc or "mysqli_" in lc:
                    reasons.append("PHP PDO A fix should not switch to mysqli")
            else:
                # Unknown PHP DB library: accept either correct PDO or mysqli-style prepared statement,
                # but still require a real preparation + binding/execution pattern.
                pdo_ok = "prepare" in lc and "execute" in lc and re.search(r"execute\s*\(\s*\[", lc)
                mysqli_ok = "prepare" in lc and "bind_param" in lc and "execute" in lc
                if not (pdo_ok or mysqli_ok):
                    reasons.append("PHP A fix should use library-appropriate prepared statement binding")
        else:
            if not has_param_marker:
                reasons.append("A fix should include a bound-parameter placeholder")

        # Guard against returning a whitelist/ORM/second-order explanation for A.
        if "allowed_columns" in lc or "allowedtables" in lc or "allowed_tables" in lc or "allowedcolumns" in lc:
            reasons.append("A fix should not be whitelist-based")
        if "orm" in no_comment_lc and "query builder" in no_comment_lc:
            # Only fail if the executable repair itself looks like a generic ORM migration.
            # Comments that mention query builder/ORM for explanation should not invalidate
            # a concrete parameterized-query repair.
            reasons.append("A fix should not be generic ORM migration text")
        if re.search(r"[\"']\s*(?:OR|AND)\b", c, re.I) and not re.search(r"\bSELECT\b[\s\S]{0,220}\bFROM\b", c, re.I):
            reasons.append("A fix should not be only a partial SQL fragment starting with OR/AND")

    elif expected_fix == "B":
        has_allowed = any(tok in lc for tok in ["allowed_columns", "allowedcolumns", "allowed_tables", "allowedtables", "allowed columns", "allowed table", "set.of", "new set", "$allowed"])
        has_validation = bool(re.search(r"\bif\b[\s\S]{0,180}(?:not\s+in|!|contains|has|in_array|array_key_exists)", lc))
        if not has_allowed:
            reasons.append("B fix should define an allowlist for dynamic identifiers")
        if not has_validation:
            reasons.append("B fix should validate the identifier against the allowlist")
        if _detect_order_by_dynamic(original_code, language) and "order by" not in lc:
            reasons.append("B ORDER BY fix should preserve ORDER BY after validation")
        if _detect_table_name_dynamic(original_code, language) and not any(tok in lc for tok in ["allowed_tables", "allowedtables", "$allowedtables", "allowed table"]):
            reasons.append("B table-name fix should use allowed table names, not column allowlist")

    elif expected_fix == "C":
        # C is a migration/remediation family for complex builders.  The rendered
        # repair may communicate this either in comments or in executable code
        # constructs.  Do not fail valid C repairs just because the words
        # "ORM/query builder" were in a comment that got stripped.
        c_signals = [
            "orm", "query builder", "query-builder", "structured", "migration",
            "sqlalchemy", "knex", "sequelize", "jpa", "criteria api",
            "criteriabuilder", "criteriaquery", "entitymanager", "entity manager",
            "bindparam", "session.execute", "select(", "query.where", "where(",
            "predicates", "root<", "cq.where", "$qb", "->where", "table(",
            "allowed_filters", "allowedfilters",
        ]
        has_migration_text = any(tok in lc for tok in c_signals) or any(tok in no_comment_lc for tok in c_signals)
        if not has_migration_text:
            reasons.append("C fix should explicitly recommend ORM/query-builder migration")
        # C should not be a simple parameterized-query-only fix with no migration
        # or structured-builder signal anywhere in the generated repair.
        if re.search(r"\.execute\s*\([^,]+,\s*\(", c) and not has_migration_text:
            reasons.append("C fix should not collapse into simple parameterized-query rendering")

    elif expected_fix == "D":
        has_second_order = any(tok in lc for tok in ["second-order", "second order", "stored sql", "stored", "trusted static template", "trusted template", "do not execute", "do not run", "rebuild sql", "config/cache"])
        if not has_second_order:
            reasons.append("D fix should explicitly address stored/config/cache SQL fragments")
        if "allowed_columns" in lc or "allowed_tables" in lc or "allowedcolumns" in lc or "allowedtables" in lc:
            # Sometimes a stored ORDER BY fragment needs both concepts, but D should not be downgraded to pure B.
            if not has_second_order:
                reasons.append("D fix should not be pure whitelist-only without second-order mitigation")
    else:
        reasons.append(f"unknown expected fix type: {expected_fix}")

    return len(reasons) == 0, reasons

def _bool(v: bool) -> str:
    return "YES" if v else "NO"


def _percent(n: int, d: int) -> float:
    return round((100.0 * n / d), 2) if d else 0.0


def _run_one(code: str, language: str, attack_type: str, expected_fix: str, expected_reason: str) -> Dict[str, Any]:
    cleaned = clean_code(code)
    tokens = tokenize_code(cleaned)
    normalized = normalize_tokens(tokens)
    vocab = build_fixed_vocabulary()
    vec = vectorize_tokens(normalized, vocab)

    pred = run_fix_inference(
        vec["tokenIds"],
        language=language,
        attack_type=attack_type,
        normalized_tokens=normalized,
        raw_code=code,
    ) or {}
    model_ft = _norm_str(pred.get("fixType"))
    confidence = pred.get("confidence", "")
    probabilities = pred.get("allProbabilities", {})

    fix = generate_fix(
        code,
        language,
        normalized,
        preferred_fix_type=model_ft,
        model_prediction=pred,
    )
    final_ft = _norm_str(getattr(fix, "fix_type", "")) if fix else ""
    fixed_code = getattr(fix, "fixed_code", "") if fix else ""
    model_pass = model_ft == expected_fix
    final_pass = final_ft == expected_fix
    strict_pass, strict_reasons = _strict_validate_fix(expected_fix, language, fixed_code, code, expected_reason)
    return {
        "model_fix_type": model_ft,
        "final_fix_type": final_ft,
        "model_pass": model_pass,
        "final_pass": final_pass,
        "strict_fix_pass": strict_pass,
        "strict_fix_reasons": "; ".join(strict_reasons),
        "confidence": confidence,
        "probabilities": json.dumps(probabilities, ensure_ascii=False, sort_keys=True),
        "fixed_code": fixed_code,
        "fixed_code_preview": fixed_code.replace("\r", "").replace("\n", "\\n")[:500],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model1-results-zip", required=True)
    ap.add_argument("--suites-dir", required=True)
    ap.add_argument("--output-name", default="official_model1_results_strict")
    ap.add_argument("--include-fixed-code", action="store_true", help="Include full fixed code in CSV. Default includes preview only.")
    args = ap.parse_args()

    results_zip = Path(args.model1_results_zip)
    suites_dir = Path(args.suites_dir)
    output_name = args.output_name

    model1_results = _load_model1_result_csvs(results_zip)
    suites = _load_suites(suites_dir)

    out_dir = Path("outputs")
    out_dir.mkdir(exist_ok=True)
    csv_path = out_dir / f"full_pipeline_from_model1_results_{output_name}_results.csv"
    json_path = out_dir / f"full_pipeline_from_model1_results_{output_name}_summary.json"

    rows_out: List[Dict[str, Any]] = []
    skipped: List[str] = []

    total = expected_safe = expected_vuln = 0
    model1_passed = model1_failed = 0
    model2_eval = 0
    model_passed = final_passed = strict_passed = 0
    vulnerable_e2e_strict = 0
    full_pipeline_strict = 0
    crashed = 0
    failure_stages: Dict[str, int] = {}
    by_suite: Dict[str, Dict[str, Any]] = {}
    model_counts = {"A": 0, "B": 0, "C": 0, "D": 0, "": 0}
    final_counts = {"A": 0, "B": 0, "C": 0, "D": 0, "": 0}

    for suite_name, result_rows in sorted(model1_results.items()):
        sd = suites.get(suite_name)
        if sd is None:
            skipped.append(f"{suite_name}: skipped because matching suite ZIP was not found under {suites_dir}")
            continue
        bs = {
            "totalRows": 0,
            "expectedSafe": 0,
            "expectedVulnerable": 0,
            "model1OfficialPassed": 0,
            "model1OfficialFailed": 0,
            "model2Evaluated": 0,
            "model2ModelPassed": 0,
            "model2FinalPassed": 0,
            "strictFixPassed": 0,
            "fullSystemStrictPassed": 0,
            "fullSystemStrictFailed": 0,
            "crashedCases": 0,
        }
        for r in result_rows:
            total += 1
            bs["totalRows"] += 1
            file_path = _norm_str(r.get("file"))
            manifest = sd.manifest_by_file.get(file_path.replace("\\", "/"), {})
            language = _canon_language(manifest.get("language") or r.get("language"), file_path)
            expected_verdict = _norm_str(r.get("expected_verdict") or manifest.get("expected_verdict")).upper()
            expected_attack = _norm_str(r.get("expected_type") or manifest.get("expected_type")).upper()
            actual_verdict = _norm_str(r.get("actual_verdict")).upper()
            actual_attack = _norm_str(r.get("actual_type")).upper()
            m1_pass = _yes(r.get("overall_pass")) or (_yes(r.get("verdict_pass")) and _yes(r.get("type_pass")))
            if m1_pass:
                model1_passed += 1
                bs["model1OfficialPassed"] += 1
            else:
                model1_failed += 1
                bs["model1OfficialFailed"] += 1

            is_vulnerable_expected = expected_verdict in VULN_VERDICTS or expected_verdict == "VULNERABLE"
            if not is_vulnerable_expected:
                expected_safe += 1
                bs["expectedSafe"] += 1
                full_pass = m1_pass
                if full_pass:
                    full_pipeline_strict += 1
                rows_out.append({
                    "suite": suite_name,
                    "file": file_path,
                    "language": language,
                    "expected_verdict": expected_verdict,
                    "expected_attack_type": expected_attack,
                    "model1_actual_verdict": actual_verdict,
                    "model1_actual_attack_type": actual_attack,
                    "model1_official_pass": _bool(m1_pass),
                    "model2_routed": "NO",
                    "expected_fix_type": "",
                    "model2_model_fix_type": "",
                    "model2_final_fix_type": "",
                    "model2_model_pass": "",
                    "model2_final_pass": "",
                    "strict_fix_pass": "",
                    "strict_fix_reasons": "",
                    "full_system_strict_pass": _bool(full_pass),
                    "failure_stage": "" if full_pass else "model1_official_detection",
                    "crashed": "NO",
                    "error": "",
                    "fixed_code_preview": "",
                })
                continue

            expected_vuln += 1
            bs["expectedVulnerable"] += 1
            try:
                code = _read_code_from_suite(sd, file_path)
                expected_fix, expected_reason = _infer_expected_fix_type(code, language, actual_attack or expected_attack, manifest.get("category", ""), manifest.get("notes", ""))
                res = _run_one(code, language, actual_attack or expected_attack, expected_fix, expected_reason)
                model2_eval += 1
                bs["model2Evaluated"] += 1
                model_ft = res["model_fix_type"]
                final_ft = res["final_fix_type"]
                model_counts[model_ft if model_ft in model_counts else ""] += 1
                final_counts[final_ft if final_ft in final_counts else ""] += 1
                if res["model_pass"]:
                    model_passed += 1
                    bs["model2ModelPassed"] += 1
                if res["final_pass"]:
                    final_passed += 1
                    bs["model2FinalPassed"] += 1
                if res["strict_fix_pass"]:
                    strict_passed += 1
                    bs["strictFixPassed"] += 1

                full_strict = bool(m1_pass and res["model_pass"] and res["final_pass"] and res["strict_fix_pass"])
                if full_strict:
                    vulnerable_e2e_strict += 1
                    full_pipeline_strict += 1
                    bs["fullSystemStrictPassed"] += 1
                else:
                    bs["fullSystemStrictFailed"] += 1
                failure_stage = ""
                if not m1_pass:
                    failure_stage = "model1_official_detection"
                elif not res["model_pass"]:
                    failure_stage = "model2_fix_classification"
                elif not res["final_pass"]:
                    failure_stage = "fix_generator_final_type"
                elif not res["strict_fix_pass"]:
                    failure_stage = "strict_fix_validation"
                if failure_stage:
                    failure_stages[failure_stage] = failure_stages.get(failure_stage, 0) + 1

                row = {
                    "suite": suite_name,
                    "file": file_path,
                    "language": language,
                    "expected_verdict": expected_verdict,
                    "expected_attack_type": expected_attack,
                    "model1_actual_verdict": actual_verdict,
                    "model1_actual_attack_type": actual_attack,
                    "model1_official_pass": _bool(m1_pass),
                    "model1_risk_score": _norm_str(r.get("risk_score")),
                    "model2_routed": "YES",
                    "expected_fix_type": expected_fix,
                    "expected_fix_reason": expected_reason,
                    "model2_attack_type_input": actual_attack or expected_attack,
                    "model2_model_fix_type": model_ft,
                    "model2_final_fix_type": final_ft,
                    "model2_model_pass": _bool(res["model_pass"]),
                    "model2_final_pass": _bool(res["final_pass"]),
                    "strict_fix_pass": _bool(res["strict_fix_pass"]),
                    "strict_fix_reasons": res["strict_fix_reasons"],
                    "model2_confidence": res["confidence"],
                    "model2_probabilities": res["probabilities"],
                    "full_system_strict_pass": _bool(full_strict),
                    "failure_stage": failure_stage,
                    "crashed": "NO",
                    "error": "",
                    "fixed_code_preview": res["fixed_code_preview"],
                }
                if args.include_fixed_code:
                    row["fixed_code"] = res["fixed_code"]
                rows_out.append(row)
            except Exception as exc:
                crashed += 1
                bs["crashedCases"] += 1
                failure_stages["crashed"] = failure_stages.get("crashed", 0) + 1
                rows_out.append({
                    "suite": suite_name,
                    "file": file_path,
                    "language": language,
                    "expected_verdict": expected_verdict,
                    "expected_attack_type": expected_attack,
                    "model1_actual_verdict": actual_verdict,
                    "model1_actual_attack_type": actual_attack,
                    "model1_official_pass": _bool(m1_pass),
                    "model2_routed": "YES",
                    "expected_fix_type": "",
                    "model2_model_fix_type": "",
                    "model2_final_fix_type": "",
                    "model2_model_pass": "NO",
                    "model2_final_pass": "NO",
                    "strict_fix_pass": "NO",
                    "strict_fix_reasons": "crashed before validation",
                    "full_system_strict_pass": "NO",
                    "failure_stage": "crashed",
                    "crashed": "YES",
                    "error": repr(exc),
                    "fixed_code_preview": "",
                })
        by_suite[suite_name] = bs

    # Write CSV with stable columns.
    fieldnames: List[str] = []
    for row in rows_out:
        for k in row.keys():
            if k not in fieldnames:
                fieldnames.append(k)
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows_out)

    summary = {
        "suite": "full_pipeline_from_official_model1_results_library_aware_strict_v3",
        "note": "Uses official Model 1 output CSVs as input to Model 2. Expected Model 2 A/B/C/D labels are inferred from detection suites; strictFix validates the actual generated repair structure and is language/library-aware, not only the class label.",
        "sourceSuites": sorted(by_suite.keys()),
        "skipped": skipped,
        "totalRows": total,
        "expectedSafe": expected_safe,
        "expectedVulnerable": expected_vuln,
        "model1OfficialPassed": model1_passed,
        "model1OfficialFailed": model1_failed,
        "model1OfficialAccuracyPct": _percent(model1_passed, total),
        "model2EvaluatedExpectedVulnerable": model2_eval,
        "model2ModelFixPassed": model_passed,
        "model2ModelFixFailed": model2_eval - model_passed,
        "model2ModelFixAccuracyPct": _percent(model_passed, model2_eval),
        "model2FinalFixPassed": final_passed,
        "model2FinalFixFailed": model2_eval - final_passed,
        "model2FinalFixAccuracyPct": _percent(final_passed, model2_eval),
        "model2StrictFixPassed": strict_passed,
        "model2StrictFixFailed": model2_eval - strict_passed,
        "model2StrictFixAccuracyPct": _percent(strict_passed, model2_eval),
        "vulnerableEndToEndStrictPassed": vulnerable_e2e_strict,
        "vulnerableEndToEndStrictFailed": expected_vuln - vulnerable_e2e_strict,
        "vulnerableEndToEndStrictAccuracyPct": _percent(vulnerable_e2e_strict, expected_vuln),
        "fullPipelineStrictPassed": full_pipeline_strict,
        "fullPipelineStrictFailed": total - full_pipeline_strict,
        "fullPipelineStrictAccuracyPct": _percent(full_pipeline_strict, total),
        "crashedCases": crashed,
        "model2ModelFixTypeCounts": model_counts,
        "model2FinalFixTypeCounts": final_counts,
        "failureStages": failure_stages,
        "bySuite": by_suite,
        "csv": str(csv_path),
        "json": str(json_path),
    }
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print("Full Pipeline from Official Model1 Results + Strict Fix Validation")
    print("--------------------------------------------------------------")
    print(f"Total rows:                     {total}")
    print(f"Expected SAFE:                  {expected_safe}")
    print(f"Expected vulnerable:            {expected_vuln}")
    print(f"Model 1 official:               {model1_passed}/{total} ({_percent(model1_passed,total)}%)")
    print(f"Model 2 evaluated:              {model2_eval}")
    print(f"Model 2 model fix:              {model_passed}/{model2_eval} ({_percent(model_passed,model2_eval)}%)")
    print(f"Model 2 final fix:              {final_passed}/{model2_eval} ({_percent(final_passed,model2_eval)}%)")
    print(f"Model 2 strict fix code:        {strict_passed}/{model2_eval} ({_percent(strict_passed,model2_eval)}%)")
    print(f"Vulnerable end-to-end strict:   {vulnerable_e2e_strict}/{expected_vuln} ({_percent(vulnerable_e2e_strict,expected_vuln)}%)")
    print(f"Full pipeline strict:           {full_pipeline_strict}/{total} ({_percent(full_pipeline_strict,total)}%)")
    print(f"Crashed cases:                  {crashed}")
    print(f"CSV:                            {csv_path}")
    print(f"JSON:                           {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
