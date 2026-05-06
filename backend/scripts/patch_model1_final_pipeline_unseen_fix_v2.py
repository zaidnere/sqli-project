#!/usr/bin/env python3
r"""
Patch Model 1 final pipeline for unseen-suite failures.

Run from backend:
    venv\Scripts\python.exe scripts\patch_model1_final_pipeline_unseen_fix_v2.py

This script modifies only app/services/scan_service.py. It does not touch
Model 1 weights, Model 2 weights, notebooks, or training data.
"""
from __future__ import annotations

from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
SCAN_SERVICE = ROOT / "app" / "services" / "scan_service.py"
BACKUP = SCAN_SERVICE.with_suffix(".py.bak_unseen_patch_v2")


def fail(msg: str) -> None:
    print(f"[ERROR] {msg}")
    raise SystemExit(1)


def replace_top_level_function(text: str, name: str, new_func: str) -> str:
    # Match from `def name(` until the next top-level def/class/comment section.
    pattern = rf"^def {re.escape(name)}\([^\n]*\):\n(?:(?:    |\t|\n).*)?(?=^def |^# ──|\Z)"
    new_text, n = re.subn(pattern, lambda _m: new_func.rstrip() + "\n\n", text, count=1, flags=re.M)
    if n != 1:
        fail(f"Could not replace function {name}")
    return new_text


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        print(f"[skip] anchor not found or already patched: {label}")
        return text
    return text.replace(old, new, 1)


NEW_RAW_JAVA_SAFE_ALLOWLIST_ORDER = r'''def _raw_java_safe_allowlist_order(code: str) -> bool:
    """Java ORDER BY identifier is safe only when selected through a strict allowlist.

    Handles common forms such as:
        Set.of("id", "name").contains(sort) ? sort : "id"
        allowed.contains(sort) ? sort : "id"
        Arrays.asList(...).contains(sort) ? sort : "id"

    The resulting safe variable may be concatenated into ORDER BY, while the
    raw request variable must not be concatenated directly.
    """
    c = _strip_comments(code, "java")
    safe_vars: list[tuple[str, str | None]] = []

    # String safe = allowed.contains(raw) ? raw : "id";
    for m in re.finditer(
        r"String\s+(\w+)\s*=\s*(?:[\w.]+|Set\.of\s*\([^;]+?\)|Arrays\.asList\s*\([^;]+?\))\.contains\s*\(\s*(\w+)\s*\)\s*\?\s*\2\s*:\s*['\"]\w+['\"]",
        c,
        re.I | re.S,
    ):
        safe_vars.append((m.group(1), m.group(2)))

    # String safe = Set.of("id", "name").contains(req.getParameter("sort")) ? req.getParameter("sort") : "id";
    for m in re.finditer(
        r"String\s+(\w+)\s*=\s*(?:Set\.of\s*\([^;]+?\)|Arrays\.asList\s*\([^;]+?\)|[\w.]+)\.contains\s*\(\s*([^?;]+?)\s*\)\s*\?\s*\2\s*:\s*['\"]\w+['\"]",
        c,
        re.I | re.S,
    ):
        safe_vars.append((m.group(1), None))

    # Map lookup allowlist: String safe = SORTS.getOrDefault(raw, "id");
    for m in re.finditer(
        r"String\s+(\w+)\s*=\s*\w+\.getOrDefault\s*\(\s*(\w+)\s*,\s*['\"]\w+['\"]\s*\)",
        c,
        re.I | re.S,
    ):
        safe_vars.append((m.group(1), m.group(2)))

    if not safe_vars:
        return False

    has_prepared_or_safe_sink = (
        _rx(r"prepareStatement\s*\(\s*sql\s*\)", c)
        or _rx(r"\.execute(?:Query|Update)?\s*\(\s*\)", c)
        or _rx(r"\.query\s*\(\s*sql\s*[,)]", c)
        or _rx(r"\.queryForList\s*\(\s*sql\s*[,)]", c)
    )

    for safe, raw in safe_vars:
        safe_used_in_order = _rx(rf"ORDER\s+BY[\s\S]{{0,120}}\+\s*{re.escape(safe)}\b", c)
        raw_used_in_order = bool(raw and _rx(rf"ORDER\s+BY[\s\S]{{0,120}}\+\s*{re.escape(raw)}\b", c))
        if safe_used_in_order and not raw_used_in_order and has_prepared_or_safe_sink:
            return True
    return False
'''


NEW_RAW_BLIND_BOOLEAN_SINK = r'''def _raw_blind_boolean_sink(code: str, language: str) -> bool:
    """Detect SQLi whose result is used as a boolean/security decision."""
    c = _strip_comments(code, language)
    if language == "python":
        # Avoid treating ordinary list-returning repository methods as blind.
        if _rx(r"return\s+\[\s*dict\s*\(\s*row\s*\)\s+for\s+row\s+in", c):
            return False
        return (
            _rx(r"return\s+bool\s*\([^)]*(?:execute|fetchone)", c)
            or _rx(r"return\s+.*fetchone\s*\(\s*\)\s+is\s+not\s+None", c)
            or _rx(r"\b\w+\s*=\s*\w+\.fetchone\s*\(\s*\)[\s\S]{0,160}?return\s+\w+\s+is\s+not\s+None", c)
            or _rx(r"\b\w+\s*=\s*\w+\.fetchone\s*\(\s*\)[\s\S]{0,160}?return\s+\w+\s*!?=\s*None", c)
            or _rx(r"return\s+\w+\s*\[\s*0\s*\]\s*(?:>|<|==|!=|>=|<=)", c)
            or _rx(r"return\s+\w+\s+is\s+not\s+None\s+and", c)
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
            _rx(r"mysqli_num_rows\s*\(\s*\$\w+\s*\)\s*>\s*0", c)
            or _rx(r"return\s+mysqli_num_rows\s*\(\s*\$\w+\s*\)\s*>\s*0", c)
            or _rx(r"\$\w+->num_rows\s*>\s*0", c)
            or _rx(r"return\s*\(\s*bool\s*\)\s*\$?\w*->\s*query\s*\([^;]+\)->\s*fetch", c)
            or _rx(r"return\s*\$?\w*->\s*query\s*\([^;]+\)->\s*fetch(?:Column)?\s*\([^)]*\)\s*(?:>|!==|!=|==)", c)
            or _rx(r"return\s*\$\w+\s*&&\s*\$\w+->\s*(?:num_rows|fetch_assoc\s*\(\s*\))\s*(?:>|!==|!=|==)", c)
            or _rx(r"return\s*\$\w+->\s*num_rows\s*>\s*0", c)
            or _rx(r"return\s*\$\w+\s*&&\s*\$\w+->fetch_assoc\s*\(\s*\)\s*!==\s*null", c)
            or _rx(r"return\s*\$\w+\s*\[[^\]]+\]\s*(?:>|<|==|!=|>=|<=)", c)
            or (_rx(r"(?:num_rows|fetch\s*\(|fetch_assoc\s*\(|mysqli_fetch_assoc\s*\(|fetchColumn\s*\()", c) and _rx(r"\b(?:login|authenticate|permission|feature|token|session|allowed|valid|canDelete|canAccess|canEdit|enabled|registered)\b", c))
        )
    return False
'''


PHP_SECOND_ORDER_INSERT = r'''    # Additive PHP second-order evidence: SQL-ish data is loaded from DB/config/cache
    # and later reused as SQL syntax or direct SQL text.
    if language == "php":
        if _rx(r"function\s+\w*(?:Clause|Filter|Sql|Condition|Order)\w*\s*\([^)]*\)[\s\S]*?(?:SELECT|fetch|fetchColumn)[\s\S]*?return\s+\$\w+(?:\s*\[\s*['\"](?:value|where_clause|where_fragment|order_clause|filter|condition|sql_text|sql_body|query_sql)['\"]\s*\])?", c) and _rx(r"\$\w+\s*=\s*(?:\$this->)?\w*(?:Clause|Filter|Sql|Condition|Order)\w*\s*\([^)]*\)\s*;[\s\S]{0,260}?(?:WHERE|AND|ORDER\s+BY|HAVING|GROUP\s+BY)[^;]*\.\s*\$\w+", c):
            return True
        if _rx(r"\$\w+\s*=\s*\$\w+->query\s*\([^;]*(?:config|saved|filter|report|tenant)[^;]*\)->fetchColumn\s*\(\s*\)", c) and _rx(r"\$sql\s*=\s*[^;]*\.\s*\$\w+|->\s*query\s*\([^;]*\.\s*\$\w+", c):
            return True
'''


def main() -> int:
    if not SCAN_SERVICE.exists():
        fail(f"scan_service.py not found: {SCAN_SERVICE}")

    if not BACKUP.exists():
        shutil.copy2(SCAN_SERVICE, BACKUP)
        print(f"[backup] {BACKUP}")
    else:
        print(f"[backup] already exists: {BACKUP}")

    text = SCAN_SERVICE.read_text(encoding="utf-8")
    original = text

    text = replace_top_level_function(text, "_raw_java_safe_allowlist_order", NEW_RAW_JAVA_SAFE_ALLOWLIST_ORDER)
    text = replace_top_level_function(text, "_raw_blind_boolean_sink", NEW_RAW_BLIND_BOOLEAN_SINK)

    # Insert PHP second-order additive checks once, after the sqlish regex definition.
    anchor = '    sqlish = r"(?:sql_body|sql_text|sql_script|saved_sql|stored_sql|admin_query|query_sql|query_text|where_clause|where_fragment|filter|predicate|fragment|order_expression|order_clause|condition|clause|config)"\n'
    if PHP_SECOND_ORDER_INSERT.strip() not in text:
        text = replace_once(text, anchor, anchor + PHP_SECOND_ORDER_INSERT + "\n", "php second-order insert")

    # In raw_fast_detection, safe Java allowlist must be checked before broad Java in-band danger.
    old = '''    if language == "javascript" and _raw_js_inband_danger(raw_code):
        return make("VULNERABLE", "IN_BAND", 0.90, "raw_js_sqli", "Raw JavaScript SQL reaches a framework/alias execution sink.")
    if language == "java" and _raw_java_inband_danger(raw_code):
        return make("VULNERABLE", "IN_BAND", 0.90, "raw_java_sqli", "Raw Java SQL reaches JdbcTemplate/query execution.")
'''
    new = '''    if language == "javascript" and _raw_js_inband_danger(raw_code):
        return make("VULNERABLE", "IN_BAND", 0.90, "raw_js_sqli", "Raw JavaScript SQL reaches a framework/alias execution sink.")
    if language == "java" and _raw_java_safe_allowlist_order(raw_code):
        return make("SAFE", "NONE", 0.08, "raw_java_allowlist_order", "ORDER BY value is selected by exact allowlist before execution.")
    if language == "java" and _raw_java_inband_danger(raw_code):
        return make("VULNERABLE", "IN_BAND", 0.90, "raw_java_sqli", "Raw Java SQL reaches JdbcTemplate/query execution.")
'''
    text = replace_once(text, old, new, "raw_fast_detection java safe-before-danger")

    # Protect ML / previous type-head specificity in PHP raw-danger branch.
    old_php = '''    if language == "php" and _raw_php_danger(raw_code):
        signals.add("SQL_CONCAT")
        if _raw_blind_boolean_sink(raw_code, language):
            signals.add("BOOLEAN_SINK")
            return "VULNERABLE", "BLIND", max(score, 0.90), "raw_php_blind_sqli", signals
        return "VULNERABLE", "IN_BAND", max(score, 0.90), "raw_php_sqli", signals
'''
    new_php = '''    if language == "php" and _raw_php_danger(raw_code):
        signals.add("SQL_CONCAT")
        if _raw_second_order_stored_sql(raw_code, language) or attack_type == "SECOND_ORDER":
            signals.add("SECOND_ORDER_FLOW")
            return "VULNERABLE", "SECOND_ORDER", max(score, 0.90), "raw_php_second_order_flow", signals
        if _raw_blind_boolean_sink(raw_code, language) or attack_type == "BLIND":
            signals.add("BOOLEAN_SINK")
            return "VULNERABLE", "BLIND", max(score, 0.90), "raw_php_blind_sqli", signals
        return "VULNERABLE", "IN_BAND", max(score, 0.90), "raw_php_sqli", signals
'''
    text = replace_once(text, old_php, new_php, "php raw-danger preserves specific type")

    if text == original:
        fail("No changes were applied. Your scan_service.py may already be patched or structurally different.")

    SCAN_SERVICE.write_text(text, encoding="utf-8")
    print(f"[patched] {SCAN_SERVICE}")
    print("[next] run: venv\\Scripts\\python.exe -m py_compile app\\services\\scan_service.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
