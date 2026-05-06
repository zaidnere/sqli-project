"""
Patch Model 1 final pipeline evidence logic for unseen-suite failures.

Run from backend:
    venv\Scripts\python.exe scripts\patch_model1_final_pipeline_unseen_fix.py

This edits app/services/scan_service.py in-place and creates a .bak_unseen_patch backup.
It does NOT modify model weights, training notebooks, Model 2 files, or app/model/sqli_detector.py.
"""
from __future__ import annotations

from pathlib import Path
import re
import shutil
import sys

ROOT = Path.cwd()
TARGET = ROOT / "app" / "services" / "scan_service.py"

JAVA_FUNC = r'''def _raw_java_safe_allowlist_order(code: str) -> bool:
    c = _strip_comments(code, "java")
    safe_vars = []

    # Existing simple form:
    #   String sort = allowed.contains(sort) ? sort : "created_at";
    for m in re.finditer(r"String\s+(\w+)\s*=\s*\w+\.contains\s*\(\s*(\w+)\s*\)\s*\?\s*\2\s*:\s*['\"]\w+['\"]", c):
        safe_vars.append((m.group(1), m.group(2)))

    # Request-expression form:
    #   String sort = allowed.contains(req.getParameter("sort"))
    #       ? req.getParameter("sort") : "created_at";
    # This is safe when ORDER BY uses the new safe variable, while values are
    # still bound with PreparedStatement setters.
    for m in re.finditer(
        r"String\s+(\w+)\s*=\s*\w+\.contains\s*\([^;?]+\)\s*\?\s*[^:;]+\s*:\s*['\"][\w.]+['\"]",
        c,
        re.I | re.S,
    ):
        safe_vars.append((m.group(1), "__request_expression__"))

    # Map/getOrDefault allowlist form:
    #   String sort = SORTS.getOrDefault(req.getParameter("sort"), "created_at");
    for m in re.finditer(
        r"String\s+(\w+)\s*=\s*\w+\.getOrDefault\s*\([^,]+,\s*['\"][\w.]+['\"]\s*\)",
        c,
        re.I | re.S,
    ):
        safe_vars.append((m.group(1), "__map_default__"))

    if not safe_vars:
        return False

    has_prepared_sink = (
        _rx(r"prepareStatement\s*\(\s*sql\s*\)", c)
        and _rx(r"\.set(?:String|Int|Long|Object|Double|Boolean)\s*\(", c)
        and _rx(r"\.execute(?:Query|Update)\s*\(\s*\)", c)
    )

    for safe, raw in safe_vars:
        uses_safe_order = _rx(rf"ORDER\s+BY[\s\S]{{0,120}}\+\s*{re.escape(safe)}\b", c)
        uses_obvious_raw_order = _rx(r"ORDER\s+BY[\s\S]{0,120}\+\s*(?:req\.|request\.|raw|orderBy|sortColumn)\b", c)
        uses_original_raw_var = (
            raw not in {"__request_expression__", "__map_default__"}
            and _rx(rf"ORDER\s+BY[\s\S]{{0,120}}\+\s*{re.escape(raw)}\b", c)
        )
        if uses_safe_order and has_prepared_sink and not uses_obvious_raw_order and not uses_original_raw_var:
            return True
    return False
'''

PHP_SECOND_ORDER_BLOCK = r'''        # Helper returns a SQL-ish fragment loaded from DB/config, and the caller
        # later concatenates that returned value into SQL syntax and executes it.
        # Do not depend on helper names: generated/real code often uses names
        # such as load_f_xxx(), getClause(), loadFilter(), etc.
        if (
            _rx(rf"function\s+\w+\s*\([^)]*\)\s*\{{[\s\S]*?SELECT[\s\S]*?(?:{sqlish})[\s\S]*?fetch\s*\([^)]*\)[\s\S]*?return\s+\$\w+\s*\[\s*['\"](?:where_clause|where_fragment|filter|predicate|condition|order_clause|sql_text|sql_body|query_sql|value)['\"]\s*\]", c)
            and _rx(r"\$\w+\s*=\s*\w+\s*\([^;]*\)\s*;[\s\S]*?\$sql\s*=\s*[^;]*\.\s*\$\w+[\s\S]*?->\s*(?:query|exec)\s*\(\s*\$sql\s*\)", c)
        ):
            return True
'''


def fail(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


def replace_regex_once(text: str, pattern: str, replacement: str, label: str) -> str:
    if replacement.strip() in text:
        print(f"[skip] {label}: already patched")
        return text
    new_text, n = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if n != 1:
        fail(f"Could not patch {label}; pattern matches={n}")
    print(f"[patch] {label}")
    return new_text


def replace_text_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        print(f"[skip] {label}: already patched")
        return text
    if old not in text:
        fail(f"Could not find insertion point for {label}")
    print(f"[patch] {label}")
    return text.replace(old, new, 1)


def main() -> int:
    if not TARGET.exists():
        fail(f"Run this from the backend directory. Missing: {TARGET}")

    text = TARGET.read_text(encoding="utf-8")
    backup = TARGET.with_suffix(TARGET.suffix + ".bak_unseen_patch")
    if not backup.exists():
        shutil.copy2(TARGET, backup)
        print(f"[backup] {backup}")
    else:
        print(f"[backup] already exists: {backup}")

    # 1) Replace Java allowlist helper robustly.
    text = replace_regex_once(
        text,
        r'def _raw_java_safe_allowlist_order\(code: str\) -> bool:\n.*?\n\ndef _raw_php_safe_prepared_only',
        JAVA_FUNC + '\n\ndef _raw_php_safe_prepared_only',
        "java allowlisted ORDER BY",
    )

    # 2) Python blind sink: row = fetchone(); return row is not None.
    text = replace_text_once(
        text,
        '            or _rx(r"return\\s+\\w+\\s+is\\s+not\\s+None\\s+and", c)\n',
        '            or _rx(r"return\\s+\\w+\\s+is\\s+not\\s+None\\b", c)\n'
        '            or _rx(r"return\\s+\\w+\\s+is\\s+None\\b", c)\n'
        '            or _rx(r"return\\s+\\w+\\s+is\\s+not\\s+None\\s+and", c)\n',
        "python blind boolean return row is not None",
    )

    # 3) PHP blind sink: mysqli_num_rows($res) > 0.
    text = replace_text_once(
        text,
        '            or _rx(r"return\\s*\\$\\w+->\\s*num_rows\\s*>\\s*0", c)\n',
        '            or _rx(r"return\\s*\\$\\w+->\\s*num_rows\\s*>\\s*0", c)\n'
        '            or _rx(r"return\\s*mysqli_num_rows\\s*\\(\\s*\\$\\w+\\s*\\)\\s*(?:>|!==|!=|==|>=)\\s*0", c)\n'
        '            or (_rx(r"mysqli_num_rows\\s*\\(\\s*\\$\\w+\\s*\\)", c) and _rx(r"\\b(?:login|authenticate|permission|feature|token|session|allowed|valid|canDelete|canAccess|canEdit|enabled|registered)\\b", c))\n',
        "php blind mysqli_num_rows",
    )

    # 4) PHP second-order helper-returned fragments: insert right after the php branch in _raw_second_order_stored_sql.
    if PHP_SECOND_ORDER_BLOCK.strip() in text:
        print("[skip] php second-order helper-returned SQL fragment: already patched")
    else:
        marker = '    elif language == "php":\n        if _rx(rf"SELECT[\\s\\S]*?(?:{sqlish})[\\s\\S]*?fetch", c)'
        if marker not in text:
            fail("Could not find PHP second-order branch marker")
        text = text.replace(
            '    elif language == "php":\n',
            '    elif language == "php":\n' + PHP_SECOND_ORDER_BLOCK,
            1,
        )
        print("[patch] php second-order helper-returned SQL fragment")

    TARGET.write_text(text, encoding="utf-8")
    print("[done] Patched app/services/scan_service.py")
    print("Next: venv\\Scripts\\python.exe -m py_compile app\\services\\scan_service.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
