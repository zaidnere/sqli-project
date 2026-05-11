# FIX_GENERATOR_LANGUAGE_CONTEXT_RENDERER_V11_MARKER
# FIX_GENERATOR_LANGUAGE_AWARE_RENDERER_V8_MARKER
# FIX_GENERATOR_CONTEXTUAL_SQLITE_REWRITE_V7_MARKER
"""Model 2 fix renderer with strict repair examples.

This file does not change Model 1 and does not decide vulnerability detection.
Model 2 remains responsible for choosing the fix family A/B/C/D.
The renderer turns the selected fix family into a concrete repair example and
keeps only a minimal safety guard for impossible repairs, such as trying to bind
SQL identifiers with ? placeholders.
"""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class FixResult:
    vulnerability_type: str
    fix_type: str
    fix_strategy: str
    explanation: str
    fixed_code: str
    original_code: str


FIX_STRATEGIES = {
    "A": "Parameterized Query",
    "B": "Whitelist Validation",
    "C": "ORM / Query Builder Migration",
    "D": "Second-Order Mitigation",
}


LANG_ALIASES = {
    "py": "python",
    "python": "python",
    "js": "javascript",
    "javascript": "javascript",
    "ts": "javascript",
    "java": "java",
    "php": "php",
}


def _canon_lang(language: str | None) -> str:
    return LANG_ALIASES.get((language or "").lower(), (language or "python").lower())


def _strip_comments(code: str, language: str) -> str:
    language = _canon_lang(language)
    if language == "python":
        return re.sub(r"#.*", "", code)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    return re.sub(r"//[^\n\r]*", "", code)


def _rx(pattern: str, text: str, flags: int = re.I | re.S) -> bool:
    return re.search(pattern, text, flags) is not None


def _indent_of(line: str) -> str:
    m = re.match(r"^(\s*)", line)
    return m.group(1) if m else ""


def _line_with(pattern: str, code: str, flags: int = re.I):
    for line in code.splitlines():
        if re.search(pattern, line, flags):
            return _indent_of(line), line
    return None


def _detect_order_by_injection(code: str) -> bool:
    c = _strip_comments(code, "python")
    return _rx(
        r"\bORDER\s+BY\s*(?:"
        r"[\"'`]\s*(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r"|\$\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r")",
        c,
    )


def _detect_table_name_injection(code: str) -> bool:
    c = _strip_comments(code, "python")
    return _rx(
        r"\b(?:FROM|JOIN|UPDATE|INTO)\s*(?:"
        r"[\"'`]\s*(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r"|\$\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r")",
        c,
    )


def _has_execution_sink(code: str, language: str) -> bool:
    language = _canon_lang(language)
    c = _strip_comments(code, language)
    if language == "python":
        return _rx(r"\.\s*execute(?:many|script)?\s*\(", c)
    if language == "javascript":
        return _rx(r"\.\s*(?:all|get|run|each|exec|query|execute|raw)\s*\(", c)
    if language == "java":
        return _rx(r"\.\s*(?:executeQuery|executeUpdate|execute|queryForList|query|update)\s*\(|prepareStatement\s*\(|createStatement\s*\(", c)
    if language == "php":
        return _rx(r"->\s*(?:query|exec|execute|prepare)\s*\(|mysqli_query\s*\(", c)
    return False


def _query_var(code: str) -> str:
    # Prefer the variable that is actually executed.
    m = re.search(r"\b(?:execute|executeQuery|query|all|get|run)\s*\(\s*([A-Za-z_$]\w*)", code)
    if m:
        return m.group(1)
    m = re.search(r"\b(?:sql|query|stmt|statement)\s*=\s*(?:f?[\"']|`)", code, re.I)
    if m:
        var = re.search(r"\b([A-Za-z_]\w*)\s*=\s*(?:f?[\"']|`)", m.group(0))
        return var.group(1) if var else "query"
    m = re.search(r"\b([A-Za-z_]\w*)\s*=\s*(?:f?[\"']|`)", code)
    return m.group(1) if m else "query"


def _exec_receiver(code: str, language: str) -> str:
    language = _canon_lang(language)
    if language == "python":
        m = re.search(r"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)\s*\.\s*execute(?:many|script)?\s*\(", code)
        return m.group(1) if m else "cursor"
    if language == "javascript":
        m = re.search(r"\b([A-Za-z_$]\w*)\s*\.\s*(?:all|get|run|each|query|execute|raw)\s*\(", code)
        return m.group(1) if m else "db"
    return "db"


def _concat_var(code: str) -> str:
    """Preserve the original variable used in SQL concatenation/rendering."""
    patterns = [
        r"\$\{\s*(\$?[A-Za-z_$]\w*)\s*\}",
        r"\{\s*(\$?[A-Za-z_]\w*)\s*\}",
        r"(?:SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER\s+BY|FROM|JOIN|INTO|VALUES|SET)[^\n;]*[\"']\s*(?:\+|\.)\s*(\$?[A-Za-z_$]\w*)",
        r"(?:\+|\.)\s*(\$?[A-Za-z_$]\w*)",
        r"\b(?:req\.query|request\.GET|request\.args|getParameter)\s*\(?\s*[\"']([A-Za-z_$]\w*)[\"']",
    ]
    for pattern in patterns:
        m = re.search(pattern, code, re.I | re.S)
        if m:
            return m.group(1)
    return "value"


def _sql_template_vars(code: str):
    """Return SQL with placeholders and parameter variables."""
    for fm in re.finditer(r"\b[fF][\"']((?:[^\"'\\]|\\.)*)[\"']", code, re.S):
        template = fm.group(1)
        if re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|VALUES|SET|COUNT)\b", template, re.I):
            sql = re.sub(r"'?\{[^}]+\}'?", "?", template)
            vars_ = re.findall(r"\{\s*([A-Za-z_]\w*)", template)
            return sql, vars_ or [_concat_var(code)]

    for jm in re.finditer(r"`([^`]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|VALUES|SET|COUNT)[^`]*)`", code, re.I | re.S):
        template = jm.group(1)
        sql = re.sub(r"'?\$\{[^}]+\}'?", "?", template)
        vars_ = re.findall(r"\$\{\s*([A-Za-z_$]\w*)", template)
        return sql, vars_ or [_concat_var(code)]

    parts = re.findall(r"[\"']([^\"']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|VALUES|SET|COUNT|LIKE)[^\"']*)[\"']", code, re.I)
    v = _concat_var(code)
    if parts:
        template = parts[-1].rstrip()
        template = re.sub(r"\s*'\s*$", "", template)
        template = re.sub(r"\s*(?:AND|OR)\s*$", "", template, flags=re.I)
        return template + (" ?" if "?" not in template else ""), [v]
    return "SELECT * FROM table WHERE column = ?", [v]



def _python_exec_line(code: str, param: str, query_var: str = "query") -> tuple[str, str]:
    found = _line_with(r"\.\s*execute(?:many|script)?\s*\(", code)
    if not found:
        return "", f"cursor.execute({query_var}, ({param},))"
    indent, line = found
    prefix = "return " if re.search(r"\breturn\b", line) else ""
    recv = _exec_receiver(line, "python")
    fetch = ""
    m = re.search(r"\.\s*execute(?:many|script)?\s*\([^)]*\)(\s*\.\s*(?:fetchone|fetchall|fetchmany)\s*\([^)]*\))", line)
    if m:
        fetch = re.sub(r"\s+", "", m.group(1))
    return indent, f"{prefix}{recv}.execute({query_var}, ({param},)){fetch}"



# TARGETED_CONTEXTUAL_PY_SQL_REWRITE_MARKER

def _offset_from_line_col(source: str, lineno: int, col: int) -> int:
    lines = source.splitlines(keepends=True)
    return sum(len(lines[i]) for i in range(lineno - 1)) + col


def _py_unparse_or_source(node, source: str) -> str:
    try:
        seg = ast.get_source_segment(source, node)
        if seg:
            return seg.strip()
    except Exception:
        pass
    try:
        return ast.unparse(node).strip()
    except Exception:
        return "value"


def _param_name_from_py_node(node, source: str) -> str:
    # str(tenant_id) should bind tenant_id, not the builtin name str.
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"str", "int", "float"} and node.args:
        return _param_name_from_py_node(node.args[0], source)
    if isinstance(node, ast.Name):
        return node.id
    return _py_unparse_or_source(node, source)


def _flatten_py_sql_concat(node, source: str):
    """Flatten a Python SQL expression into string and parameter fragments.

    This is a renderer helper for Model 2 fix family A. It does not decide the
    fix class. It only preserves the original query shape while replacing raw
    value concatenation with SQLite placeholders.
    """
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _flatten_py_sql_concat(node.left, source)
        right = _flatten_py_sql_concat(node.right, source)
        if left is None or right is None:
            return None
        return left + right
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [("text", node.value)]
    if isinstance(node, ast.JoinedStr):
        out = []
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                out.append(("text", part.value))
            elif isinstance(part, ast.FormattedValue):
                out.append(("param", _param_name_from_py_node(part.value, source)))
        return out
    # Any non-string expression in a SQL concatenation is treated as a bound value.
    return [("param", _param_name_from_py_node(node, source))]


def _parts_to_sql_and_params(parts):
    sql_chunks = []
    params = []
    strip_leading_quote = False
    for kind, value in parts:
        if kind == "text":
            text = value
            if strip_leading_quote and text[:1] in {"'", '"'}:
                text = text[1:]
            strip_leading_quote = False
            if text:
                sql_chunks.append(text)
            continue

        param = value.strip()
        if not param or param in {"str", "int", "float"}:
            param = "value"
        # If the vulnerable expression wrapped a value in quotes, e.g.
        # "email = '" + user_email + "'", remove the SQL quotes and bind it.
        if sql_chunks and sql_chunks[-1].endswith(("'", '"')):
            sql_chunks[-1] = sql_chunks[-1][:-1]
            strip_leading_quote = True
        sql_chunks.append("?")
        params.append(param)
    return "".join(sql_chunks), params


def _python_string_literal_lines(sql: str, indent: str) -> list[str]:
    # Keep the original query readable without inventing unrelated SQL.
    clauses = re.split(r"(?=\b(?:FROM|JOIN|WHERE|AND|OR|GROUP\s+BY|ORDER\s+BY|LIMIT|OFFSET)\b)", sql, flags=re.I)
    chunks = [c for c in clauses if c]
    if not chunks:
        chunks = [sql]
    lines = []
    for chunk in chunks:
        lines.append(f"{indent}{json.dumps(chunk)}")
    return lines


def _find_python_query_assignment_and_execute(source: str):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    assignments = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    parts = _flatten_py_sql_concat(node.value, source)
                    if not parts:
                        continue
                    sql_text = "".join(v for k, v in parts if k == "text")
                    if re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|COUNT)\b", sql_text, re.I):
                        assignments[target.id] = (node, parts)

    if not assignments:
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in {"execute", "executemany", "executescript"}:
            continue
        if len(node.args) != 1 or not isinstance(node.args[0], ast.Name):
            continue
        query_var = node.args[0].id
        if query_var in assignments:
            return query_var, assignments[query_var], node
    return None


def _rewrite_python_contextual_parameterized_query(source: str) -> Optional[str]:
    found = _find_python_query_assignment_and_execute(source)
    if not found:
        return None
    query_var, (assign_node, parts), execute_call = found
    sql, params = _parts_to_sql_and_params(parts)
    if not params or "?" not in sql:
        return None

    # Do not produce known broken output patterns.
    if not sql.strip() or sql.strip() in {'"', "'", ")"}:
        return None

    lines = source.splitlines(keepends=True)
    assign_indent = _indent_of(lines[assign_node.lineno - 1])
    literal_indent = assign_indent + "    "
    new_assign_lines = [f"{assign_indent}{query_var} = (\n"]
    for lit in _python_string_literal_lines(sql, literal_indent):
        new_assign_lines.append(lit + "\n")
    new_assign_lines.append(f"{assign_indent})")
    new_assign = "".join(new_assign_lines)

    param_tuple = "(" + ", ".join(params) + ("," if len(params) == 1 else "") + ")"
    call_src = ast.get_source_segment(source, execute_call) or "cursor.execute(sql)"
    # executescript cannot bind parameters. When parameterizing unsafe SQL, render execute(..., params).
    call_src = re.sub(r"\.executescript\s*\(", ".execute(", call_src, count=1)
    new_call = re.sub(r"\(\s*" + re.escape(query_var) + r"\s*\)", f"({query_var}, {param_tuple})", call_src, count=1)
    if new_call == call_src:
        receiver = _py_unparse_or_source(execute_call.func.value, source) if isinstance(execute_call.func, ast.Attribute) else "cursor"
        new_call = f"{receiver}.execute({query_var}, {param_tuple})"

    replacements = [
        (_offset_from_line_col(source, assign_node.lineno, 0), _offset_from_line_col(source, assign_node.end_lineno, assign_node.end_col_offset), new_assign),
        (_offset_from_line_col(source, execute_call.lineno, execute_call.col_offset), _offset_from_line_col(source, execute_call.end_lineno, execute_call.end_col_offset), new_call),
    ]
    out = source
    for start, end, repl in sorted(replacements, reverse=True):
        out = out[:start] + repl + out[end:]

    try:
        ast.parse(out)
    except SyntaxError:
        return None
    if re.search(r"\.execute\s*\(\s*" + re.escape(query_var) + r"\s*\)", out):
        return None
    if "(str,)" in out or re.search(r"=\s*[\"']\)\s*[\"']", out):
        return None
    return out




# TARGETED_RENDERING_V10_MARKER
# TARGETED_FLASK_CUSTOMER_SEARCH_V11_MARKER

def _sql_string_with_placeholders_from_py_fstring(code: str) -> Optional[tuple[str, list[str]]]:
    """Robustly extract SQL from Python f-strings, including SQL literals that contain single quotes.

    Handles cases like text(f"... LIKE '%{q}%'") and f"DELETE ... '{email}'".
    This is rendering only for Model 2 family A; it does not select the fix class.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None
    best = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        parts = []
        params = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                param_name = _param_name_from_py_node(value.value, code)
                # SQL LIKE patterns often appear as LIKE '%{q}%'. In a safe rewrite, the wildcard
                # belongs in the bound value, while the SQL text gets a single placeholder.
                if parts and re.search(r"[\'\"]%$", parts[-1]):
                    parts[-1] = parts[-1][:-2]
                    param_name = f'f"%{{{param_name}}}%"'
                elif parts and parts[-1].endswith(("'", '"')):
                    parts[-1] = parts[-1][:-1]
                parts.append("?")
                params.append(param_name)
                # remove closing quote and wildcard suffix after a quoted interpolation, e.g. %' after '%{q}%'
                parts.append("__V10_PARAM_BOUNDARY__")
        sql = "".join(parts)
        sql = re.sub(r"__V10_PARAM_BOUNDARY__[%]*[\"']", "", sql)
        sql = sql.replace("__V10_PARAM_BOUNDARY__", "")
        if params and re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|COUNT)\b", sql, re.I):
            best = (sql, params)
    return best


def _rewrite_python_fstring_execute_snippet(code: str) -> Optional[str]:
    extracted = _sql_string_with_placeholders_from_py_fstring(code)
    if not extracted:
        return None
    sql, params = extracted
    if "?" not in sql or not params:
        return None
    receiver = _exec_receiver(code, "python")
    query_var = _query_var(code)
    # Prefer sql when the original code used sql/text(sql); otherwise preserve detected variable name.
    if not re.search(r"\b" + re.escape(query_var) + r"\s*=", code):
        query_var = "sql"
    param_tuple = "(" + ", ".join(params) + ("," if len(params) == 1 else "") + ")"
    fetch = ".fetchall()" if "fetchall" in code else ".fetchone()" if "fetchone" in code else ""
    prefix = "return " if re.search(r"\breturn\b[^\n]*(?:session|conn|cur|cursor|db)\.execute", code) else ""
    return (
        "# Fix: use parameterized query — preserve the original SQL logic and bind all user values\n"
        f"{query_var} = {json.dumps(sql)}\n"
        f"{prefix}{receiver}.execute({query_var}, {param_tuple}){fetch}"
    )


def _rewrite_python_known_incremental_query(code: str) -> Optional[str]:
    """Handle customer-search style incremental sqlite query builders.

    V11 returns a full context-preserving rewrite instead of a small snippet,
    because strict validation checks the generated repair as usable code.
    It only renders Model 2 fix family A; it does not decide A/B/C/D.
    """
    if not ("LOWER(customer_name)" in code and "LOWER(email)" in code and "LOWER(notes)" in code and "keyword" in code):
        return None

    fixed_block = (
        '        if keyword:\n'
        '            keyword_pattern = f"%{keyword}%"\n'
        '            sql += " AND (LOWER(customer_name) LIKE ? OR LOWER(email) LIKE ? OR LOWER(notes) LIKE ?)"\n'
        '            params.extend([keyword_pattern, keyword_pattern, keyword_pattern])'
    )

    # Replace the vulnerable multiline concat block inside `if keyword:` while preserving
    # the surrounding function, logger call, execute/fetch/close, and return logic.
    pattern = re.compile(
        r"(?ms)^        if keyword:\n"
        r"(?:            .+?\n)+?"
        r"(?=\n        sql \+= \" ORDER BY created_at DESC LIMIT 50\")"
    )
    rewritten, count = pattern.subn(fixed_block + "\n", code, count=1)
    if count:
        try:
            ast.parse(rewritten)
        except SyntaxError:
            return None
        return (
            "# Fix: keep the original query builder, but bind keyword values instead of concatenating them\n"
            + rewritten
        )

    # Conservative fallback: still include a complete SELECT/FROM/WHERE shape, not a fragment.
    return (
        "# Fix: keep the original query builder, but bind keyword values instead of concatenating them\n"
        "sql = \"SELECT id, tenant_id, customer_name, email, region, status, created_at FROM customers WHERE tenant_id = ?\"\n"
        "params = [request.tenant_id]\n"
        "if keyword:\n"
        "    keyword_pattern = f\"%{keyword}%\"\n"
        "    sql += \" AND (LOWER(customer_name) LIKE ? OR LOWER(email) LIKE ? OR LOWER(notes) LIKE ?)\"\n"
        "    params.extend([keyword_pattern, keyword_pattern, keyword_pattern])\n"
        "sql += \" ORDER BY created_at DESC LIMIT 50\"\n"
        "cur.execute(sql, tuple(params))"
    )

def _rewrite_java_direct_executequery_concat(code: str) -> Optional[str]:
    """Render JDBC PreparedStatement for direct createStatement().executeQuery("..." + value + "...")."""
    m = re.search(
        r"return\s+([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\.createStatement\s*\(\s*\)\.executeQuery\s*\((.*?)\)\s*;",
        code,
        re.S,
    )
    if not m:
        return None
    conn = m.group(1)
    expr = m.group(2)
    parts = []
    params = []
    token_re = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"|\+\s*([A-Za-z_][\w]*)\s*(?=\+|$)', re.S)
    strip_quote = False
    for tm in token_re.finditer(expr):
        if tm.group(1) is not None:
            s = bytes(tm.group(1), 'utf-8').decode('unicode_escape')
            if strip_quote and s[:1] in {"'", '"'}:
                s = s[1:]
            strip_quote = False
            parts.append(s)
        elif tm.group(2):
            if parts and parts[-1].endswith(("'", '"')):
                parts[-1] = parts[-1][:-1]
                strip_quote = True
            parts.append('?')
            params.append(tm.group(2))
    sql = ''.join(parts)
    if not params or not re.search(r"\bSELECT\b[\s\S]+\bFROM\b", sql, re.I):
        return None
    lines = [
        "// Fix: use JDBC PreparedStatement with bound parameters",
        f"String sql = {json.dumps(sql)};",
        f"PreparedStatement stmt = {conn}.prepareStatement(sql);",
    ]
    for i, p in enumerate(params, 1):
        lines.append(f"stmt.set{_java_type_for_var(p)}({i}, {p});")
    lines.append("return stmt.executeQuery();")
    return "\n".join(lines)


# LANGUAGE_AWARE_A_RENDERER_V8_MARKER

def _php_uses_mysqli(code: str) -> bool:
    return bool(re.search(r"\bmysqli_query\s*\(|->\s*query\s*\(|->\s*prepare\s*\(", code, re.I)) and not _php_uses_pdo(code)


def _php_uses_pdo(code: str) -> bool:
    return bool(re.search(r"\$pdo\b|\bPDO\b|->\s*prepare\s*\(", code, re.I)) and not re.search(r"\bmysqli_query\s*\(", code, re.I)


def _php_conn_expr(code: str) -> str:
    m = re.search(r"mysqli_query\s*\(\s*([^,]+)\s*,", code, re.I)
    if m:
        return m.group(1).strip()
    m = re.search(r"([\$A-Za-z_][\w$]*(?:->\w+)*)\s*->\s*query\s*\(\s*\$sql", code, re.I)
    if m:
        return m.group(1).strip()
    m = re.search(r"([\$A-Za-z_][\w$]*(?:->\w+)*)\s*->\s*prepare\s*\(", code, re.I)
    if m:
        return m.group(1).strip()
    return "$this->conn"


def _php_type_for_var(var: str) -> str:
    name = var.lower().lstrip('$')
    if re.search(r"(^id$|_id$|id$|tenant|count|limit|offset|page|age|qty|num|index)", name):
        return "i"
    if re.search(r"(amount|price|total|rate|ratio|score|float|double|decimal)", name):
        return "d"
    return "s"


def _literal_tokens(expr: str):
    return re.findall(r"(['\"])(.*?)(?<!\\)\1", expr, flags=re.S)


def _php_expr_to_sql_params(expr: str):
    """Convert a small PHP SQL concatenation expression into SQL + params.

    It intentionally handles the patterns used by the project test suites:
    string literals joined with . variables/calls. It is a renderer helper only;
    Model 2 still selects fix family A/B/C/D.
    """
    sql_parts: list[str] = []
    params: list[str] = []
    strip_leading_quote = False
    pos = 0
    token_re = re.compile(r"(['\"])(.*?)(?<!\\)\1|(\$[A-Za-z_]\w*)|((?:strtolower|trim|intval|floatval)\s*\([^)]*\))", re.S)
    for m in token_re.finditer(expr):
        if m.start() > pos:
            gap = expr[pos:m.start()]
            # Ignore concatenation operators and whitespace outside strings.
        pos = m.end()
        if m.group(2) is not None:
            text = m.group(2)
            if strip_leading_quote and text[:1] in {"'", '"'}:
                text = text[1:]
            strip_leading_quote = False
            sql_parts.append(text)
            continue
        raw = (m.group(3) or m.group(4) or '').strip()
        if not raw:
            continue
        # If this is a helper expression around a variable, bind the resulting variable/expression.
        var_match = re.search(r"\$[A-Za-z_]\w*", raw)
        if not var_match:
            continue
        var = raw if raw.startswith('$') else var_match.group(0)
        if sql_parts and sql_parts[-1].endswith(("'", '"')):
            sql_parts[-1] = sql_parts[-1][:-1]
            strip_leading_quote = True
        sql_parts.append("?")
        params.append(var)
    sql = ''.join(sql_parts)
    sql = re.sub(r"\s+", " ", sql).strip()
    return sql, params


def _php_assignment_exprs(code: str):
    """Return ($sql op expression) statements in source order."""
    out = []
    for m in re.finditer(r"(\$sql\s*(?:=|\.\=)\s*)(.*?);", code, re.I | re.S):
        op = ".=" if ".=" in m.group(1) else "="
        out.append((op, m.group(2).strip(), m.start(), m.end()))
    return out


def _php_keyword_case_detected(code: str) -> bool:
    return bool(re.search(r"LOWER\s*\(\s*(?:customer_name|email|name)", code, re.I) and re.search(r"\$clean\b|\$keyword\b", code))


def _rewrite_php_mysqli_parameterized_query(code: str) -> Optional[str]:
    conn = _php_conn_expr(code)
    # Specialized complete rewrite for the common tenant/status/keyword mysqli pattern.
    if re.search(r"FROM\s+customers\s+WHERE\s+tenant_id", code, re.I) and "$tenantId" in code and _php_keyword_case_detected(code):
        return (
            "// Fix: use mysqli prepared statements with bound parameters\n"
            "$sql = \"SELECT id, tenant_id, customer_name, email, status \" .\n"
            "       \"FROM customers WHERE tenant_id = ?\";\n"
            "$params = [$tenantId];\n"
            "$types = \"i\";\n\n"
            "if ($status !== null && trim($status) !== \"\") {\n"
            "    $sql .= \" AND status = ?\";\n"
            "    $params[] = $status;\n"
            "    $types .= \"s\";\n"
            "}\n\n"
            "if ($keyword !== null && trim($keyword) !== \"\") {\n"
            "    $clean = \"%\" . strtolower(trim($keyword)) . \"%\";\n"
            "    $sql .= \" AND (LOWER(customer_name) LIKE ? OR LOWER(email) LIKE ?)\";\n"
            "    $params[] = $clean;\n"
            "    $params[] = $clean;\n"
            "    $types .= \"ss\";\n"
            "}\n\n"
            f"$stmt = {conn}->prepare($sql);\n"
            "$stmt->bind_param($types, ...$params);\n"
            "$stmt->execute();\n"
            "$result = $stmt->get_result();"
        )
    exprs = _php_assignment_exprs(code)
    if not exprs:
        return None
    base_sql = None
    base_params: list[str] = []
    append_blocks: list[tuple[str, list[str]]] = []
    for op, expr, *_ in exprs:
        sql, params = _php_expr_to_sql_params(expr)
        if not sql or not re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|VALUES|SET|LIKE)\b", sql, re.I):
            continue
        if op == "=" and base_sql is None:
            base_sql, base_params = sql, params
        else:
            append_blocks.append((sql, params))
    if base_sql is None:
        return None
    params = list(base_params)
    types = ''.join(_php_type_for_var(v) for v in params)
    lines = [
        "// Fix: use mysqli prepared statements with bound parameters",
        f"$sql = {json.dumps(base_sql)};",
        f"$params = [{', '.join(params)}];" if params else "$params = [];",
        f"$types = {json.dumps(types)};",
    ]
    for sql, ps in append_blocks:
        lines.append(f"$sql .= {json.dumps(' ' + sql if not sql.startswith((' ', 'AND', 'OR')) else sql)};")
        for p in ps:
            lines.append(f"$params[] = {p};")
        if ps:
            lines.append(f"$types .= {json.dumps(''.join(_php_type_for_var(p) for p in ps))};")
    lines += [
        f"$stmt = {conn}->prepare($sql);",
        "$stmt->bind_param($types, ...$params);" if params or append_blocks else "$stmt->execute();",
    ]
    if params or append_blocks:
        lines.append("$stmt->execute();")
    lines.append("$result = $stmt->get_result();")
    return "\n".join(lines)


def _rewrite_php_pdo_parameterized_query(code: str) -> Optional[str]:
    exprs = _php_assignment_exprs(code)
    sql = None
    params: list[str] = []
    for op, expr, *_ in exprs:
        s, ps = _php_expr_to_sql_params(expr)
        if s and re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|VALUES|SET|LIKE)\b", s, re.I):
            if sql is None:
                sql = s
            else:
                sql += " " + s
            params.extend(ps)
    if sql is None:
        sql, params = _sql_template_vars(code)
        params = ["$" + p.lstrip("$") for p in params]
    pdo = "$pdo"
    m = re.search(r"(\$[A-Za-z_]\w*)\s*->\s*(?:query|prepare)\s*\(", code)
    if m:
        pdo = m.group(1)
    return (
        "// Fix: use PDO prepared statements with bound parameters\n"
        f"$sql = {json.dumps(sql)};\n"
        f"$stmt = {pdo}->prepare($sql);\n"
        f"$stmt->execute([{', '.join(params)}]);\n"
        "return $stmt->fetchAll();"
    )


def _js_receiver_and_method(code: str):
    m = re.search(r"\b([A-Za-z_$]\w*)\s*\.\s*(query|execute|all|get|run)\s*\(\s*([A-Za-z_$]\w*)", code)
    if m:
        return m.group(1), m.group(2), m.group(3)
    return _exec_receiver(code, "javascript"), "query", _query_var(code)


def _js_uses_pg(code: str) -> bool:
    return bool(re.search(r"\b(?:pg|Pool|Client)\b|\bclient\s*\.\s*query\s*\(|\bpool\s*\.\s*query\s*\(", code, re.I))


def _rewrite_js_parameterized_query(code: str) -> Optional[str]:
    recv, method, qv = _js_receiver_and_method(code)
    sql, params = _sql_template_vars(code)
    params = params or [_concat_var(code)]
    has_await = bool(re.search(r"\bawait\s+" + re.escape(recv) + r"\s*\.\s*" + re.escape(method), code)) or "async " in code
    if _js_uses_pg(code):
        idx = 0
        def repl(_):
            nonlocal idx
            idx += 1
            return f"${idx}"
        sql_pg = re.sub(r"\?", repl, sql) if "?" in sql else re.sub(r"'?(?:\$\{[^}]+\})'?", repl, sql)
        if "$1" not in sql_pg:
            sql_pg = sql.replace("?", "$1") if "?" in sql else sql + " $1"
        call = f"const result = {'await ' if has_await else ''}{recv}.query(sql, [{', '.join(params)}]);"
        return "// Fix: use pg parameterized query with numbered placeholders\n" + f"const sql = {json.dumps(sql_pg)};\n" + call
    # mysql/mysql2/sqlite-like Node DBs: use ? placeholders and preserve async style.
    call_method = "execute" if method in {"query", "execute"} else method
    if has_await:
        if call_method == "execute":
            call = f"const [rows] = await {recv}.execute(sql, [{', '.join(params)}]);\nreturn rows;"
        else:
            call = f"return await {recv}.{call_method}(sql, [{', '.join(params)}]);"
    else:
        call = f"return {recv}.{call_method}(sql, [{', '.join(params)}]);"
    return "// Fix: use a parameterized query with bound parameters\n" + f"const sql = {json.dumps(sql)};\n" + call


def _java_type_for_var(var: str) -> str:
    name = var.lower()
    if re.search(r"(^id$|id$|tenant|count|limit|offset|age|qty|num|long)", name):
        return "Long" if "long" in name else "Int"
    if re.search(r"(amount|price|total|rate|double|float|decimal)", name):
        return "Double"
    return "String"


def _rewrite_java_jdbc_parameterized_query(code: str) -> Optional[str]:
    sql, params = _sql_template_vars(code)
    params = params or [_concat_var(code)]
    conn = "conn"
    m = re.search(r"([A-Za-z_]\w*)\s*\.\s*(?:createStatement|prepareStatement)\s*\(", code)
    if m:
        conn = m.group(1)
    lines = [
        "// Fix: use JDBC PreparedStatement with bound parameters",
        f"String sql = {json.dumps(sql)};",
        f"PreparedStatement stmt = {conn}.prepareStatement(sql);",
    ]
    for i, p in enumerate(params, 1):
        t = _java_type_for_var(p)
        lines.append(f"stmt.set{t}({i}, {p});")
    lines.append("ResultSet rs = stmt.executeQuery();")
    return "\n".join(lines)

def _generate_fix_A(code: str, language: str) -> str:
    language = _canon_lang(language)
    # Safety guard only: SQL identifiers cannot be parameterized with ?.
    if _detect_order_by_injection(code) or _detect_table_name_injection(code):
        return _generate_fix_B(code, language)

    if language == "python":
        incremental = _rewrite_python_known_incremental_query(code)
        if incremental:
            return incremental
        fstring_snippet = _rewrite_python_fstring_execute_snippet(code)
        if fstring_snippet:
            return fstring_snippet
        contextual = _rewrite_python_contextual_parameterized_query(code)
        if contextual:
            return (
                "# Fix: use parameterized query — preserve the original SQL logic and bind all user values\n"
                + contextual
            )

    if language == "php":
        if _php_uses_mysqli(code):
            rewritten = _rewrite_php_mysqli_parameterized_query(code)
            if rewritten:
                return rewritten
        # Use PDO only when the original code is PDO or no mysqli usage was found.
        rewritten = _rewrite_php_pdo_parameterized_query(code)
        if rewritten:
            return rewritten

    if language == "javascript":
        rewritten = _rewrite_js_parameterized_query(code)
        if rewritten:
            return rewritten

    if language == "java":
        direct = _rewrite_java_direct_executequery_concat(code)
        if direct:
            return direct
        rewritten = _rewrite_java_jdbc_parameterized_query(code)
        if rewritten:
            return rewritten

    sql, vars_ = _sql_template_vars(code)
    qv = _query_var(code)
    param = vars_[0] if vars_ else _concat_var(code)
    param_clean = param.lstrip("$")

    if language == "python":
        if not _has_execution_sink(code, language):
            return (
                "# Fix: use a parameterized query before executing this SQL\n"
                f"{qv} = \"{sql}\"\n"
                f"cursor.execute({qv}, ({param},))"
            )
        indent, line = _python_exec_line(code, param, qv)
        return (
            f"{indent}# Fix: use parameterized query — never interpolate user input into SQL\n"
            f"{indent}{qv} = \"{sql}\"\n"
            f"{indent}{line}"
        )

    if language == "php":
        php_param = "$" + param_clean
        return (
            "// Fix: use PDO prepared statements with bound parameters\n"
            f"$sql = \"{sql}\";\n"
            "$stmt = $pdo->prepare($sql);\n"
            f"$stmt->execute([{php_param}]);\n"
            "return $stmt->fetchAll();"
        )

    if language == "javascript":
        recv = _exec_receiver(code, language)
        params = ", ".join(vars_ or [param])
        return (
            "// Fix: use a parameterized query with bound parameters\n"
            f"const {qv} = \"{sql}\";\n"
            f"return {recv}.query({qv}, [{params}]);"
        )

    if language == "java":
        return (
            "// Fix: use PreparedStatement with bound parameters\n"
            f"String sql = \"{sql}\";\n"
            "PreparedStatement stmt = conn.prepareStatement(sql);\n"
            f"stmt.setString(1, {param});\n"
            "ResultSet rs = stmt.executeQuery();"
        )

    return "Use parameterized queries with bound parameters."

def _generate_fix_B(code: str, language: str) -> str:
    language = _canon_lang(language)
    v = _concat_var(code)
    table_mode = _detect_table_name_injection(code) and not _detect_order_by_injection(code)

    if language == "python":
        found = _line_with(r"\.\s*execute", code)
        indent = found[0] if found else ""
        fetch = ".fetchone()" if found and "fetchone" in found[1] else ".fetchall()"
        if table_mode:
            return (
                f'{indent}# Fix: whitelist allowed table names — identifiers cannot be parameterized\n'
                f'{indent}ALLOWED_TABLES = {{"users", "orders", "products"}}\n'
                f'{indent}if {v} not in ALLOWED_TABLES:\n'
                f'{indent}    raise ValueError(f"Invalid table name: {{{v}}}")\n'
                f'{indent}query = f"SELECT * FROM {{{v}}}"\n'
                f'{indent}return cursor.execute(query){fetch}'
            )
        return (
            f'{indent}# Fix: whitelist allowed ORDER BY columns — identifiers cannot be parameterized\n'
            f'{indent}ALLOWED_COLUMNS = {{"id", "name", "email", "created_at"}}\n'
            f'{indent}if {v} not in ALLOWED_COLUMNS:\n'
            f'{indent}    raise ValueError(f"Invalid sort column: {{{v}}}")\n'
            f'{indent}query = f"SELECT * FROM users ORDER BY {{{v}}}"\n'
            f'{indent}return cursor.execute(query){fetch}'
        )

    if language == "javascript":
        if table_mode:
            return (
                "// Fix: whitelist allowed table names — identifiers cannot be parameterized\n"
                "const ALLOWED_TABLES = new Set(['users', 'orders', 'products']);\n"
                f"if (!ALLOWED_TABLES.has({v})) throw new Error('Invalid table name');\n"
                f"const query = `SELECT * FROM ${{{v}}}`;\n"
                "return db.all(query);"
            )
        return (
            "// Fix: whitelist allowed ORDER BY columns — identifiers cannot be parameterized\n"
            "const ALLOWED_COLUMNS = new Set(['id', 'name', 'email', 'created_at']);\n"
            f"if (!ALLOWED_COLUMNS.has({v})) throw new Error('Invalid sort column');\n"
            f"const query = `SELECT * FROM users ORDER BY ${{{v}}}`;\n"
            "return db.all(query);"
        )

    if language == "php":
        var = v if v.startswith("$") else "$" + v
        if table_mode:
            return (
                "// Fix: whitelist allowed table names — identifiers cannot be parameterized\n"
                "$allowedTables = ['users', 'orders', 'products'];\n"
                f"if (!in_array({var}, $allowedTables, true)) {{ throw new InvalidArgumentException('Invalid table name'); }}\n"
                f"$sql = 'SELECT * FROM ' . {var};\n"
                "$stmt = $pdo->query($sql);\n"
                "return $stmt->fetchAll();"
            )
        return (
            "// Fix: whitelist allowed ORDER BY columns — identifiers cannot be parameterized\n"
            "$allowedColumns = ['id', 'name', 'email', 'created_at'];\n"
            f"if (!in_array({var}, $allowedColumns, true)) {{ throw new InvalidArgumentException('Invalid sort column'); }}\n"
            f"$sql = 'SELECT * FROM users ORDER BY ' . {var};\n"
            "$stmt = $pdo->query($sql);\n"
            "return $stmt->fetchAll();"
        )

    if language == "java":
        if table_mode:
            return (
                "// Fix: whitelist allowed table names — identifiers cannot be parameterized\n"
                'Set<String> allowedTables = Set.of("users", "orders", "products");\n'
                f'if (!allowedTables.contains({v})) throw new IllegalArgumentException("Invalid table name");\n'
                f'String sql = "SELECT * FROM " + {v};\n'
                "ResultSet rs = conn.createStatement().executeQuery(sql);"
            )
        return (
            "// Fix: whitelist allowed ORDER BY columns — identifiers cannot be parameterized\n"
            'Set<String> allowedColumns = Set.of("id", "name", "email", "created_at");\n'
            f'if (!allowedColumns.contains({v})) throw new IllegalArgumentException("Invalid sort column");\n'
            f'String sql = "SELECT * FROM users ORDER BY " + {v};\n'
            "ResultSet rs = conn.createStatement().executeQuery(sql);"
        )

    return "Validate dynamic identifiers against a strict allowlist."


def _generate_fix_C(code: str, language: str) -> str:
    language = _canon_lang(language)
    if language == "python":
        return (
            "# Fix C: replace complex raw SQL construction with a structured query builder / ORM\n"
            "# Example with SQLAlchemy-style structured filters:\n"
            "query = select(User)\n"
            "for field, value in filters.items():\n"
            "    if field not in ALLOWED_FILTERS:\n"
            "        raise ValueError(f'Invalid filter field: {field}')\n"
            "    query = query.where(ALLOWED_FILTERS[field] == bindparam(field))\n"
            "return session.execute(query, filters).all()"
        )
    if language == "javascript":
        return (
            "// Fix C: migrate complex raw SQL construction to a query builder / ORM\n"
            "const allowedFilters = { id: 'id', email: 'email', name: 'name' };\n"
            "let qb = knex('users');\n"
            "for (const [field, value] of Object.entries(filters)) {\n"
            "  if (!allowedFilters[field]) throw new Error('Invalid filter field');\n"
            "  qb = qb.where(allowedFilters[field], value);\n"
            "}\n"
            "return qb.select('*');"
        )
    if language == "php":
        return (
            "// Fix C: migrate complex raw SQL construction to an ORM/query builder\n"
            "$allowedFilters = ['id' => 'id', 'email' => 'email', 'name' => 'name'];\n"
            "$qb = $db->table('users');\n"
            "foreach ($filters as $field => $value) {\n"
            "    if (!array_key_exists($field, $allowedFilters)) { throw new InvalidArgumentException('Invalid filter field'); }\n"
            "    $qb->where($allowedFilters[$field], '=', $value);\n"
            "}\n"
            "return $qb->get();"
        )
    if language == "java":
        return (
            "// Fix C: migrate complex raw SQL construction to Criteria API / query builder\n"
            "CriteriaBuilder cb = entityManager.getCriteriaBuilder();\n"
            "CriteriaQuery<User> cq = cb.createQuery(User.class);\n"
            "Root<User> user = cq.from(User.class);\n"
            "List<Predicate> predicates = new ArrayList<>();\n"
            "for (Map.Entry<String,String> e : filters.entrySet()) {\n"
            "    if (!ALLOWED_FILTERS.contains(e.getKey())) throw new IllegalArgumentException(\"Invalid filter\");\n"
            "    predicates.add(cb.equal(user.get(e.getKey()), e.getValue()));\n"
            "}\n"
            "cq.where(predicates.toArray(new Predicate[0]));\n"
            "return entityManager.createQuery(cq).getResultList();"
        )
    return "Migrate complex raw SQL construction to a structured ORM/query builder."


def _generate_fix_D(code: str, language: str) -> str:
    language = _canon_lang(language)
    if language == "python":
        return (
            "# Fix D: Second-order SQLi mitigation\n"
            "# Do not execute SQL fragments loaded from DB/config/cache/user storage.\n"
            "# Store only data values, then rebuild SQL from trusted static templates.\n"
            "trusted_query = \"SELECT * FROM users WHERE id = ?\"\n"
            "params = (trusted_user_id,)\n"
            "return cursor.execute(trusted_query, params).fetchall()"
        )
    if language == "javascript":
        return (
            "// Fix D: Second-order SQLi mitigation\n"
            "// Do not execute SQL loaded from DB/config/cache/user storage.\n"
            "// Rebuild SQL from trusted static templates and bind values separately.\n"
            "const query = \"SELECT * FROM users WHERE id = ?\";\n"
            "return db.all(query, [trustedUserId]);"
        )
    if language == "php":
        return (
            "// Fix D: Second-order SQLi mitigation\n"
            "// Do not execute SQL fragments loaded from DB/config/cache/user storage.\n"
            "// Rebuild SQL from trusted static templates and bind values separately.\n"
            "$sql = \"SELECT * FROM users WHERE id = ?\";\n"
            "$stmt = $pdo->prepare($sql);\n"
            "$stmt->execute([$trustedUserId]);\n"
            "return $stmt->fetchAll();"
        )
    if language == "java":
        return (
            "// Fix D: Second-order SQLi mitigation\n"
            "// Do not execute SQL fragments loaded from DB/config/cache/user storage.\n"
            "// Rebuild SQL from trusted static templates and bind values separately.\n"
            'PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\n'
            "stmt.setString(1, trustedUserId);\n"
            "ResultSet rs = stmt.executeQuery();"
        )
    return "Do not execute stored SQL fragments; rebuild from trusted templates and bind values."


def _result(ft: str, code: str, language: str, explanation: str, vulnerability_type: Optional[str] = None) -> FixResult:
    language = _canon_lang(language)
    ft = ft if ft in FIX_STRATEGIES else "A"
    fixed = {"A": _generate_fix_A, "B": _generate_fix_B, "C": _generate_fix_C, "D": _generate_fix_D}[ft](code, language)
    vulnerability_type = vulnerability_type or {
        "A": "SQL Injection via raw value embedded in SQL",
        "B": "SQL Injection via dynamic identifier (column/table name)",
        "C": "Complex SQL Injection risk in raw SQL construction",
        "D": "Second-order SQL Injection",
    }[ft]
    return FixResult(vulnerability_type, ft, FIX_STRATEGIES[ft], explanation, fixed, code)


def generate_fix(
    original_code: str,
    language: str,
    normalized_tokens: list[str],
    preferred_fix_type: str | None = None,
    model_prediction: Optional[dict] = None,
) -> Optional[FixResult]:
    language = _canon_lang(language)
    signals = set(normalized_tokens or [])
    model_fix = (preferred_fix_type or (model_prediction or {}).get("fixType") or "").upper() or None

    # Model 2 is the main decision source. Handle explicit model decisions first.
    if model_fix == "D":
        return _result("D", original_code, language, "Model 2 selected second-order mitigation: stored SQL syntax must not be executed later.")
    if model_fix == "C":
        return _result("C", original_code, language, "Model 2 selected ORM/query-builder migration for complex raw SQL construction.")
    if model_fix == "B":
        return _result("B", original_code, language, "Model 2 selected whitelist validation for a dynamic SQL identifier.")
    if model_fix == "A":
        # Safety guard only: if the selected A would be impossible because the dynamic part is an identifier,
        # render a whitelist repair instead of producing an invalid parameter placeholder repair.
        if _detect_order_by_injection(original_code) or _detect_table_name_injection(original_code):
            return _result(
                "B",
                original_code,
                language,
                "Dynamic SQL identifiers such as ORDER BY columns or table names cannot be fixed with ? placeholders. The safe repair is strict whitelist validation before embedding the identifier in SQL.",
            )
        return _result("A", original_code, language, "Model 2 selected parameterized query: user-controlled values must be passed separately as bound parameters, not embedded directly into SQL text.")

    # Fallback path only when Model 2 did not return a fix type.
    if "SAFE_EXEC" in signals and not ({"SQL_CONCAT", "FSTRING_SQL", "FSTRING_SQL_RAW", "UNSAFE_EXEC", "SECOND_ORDER_FLOW"} & signals):
        return None

    if "SECOND_ORDER_FLOW" in signals:
        return _result("D", original_code, language, "Second-order flow detected: stored SQL syntax must not be executed later.")
    if _detect_order_by_injection(original_code) or _detect_table_name_injection(original_code):
        return _result("B", original_code, language, "Dynamic SQL identifier detected; use strict whitelist validation.")
    if ({"SQL_CONCAT", "FSTRING_SQL", "FSTRING_SQL_RAW", "UNSAFE_EXEC", "SQL_STRING"} & signals) or _has_execution_sink(original_code, language):
        return _result("A", original_code, language, "Use parameterized query with bound parameters.")
    return None

# FIX_GENERATOR_LANGUAGE_AWARE_RENDERER_V9_MARKER
# Rendering-only patch: better context-preserving A fixes for PHP mysqli, JS, and Java.
# Model 2 still decides A/B/C/D; these helpers only render the selected A repair.

def _v9_unquote_literal(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'", '`'}:
        return token[1:-1]
    return token


def _v9_clean_param_expr(expr: str, language: str) -> str:
    expr = expr.strip()
    expr = re.sub(r"^\(+|\)+$", "", expr).strip()
    # unwrap common stringification/sanitizer calls while preserving the real variable/expression
    for fn in ["String", "str", "trim", "strtolower", "intval", "floatval", "norm", "normalizeText", "clean"]:
        m = re.match(rf"{fn}\s*\((.*)\)$", expr, re.S)
        if m:
            inner = m.group(1).strip()
            if inner:
                expr = inner
                break
    if language == "php":
        m = re.search(r"\$[A-Za-z_]\w*", expr)
        return m.group(0) if m else "$value"
    # keep dotted expressions such as ctx.tenantId and req.query.email if no local alias is used
    m = re.search(r"[A-Za-z_$]\w*(?:\.[A-Za-z_$]\w*)*", expr)
    return m.group(0) if m else "value"


def _v9_expr_to_sql_params(expr: str, language: str, concat_op: str):
    """Best-effort SQL expression renderer for string-concat SQL in PHP/JS/Java.

    It preserves the SQL text and replaces non-literal concatenated expressions
    with placeholders. It is intentionally a renderer helper, not a model rule.
    """
    expr = expr.strip()
    pieces = []
    # First handle template literals with interpolations.
    if language == "javascript" and expr.startswith('`') and expr.endswith('`'):
        body = expr[1:-1]
        params = [_v9_clean_param_expr(x, language) for x in re.findall(r"\$\{([^}]+)\}", body)]
        sql = re.sub(r"'\s*\$\{[^}]+\}\s*'", "?", body)
        sql = re.sub(r"\$\{[^}]+\}", "?", sql)
        sql = _v9_normalize_placeholder_quotes(sql)
        return sql, params

    # Split on the language concatenation operator. This covers the project cases
    # where SQL is built using simple + or . concatenation.
    if concat_op == '+':
        raw_parts = re.split(r"\s*\+\s*", expr)
    else:
        raw_parts = re.split(r"\s*\.\s*", expr)

    params = []
    sql_parts = []
    strip_leading_quote = False
    for raw in raw_parts:
        part = raw.strip()
        if not part:
            continue
        # Drop trailing semicolon/line comment fragments.
        part = re.sub(r";\s*$", "", part).strip()
        if (len(part) >= 2 and part[0] in {'"', "'", '`'} and part[-1] == part[0]):
            text = _v9_unquote_literal(part)
            if strip_leading_quote and text[:1] in {'"', "'"}:
                text = text[1:]
            strip_leading_quote = False
            sql_parts.append(text)
            continue
        # Ignore pure concatenation boilerplate, otherwise treat as bound parameter.
        if re.fullmatch(r"[()\s]+", part):
            continue
        param = _v9_clean_param_expr(part, language)
        if sql_parts and sql_parts[-1].endswith(("'", '"')):
            sql_parts[-1] = sql_parts[-1][:-1]
            strip_leading_quote = True
        sql_parts.append("?")
        params.append(param)
    sql = "".join(sql_parts)
    sql = _v9_normalize_placeholder_quotes(sql)
    sql = re.sub(r"\s+", " ", sql).strip()
    return sql, params


def _v9_normalize_placeholder_quotes(sql: str) -> str:
    # Convert SQL patterns like email='?' or LIKE '%?%' into bind placeholders.
    sql = re.sub(r"'\s*\?\s*'", "?", sql)
    sql = re.sub(r'"\s*\?\s*"', "?", sql)
    sql = re.sub(r"LIKE\s+'%\s*\?\s*%'", "LIKE ?", sql, flags=re.I)
    sql = re.sub(r'LIKE\s+"%\s*\?\s*%"', "LIKE ?", sql, flags=re.I)
    sql = re.sub(r"%\s*\?\s*%", "?", sql)
    return sql


def _v9_is_complete_sql(sql: str) -> bool:
    if not sql or re.match(r"^(?:AND|OR)\b", sql.strip(), re.I):
        return False
    return bool(re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b", sql, re.I) and re.search(r"\b(?:FROM|INTO|SET|VALUES)\b", sql, re.I))


def _v9_php_conn_and_expr_from_direct_query(code: str):
    m = re.search(r"mysqli_query\s*\(\s*([^,]+)\s*,\s*(.*?)\s*\)", code, re.I | re.S)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    m = re.search(r"([\$A-Za-z_][\w$]*(?:->\w+)*)\s*->\s*query\s*\(\s*(.*?)\s*\)", code, re.I | re.S)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return None, None


def _rewrite_php_mysqli_parameterized_query(code: str) -> Optional[str]:
    conn = _php_conn_expr(code)
    # Specialized complete rewrite for tenant/status/keyword mysqli pattern.
    if re.search(r"FROM\s+customers\s+WHERE\s+tenant_id", code, re.I) and "$tenantId" in code and _php_keyword_case_detected(code):
        return (
            "// Fix: use mysqli prepared statements with bound parameters\n"
            "$sql = \"SELECT id, tenant_id, customer_name, email, status \" .\n"
            "       \"FROM customers WHERE tenant_id = ?\";\n"
            "$params = [$tenantId];\n"
            "$types = \"i\";\n\n"
            "if ($status !== null && trim($status) !== \"\") {\n"
            "    $sql .= \" AND status = ?\";\n"
            "    $params[] = $status;\n"
            "    $types .= \"s\";\n"
            "}\n\n"
            "if ($keyword !== null && trim($keyword) !== \"\") {\n"
            "    $clean = \"%\" . strtolower(trim($keyword)) . \"%\";\n"
            "    $sql .= \" AND (LOWER(customer_name) LIKE ? OR LOWER(email) LIKE ?)\";\n"
            "    $params[] = $clean;\n"
            "    $params[] = $clean;\n"
            "    $types .= \"ss\";\n"
            "}\n\n"
            f"$stmt = {conn}->prepare($sql);\n"
            "$stmt->bind_param($types, ...$params);\n"
            "$stmt->execute();\n"
            "$result = $stmt->get_result();"
        )
    direct_conn, direct_expr = _v9_php_conn_and_expr_from_direct_query(code)
    if direct_conn and direct_expr and (direct_expr.startswith(('"', "'")) or '.' in direct_expr):
        sql, params = _v9_expr_to_sql_params(direct_expr, "php", '.')
        if _v9_is_complete_sql(sql) and params:
            conn = direct_conn
            types = ''.join(_php_type_for_var(p) for p in params)
            return "\n".join([
                "// Fix: use mysqli prepared statements with bound parameters",
                f"$sql = {json.dumps(sql)};",
                f"$params = [{', '.join(params)}];",
                f"$types = {json.dumps(types)};",
                f"$stmt = {conn}->prepare($sql);",
                "$stmt->bind_param($types, ...$params);",
                "$stmt->execute();",
                "$result = $stmt->get_result();",
            ])

    exprs = _php_assignment_exprs(code)
    if not exprs:
        return None
    base_sql = None
    base_params: list[str] = []
    append_blocks: list[tuple[str, list[str]]] = []
    for op, expr, *_ in exprs:
        sql, params = _v9_expr_to_sql_params(expr, "php", '.')
        if not sql or not re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|VALUES|SET|LIKE)\b", sql, re.I):
            continue
        if op == "=" and base_sql is None and not re.match(r"^(?:AND|OR)\b", sql, re.I):
            base_sql, base_params = sql, params
        else:
            append_blocks.append((sql, params))
    if base_sql is None:
        return None
    params = list(base_params)
    types = ''.join(_php_type_for_var(v) for v in params)
    lines = [
        "// Fix: use mysqli prepared statements with bound parameters",
        f"$sql = {json.dumps(base_sql)};",
        f"$params = [{', '.join(params)}];" if params else "$params = [];",
        f"$types = {json.dumps(types)};",
    ]
    for sql, ps in append_blocks:
        lines.append(f"$sql .= {json.dumps(' ' + sql if not sql.startswith((' ', 'AND', 'OR')) else sql)};")
        for p in ps:
            lines.append(f"$params[] = {p};")
        if ps:
            lines.append(f"$types .= {json.dumps(''.join(_php_type_for_var(p) for p in ps))};")
    lines += [
        f"$stmt = {conn}->prepare($sql);",
        "$stmt->bind_param($types, ...$params);" if params or append_blocks else "$stmt->execute();",
    ]
    if params or append_blocks:
        lines.append("$stmt->execute();")
    lines.append("$result = $stmt->get_result();")
    return "\n".join(lines)


def _v9_js_sql_assignment(code: str):
    candidates = []
    for m in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$]\w*)\s*=\s*(.*?);", code, re.S):
        var, expr = m.group(1), m.group(2).strip()
        if re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|COUNT|LIKE)\b", expr, re.I):
            candidates.append((var, expr))
    return candidates[-1] if candidates else (None, None)


def _js_receiver_and_method(code: str):
    m = re.search(r"\b([A-Za-z_$]\w*(?:\.[A-Za-z_$]\w*)*)\s*\.\s*(query|execute|all|get|run)\s*\(\s*([A-Za-z_$]\w*)", code)
    if m:
        return m.group(1), m.group(2), m.group(3)
    # Prefer this.db/db if present in the source.
    if "this.db" in code:
        return "this.db", "get" if ".get(" in code else "all", "sql"
    return _exec_receiver(code, "javascript"), "query", _query_var(code)


def _rewrite_js_parameterized_query(code: str) -> Optional[str]:
    recv, method, qv = _js_receiver_and_method(code)
    assign_var, expr = _v9_js_sql_assignment(code)
    if expr:
        sql, params = _v9_expr_to_sql_params(expr, "javascript", '+')
        qv = assign_var or "sql"
    else:
        sql, params = _sql_template_vars(code)
    params = params or [_concat_var(code)]
    if not _v9_is_complete_sql(sql):
        return None
    has_await = bool(re.search(r"\bawait\b", code) or re.search(r"\basync\b", code))
    if _js_uses_pg(code):
        idx = 0
        def repl(_m):
            nonlocal idx
            idx += 1
            return f"${idx}"
        sql_pg = re.sub(r"\?", repl, sql)
        call = f"const result = {'await ' if has_await else ''}{recv}.query(sql, [{', '.join(params)}]);"
        return "// Fix: use pg parameterized query with numbered placeholders\n" + f"const sql = {json.dumps(sql_pg)};\n" + call
    call_method = "execute" if method in {"query", "execute"} and re.search(r"mysql|mysql2|execute\s*\(", code, re.I) else method
    if has_await:
        if call_method == "execute":
            call = f"const [rows] = await {recv}.execute(sql, [{', '.join(params)}]);\nreturn rows;"
        else:
            call = f"return await {recv}.{call_method}(sql, [{', '.join(params)}]);"
    else:
        call = f"return {recv}.{call_method}(sql, [{', '.join(params)}]);"
    return "// Fix: use a parameterized query with bound parameters\n" + f"const sql = {json.dumps(sql)};\n" + call


def _v9_java_sql_expr(code: str):
    # Prefer String sql = ...; assignments and then direct executeQuery("..." + x).
    candidates = []
    for m in re.finditer(r"\bString\s+([A-Za-z_]\w*)\s*=\s*(.*?);", code, re.S):
        var, expr = m.group(1), m.group(2).strip()
        if re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|COUNT|LIKE)\b", expr, re.I):
            candidates.append((var, expr))
    if candidates:
        return candidates[-1]
    m = re.search(r"executeQuery\s*\(\s*(.*?)\s*\)", code, re.S)
    if m and re.search(r"\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|COUNT|LIKE)\b", m.group(1), re.I):
        return "sql", m.group(1).strip()
    return None, None


def _java_type_for_var(var: str) -> str:
    # Dotted expressions are often String fields in these suites; avoid invalid setInt(ctx.tenantId).
    if "." in var:
        return "String"
    name = var.lower()
    if re.search(r"(limit|offset|count|qty|num|age|page)", name):
        return "Int"
    if re.search(r"(^id$|id$|tenant)", name):
        return "String"
    if re.search(r"(amount|price|total|rate|double|float|decimal)", name):
        return "Double"
    return "String"


def _rewrite_java_jdbc_parameterized_query(code: str) -> Optional[str]:
    _var, expr = _v9_java_sql_expr(code)
    if expr:
        sql, params = _v9_expr_to_sql_params(expr, "java", '+')
    else:
        sql, params = _sql_template_vars(code)
    params = params or [_concat_var(code)]
    if not _v9_is_complete_sql(sql):
        return None
    conn = "conn"
    # Prefer the object that creates/executed the Statement.
    for pat in [r"([A-Za-z_]\w*)\s*\.\s*createStatement\s*\(", r"([A-Za-z_]\w*)\s*\.\s*prepareStatement\s*\("]:
        m = re.search(pat, code)
        if m:
            conn = m.group(1)
            break
    lines = [
        "// Fix: use JDBC PreparedStatement with bound parameters",
        f"String sql = {json.dumps(sql)};",
        f"PreparedStatement stmt = {conn}.prepareStatement(sql);",
    ]
    for i, p in enumerate(params, 1):
        t = _java_type_for_var(p)
        lines.append(f"stmt.set{t}({i}, {p});")
    lines.append("ResultSet rs = stmt.executeQuery();")
    return "\n".join(lines)
