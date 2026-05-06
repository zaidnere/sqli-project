"""Model 2 fix renderer with semantic safety guards. Does not affect Model 1."""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional
@dataclass
class FixResult:
    vulnerability_type: str; fix_type: str; fix_strategy: str; explanation: str; fixed_code: str; original_code: str
FIX_STRATEGIES={"A":"Parameterized Query","B":"Whitelist Validation","C":"ORM / Query Builder Migration","D":"Second-Order Mitigation"}
def _strip_comments(code, language):
    if language == "python": return re.sub(r"#.*", "", code)
    code=re.sub(r"/\*.*?\*/", "", code, flags=re.S); return re.sub(r"//[^\n\r]*", "", code)
def _rx(p,t,flags=re.I|re.S): return re.search(p,t,flags) is not None
def _indent_of(line): return re.match(r"^(\s*)", line).group(1)
def _line_with(p, code):
    for line in code.splitlines():
        if re.search(p,line,re.I): return _indent_of(line), line
    return None
def _detect_order_by_injection(code): return _rx(r"ORDER\s+BY[\s\S]{0,140}(?:\+\s*\w+|\$\{|\.\s*\$\w+)", _strip_comments(code,"python"))
def _detect_table_name_injection(code): return _rx(r"FROM[\s\S]{0,100}(?:\+\s*\w+|\$\{|\.\s*\$\w+)", _strip_comments(code,"python"))
def _has_execution_sink(code, language):
    c=_strip_comments(code,language)
    if language=="python": return _rx(r"\.\s*execute(?:many|script)?\s*\(", c)
    if language=="javascript": return _rx(r"\.\s*(?:all|get|run|each|exec|query|execute|raw)\s*\(", c)
    if language=="java": return _rx(r"\.\s*(?:executeQuery|executeUpdate|execute|queryForList|query|update)\s*\(|prepareStatement\s*\(|createStatement\s*\(", c)
    if language=="php": return _rx(r"->\s*(?:query|exec|execute|prepare)\s*\(|mysqli_query\s*\(", c)
    return False
def _query_var(code):
    m=re.search(r"\b([A-Za-z_]\w*)\s*=\s*(?:f?[\"']|`)", code); return m.group(1) if m else "query"
def _exec_receiver(code, language):
    m=re.search(r"\b([A-Za-z_]\w*)\s*\.\s*execute\s*\(", code) if language=="python" else re.search(r"\b([A-Za-z_$]\w*)\s*\.\s*(?:all|get|run|each|query|execute)\s*\(", code)
    return m.group(1) if m else ("cursor" if language=="python" else "db")
def _concat_var(code):
    m=re.search(r"(?:SELECT|INSERT|UPDATE|DELETE|WHERE|ORDER\s+BY|FROM)[^\n;]*[\"']\s*\+\s*([A-Za-z_$]\w*)", code, re.I)
    if m: return m.group(1)
    m=re.search(r"\+\s*([A-Za-z_$]\w*)", code); return m.group(1) if m else "value"
def _sql_template_vars(code):
    fm=re.search(r"\b[fF][\"']((?:[^\"'\\]|\\.)*)[\"']", code, re.S)
    if fm:
        t=fm.group(1); return re.sub(r"'?\{[^}]+\}'?","?",t), re.findall(r"\{\s*([A-Za-z_]\w*)",t) or ["value"]
    jm=re.search(r"`([^`]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^`]*)`", code, re.I|re.S)
    if jm:
        t=jm.group(1); return re.sub(r"'?\$\{[^}]+\}'?","?",t), re.findall(r"\$\{\s*([A-Za-z_$]\w*)",t) or ["value"]
    parts=re.findall(r"[\"']([^\"']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|ORDER\s+BY)[^\"']*)[\"']", code, re.I); v=_concat_var(code)
    if parts:
        t=parts[0].rstrip(); return (t + (" ?" if not re.search(r"(?:=|LIKE|>|<|>=|<=)\s*$",t,re.I) else " ?")), [v]
    return "SELECT * FROM table WHERE column = ?", [v]
def _python_exec_line(code):
    found=_line_with(r"\.\s*execute\s*\(", code)
    if not found: return "", "cursor.execute(query, (value,))"
    indent,line=found; prefix="return " if re.search(r"\breturn\b", line) else ""; recv=_exec_receiver(line,"python")
    suffix=""; m=re.search(r"\.\s*execute\s*\([^)]*\)(\s*\.\s*(?:fetchone|fetchall|fetchmany)\s*\([^)]*\))", line)
    if m: suffix=re.sub(r"\s+","",m.group(1))
    return indent, f"{prefix}{recv}.execute(query, ({_concat_var(code)},)){suffix}"
def _generate_fix_A(code, language):
    if _detect_order_by_injection(code) or _detect_table_name_injection(code): return _generate_fix_B(code, language)
    sql, vars_=_sql_template_vars(code); qv=_query_var(code); param=vars_[0] if vars_ else "value"
    if not _has_execution_sink(code, language): return f"# Advisory fix: SQL is built but not executed here.\n{qv} = \"{sql}\"\nparams = ({param},)"
    if language=="python":
        indent, line=_python_exec_line(code); return f"{indent}# Fix: use parameterized query — never interpolate user input into SQL\n{indent}{qv} = \"{sql}\"\n{indent}{line}"
    if language=="javascript": return f"// Fix: use parameterized query\nconst {qv} = \"{sql}\";\nreturn {_exec_receiver(code,language)}.all({qv}, [{', '.join(vars_)}]);"
    if language=="php": return f"// Fix: use PDO prepared statements\n$stmt = $pdo->prepare(\"{sql}\");\n$stmt->execute([$${param.lstrip('$')}]);"
    if language=="java": return f"// Fix: use PreparedStatement\nPreparedStatement stmt = conn.prepareStatement(\"{sql}\");\nstmt.setString(1, {param});\nResultSet rs = stmt.executeQuery();"
    return "Use parameterized queries with bound parameters."
def _generate_fix_B(code, language):
    v=_concat_var(code); table_mode=_detect_table_name_injection(code) and not _detect_order_by_injection(code)
    if language=="python":
        found=_line_with(r"\.\s*execute\s*\(", code); indent=found[0] if found else ""; fetch=".fetchone()" if found and "fetchone" in found[1] else ".fetchall()"
        if table_mode: return f"{indent}# Fix: whitelist allowed table names — identifiers cannot be parameterized\n{indent}ALLOWED_TABLES = {{\"users\", \"orders\", \"products\"}}\n{indent}if {v} not in ALLOWED_TABLES:\n{indent}    raise ValueError(f\"Invalid table name: {{{v}}}\")\n{indent}query = f\"SELECT * FROM {{{v}}}\"\n{indent}return cursor.execute(query){fetch}"
        return f"{indent}# Fix: whitelist allowed ORDER BY columns — identifiers cannot be parameterized\n{indent}ALLOWED_COLUMNS = {{\"id\", \"name\", \"email\", \"created_at\"}}\n{indent}if {v} not in ALLOWED_COLUMNS:\n{indent}    raise ValueError(f\"Invalid sort column: {{{v}}}\")\n{indent}query = f\"SELECT * FROM users ORDER BY {{{v}}}\"\n{indent}return cursor.execute(query){fetch}"
    if language=="javascript": return f"// Fix: whitelist allowed ORDER BY columns\nconst ALLOWED_COLUMNS = new Set(['id','name','email','created_at']);\nif (!ALLOWED_COLUMNS.has({v})) throw new Error('Invalid sort column');\nconst query = `SELECT * FROM users ORDER BY ${{{v}}}`;\nreturn db.all(query);"
    if language=="php":
        var=v if v.startswith('$') else '$'+v; return f"// Fix: whitelist allowed ORDER BY columns\n$allowedColumns = ['id','name','email','created_at'];\nif (!in_array({var}, $allowedColumns, true)) {{ throw new InvalidArgumentException('Invalid sort column'); }}\n$sql = \"SELECT * FROM users ORDER BY \" . {var};\n$stmt = $pdo->query($sql);"
    if language=="java": return f"// Fix: whitelist allowed ORDER BY columns\nSet<String> allowedColumns = Set.of(\"id\",\"name\",\"email\",\"created_at\");\nif (!allowedColumns.contains({v})) throw new IllegalArgumentException(\"Invalid sort column\");\nString sql = \"SELECT * FROM users ORDER BY \" + {v};\nResultSet rs = conn.createStatement().executeQuery(sql);"
    return "Validate dynamic identifiers against a strict allowlist."
def _generate_fix_C(code, language): return "# Fix C: migrate complex raw SQL construction to a structured ORM/query builder."
def _generate_fix_D(code, language): return "# Fix D: do not execute SQL loaded from DB/config/user storage. Rebuild SQL from trusted static templates."
def _result(ft, code, language, exp, vt=None):
    ft=ft if ft in FIX_STRATEGIES else "A"; fixed={"A":_generate_fix_A,"B":_generate_fix_B,"C":_generate_fix_C,"D":_generate_fix_D}[ft](code, language)
    vt=vt or {"A":"SQL Injection via raw value embedded in SQL","B":"SQL Injection via dynamic identifier (column/table name)","C":"Complex SQL Injection risk in raw SQL construction","D":"Second-order SQL Injection"}[ft]
    return FixResult(vt, ft, FIX_STRATEGIES[ft], exp, fixed, code)
def generate_fix(original_code: str, language: str, normalized_tokens: list[str], preferred_fix_type: str | None=None, model_prediction: Optional[dict]=None) -> Optional[FixResult]:
    signals=set(normalized_tokens or []); mf=(preferred_fix_type or (model_prediction or {}).get("fixType") or "").upper() or None
    if "SAFE_EXEC" in signals and not ({"SQL_CONCAT","FSTRING_SQL","FSTRING_SQL_RAW","UNSAFE_EXEC","SECOND_ORDER_FLOW"}&signals): return None
    if _detect_order_by_injection(original_code) or _detect_table_name_injection(original_code): return _result("B", original_code, language, "Dynamic SQL identifiers such as ORDER BY columns or table names cannot be fixed with ? placeholders. The safe repair is strict whitelist validation before embedding the identifier in SQL.")
    if "SECOND_ORDER_FLOW" in signals or mf=="D": return _result("D", original_code, language, "Model 2 selected second-order mitigation: stored SQL syntax must not be executed later.")
    if mf=="C": return _result("C", original_code, language, "Model 2 selected ORM/query-builder migration for complex raw SQL construction.")
    if mf=="B": return _result("B", original_code, language, "Model 2 selected whitelist validation for a dynamic SQL identifier.")
    if ({"SQL_CONCAT","FSTRING_SQL","FSTRING_SQL_RAW","UNSAFE_EXEC","SQL_STRING"}&signals) or _has_execution_sink(original_code, language): return _result("A", original_code, language, "Model 2 selected parameterized query: user-controlled values must be passed separately as bound parameters, not embedded directly into SQL text.")
    return None
