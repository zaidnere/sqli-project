"""
Fix Recommendation Engine.

Analyses vulnerable code and produces:
  - vulnerability_type  : the category of SQLi found
  - fix_type            : which fix strategy applies
  - explanation         : plain-language description of the problem
  - fixed_code          : the corrected code (same variable names, safe pattern)
  - fix_strategy        : short label for the fix category

The engine is rule-based — it examines the original source code directly
using regex and AST patterns. This lets it generate fixes even before the
CNN+BiLSTM model is fully trained, and the output can also train the
Fix Recommendation Model in Colab.

Fix strategies:
  A — Parameterized query  (replaces concat / f-string injection)
  B — Input validation     (whitelist-based for column/table names)
  C — ORM migration        (when a full ORM alternative is cleaner)
  D — Second-order fix     (stored value re-used in unsafe query)
"""

import re
from dataclasses import dataclass
from typing import Optional


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class FixResult:
    vulnerability_type: str            # e.g. "SQL Injection via f-string interpolation"
    fix_type: str                       # "A" | "B" | "C" | "D"
    fix_strategy: str                   # Human label for fix_type
    explanation: str                    # What is wrong and why
    fixed_code: str                     # The corrected code
    original_code: str                  # The original (for reference)


# ── SQL keyword patterns ──────────────────────────────────────────────────────

_SQL_KEYWORDS = re.compile(
    r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION|FROM|WHERE|INTO|SET)\b',
    re.IGNORECASE,
)

_EXECUTE_CALLS = re.compile(
    r'(?:cursor|conn|connection|db|stmt|statement)\s*\.\s*execute\s*\(',
    re.IGNORECASE,
)


# ── Vulnerability detectors ───────────────────────────────────────────────────

def _detect_fstring_sql(code: str) -> Optional[re.Match]:
    """Detect f-string with SQL content: f\"SELECT...{var}...\""""
    return re.search(
        r'\bf["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|WHERE|FROM)[^"\']*\{[^}]+\}[^"\']*["\']',
        code, re.IGNORECASE | re.DOTALL,
    )


def _detect_concat_sql(code: str) -> Optional[re.Match]:
    """Detect string concatenation into SQL: \"SELECT...\" + var  or  var + \"...WHERE...\""""
    return re.search(
        r'(?:(?:\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^\"]*\"'
        r'|\'[^\']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^\']*\')'
        r'\s*\+.*|.*\+\s*(?:\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^\"]*\"'
        r'|\'[^\']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^\']*\'))',
        code, re.IGNORECASE,
    )


def _detect_format_sql(code: str) -> Optional[re.Match]:
    """Detect .format() or % formatting into SQL."""
    return re.search(
        r'(?:\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^\"]*\"'
        r'|\'[^\']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^\']*\')'
        r'\s*[%.]',
        code, re.IGNORECASE,
    )


def _detect_unsafe_execute(code: str) -> bool:
    """Detect execute(var) with single argument (no params tuple)."""
    for m in _EXECUTE_CALLS.finditer(code):
        start = m.end()
        depth = 1
        i = start
        commas = 0
        while i < len(code) and depth > 0:
            c = code[i]
            if c in ('(', '[', '{'):
                depth += 1
            elif c in (')', ']', '}'):
                depth -= 1
            elif c == ',' and depth == 1:
                commas += 1
            i += 1
        if commas == 0:
            return True
    return False


def _detect_order_by_injection(code: str) -> bool:
    """Detect dynamic ORDER BY / column name without whitelist."""
    return bool(re.search(
        r'ORDER\s+BY["\'\s]*\+\s*\w+|f["\'].*ORDER\s+BY.*\{',
        code, re.IGNORECASE,
    ))


def _detect_table_name_injection(code: str) -> bool:
    """Detect dynamic table name without whitelist."""
    return bool(re.search(
        r'FROM["\'\s]*\+\s*\w+|f["\'].*FROM\s+\{',
        code, re.IGNORECASE,
    ))


# ── Fix generators ────────────────────────────────────────────────────────────

def _extract_sql_template_and_vars(code: str) -> tuple[str, list[str]]:
    """
    Extract the SQL template and variable names from vulnerable code.
    Returns (safe_sql_template, [var_names]) ready for parameterized use.
    """
    # ── F-string: f"SELECT...{username}...{password}..." ─────────────────
    # Match the full f-string including escaped quotes inside
    fm = re.search(r'\b[fF]"((?:[^"\\]|\\.)*)"', code)
    if not fm:
        fm = re.search(r"\b[fF]'((?:[^'\\]|\\.)*)'", code)
    if fm:
        template = fm.group(1)
        # Extract variable names from {var} or '{var}'
        flat_vars = re.findall(r"'?\{([^}:!']+)\}'?", template)
        if not flat_vars:
            flat_vars = re.findall(r'\{([^}:!]+)\}', template)
        # Replace '{var}' and '{var}' (with surrounding SQL quotes) with ?
        param_template = re.sub(r"'?\{[^}]+\}'?", "?", template)
        return param_template, flat_vars

    # ── Concatenation: "SELECT..." + var ──────────────────────────────────
    parts = re.findall(
        r'["\']([^"\']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^"\']*)["\']',
        code, re.IGNORECASE,
    )
    var_parts = re.findall(r'\+\s*([A-Za-z_]\w*)', code)

    if parts:
        template = parts[0]
        # Strip trailing = value if already embedded
        param_template = re.sub(r"=\s*'[^']*'", "= ?", template)
        if '?' not in param_template:
            param_template = template.rstrip() + " ?"
        return param_template, var_parts

    return "", []


def _generate_fix_A(code: str, language: str) -> str:
    """
    Fix A — Parameterized query.
    Generates language-appropriate prepared statement.
    """
    sql_template, var_names = _extract_sql_template_and_vars(code)

    # Detect which execute variable is used
    exec_var = "cursor"
    em = re.search(r'(\w+)\s*\.\s*execute\s*\(', code)
    if em:
        exec_var = em.group(1)

    # Detect which variable holds the query
    query_var = "query"
    qm = re.search(r'(\w+)\s*=\s*(?:f["\']|["\'])', code)
    if qm:
        query_var = qm.group(1)

    params_str = ', '.join(var_names) if var_names else 'param1, param2'
    params_tuple = f"({params_str},)" if len(var_names) == 1 else f"({params_str})"

    if language in ("python",):
        placeholder = "?" if "sqlite" in code.lower() else "%s"
        if sql_template and var_names:
            placeholders = ", ".join([placeholder] * len(var_names))
            safe_sql = re.sub(r'\{[^}]+\}', placeholder, sql_template) \
                if '{' in sql_template else sql_template
            return (
                f'# Fix: use parameterized query — never interpolate user input into SQL\n'
                f'{query_var} = "{safe_sql}"\n'
                f'{exec_var}.execute({query_var}, {params_tuple})'
            )
        return (
            f'# Fix: use parameterized query — never interpolate user input into SQL\n'
            f'{query_var} = "SELECT * FROM table WHERE column = {placeholder}"\n'
            f'{exec_var}.execute({query_var}, ({params_str},))'
        )

    if language == "javascript":
        if var_names:
            placeholders = ", ".join(["?"] * len(var_names))
            params_arr = f"[{params_str}]"
            return (
                f'// Fix: use parameterized query\n'
                f'const {query_var} = "SELECT * FROM table WHERE column = ?";\n'
                f'{exec_var}.execute({query_var}, {params_arr});'
            )
        return (
            f'// Fix: use parameterized query\n'
            f'db.query("SELECT * FROM table WHERE column = ?", [param]);'
        )

    if language == "php":
        return (
            f'// Fix: use PDO prepared statements\n'
            f'$stmt = $pdo->prepare("SELECT * FROM table WHERE column = ?");\n'
            f'$stmt->execute([$param]);'
        )

    if language == "java":
        return (
            f'// Fix: use PreparedStatement\n'
            f'PreparedStatement stmt = conn.prepareStatement("SELECT * FROM table WHERE column = ?");\n'
            f'stmt.setString(1, param);\n'
            f'ResultSet rs = stmt.executeQuery();'
        )

    return (
        '# Fix: replace string concatenation / interpolation with parameterized queries.\n'
        '# Pass user input as bound parameters, never directly into the SQL string.'
    )


def _generate_fix_B(code: str, language: str) -> str:
    """Fix B — Whitelist validation for column/table names that cannot be parameterized."""
    if language == "python":
        return (
            '# Fix: whitelist allowed values — column/table names cannot be parameterized\n'
            'ALLOWED_COLUMNS = {"name", "email", "created_at"}  # define your safe set\n'
            'if sort_column not in ALLOWED_COLUMNS:\n'
            '    raise ValueError(f"Invalid column: {sort_column}")\n'
            'query = f"SELECT * FROM users ORDER BY {sort_column}"  # safe: whitelisted\n'
            'cursor.execute(query)'
        )
    if language == "javascript":
        return (
            '// Fix: whitelist allowed values\n'
            "const ALLOWED_COLUMNS = new Set(['name', 'email', 'created_at']);\n"
            'if (!ALLOWED_COLUMNS.has(sortColumn)) throw new Error("Invalid column");\n'
            'db.query(`SELECT * FROM users ORDER BY ${sortColumn}`);'
        )
    return (
        '# Fix: validate column/table names against a strict whitelist before use.\n'
        '# These identifiers cannot be parameterized — whitelisting is the only safe approach.'
    )


# ── Main engine ───────────────────────────────────────────────────────────────

def generate_fix(
    original_code: str,
    language: str,
    normalized_tokens: list[str],
) -> Optional[FixResult]:
    """
    Analyse the original source code and return a FixResult, or None if
    no vulnerability is detected by the rule-based engine.

    Parameters
    ----------
    original_code     : raw source code as uploaded
    language          : "python" | "javascript" | "php" | "java"
    normalized_tokens : output of normalize_tokens(), used to read semantic signals
    """
    signals = set(normalized_tokens)

    has_fstring_sql  = "FSTRING_SQL"  in signals
    has_unsafe_exec  = "UNSAFE_EXEC"  in signals
    has_sql_concat   = "SQL_CONCAT"   in signals
    has_safe_exec    = "SAFE_EXEC"    in signals
    has_sql_string   = "SQL_STRING"   in signals

    # Nothing to fix if all signals are safe
    if has_safe_exec and not has_fstring_sql and not has_unsafe_exec and not has_sql_concat:
        return None

    # ── Detect ORDER BY / column injection (Fix B) ────────────────────────
    if _detect_order_by_injection(original_code) or _detect_table_name_injection(original_code):
        return FixResult(
            vulnerability_type="SQL Injection via dynamic identifier (column/table name)",
            fix_type="B",
            fix_strategy="Whitelist Validation",
            explanation=(
                "Column names and table names cannot be passed as SQL parameters — "
                "they must be embedded in the query string directly. This means the "
                "only safe approach is to validate the value against a strict whitelist "
                "of allowed identifiers before using it. Never accept arbitrary column "
                "or table names from user input."
            ),
            fixed_code=_generate_fix_B(original_code, language),
            original_code=original_code,
        )

    # ── F-string SQL injection (Fix A) ────────────────────────────────────
    if has_fstring_sql:
        return FixResult(
            vulnerability_type="SQL Injection via f-string interpolation",
            fix_type="A",
            fix_strategy="Parameterized Query",
            explanation=(
                "The query is built using a Python f-string that embeds user-controlled "
                "variables directly into the SQL text (e.g. f\"SELECT...{username}\"). "
                "This allows an attacker to inject arbitrary SQL by supplying a malicious "
                "value such as: username = \"' OR '1'='1\". "
                "Fix: replace the f-string with a plain string containing ? or %s "
                "placeholders, and pass the variables as a separate tuple to execute()."
            ),
            fixed_code=_generate_fix_A(original_code, language),
            original_code=original_code,
        )

    # ── String concatenation SQL injection (Fix A) ────────────────────────
    if has_sql_concat or (has_sql_string and has_unsafe_exec):
        vuln_detail = "string concatenation (+ operator)" if has_sql_concat else \
                      "unsafe execute() call with no parameter tuple"
        return FixResult(
            vulnerability_type=f"SQL Injection via {vuln_detail}",
            fix_type="A",
            fix_strategy="Parameterized Query",
            explanation=(
                f"The SQL query is constructed by {vuln_detail}, which allows "
                "an attacker to inject arbitrary SQL. For example, passing "
                "username = \"admin'--\" would bypass authentication. "
                "Fix: use a parameterized query — write the SQL with ? or %s "
                "placeholders and pass user values separately to execute()."
            ),
            fixed_code=_generate_fix_A(original_code, language),
            original_code=original_code,
        )

    # ── Format-string injection (Fix A) ───────────────────────────────────
    if _detect_format_sql(original_code):
        return FixResult(
            vulnerability_type="SQL Injection via string formatting (% or .format())",
            fix_type="A",
            fix_strategy="Parameterized Query",
            explanation=(
                "The query uses Python % formatting or .format() to insert user input "
                "directly into the SQL string. These are equivalent to f-string injection "
                "and equally dangerous. Fix: use parameterized queries with ? or %s."
            ),
            fixed_code=_generate_fix_A(original_code, language),
            original_code=original_code,
        )

    # ── Unsafe execute with SQL string (catch-all) ────────────────────────
    if has_unsafe_exec and has_sql_string:
        return FixResult(
            vulnerability_type="Possible SQL Injection — execute() called without parameters",
            fix_type="A",
            fix_strategy="Parameterized Query",
            explanation=(
                "execute() is called with a single argument (no parameter tuple). "
                "If the query string was built from user input anywhere upstream, "
                "this is vulnerable. Always pass user-controlled values as bound "
                "parameters: cursor.execute(query, (value,))."
            ),
            fixed_code=_generate_fix_A(original_code, language),
            original_code=original_code,
        )

    return None
