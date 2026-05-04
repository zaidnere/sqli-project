"""
Semantic normalization of tokenized source code.

Maps raw tokens to a fixed vocabulary of semantic placeholders:
  - Variable names  → VAR_n
  - Function calls  → FUNC_n
  - Properties      → PROPERTY_n
  - Plain strings   → STRING
  - SQL strings     → SQL_STRING
  - F-string SQL    → FSTRING_SQL   ← NEW: f"...{var}..." with SQL content
  - Numbers         → NUMBER
  - Keywords / operators stay as-is

Semantic signal tokens injected into the sequence:
  UNSAFE_EXEC      — execute(single_var) with no parameter tuple (vulnerable)
  SAFE_EXEC        — execute(var, params_tuple) (parameterized, safe)
  SQL_CONCAT       — SQL_STRING followed by + operator (dangerous concatenation)

Data-flow signal tokens (Gap-A v2 — semantic flow, not surface patterns):
  WHITELIST_VAR    — variable assigned via `X if X in <SET> else default` pattern.
                     Marks a strict-allowlist-validated identifier; safe even
                     inside FSTRING_SQL (e.g. ORDER BY {safe_col}).
  DB_LOADED_VAR    — variable assigned from cursor.fetchone()/.fetchall()/
                     .fetchval() etc. Marks the source of a SECOND_ORDER chain.
  BOOLEAN_SINK     — function ends with `return <comparison-of-fetch-result>`
                     (e.g. `return row is not None`, `return count > 0`).
                     Marks a BLIND outcome — query result reduced to bool.

These signals give the CNN+BiLSTM strong local features to learn from.
"""

import re

from app.core.constants import (
    LANGUAGE_KEYWORDS,
    SQL_PATTERNS,
    SQL_FRAGMENT_KEYWORDS,
    SQL_FRAGMENT_COMBOS,
    MAX_VAR_TOKENS,
    MAX_FUNC_TOKENS,
    MAX_PROPERTY_TOKENS,
)


# ── Token classification helpers ──────────────────────────────────────────────

def is_number(token: str) -> bool:
    try:
        float(token)
        return True
    except ValueError:
        return False


def is_string_literal(token: str) -> bool:
    """True for plain string literals (not f-strings, not template literals)."""
    return (
        len(token) >= 2
        and (
            (token[0] == '"' and token[-1] == '"')
            or (token[0] == "'" and token[-1] == "'")
        )
    )


def is_template_literal(token: str) -> bool:
    """True for JavaScript template literals (backtick strings)."""
    return len(token) >= 2 and token[0] == "`" and token[-1] == "`"


def _has_interpolation(token: str) -> bool:
    """True if a template literal contains ${...} interpolation."""
    return is_template_literal(token) and "${" in token


def is_fstring(token: str) -> bool:
    """
    True for f-string tokens — Python f-strings (f"..." / f'...') OR
    JavaScript template literals containing ${...} interpolation.
    """
    if len(token) >= 3 and token[0].lower() == 'f' and token[1] in ('"', "'"):
        return True
    if _has_interpolation(token):
        return True
    return False


def _contains_sql(content: str) -> bool:
    """Check if a string body contains SQL keywords (full statements or fragments)."""
    normalized = " ".join(content.lower().split())
    # Pad with spaces so word-boundary checks like " and " work at start/end
    padded = " " + normalized + " "

    # Full-statement patterns (SELECT...FROM, INSERT...INTO, etc.)
    for first, second in SQL_PATTERNS:
        if first in normalized and second in normalized:
            return True

    # Single-keyword markers strong enough on their own (WHERE, ORDER BY, etc.)
    for fragment in SQL_FRAGMENT_KEYWORDS:
        if fragment in normalized:
            return True

    # Two-feature combos for partial fragments built incrementally
    # (e.g. " AND foo LIKE '%"). Both features must be present.
    for combo in SQL_FRAGMENT_COMBOS:
        if all(feature in padded for feature in combo):
            return True

    return False


def is_sql_string(token: str) -> bool:
    """Plain string literal that contains SQL. Includes template literals
    that do NOT have ${...} interpolation (treated as plain SQL strings)."""
    if is_string_literal(token):
        return _contains_sql(token[1:-1])
    if is_template_literal(token) and not _has_interpolation(token):
        return _contains_sql(token[1:-1])
    return False


def is_fstring_sql(token: str) -> bool:
    """F-string / template literal containing SQL — dangerous interpolation."""
    # Python f-string: f"..." / f'...'
    if len(token) >= 3 and token[0].lower() == 'f' and token[1] in ('"', "'"):
        body = token[1:]
        if len(body) < 2:
            return False
        return _contains_sql(body[1:-1])
    # JavaScript template literal with interpolation
    if _has_interpolation(token):
        return _contains_sql(token[1:-1])
    return False


def is_identifier(token: str) -> bool:
    return token.isidentifier()


_INTERP_VAR_RE = re.compile(r"\{(\s*[A-Za-z_][A-Za-z0-9_]*\s*)(?:[\[\.\}!:])")
_JS_INTERP_VAR_RE = re.compile(r"\$\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*[\}\.\[\?]")


def _extract_interpolated_vars(token: str) -> set[str]:
    """
    Return the set of bare identifier names interpolated inside an f-string
    or template literal token. Only top-level identifiers — `{a.b}` returns
    `{a}`, `{a[0]}` returns `{a}`. Format spec like `{x:.2f}` returns `{x}`.

    Returns empty set for plain strings or interpolations of non-identifier
    expressions (e.g. `{a + b}`, `{f(x)}`, literal text).
    """
    # Python f-string body
    if len(token) >= 3 and token[0].lower() == 'f' and token[1] in ('"', "'"):
        body = token[1:]
        if len(body) < 2:
            return set()
        inner = body[1:-1]
        # Wrap with sentinel so the regex's lookahead always has a char to match
        return {m.group(1).strip() for m in _INTERP_VAR_RE.finditer(inner + "}")}
    # JS template literal body
    if _has_interpolation(token):
        inner = token[1:-1]
        return {m.group(1) for m in _JS_INTERP_VAR_RE.finditer(inner + "}")}
    return set()


# ── Placeholder management ────────────────────────────────────────────────────

def get_or_create_placeholder(
    token: str,
    mapping: dict,
    current_count: int,
    prefix: str,
    max_tokens: int,
    fallback: str,
) -> tuple[str, int]:
    if token in mapping:
        return mapping[token], current_count
    if current_count < max_tokens:
        placeholder = f"{prefix}_{current_count}"
        mapping[token] = placeholder
        return placeholder, current_count + 1
    mapping[token] = fallback
    return fallback, current_count


# ── Execute-call pattern detector ─────────────────────────────────────────────

def _classify_execute_call(tokens: list[str], exec_idx: int) -> str | None:
    """
    Look at cursor.execute(…) and decide:
      SAFE_EXEC    — parameterized (has a second argument)
                   — OR single arg is a literal SQL string (static SQL)
      UNSAFE_EXEC  — single arg is a variable / expression carrying user data
      None         — cannot determine

    Called when tokens[exec_idx] == 'execute' and tokens[exec_idx+1] == '('
    """
    if exec_idx + 1 >= len(tokens) or tokens[exec_idx + 1] != '(':
        return None

    # Scan for matching closing paren, counting commas at depth 1, and
    # collecting argument tokens at depth 1.
    depth = 0
    commas_at_depth1 = 0
    arg1_tokens: list[str] = []
    i = exec_idx + 1
    while i < len(tokens):
        t = tokens[i]
        if t in ('(', '[', '{'):
            depth += 1
            if depth > 1:
                arg1_tokens.append(t)
        elif t in (')', ']', '}'):
            depth -= 1
            if depth == 0:
                break
            if depth >= 1:
                arg1_tokens.append(t)
        elif t == ',' and depth == 1:
            commas_at_depth1 += 1
            # Only collect tokens BEFORE first comma (= first arg)
            if commas_at_depth1 == 1:
                # arg1_tokens already complete; keep scanning for closing paren
                pass
        else:
            if depth >= 1 and commas_at_depth1 == 0:
                arg1_tokens.append(t)
        i += 1

    # Parameterized — has a second arg
    if commas_at_depth1 >= 1:
        return 'SAFE_EXEC'

    # Single arg — check whether it's a literal-only string (static SQL).
    # Tokens in arg1_tokens (excluding outer paren). If all tokens are
    # string-literal-like (start with " ' or `) or string concatenation of
    # literals only, it's static SAFE.
    non_string_meaningful = [
        t for t in arg1_tokens
        if t not in (',', '+', '.')
        and not (len(t) >= 2 and t[0] in '"\'`' and t[-1] in '"\'`')
    ]
    if not non_string_meaningful:
        return 'SAFE_EXEC'

    return 'UNSAFE_EXEC'


# ── Data-flow signal detectors (Gap-A v2) ────────────────────────────────────

# Container types that signal an allowlist when used with `in`
_ALLOWLIST_CONTAINERS = {"set", "frozenset", "tuple", "list", "dict"}

# Identifier-name hints that strongly suggest an allowlist constant
_ALLOWLIST_NAME_HINTS = (
    "allowed", "allowlist", "whitelist", "valid_", "permitted", "safe_",
)

# Suffixes specific to closed-mapping constants used as allowlists.
# Strict — only matches at end of identifier.
_ALLOWLIST_SUFFIXES = (
    "_MAP", "_LOOKUP", "_DICT",
    "_TABLES", "_COLUMNS", "_FIELDS", "_KEYS", "_NAMES",
    "_TABLE_MAP",
)


def _is_allowlist_identifier(token: str) -> bool:
    """
    Strict heuristic: identifier looks like an allowlist constant.

    A name qualifies if UPPER_CASE AND either:
      (a) is an exact short allowlist name (ALLOWED, WHITELIST, ALLOWLIST,
          PERMITTED — strong intent on their own), or
      (b) contains an allowlist hint substring (ALLOWED, WHITELIST, VALID_,
          PERMITTED, SAFE_), or
      (c) ends with a closed-mapping suffix (_MAP, _LOOKUP, _DICT).

    Examples that PASS:
      ALLOWED_SORT_COLUMNS, WHITELIST_TABLES, VALID_OPERATORS, SAFE_COLUMNS,
      TABLE_MAP, COLUMN_LOOKUP, ROUTING_DICT,
      ALLOWED, WHITELIST  (exact short names)
    Examples that FAIL:
      sort_by, columns, my_list, get_columns(), AllowedColumns,
      USER_ID, MAX_ROWS, USER_TABLE_NAME
    """
    if not token or not token.isupper():
        return False
    # Exact short names
    if token in ("ALLOWED", "ALLOWLIST", "WHITELIST", "PERMITTED"):
        return True
    if "_" not in token:
        return False
    if any(hint.upper() in token for hint in _ALLOWLIST_NAME_HINTS):
        return True
    if any(token.endswith(suffix) for suffix in _ALLOWLIST_SUFFIXES):
        return True
    return False


def _detect_whitelist_assignment(tokens: list[str], eq_idx: int) -> bool:
    """
    Detect strict-allowlist patterns across languages:

      Pattern A (Python ternary):
        <var> = <expr> if <expr> in <ALLOWLIST_NAME> else <default>

      Pattern B (Python dict lookup):
        <var> = <ALLOWLIST_DICT>.get(<expr>, <default>)
        <var> = <ALLOWLIST_DICT>[<expr>] if <expr> in <ALLOWLIST_DICT> else <default>

      Pattern C (Java/JS Set.contains / Set.has ternary):
        <var> = <NAME>.contains(<expr>) ? <expr> : <default>
        <var> = <NAME>.has(<expr>) ? <expr> : <default>
        Where NAME is allowlist-named (UPPER_CASE with hint or _MAP/_LOOKUP).

      Pattern D (PHP/JS null-coalescing on closed mapping):
        <var> = <name>[<expr>] ?? <default>
        <var> = <name>.get(<expr>) ?? <default>
        Where the array literal `["k" => "v", ...]` was assigned to <name>
        in the same chunk (PHP convention is lowercase).

      Pattern E (helper-call propagation):
        <var> = <helper>(value, <ALLOWLIST_NAME>, default)
        <var> = <helper>(<ALLOWLIST_NAME>, value, default)
        Where any argument to the helper is an allowlist-named identifier.
        The helper is presumed to validate value against the allowlist.
        This handles user-defined wrappers like `pick_allowed(value, allowed,
        default)` that encapsulate the `value if value in allowed else default`
        ternary — the call signature itself reveals the intent.

    Generic validation functions / null checks rejected.
    Scan bounded to current statement.
    """
    n = len(tokens)
    i = eq_idx + 1
    saw_if = False
    saw_in = False
    saw_else = False
    found_allowlist = False
    depth = 0
    stmt_boundary_kw = {
        "def", "class", "return", "elif", "for", "while",
        "try", "except", "finally", "with", "import", "from", "raise",
        "yield", "pass", "break", "continue",
    }
    # Pattern E pre-pass: scan RHS for `<helper>(... ALLOWLIST_NAME ...)`.
    # If the RHS is a function call AND any of its arguments is an allowlist-
    # named identifier, treat the assignment as whitelist-validated (the
    # helper presumably implements the validation against that allowlist).
    j = eq_idx + 1
    pattern_e_depth = 0
    pattern_e_in_call = False
    pattern_e_helper_seen = False
    while j < n:
        tj = tokens[j]
        if tj in (";", "\n") and pattern_e_depth == 0:
            break
        if pattern_e_depth == 0 and tj == "=" and j > eq_idx + 1:
            prev_t = tokens[j - 1] if j - 1 >= 0 else None
            next_t = tokens[j + 1] if j + 1 < n else None
            if prev_t not in ("=", "!", "<", ">", "+", "-", "*", "/", "%") and next_t != "=":
                break
        if tj in ("(", "[", "{"):
            pattern_e_depth += 1
            # `(` after an identifier → that identifier is the helper
            if tj == "(" and j > eq_idx + 1 and is_identifier(tokens[j - 1]):
                pattern_e_in_call = True
                pattern_e_helper_seen = True
        elif tj in (")", "]", "}"):
            pattern_e_depth -= 1
            if pattern_e_depth < 0:
                break
        # Inside a helper call AND token is allowlist-named → Pattern E hit
        if pattern_e_in_call and pattern_e_depth >= 1 and _is_allowlist_identifier(tj):
            # Helper call must be the OUTERMOST call (depth 1 at the point of
            # the allowlist arg). Avoids matching e.g. `foo(bar(ALLOWED))`
            # where the allowlist is in a nested position. We accept depth>=1
            # because helper can have nested numeric literals etc.
            return True
        j += 1

    while i < n:
        t = tokens[i]
        if t in ("(", "[", "{"):
            depth += 1
        elif t in (")", "]", "}"):
            depth -= 1
            if depth < 0:
                break
        if depth == 0 and t in (";", "\n"):
            break
        if depth == 0:
            if t == "=" and i > eq_idx + 1:
                prev_t = tokens[i - 1] if i - 1 >= 0 else None
                next_t = tokens[i + 1] if i + 1 < n else None
                if prev_t not in ("=", "!", "<", ">", "+", "-", "*", "/", "%") and next_t != "=":
                    break
            if t in stmt_boundary_kw:
                break
            # Pattern B/C: <NAME>.<method>(...) where method is get/contains/has
            if _is_allowlist_identifier(t):
                k = i + 1
                if k < n and tokens[k] == "." and k + 2 < n:
                    method = tokens[k + 1]
                    if method in ("get", "contains", "has") and tokens[k + 2] == "(":
                        if method == "get":
                            return True
                        return True
                if k < n and tokens[k] == "[":
                    return True
                found_allowlist = True
            # Pattern A: ternary if/in/else
            if t == "if":
                saw_if = True
            elif saw_if and t == "in":
                saw_in = True
            elif saw_in and not saw_else:
                if t == "else":
                    saw_else = True
                elif _is_allowlist_identifier(t):
                    found_allowlist = True
            elif t == "else":
                saw_else = True
            # Pattern D: <ident>[<expr>] ?? <default>
            # Detect by seeing a `??` operator following a `]`. The lhs is
            # any identifier — we accept lowercase too because PHP convention
            # often uses `$allowed[...] ?? default`.
            if t == "??":
                # walk back past `]` to find the array name
                j = i - 1
                bracket_depth = 0
                seen_close = False
                while j >= 0:
                    tj = tokens[j]
                    if tj == "]":
                        bracket_depth += 1
                        seen_close = True
                    elif tj == "[":
                        bracket_depth -= 1
                        if bracket_depth == 0 and j > 0 and is_identifier(tokens[j - 1]):
                            # Found `<name>[<expr>] ??` — accept
                            return True
                        if bracket_depth < 0:
                            break
                    elif not seen_close:
                        # `??` not preceded by `]` — could be `func() ?? default`
                        # Walk back for a `.get(` or `.contains(` pattern
                        if tj == ")":
                            paren_depth = 1
                            jj = j - 1
                            while jj >= 0 and paren_depth > 0:
                                if tokens[jj] == ")":
                                    paren_depth += 1
                                elif tokens[jj] == "(":
                                    paren_depth -= 1
                                jj -= 1
                            if jj >= 0 and tokens[jj] in ("get", "contains", "has"):
                                if jj > 0 and tokens[jj - 1] == "." and jj > 1:
                                    return True
                        break
                    j -= 1
        i += 1
    return saw_if and saw_in and saw_else and found_allowlist


def _detect_safe_placeholder_list(tokens: list[str], eq_idx: int) -> bool:
    """
    Detect:
      <var> = ",".join("?" for _ in <iter>)          # Python
      <var> = ",".join(["?"] * len(<iter>))          # Python alt
      const <var> = <iter>.map(() => "?").join(",")  # JavaScript

    Strict: requires both a `.join(` call AND a `"?"` literal in the same
    statement.
    """
    n = len(tokens)
    i = eq_idx + 1
    depth = 0
    has_join = False
    has_qmark = False
    stmt_boundary_kw = {
        "def", "class", "return", "if", "elif", "else", "for", "while",
        "try", "except", "finally", "with", "import", "from", "raise",
        "yield", "pass", "break", "continue",
    }
    while i < n:
        t = tokens[i]
        if t in ("(", "[", "{"):
            depth += 1
        elif t in (")", "]", "}"):
            depth -= 1
            if depth < 0:
                break
        if depth == 0:
            if t in (";", "\n"):
                break
            if t == "=" and i > eq_idx + 1:
                prev_t = tokens[i - 1] if i - 1 >= 0 else None
                next_t = tokens[i + 1] if i + 1 < n else None
                if prev_t not in ("=", "!", "<", ">", "+", "-", "*", "/", "%") and next_t != "=":
                    break
            if t in stmt_boundary_kw:
                break
        if t == "join":
            if i > 0 and tokens[i - 1] == "." and i + 1 < n and tokens[i + 1] == "(":
                has_join = True
        if t in ('"?"', "'?'"):
            has_qmark = True
        i += 1
    return has_join and has_qmark


# Functions that return a numeric value safe to interpolate into LIMIT/OFFSET.
_NUMERIC_SAFE_FUNCS = {"int", "min", "max", "abs", "len", "round", "Math"}


def _detect_safe_numeric_assignment(
    tokens: list[str], eq_idx: int, known_safe_numeric: set[str]
) -> bool:
    """
    Detect assignment whose RHS is composed exclusively of numeric-safe parts:
      - calls to int()/min()/max()/abs()/len()/round()
      - already-known-safe numeric vars
      - integer/float literals
      - arithmetic operators + - * / %
      - parentheses

    Examples that PASS:
      safe_page = int(page)
      safe_page_size = min(100, max(1, int(page_size)))
      offset = (safe_page - 1) * safe_page_size

    Examples that FAIL:
      x = some_string + page
      x = page                       (raw — int() not applied)
      x = "literal"
    """
    n = len(tokens)
    i = eq_idx + 1
    depth = 0
    has_numeric_source = False
    only_safe = True
    stmt_boundary_kw = {
        "def", "class", "return", "if", "elif", "else", "for", "while",
        "try", "except", "finally", "with", "import", "from", "raise",
        "yield", "pass", "break", "continue",
    }
    arithmetic_ops = {"+", "-", "*", "/", "%", "//"}
    structural = {"(", ")", "[", "]", "{", "}", ","}

    # Helper: is identifier at idx the argument of a numeric-safe wrapper?
    def _is_numeric_wrapped_arg(idx: int) -> bool:
        j = idx - 1
        d = 0
        while j >= eq_idx:
            tj = tokens[j]
            if tj in (")", "]", "}"):
                d += 1
            elif tj in ("(", "[", "{"):
                if d == 0:
                    if j - 1 >= 0 and tokens[j - 1] in _NUMERIC_SAFE_FUNCS:
                        return True
                    return False
                d -= 1
            j -= 1
        return False

    while i < n:
        t = tokens[i]
        if t in ("(", "[", "{"):
            depth += 1
        elif t in (")", "]", "}"):
            depth -= 1
            if depth < 0:
                break
        if depth == 0:
            if t in (";", "\n"):
                break
            if t == "=" and i > eq_idx + 1:
                prev_t = tokens[i - 1] if i - 1 >= 0 else None
                next_t = tokens[i + 1] if i + 1 < n else None
                if prev_t not in ("=", "!", "<", ">", "+", "-", "*", "/", "%") and next_t != "=":
                    break
            if t in stmt_boundary_kw:
                break

        if t in _NUMERIC_SAFE_FUNCS and i + 1 < n and tokens[i + 1] == "(":
            has_numeric_source = True
        elif t in known_safe_numeric:
            has_numeric_source = True
        elif t.replace(".", "", 1).isdigit():
            pass  # numeric literal
        elif t in arithmetic_ops or t in structural:
            pass
        elif t in ("Number", "parseInt", "parseFloat"):  # JS variants
            has_numeric_source = True
        elif is_identifier(t):
            # Bare identifier — must be inside a numeric-safe-func call
            if not _is_numeric_wrapped_arg(i):
                only_safe = False
        elif t.startswith(('"', "'", "`")):
            only_safe = False
        i += 1
    return has_numeric_source and only_safe


# DB-fetch method names that load a value from the database.
# Source of SECOND_ORDER chains. Cross-language coverage:
#   Python (sqlite3, psycopg2, mysql.connector, asyncpg, SQLAlchemy)
#   PHP    (mysqli, PDO)
#   Java   (JDBC ResultSet)
#   JavaScript (sqlite, mysql2, pg, knex)
_DB_FETCH_METHODS = {
    # Python
    "fetchone", "fetchall", "fetchval", "fetchmany",
    "first", "scalar", "scalar_one", "one_or_none", "one",
    # PHP mysqli/PDO
    "get_result", "fetch_assoc", "fetch_row", "fetch_array",
    "fetchColumn", "fetch", "fetchAll", "fetch_object",
    # Java JDBC
    "getString", "getInt", "getLong", "getDouble", "getFloat",
    "getBoolean", "getBigDecimal", "getDate", "getTimestamp",
    "getObject", "getBytes",
    # JavaScript (when used as await db.get/all/one)
    "all", "get", "query", "queryOne",
}

# Methods that ARE DB-fetch only when called on a "db-like" object.
# `.get`/`.all`/`.query` are too generic on their own (e.g. Map.get()).
# Require either `await` keyword OR a db-like name preceding `.`
_DB_FETCH_AMBIGUOUS = {"all", "get", "query", "queryOne"}
_DB_LIKE_NAMES = {
    "db", "conn", "connection", "client", "pool",
    "database", "sql", "knex", "pg", "mysql", "sqlite", "cur", "cursor",
}

# PHP global functions that load DB rows (no `.` receiver).
# These are called as `mysqli_fetch_assoc($r)` not `$conn.fetch_assoc($r)`.
_PHP_FETCH_FUNCS = {
    "mysqli_fetch_assoc", "mysqli_fetch_row", "mysqli_fetch_array",
    "mysqli_fetch_object", "mysqli_fetch_all",
    "pg_fetch_assoc", "pg_fetch_row", "pg_fetch_array", "pg_fetch_object",
    "sqlite_fetch_array", "sqlsrv_fetch_array", "odbc_fetch_array",
}

# Methods that return a boolean and act as "row exists" check.
# Java JDBC: `rs.next()` returns boolean. SQLAlchemy: `result.scalar()` etc.
# treat these as boolean-of-fetch when used in a return statement.
_DB_BOOL_METHODS = {"next"}


def _is_db_fetch_call(tokens: list[str], idx: int) -> bool:
    """
    True if tokens[idx] is a DB-fetch call.

    Recognised forms:
      .<method>(...)       — Python/PHP/JS/Java method calls
      <php_fetch_func>(...) — PHP global functions (mysqli_fetch_assoc, etc.)

    For ambiguous methods (`.get`, `.all`, `.query`, `.queryOne`), require
    EITHER an `await` keyword in the same expression OR a db-like receiver
    name before the `.`. Otherwise these match common library calls
    (Map.get(), array.all(), etc.) and create false positives.
    """
    if idx >= len(tokens):
        return False
    method = tokens[idx]
    nxt = tokens[idx + 1] if idx + 1 < len(tokens) else None

    # PHP global fetch function: <fn>(...)
    if method in _PHP_FETCH_FUNCS:
        if nxt == "(":
            return True
        return False

    # Method-call form: <obj>.<method>(...)  or PHP <obj>-><method>(...)
    if method not in _DB_FETCH_METHODS:
        return False
    if idx == 0 or tokens[idx - 1] not in (".", "->"):
        return False
    if nxt != "(":
        return False

    if method in _DB_FETCH_AMBIGUOUS:
        # Look back for a db-like receiver name or `await` keyword
        if idx >= 2:
            receiver = tokens[idx - 2]
            if receiver.lower() in _DB_LIKE_NAMES:
                return True
        for j in range(max(0, idx - 5), idx):
            if tokens[j] == "await":
                return True
        return False

    return True


def _is_db_bool_call(tokens: list[str], idx: int) -> bool:
    """
    True if tokens[idx] is a `.next()`-style call returning a boolean
    derived from a DB query (Java JDBC `ResultSet.next()`).
    """
    if idx >= len(tokens):
        return False
    if tokens[idx] not in _DB_BOOL_METHODS:
        return False
    if idx == 0 or tokens[idx - 1] not in (".", "->"):
        return False
    nxt = tokens[idx + 1] if idx + 1 < len(tokens) else None
    if nxt != "(":
        return False
    # Receiver name should be a ResultSet-like identifier. Heuristic: any
    # identifier ending with "rs" or named "rs"/"result"/"results".
    if idx >= 2:
        receiver = tokens[idx - 2].lower()
        if receiver in ("rs", "result", "results", "resultset", "rset"):
            return True
        if receiver.endswith("rs"):
            return True
    return False


def _detect_db_loaded_assignment(tokens: list[str], eq_idx: int) -> bool:
    """
    Detect:  <var> = <obj>.<fetch_method>(...)[ ... ]?

    The right-hand side must contain a call to a known DB fetch method.
    Examples that PASS:
      row = cursor.fetchone()
      name = cur.fetchone()[0]
      bio = cursor.execute(...).fetchone()[0]
      x = (await db.fetch_one(...))[0]
    Strict: requires literal method-name match. Rejects custom helpers like
    `load_from_db()` because their semantics are unknown.

    The scan is bounded to the current statement — stops at the NEXT
    assignment-like token, the next `def`/`class`/`return`/control-flow
    keyword, or end of tokens. This prevents firing on `cur = conn.cursor()`
    just because some later line in the function calls `.fetchall()`.
    """
    n = len(tokens)
    i = eq_idx + 1
    depth = 0
    # Statement-boundary keywords — anything here means we've left the RHS
    stmt_boundary_kw = {
        "def", "class", "return", "if", "elif", "else", "for", "while",
        "try", "except", "finally", "with", "import", "from", "raise",
        "yield", "pass", "break", "continue",
    }
    while i < n:
        t = tokens[i]
        if t in ("(", "[", "{"):
            depth += 1
        elif t in (")", "]", "}"):
            depth -= 1
            if depth < 0:
                break
        # Statement-end markers when at top level
        if depth == 0:
            if t in (";", "\n"):
                break
            # Next assignment statement (LHS = RHS) — when at top level,
            # any `=` not preceded by comparison-op chars marks a new stmt
            if t == "=" and i > eq_idx + 1:
                prev_t = tokens[i - 1] if i - 1 >= 0 else None
                next_t = tokens[i + 1] if i + 1 < n else None
                # Skip == != >= <= operators
                if prev_t not in ("=", "!", "<", ">", "+", "-", "*", "/", "%") and next_t != "=":
                    break
            # Statement-keyword starts a new statement
            if t in stmt_boundary_kw:
                break
        if _is_db_fetch_call(tokens, i):
            return True
        i += 1
    return False


# ── Safe-pattern detectors (Mega Suite groups 2 + 3) ──────────────────────

# Numeric coercion functions whose output is bounded numeric.
# When the RHS of `var = ...` consists only of these, var is safely numeric.
_NUMERIC_FUNCS = {
    # Python
    "int", "float", "min", "max", "abs", "len", "round", "floor", "ceil",
    # JavaScript
    "Number", "parseInt", "parseFloat",
    # Java
    "Integer", "Long", "Double", "Float",
}

# Namespace prefixes that mean "the next token after `.` is a numeric op"
# JS: Math.max, Math.min, Math.floor, Math.ceil, Math.abs, Math.round, Math.trunc
_NUMERIC_NAMESPACES = {"Math"}

def _detect_safe_placeholder_list(tokens: list[str], eq_idx: int) -> bool:
    """
    Detect:  <var> = "?,?,?".join("?" for _ in <iter>)
            or:    <var> = ",".join(["?"] * <n>)
            or:    <var> = ",".join("?" * <n>)
            JS:    <var> = ids.map(() => "?").join(",")

    Strict — must be obvious placeholder list construction, NOT raw value
    joining. Both `","` and `"?"` (or `"?,"` etc.) must appear; no raw vars
    interpolated as values.
    """
    n = len(tokens)
    has_join = False
    has_q_mark_lit = False
    has_q_only_strings = True   # all string literals seen in RHS are placeholder-only
    seen_string = False
    has_value_var = False  # any variable that could carry raw values?
    depth = 0
    i = eq_idx + 1
    stmt_kw = {"def", "class", "return", "if", "elif", "for", "while",
               "try", "except", "finally", "with", "import", "from"}
    while i < n:
        t = tokens[i]
        # Boundary check FIRST
        if depth == 0:
            if t in (";", "\n"): break
            if i > eq_idx + 1 and t == "=":
                prev_t = tokens[i - 1] if i - 1 >= 0 else None
                next_t = tokens[i + 1] if i + 1 < n else None
                if prev_t not in ("=", "!", "<", ">", "+", "-", "*", "/", "%") and next_t != "=":
                    break
            if t in stmt_kw and i > eq_idx + 1:
                break
        if t in ("(", "[", "{"):
            depth += 1
        elif t in (")", "]", "}"):
            depth -= 1
            if depth < 0: break
        if t == "join":
            has_join = True
        # String literals — must contain ONLY ?, comma, space, or be empty
        if (len(t) >= 2 and t[0] in '"\'`' and t[-1] in '"\'`'):
            seen_string = True
            inner = t[1:-1]
            if "?" in inner:
                has_q_mark_lit = True
            # If the literal contains anything other than ?,  space → not safe
            if any(c not in "?, " for c in inner):
                has_q_only_strings = False
        i += 1
    return has_join and has_q_mark_lit and seen_string and has_q_only_strings


def _detect_safe_numeric_assignment(
    tokens: list[str], eq_idx: int, known_numeric: set[str]
) -> bool:
    """
    Detect:  <var> = int(...) / min(...) / max(...) / arithmetic over
             already-known-numeric vars / numeric literals.

    Examples that PASS:
      safe_page = int(page)
      safe_page_size = min(100, max(1, int(page_size)))
      offset = (safe_page - 1) * safe_page_size

    Examples that FAIL:
      x = page              (raw, no coercion)
      x = page + ""         (string concat)
      x = str(page)         (string coercion)
    """
    n = len(tokens)
    i = eq_idx + 1
    stmt_kw = {"def", "class", "return", "if", "elif", "for", "while",
               "try", "except", "finally", "with", "import", "from"}
    saw_numeric_func = False
    saw_arithmetic = False
    saw_only_safe_components = True
    saw_any = False
    depth = 0
    arith_ops = {"+", "-", "*", "/", "%", "//"}
    while i < n:
        t = tokens[i]
        # Boundary check FIRST — before consuming the token
        if depth == 0:
            if t in (";", "\n"):
                break
            if i > eq_idx + 1 and t == "=":
                prev_t = tokens[i - 1] if i - 1 >= 0 else None
                next_t = tokens[i + 1] if i + 1 < n else None
                if prev_t not in ("=", "!", "<", ">", "+", "-", "*", "/", "%") and next_t != "=":
                    break
            if t in stmt_kw and i > eq_idx + 1:
                break
            # Look-ahead: if NEXT token is `=` (assignment), the current
            # identifier belongs to the next statement. Break before
            # consuming it.
            if i > eq_idx + 1 and is_identifier(t) and i + 1 < n and tokens[i + 1] == "=":
                next_next = tokens[i + 2] if i + 2 < n else None
                if next_next != "=":   # not == comparison
                    break
        # Track depth
        if t in ("(", "[", "{"):
            depth += 1
        elif t in (")", "]", "}"):
            depth -= 1
            if depth < 0: break
        # Numeric coercion func call
        if t in _NUMERIC_FUNCS and i + 1 < n and tokens[i + 1] == "(":
            saw_numeric_func = True
            saw_any = True
        # Namespaced numeric call: Math.max(...) etc.
        elif t in _NUMERIC_NAMESPACES and i + 2 < n and tokens[i + 1] == "." and tokens[i + 2] in (
            "max", "min", "floor", "ceil", "abs", "round", "trunc", "sqrt", "pow"
        ):
            # Verify followed by `(`
            if i + 3 < n and tokens[i + 3] == "(":
                saw_numeric_func = True
                saw_any = True
        elif t in arith_ops:
            saw_arithmetic = True
            saw_any = True
        elif t.isdigit() or (t.replace(".", "", 1).isdigit() and t.count(".") < 2):
            saw_any = True
        elif is_identifier(t):
            if t in known_numeric:
                saw_any = True
            elif t in _NUMERIC_FUNCS:
                pass
            elif t in _NUMERIC_NAMESPACES:
                pass  # next iter will see Math.<func>
            elif i > 0 and tokens[i - 1] == "." and i >= 2 and tokens[i - 2] in _NUMERIC_NAMESPACES:
                pass  # we're the method name after Math.
            else:
                if not saw_numeric_func:
                    saw_only_safe_components = False
        elif t in (",", ".", "(", ")", "[", "]"):
            pass
        else:
            if not (t.startswith('"') or t.startswith("'") or t.startswith("`")):
                saw_only_safe_components = False
        i += 1
    if not saw_any:
        return False
    if not saw_only_safe_components:
        return False
    return saw_numeric_func or saw_arithmetic or saw_any


def _detect_boolean_sink(tokens: list[str]) -> bool:
    """
    Detect a function whose return statement reduces a fetch result to a bool.

    Patterns recognised (any one suffices):
      return cur.fetchone() is not None
      return cur.fetchone() is None
      return cur.fetchone()[0] > 0
      return cur.fetchone()[0] >= 1
      return cur.fetchone()[0] == <value>
      return bool(cur.fetchone())
      result = cur.fetchone()[0] > 0; return result
      flag = cur.fetchone() is not None; return flag

    Strict: requires `return`/`bool(...)` AND a fetch call AND a bool op
    in the SAME logical statement (bounded by next `=` assignment or
    statement keyword).
    """
    n = len(tokens)
    bool_ops = {"==", "!=", ">", "<", ">=", "<=", "is"}
    stmt_boundary_kw = {
        "def", "class", "return", "if", "elif", "else", "for", "while",
        "try", "except", "finally", "with", "import", "from", "raise",
        "yield", "pass", "break", "continue",
    }

    def _scan_stmt(start_idx: int):
        """Yield indices of tokens belonging to one statement."""
        depth = 0
        i = start_idx
        while i < n:
            t = tokens[i]
            if t in ("(", "[", "{"):
                depth += 1
            elif t in (")", "]", "}"):
                depth -= 1
                if depth < 0:
                    break
            if depth == 0:
                if t in (";", "\n"):
                    break
                if i > start_idx and t == "=":
                    prev_t = tokens[i - 1] if i - 1 >= 0 else None
                    next_t = tokens[i + 1] if i + 1 < n else None
                    if prev_t not in ("=", "!", "<", ">", "+", "-", "*", "/", "%") and next_t != "=":
                        break
                if i > start_idx and t in stmt_boundary_kw:
                    break
            yield i
            i += 1

    # Pre-pass: find vars assigned `<fetch> ... <bool_op>` in same stmt.
    bool_fetch_vars: set[str] = set()
    db_fetched_vars: set[str] = set()
    for idx in range(n):
        if tokens[idx] != "=":
            continue
        prev = tokens[idx - 1] if idx > 0 else None
        nxt  = tokens[idx + 1] if idx + 1 < n else None
        if prev in ("=", "!", "<", ">", "+", "-", "*", "/", "%", "|", "&", "^"):
            continue
        if nxt == "=":
            continue
        k = idx - 1
        while k >= 0 and tokens[k] in (",", "(", ")"):
            k -= 1
        if k < 0 or not is_identifier(tokens[k]):
            continue
        lhs = tokens[k]
        has_fetch = False
        has_bool = False
        uses_fetched_var = False
        for j in _scan_stmt(idx + 1):
            tj = tokens[j]
            if _is_db_fetch_call(tokens, j):
                has_fetch = True
            # rs.next() — Java JDBC boolean check, treat as fetch+bool
            if _is_db_bool_call(tokens, j):
                has_fetch = True
                has_bool = True
            if tj in bool_ops:
                has_bool = True
            if tj == "bool" and j + 1 < n and tokens[j + 1] == "(":
                has_bool = True
            # `allowed = result_count > 0` — RHS uses a known fetched var
            if tj in db_fetched_vars:
                uses_fetched_var = True
        if has_fetch and has_bool:
            bool_fetch_vars.add(lhs)
        elif uses_fetched_var and has_bool:
            # Indirect bool sink: var assigned bool-op of a previously
            # DB-loaded var. `return <lhs>` then qualifies as boolean sink.
            bool_fetch_vars.add(lhs)
        elif has_fetch:
            db_fetched_vars.add(lhs)

    # Main scan: `return <expr>` where expr is bool-of-fetch.
    for i, t in enumerate(tokens):
        if t != "return":
            continue
        has_fetch = False
        has_bool_op = False
        has_fetched_var = False
        for j in _scan_stmt(i + 1):
            tj = tokens[j]
            if _is_db_fetch_call(tokens, j):
                has_fetch = True
            # `return rs.next()` — bool-returning DB call
            if _is_db_bool_call(tokens, j):
                return True
            if tj in bool_ops:
                has_bool_op = True
            # `return <pre-stored bool>` — direct
            if tj in bool_fetch_vars:
                return True
            # `return <var-holding-fetch> <bool_op> ...` qualifies
            if tj in db_fetched_vars:
                has_fetched_var = True
            if tj == "bool" and j + 1 < n and tokens[j + 1] == "(":
                k = j + 2
                local_depth = 1
                while k < n and local_depth > 0:
                    if tokens[k] in ("(", "[", "{"):
                        local_depth += 1
                    elif tokens[k] in (")", "]", "}"):
                        local_depth -= 1
                    if _is_db_fetch_call(tokens, k):
                        return True
                    if tokens[k] in db_fetched_vars:
                        return True
                    k += 1
        if has_fetch and has_bool_op:
            return True
        if has_fetched_var and has_bool_op:
            return True
    return False


# ── Main normalizer ───────────────────────────────────────────────────────────

def extract_safe_returning_funcs(tokens: list[str]) -> dict[str, str]:
    """
    Scan tokens for `def <name>(...)` definitions whose body fires a safe-flow
    detector. Returns a dict mapping helper-function name → signal kind:
      "WHITELIST_VAR"        — body has whitelist pattern (Pattern A/B/E)
      "SAFE_NUMERIC_VAR"     — body uses int/min/max coercion
      "SAFE_PLACEHOLDER_LIST"— body builds ?,?,? placeholder string

    The chunker calls this on the FULL FILE before chunking, so each chunk's
    normalize_tokens() can be told about helpers defined elsewhere in the file.

    Also detects DB-loaded helpers: `def <name>(...): return db.fetch...()` —
    used for cross-function SECOND_ORDER tracking. Returns kind="DB_LOADED_VAR".
    """
    safe_returning_funcs: dict[str, str] = {}
    n_tokens = len(tokens)
    # Identify all def-sites and their body ranges (until next def or EOF).
    #
    # Cross-language function-name detection:
    #   Python:  `def <name>(...)`
    #   PHP:     `function <name>(...)`     (after function keyword)
    #   JS:      `function <name>(...)` or `async function <name>(...)`
    #   Java:    `<modifiers>* <returntype> <name>(...)` — heuristic:
    #            an identifier followed by `(` whose token before is also an
    #            identifier (not a keyword like `if`/`while`/`return`/`new`).
    def_sites: list[tuple[str, int, int]] = []  # (name, body_start, body_end)
    JS_PY_DEF_KEYWORDS = {"def", "function"}
    JAVA_NON_FUNC_PRECEDERS = {
        "if", "while", "for", "switch", "return", "throw", "new", "catch",
        "synchronized", "do", "else", ".", ",", "(", "[", "{", "=", "+", "-",
        "*", "/", "%", "&", "|", "^", "<", ">", "!", "?", ":", ";",
    }
    for fi, ftok in enumerate(tokens):
        fname = None
        if ftok in JS_PY_DEF_KEYWORDS and fi + 1 < n_tokens:
            cand = tokens[fi + 1]
            if is_identifier(cand):
                fname = cand
        else:
            # Java-style: <type> <name> ( where prev token isn't a control keyword
            if (
                fi + 1 < n_tokens
                and is_identifier(ftok)
                and is_identifier(tokens[fi + 1])
                and fi + 2 < n_tokens
                and tokens[fi + 2] == "("
                and ftok not in JAVA_NON_FUNC_PRECEDERS
                and tokens[fi + 1] not in JAVA_NON_FUNC_PRECEDERS
                # ftok must look like a type (capitalized or primitive)
                and (ftok[0].isupper() or ftok in (
                    "int", "long", "short", "byte", "double", "float",
                    "boolean", "char", "void",
                ))
            ):
                # Extra guard: the previous token shouldn't be an operator that
                # would make this a function CALL rather than a definition.
                # (E.g. `obj.foo (` or `if (cond) bar(` etc.)
                prev_tok = tokens[fi - 1] if fi > 0 else None
                if prev_tok not in (".", "->") and prev_tok not in JAVA_NON_FUNC_PRECEDERS:
                    fname = tokens[fi + 1]
        if fname is None:
            continue
        # Determine body range — find first `{` after the name then matching `}`
        body_start = fi + 2
        # Skip past param list ( ... ) to find body
        bp = fi + 2
        # Skip past arg list
        while bp < n_tokens and tokens[bp] != "(":
            bp += 1
        if bp < n_tokens:
            depth = 0
            while bp < n_tokens:
                if tokens[bp] == "(": depth += 1
                elif tokens[bp] == ")":
                    depth -= 1
                    if depth == 0:
                        bp += 1
                        break
                bp += 1
        body_start = bp
        body_end = n_tokens
        # For Python (no braces) take until next `def`. For braces find matching.
        # Simple: find next def/function or matching `}`.
        if body_start < n_tokens and tokens[body_start] == "{":
            depth = 0
            for fj in range(body_start, n_tokens):
                if tokens[fj] == "{": depth += 1
                elif tokens[fj] == "}":
                    depth -= 1
                    if depth == 0:
                        body_end = fj + 1
                        break
        else:
            for fj in range(body_start, n_tokens):
                if tokens[fj] in ("def", "function") and fj > body_start:
                    body_end = fj
                    break
        def_sites.append((fname, body_start, body_end))

    for fname, body_start, body_end in def_sites:
        body_tokens = tokens[body_start:body_end]
        bn = len(body_tokens)
        kind = None
        # Scan for whitelist Pattern A in `return` AND assignments.
        bj = 0
        while bj < bn:
            tj = body_tokens[bj]
            # `return X if X in ALLOWLIST else default`
            if tj == "return" and bj + 6 < bn:
                k = bj + 1
                saw_if = saw_in = saw_else = False
                found_aw = False
                local_d = 0
                while k < bn and k < bj + 30:
                    tk = body_tokens[k]
                    if tk in ("(", "[", "{"): local_d += 1
                    elif tk in (")", "]", "}"):
                        local_d -= 1
                        if local_d < 0: break
                    if local_d == 0:
                        if tk in (";", "\n"): break
                        if tk == "if": saw_if = True
                        elif saw_if and tk == "in": saw_in = True
                        elif saw_in and tk == "else": saw_else = True
                        elif saw_in and not saw_else and _is_allowlist_identifier(tk):
                            found_aw = True
                    k += 1
                if saw_if and saw_in and saw_else and found_aw:
                    kind = "WHITELIST_VAR"
                    break
                # `return <ALLOWLIST_NAME>.get(...) ?? default` / `return <ALLOWLIST_NAME>[k] ?? default`
                k = bj + 1
                while k < bn and k < bj + 20:
                    tk = body_tokens[k]
                    if _is_allowlist_identifier(tk):
                        # check for .get(  or [
                        if k + 1 < bn and body_tokens[k + 1] == "." and k + 2 < bn:
                            method = body_tokens[k + 2]
                            if method in ("get", "contains", "has"):
                                kind = "WHITELIST_VAR"
                                break
                        if k + 1 < bn and body_tokens[k + 1] == "[":
                            kind = "WHITELIST_VAR"
                            break
                    k += 1
                if kind == "WHITELIST_VAR":
                    break
                # `return <ARR>[<key>] ?? default` (PHP, lowercase OK if it's
                # `$this->allowedSort[...]` style)
                if "??" in body_tokens[bj:bj + 20]:
                    # Heuristic: any allowlist-named array OR `this`/`self`
                    # property access followed by ?? counts
                    for k in range(bj + 1, min(bn, bj + 20)):
                        tk = body_tokens[k]
                        if tk == "??":
                            # Accept if anything before looks like array lookup
                            # of an allowlist-named or this/self property.
                            kind = "WHITELIST_VAR"
                            break
                    if kind:
                        break
            # Body assignment with whitelist pattern (recursive Pattern E)
            if tj == "=":
                pv = body_tokens[bj - 1] if bj > 0 else None
                nv = body_tokens[bj + 1] if bj + 1 < bn else None
                if pv not in ("=", "!", "<", ">", "+", "-", "*", "/", "%", "|", "&", "^") and nv != "=":
                    if _detect_whitelist_assignment(body_tokens, bj):
                        kind = "WHITELIST_VAR"
                        break
            bj += 1

        if kind:
            safe_returning_funcs[fname] = kind
            continue

        # Fallback: numeric helper (int/min/max arithmetic)
        # Body contains return AND numeric coercion func at top level
        has_return = "return" in body_tokens
        has_numeric_func = any(
            t in _NUMERIC_FUNCS for t in body_tokens
        )
        if has_return and has_numeric_func:
            # Reject if any string concat or f-string SQL appears
            has_sql_construction = any(
                is_fstring_sql(t) or is_sql_string(t)
                for t in body_tokens
            )
            if not has_sql_construction:
                safe_returning_funcs[fname] = "SAFE_NUMERIC_VAR"
                continue

        # Fallback: DB-loaded helper. Body returns from a `.fetch...()` /
        # `.get(...)` / `.all(...)` etc. call. Only when the function literally
        # returns the DB-fetch call (or its row member).
        for bj in range(bn):
            if body_tokens[bj] != "return":
                continue
            # Scan return expression for db-fetch call
            for k in range(bj + 1, min(bn, bj + 30)):
                if _is_db_fetch_call(body_tokens, k):
                    safe_returning_funcs[fname] = "DB_LOADED_VAR"
                    break
            if fname in safe_returning_funcs:
                break

    # Transitive closure: a helper that calls a known safe-returning helper
    # propagates its safety category.
    for _ in range(3):
        added_any = False
        for fname, body_start, body_end in def_sites:
            if fname in safe_returning_funcs:
                continue
            body_tokens = tokens[body_start:body_end]
            bn = len(body_tokens)
            for bj in range(bn):
                if body_tokens[bj] != "=":
                    continue
                pv = body_tokens[bj - 1] if bj > 0 else None
                nv = body_tokens[bj + 1] if bj + 1 < bn else None
                if pv not in ("=", "!", "<", ">", "+", "-", "*", "/", "%", "|", "&", "^") and nv != "=":
                    ji = bj + 1
                    if ji < bn and is_identifier(body_tokens[ji]) and body_tokens[ji] in safe_returning_funcs:
                        if ji + 1 < bn and body_tokens[ji + 1] == "(":
                            # Inherit kind from the called helper
                            safe_returning_funcs[fname] = safe_returning_funcs[body_tokens[ji]]
                            added_any = True
                            break
        if not added_any:
            break
    return safe_returning_funcs


def normalize_tokens(
    tokens: list[str],
    extra_safe_funcs: dict[str, str] | set[str] | None = None,
) -> list[str]:
    """
    Normalize a token list into a semantic sequence.
    Injects UNSAFE_EXEC, SAFE_EXEC, SQL_CONCAT signals where detected.
    Also injects flow signals: WHITELIST_VAR, DB_LOADED_VAR, BOOLEAN_SINK.

    extra_safe_funcs: dict[name → kind] (or legacy set of names treated as
    WHITELIST_VAR) of helper functions known by the caller to return safe
    values. Calls to these on the RHS of an assignment propagate the
    appropriate signal to the LHS. Used by the chunker to share file-level
    context (helper defined in chunk A, used in chunk B).
    """
    normalized: list[str] = []

    var_map: dict[str, str] = {}
    func_map: dict[str, str] = {}
    property_map: dict[str, str] = {}

    var_counter = 0
    func_counter = 0
    property_counter = 0

    # ── Pre-scan: detect flow patterns over RAW tokens ────────────────────
    flow_signal_at_pos: dict[int, str] = {}
    whitelisted_vars: set[str] = set()
    db_loaded_vars: set[str] = set()
    safe_placeholder_vars: set[str] = set()
    safe_numeric_vars: set[str] = set()

    # safe_returning_funcs maps helper-name → signal-kind
    safe_returning_funcs: dict[str, str] = {}
    if extra_safe_funcs:
        if isinstance(extra_safe_funcs, dict):
            safe_returning_funcs.update(extra_safe_funcs)
        else:
            # Legacy: set of names — treat all as WHITELIST_VAR
            for nm in extra_safe_funcs:
                safe_returning_funcs[nm] = "WHITELIST_VAR"
    n_tokens = len(tokens)
    # Local def-scan: union with extra_safe_funcs from caller. Use the same
    # extractor for consistency.
    local_safe_funcs = extract_safe_returning_funcs(tokens)
    for nm, kind in local_safe_funcs.items():
        safe_returning_funcs.setdefault(nm, kind)

    # Type-keyword tokens that may precede a variable in a typed declaration.
    # Walk-back stops at these without including them as LHS vars.
    TYPE_DECL_KEYWORDS = {
        # JS / TS
        "const", "let", "var",
        # Java primitives & common types
        "int", "long", "short", "byte", "double", "float", "boolean", "char",
        "void", "String", "Integer", "Long", "Double", "Float", "Boolean",
        "Object", "Character", "Byte", "Short", "ResultSet", "Statement",
        "PreparedStatement", "Connection", "List", "Set", "Map", "ArrayList",
        "HashMap", "HashSet",
        # C-like
        "static", "final", "private", "public", "protected", "abstract",
    }

    for idx, tok in enumerate(tokens):
        if tok != "=":
            continue
        # Skip == != >= <= which contain `=` but aren't assignments
        prev = tokens[idx - 1] if idx > 0 else None
        nxt  = tokens[idx + 1] if idx + 1 < len(tokens) else None
        if prev in ("=", "!", "<", ">", "+", "-", "*", "/", "%", "|", "&", "^"):
            continue
        if nxt == "=":
            continue
        # Collect ALL LHS identifiers (handles tuple-unpack like `a, b = f()`).
        # Walk back from `=`, gathering identifiers separated by `,`. Stop at
        # type-decl keywords (do not include them as LHS vars).
        lhs_positions: list[int] = []
        kk = idx - 1
        while kk >= 0:
            tk = tokens[kk]
            if tk in TYPE_DECL_KEYWORDS:
                # Type annotation — stop walking back, do not include
                break
            if is_identifier(tk):
                lhs_positions.append(kk)
                kk -= 1
                continue
            if tk == ",":
                kk -= 1
                continue
            if tk in ("(", ")"):
                kk -= 1
                continue
            # Stop at any other non-identifier/non-comma token
            break
        if not lhs_positions:
            continue
        # Detection priority: most-specific first. Apply to ALL LHS vars.
        signal = None
        if _detect_safe_placeholder_list(tokens, idx):
            signal = "SAFE_PLACEHOLDER_LIST"
        elif _detect_whitelist_assignment(tokens, idx):
            signal = "WHITELIST_VAR"
        elif _detect_db_loaded_assignment(tokens, idx):
            signal = "DB_LOADED_VAR"
        elif _detect_safe_numeric_assignment(tokens, idx, safe_numeric_vars):
            signal = "SAFE_NUMERIC_VAR"
        else:
            # Pattern F: RHS calls a safe-returning helper function. Propagate
            # the helper's signal kind to LHS. Recognised forms:
            #   <var> = <helper>(...)              # bare call
            #   <var> = await <helper>(...)        # JS async
            #   <var> = self.<helper>(...)         # Python method
            #   <var> = this.<helper>(...)         # JS method
            #   <var> = $this->/$obj-><helper>(...) # PHP method
            ji = idx + 1
            # Skip leading `await` keyword
            if ji < len(tokens) and tokens[ji] == "await":
                ji += 1
            helper_name = None
            if ji < len(tokens) and is_identifier(tokens[ji]):
                cand = tokens[ji]
                if ji + 1 < len(tokens) and tokens[ji + 1] == "(" and cand in safe_returning_funcs:
                    helper_name = cand
                # method-call form: <obj>.<helper>( or <obj>-><helper>(
                elif ji + 3 < len(tokens) and tokens[ji + 1] in (".", "->"):
                    method_name = tokens[ji + 2]
                    if (
                        is_identifier(method_name)
                        and method_name in safe_returning_funcs
                        and tokens[ji + 3] == "("
                    ):
                        helper_name = method_name
            if helper_name:
                signal = safe_returning_funcs[helper_name]
            # Pattern G: RHS = <db_loaded_var>[...] or <db_loaded_var>.<member>
            # Taint propagation through subscript / property access.
            elif (
                ji < len(tokens)
                and is_identifier(tokens[ji])
                and tokens[ji] in db_loaded_vars
                and ji + 1 < len(tokens)
                and tokens[ji + 1] in ("[", ".", "->")
            ):
                signal = "DB_LOADED_VAR"
        if signal is None:
            continue
        # Mark ALL LHS positions and add ALL names to the appropriate set.
        # Emit signal at the FIRST (right-most in source) position so it
        # appears before the first VAR in the normalized stream.
        for pos in lhs_positions:
            name = tokens[pos]
            if signal == "SAFE_PLACEHOLDER_LIST":
                safe_placeholder_vars.add(name)
            elif signal == "WHITELIST_VAR":
                whitelisted_vars.add(name)
            elif signal == "DB_LOADED_VAR":
                db_loaded_vars.add(name)
            elif signal == "SAFE_NUMERIC_VAR":
                safe_numeric_vars.add(name)
        # Emit signal once, at the position of the first LHS var (left-most
        # in source = highest index in lhs_positions since we walked back).
        flow_signal_at_pos[max(lhs_positions)] = signal

    # ── Filter db_loaded_vars: keep only those reused in later SQL ─────────
    # A var holding a DB-fetch result is only "second-order taint material"
    # when it's later interpolated into another SQL string or concatenated
    # with one. If `rows = await db.all(sql); return rows[0]` then `rows`
    # never goes back into SQL — it's a sink. Marking it DB_LOADED_VAR
    # causes the attack-type rule to misclassify IN_BAND as SECOND_ORDER.
    if db_loaded_vars:
        # Find positions of each db-loaded assignment
        db_loaded_positions: dict[str, int] = {}
        for pos, sig in flow_signal_at_pos.items():
            if sig == "DB_LOADED_VAR" and pos < len(tokens):
                db_loaded_positions[tokens[pos]] = pos
        # Track which db-loaded names appear inside an SQL construction
        # AFTER their assignment.
        actually_reused: set[str] = set()
        for name, name_pos in db_loaded_positions.items():
            for ti in range(name_pos + 1, len(tokens)):
                t = tokens[ti]
                # Direct usage as token: `... + name + ...` or `... . name ...`
                # in a SQL_CONCAT context. Heuristic: token == name AND nearby
                # tokens contain a SQL string literal or an f-string.
                if t == name:
                    # Look backward up to 5 and forward up to 5 for SQL marker
                    for tj in range(max(0, ti - 6), min(len(tokens), ti + 6)):
                        tj_tok = tokens[tj]
                        if is_sql_string(tj_tok) or is_fstring_sql(tj_tok):
                            actually_reused.add(name)
                            break
                    if name in actually_reused:
                        break
                # Interpolated as `${name.x}` in template literal
                if is_fstring_sql(t):
                    interp = _extract_interpolated_vars(t)
                    if name in interp:
                        actually_reused.add(name)
                        break
        # Drop unused db_loaded_vars and remove their flow-signal emission
        unused = db_loaded_vars - actually_reused
        for name in unused:
            db_loaded_vars.discard(name)
            pos = db_loaded_positions.get(name)
            if pos is not None and flow_signal_at_pos.get(pos) == "DB_LOADED_VAR":
                del flow_signal_at_pos[pos]

    # ── Pre-scan: identify f-strings that interpolate ONLY whitelisted vars ──
    # f"... {safe_col} ..."  →  if safe_col ∈ whitelisted_vars → safe
    # f"... {sort_by} ..."   →  if sort_by ∉ whitelisted_vars → raw injection
    # Mark the position of each FSTRING_SQL token with extra context.
    # Pre-pass: detect "builder arrays" used to construct WHERE-clauses.
    #   const where = ["x = ?"];
    #   where.push("status IN (?,?,?)");
    #   sql = `... ${where.join(" AND ")} ...`
    # If a var is initialized to an array literal AND only `.push(...)` calls
    # add string literals containing only ?, identifiers, parens, spaces,
    # commas, single-quote chars (i.e. parameterized SQL fragments — no
    # unbound var interpolations), treat the var as `safe_placeholder_vars`.
    builder_init_pat = {"=", "["}  # `name = [`
    candidate_builder: set[str] = set()
    builder_unsafe: set[str] = set()
    for ti in range(len(tokens) - 2):
        if tokens[ti] == "=" and tokens[ti + 1] == "[":
            # LHS: walk back for identifier (skipping type-decl keywords)
            kk = ti - 1
            while kk >= 0 and tokens[kk] in TYPE_DECL_KEYWORDS:
                kk -= 1
            if kk >= 0 and is_identifier(tokens[kk]):
                # Verify the array literal is closed simply (no nested SQL strings)
                # Accept the init regardless of contents — verification below.
                candidate_builder.add(tokens[kk])
    # Now scan all .push() calls; if a candidate_builder.push(<unsafe arg>) found,
    # remove from candidates.
    for ti in range(len(tokens) - 4):
        if (
            tokens[ti] in candidate_builder
            and tokens[ti + 1] == "."
            and tokens[ti + 2] == "push"
            and tokens[ti + 3] == "("
        ):
            # Inspect the push argument — must be a STRING literal that contains
            # only safe-placeholder markers (no ${var} interpolation of a raw var)
            # OR a template literal whose interpolations are all in known safe sets.
            arg_tok = tokens[ti + 4] if ti + 4 < len(tokens) else None
            if arg_tok is None:
                builder_unsafe.add(tokens[ti])
                continue
            # Plain string literal — check for raw unsafe substring concat-style
            if len(arg_tok) >= 2 and arg_tok[0] in '"\'':
                inner = arg_tok[1:-1]
                # Plain SQL fragment with placeholders is OK. Reject if has
                # patterns like ' + ' or % concatenation markers.
                if "${" in inner:
                    builder_unsafe.add(tokens[ti])
                # plain literal — accept
            elif _has_interpolation(arg_tok):
                # Template literal — interpolated vars must all be safe
                interp = _extract_interpolated_vars(arg_tok)
                if interp and (interp - (whitelisted_vars | safe_placeholder_vars | safe_numeric_vars)):
                    builder_unsafe.add(tokens[ti])
            else:
                # Non-string push (e.g. variable, expression) — risky
                builder_unsafe.add(tokens[ti])
    # Confirmed safe builders
    safe_builders = candidate_builder - builder_unsafe
    safe_placeholder_vars |= safe_builders

    # All "safe" var sets are treated equivalently for interpolation safety.
    safe_interp_vars = (
        whitelisted_vars | db_loaded_vars
        | safe_placeholder_vars | safe_numeric_vars
    )
    fstring_safety: dict[int, str] = {}   # position → "WHITELIST_BOUND" / "RAW_VAR_DESPITE_WHITELIST"
    for idx, tok in enumerate(tokens):
        if not is_fstring_sql(tok):
            continue
        interpolated = _extract_interpolated_vars(tok)
        if not interpolated:
            continue
        raw_left = interpolated - safe_interp_vars
        if not raw_left and interpolated:
            # All interpolations are safe-bound (whitelist / placeholder / numeric)
            fstring_safety[idx] = "WHITELIST_BOUND"
        elif raw_left and (whitelisted_vars or safe_placeholder_vars or safe_numeric_vars):
            # Safety context exists in chunk BUT raw variable interpolated.
            # The "validated but unused" anti-pattern (py_003).
            fstring_safety[idx] = "RAW_VAR_DESPITE_WHITELIST"
        # else: no safety context at all — leave default (FSTRING_SQL)

    # First pass: build normalized sequence
    raw_norm: list[str] = []

    for i, token in enumerate(tokens):
        lower = token.lower()

        # ── Inject flow signal BEFORE the var that received the value ──────
        if i in flow_signal_at_pos:
            raw_norm.append(flow_signal_at_pos[i])

        # ── Language keywords ──────────────────────────────────────────────
        if lower in LANGUAGE_KEYWORDS:
            raw_norm.append(lower)
            continue

        # ── F-string SQL (dangerous: interpolated variables in SQL) ────────
        if is_fstring_sql(token):
            safety_tag = fstring_safety.get(i)
            if safety_tag == "RAW_VAR_DESPITE_WHITELIST":
                # Whitelist-VAR was computed in this chunk but the actual SQL
                # interpolates a NON-validated raw variable. This is the
                # "validated but unused" anti-pattern.
                # Emit FSTRING_SQL_RAW to signal "raw injection despite
                # context" — rule layer treats this as hard-vuln.
                raw_norm.append("FSTRING_SQL_RAW")
            elif safety_tag == "WHITELIST_BOUND":
                # All interpolations are safe-bound (whitelist / placeholder /
                # numeric / db-loaded). Treat this as a static SQL string —
                # the f-string brackets just hold safe values.
                raw_norm.append("SQL_STRING")
            else:
                raw_norm.append("FSTRING_SQL")
            continue

        # ── F-string (non-SQL) ─────────────────────────────────────────────
        if is_fstring(token):
            raw_norm.append("STRING")
            continue

        # ── SQL string literal ─────────────────────────────────────────────
        if is_sql_string(token):
            raw_norm.append("SQL_STRING")
            continue

        # ── Plain string ───────────────────────────────────────────────────
        if is_string_literal(token):
            raw_norm.append("STRING")
            continue

        # ── Number ────────────────────────────────────────────────────────
        if is_number(token):
            raw_norm.append("NUMBER")
            continue

        # ── Identifiers ───────────────────────────────────────────────────
        if is_identifier(token):
            prev_token = tokens[i - 1] if i > 0 else None
            next_token = tokens[i + 1] if i < len(tokens) - 1 else None

            after_dot = prev_token == "."
            before_paren = next_token == "("

            # Check for SQL execute pattern — inject semantic signal.
            # Cross-language: Python `execute`, JS `all`/`get`/`query`/`run`,
            # PHP `mysqli_query`/`pg_query`. For ambiguous JS methods, require
            # db-like receiver name OR `await` keyword (same logic as
            # _is_db_fetch_call).
            EXEC_NAMES = {
                "execute", "executescript", "executemany",  # Python
                "query", "run",                              # JS / general
                "mysqli_query", "pg_query", "sqlsrv_query",  # PHP global funcs
                "executeQuery", "executeUpdate",             # Java JDBC
            }
            JS_AMBIGUOUS_EXEC = {"query", "run", "all", "get"}
            is_exec_name = token in EXEC_NAMES
            is_ambiguous_exec = token in JS_AMBIGUOUS_EXEC
            is_php_global_exec = token in (
                "mysqli_query", "pg_query", "sqlsrv_query"
            ) and not after_dot

            should_classify = False
            if before_paren and (is_exec_name or is_ambiguous_exec or is_php_global_exec):
                if is_php_global_exec:
                    should_classify = True
                elif token in ("execute", "executescript", "executemany",
                               "executeQuery", "executeUpdate"):
                    # These are unambiguously SQL exec methods
                    if after_dot or token.startswith("execute"):
                        should_classify = True
                elif is_ambiguous_exec and after_dot:
                    # JS .query/.run/.all/.get — need db-like receiver or await
                    if i >= 2:
                        receiver = tokens[i - 2].lower()
                        if receiver in {
                            "db", "conn", "connection", "client", "pool",
                            "database", "sql", "knex", "pg", "mysql",
                            "sqlite", "cur", "cursor", "stmt",
                        }:
                            should_classify = True
                    # await within 4 tokens behind
                    if not should_classify:
                        for j in range(max(0, i - 5), i):
                            if tokens[j] == "await":
                                should_classify = True
                                break

            if should_classify:
                signal = _classify_execute_call(tokens, i)
                if signal:
                    raw_norm.append(signal)
                ph, func_counter = get_or_create_placeholder(
                    token, func_map, func_counter, "FUNC", MAX_FUNC_TOKENS, "FUNC_OTHER"
                )
                raw_norm.append(ph)
                continue

            if after_dot and before_paren:
                ph, func_counter = get_or_create_placeholder(
                    token, func_map, func_counter, "FUNC", MAX_FUNC_TOKENS, "FUNC_OTHER"
                )
                raw_norm.append(ph)
                continue

            if after_dot and not before_paren:
                ph, property_counter = get_or_create_placeholder(
                    token, property_map, property_counter, "PROPERTY",
                    MAX_PROPERTY_TOKENS, "PROPERTY_OTHER"
                )
                raw_norm.append(ph)
                continue

            if before_paren:
                ph, func_counter = get_or_create_placeholder(
                    token, func_map, func_counter, "FUNC", MAX_FUNC_TOKENS, "FUNC_OTHER"
                )
                raw_norm.append(ph)
                continue

            ph, var_counter = get_or_create_placeholder(
                token, var_map, var_counter, "VAR", MAX_VAR_TOKENS, "VAR_OTHER"
            )
            raw_norm.append(ph)
            continue

        # ── Punctuation / operators ────────────────────────────────────────
        raw_norm.append(token)

    # Second pass: inject SQL_CONCAT for all dangerous SQL-building patterns.
    #
    # Detected patterns:
    #   SQL_STRING + VAR          → concatenation injection        (+   Python/JS/Java)
    #   VAR + SQL_STRING          → concatenation injection        (+   Python/JS/Java)
    #   SQL_STRING . VAR          → PHP dot concatenation           (.   PHP)
    #   VAR . SQL_STRING          → PHP dot concatenation           (.   PHP)
    #   SQL_STRING % VAR          → % format injection             (%)
    #   SQL_STRING . FUNC ( VAR ) → .format() injection            (. FUNC)
    #   FSTRING_SQL (any context) → f-string injection             (already flagged)
    #
    # Suppression: when the var being concatenated was flagged (in the same
    # chunk) as WHITELIST_VAR / SAFE_PLACEHOLDER_LIST / SAFE_NUMERIC_VAR,
    # the concat is safe-by-construction → no SQL_CONCAT.
    # NOTE: DB_LOADED_VAR is NOT in this list — DB-loaded values are TAINTED
    # for second-order injection and concat with them is dangerous.
    #
    # Build the placeholder set from raw safe-var names mapped through BOTH
    # var_map and property_map. Variables can appear as VAR_n in some
    # contexts and PROPERTY_n in others (e.g. PHP `. $x` puts `x` in
    # property context even though it's a top-level variable).
    safe_raw_names = whitelisted_vars | safe_placeholder_vars | safe_numeric_vars
    safe_var_placeholders: set[str] = set()
    for name in safe_raw_names:
        if name in var_map:
            safe_var_placeholders.add(var_map[name])
        if name in property_map:
            safe_var_placeholders.add(property_map[name])

    def _is_safe_var(idx: int) -> bool:
        """Token at raw_norm[idx] is a safe-flagged VAR/PROPERTY placeholder."""
        if idx < 0 or idx >= len(raw_norm):
            return False
        return raw_norm[idx] in safe_var_placeholders

    for i, tok in enumerate(raw_norm):
        normalized.append(tok)

        if tok in ("SQL_STRING", "FSTRING_SQL"):
            next_tok = raw_norm[i + 1] if i + 1 < len(raw_norm) else None
            next2    = raw_norm[i + 2] if i + 2 < len(raw_norm) else None

            # + concatenation:  SQL_STRING + ...
            if next_tok == "+":
                if not _is_safe_var(i + 2):
                    normalized.append("SQL_CONCAT")

            # % format injection:  SQL_STRING % VAR
            if next_tok == "%":
                if not _is_safe_var(i + 2):
                    normalized.append("SQL_CONCAT")

            # .format() injection:  SQL_STRING . FUNC_n ( ...
            if next_tok == "." and next2 is not None and next2.startswith("FUNC"):
                normalized.append("SQL_CONCAT")

            # PHP dot concat:  SQL_STRING . VAR_n / SQL_STRING . PROPERTY_n / SQL_STRING . SQL_STRING
            if next_tok == "." and next2 is not None and (
                next2.startswith("VAR")
                or next2.startswith("PROPERTY")
                or next2 in ("SQL_STRING", "FSTRING_SQL")
            ):
                if not _is_safe_var(i + 2):
                    normalized.append("SQL_CONCAT")

        # Reverse: + SQL_STRING / % SQL_STRING / . SQL_STRING
        if tok in ("+", "%", "."):
            next_tok = raw_norm[i + 1] if i + 1 < len(raw_norm) else None
            if next_tok in ("SQL_STRING", "FSTRING_SQL"):
                if tok == "." and i > 0 and raw_norm[i - 1].startswith("FUNC"):
                    continue
                if i > 0 and _is_safe_var(i - 1):
                    continue
                normalized.append("SQL_CONCAT")

    # ── Third pass: inject BOOLEAN_SINK once if any return-bool pattern found ─
    # Scanned over RAW tokens — not placeholders — because we need real
    # method names (`fetchone`, `bool`).
    if _detect_boolean_sink(tokens):
        normalized.append("BOOLEAN_SINK")

    return normalized
