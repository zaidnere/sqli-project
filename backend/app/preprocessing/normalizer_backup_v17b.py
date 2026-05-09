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


def _has_php_dollar_interpolation(token: str) -> bool:
    """True for PHP-style double quoted strings containing $var / ${var}.

    PHP expands variables inside double quoted strings. For SQL strings this is
    equivalent to a JavaScript template literal or Python f-string from an SQLi
    perspective. Single-quoted PHP strings are not interpolated.
    """
    if not (len(token) >= 2 and token[0] == '"' and token[-1] == '"'):
        return False
    return re.search(r"(?<!\\)\$(?:\{\s*)?[A-Za-z_][A-Za-z0-9_]*", token[1:-1]) is not None


def is_fstring(token: str) -> bool:
    """
    True for f-string tokens — Python f-strings (f"..." / f'...') OR
    JavaScript template literals containing ${...} interpolation.
    """
    if len(token) >= 3 and token[0].lower() == 'f' and token[1] in ('"', "'"):
        return True
    if _has_interpolation(token):
        return True
    if _has_php_dollar_interpolation(token):
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
        if _has_php_dollar_interpolation(token):
            return False
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
    # PHP double quoted SQL string with $var interpolation
    if _has_php_dollar_interpolation(token):
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
    # PHP double quoted body with $var / ${var}
    if _has_php_dollar_interpolation(token):
        inner = token[1:-1]
        return {m.group(1) for m in re.finditer(r"(?<!\\)\$(?:\{\s*)?([A-Za-z_][A-Za-z0-9_]*)", inner)}
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

def _classify_execute_call(tokens: list[str], exec_idx: int, safe_single_arg_vars: set[str] | None = None) -> str | None:
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

    # Single argument can still be safe when it is a variable assigned from
    # static SQL text only, e.g. a triple-quoted CREATE TABLE script passed
    # into conn.executescript(script). This prevents static migrations/schema
    # scripts from being treated like user-controlled query strings.
    meaningful_args = [t for t in arg1_tokens if t not in (',', '+', '.', '(', ')', '[', ']', '{', '}')]
    if safe_single_arg_vars and len(meaningful_args) == 1 and meaningful_args[0] in safe_single_arg_vars:
        return 'SAFE_EXEC'

    # PHP PDO / prepared statement pattern:
    #   $stmt = $pdo->prepare($sql);
    #   $stmt->execute($params);
    # Tokenizer removes `$`, so this appears as `stmt -> execute ( params )`.
    # A single array argument here is the bound parameter list, not a raw SQL
    # query string. Keep Python `cursor.execute(sql)` unsafe; only apply this
    # when the receiver name is statement-like, or when execute() receives an
    # array literal (PDO params) on a non-connection receiver.
    receiver = tokens[exec_idx - 2].lower() if exec_idx >= 2 and tokens[exec_idx - 1] in ('.', '->') else ''
    if tokens[exec_idx] == 'execute' and receiver in {'stmt', 'statement', 'ps', 'preparedstatement', 'prepared'}:
        return 'SAFE_EXEC'
    if tokens[exec_idx] == 'execute' and receiver and receiver not in {'conn', 'connection', 'db', 'database', 'cursor', 'cur', 'pdo'}:
        if arg1_tokens and arg1_tokens[0] == '[':
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
    "_MAP", "_LOOKUP", "_DICT", "_TABLE_MAP",
    # Real-world query builders often use closed constants with names such as
    # REPORT_TABLES / SORT_COLUMNS / ALLOWED_METRICS.  These are still
    # allowlists even when the word "ALLOWED" is not present.
    "_TABLE", "_TABLES", "_COLUMN", "_COLUMNS", "_METRIC", "_METRICS",
    "_SORT", "_DIRECTION", "_DIRECTIONS",
)

_ALLOWLIST_DOMAIN_WORDS = (
    "TABLE", "TABLES", "COLUMN", "COLUMNS", "COL", "COLS",
    "METRIC", "METRICS", "SORT", "DIRECTION", "DIRECTIONS",
    "GROUP", "GROUPS", "FIELD", "FIELDS",
)


def _looks_like_allowlist_name(token: str) -> bool:
    """Name-level allowlist hint used for helpers/properties.

    `_is_allowlist_identifier()` is intentionally strict for top-level raw
    identifiers.  Real repositories also use lower/camel-case properties such
    as `allowedSort` or helper constants such as `SORT_COLUMNS`.  This helper
    keeps the strict function intact while giving return/helper propagation a
    slightly broader, still SQL-identifier-focused vocabulary.
    """
    if not token or not is_identifier(token):
        return False
    low = token.lower()
    if any(h.replace("_", "") in low for h in ("allowed", "allowlist", "whitelist", "permitted", "valid", "safe")):
        return True
    up = token.upper()
    if any(word in up for word in _ALLOWLIST_DOMAIN_WORDS):
        return True
    return False


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
    if any(word in token for word in _ALLOWLIST_DOMAIN_WORDS):
        return True
    return False


def _stmt_indices(tokens: list[str], start: int, stop_keywords: set[str] | None = None):
    """Yield token indices from start until the current statement ends."""
    n = len(tokens)
    depth = 0
    stop_keywords = stop_keywords or set()
    i = start
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
            if i > start and t in stop_keywords:
                break
            if i > start and t == "=":
                prev_t = tokens[i - 1] if i - 1 >= 0 else None
                next_t = tokens[i + 1] if i + 1 < n else None
                if prev_t not in ("=", "!", "<", ">", "+", "-", "*", "/", "%", "|", "&", "^") and next_t != "=":
                    break
        yield i
        i += 1


def _return_expr_indices(tokens: list[str], return_idx: int) -> list[int]:
    return list(_stmt_indices(tokens, return_idx + 1, {"def", "class", "function", "return"}))


def _expr_has_allowlist_lookup(tokens: list[str], indices: list[int]) -> bool:
    """Return True if an expression maps a raw choice through a closed set/map."""
    if not indices:
        return False
    idx_set = set(indices)
    # Direct allowlist/mapping names: ALLOWED_X.get(...), SORT_COLUMNS.has(...),
    # REPORT_TABLES[name], $this->allowedSort[$x] ?? default, etc.
    for pos in indices:
        t = tokens[pos]
        if _is_allowlist_identifier(t) or _looks_like_allowlist_name(t):
            # Method membership / map access.
            if pos + 2 < len(tokens) and tokens[pos + 1] in (".", "->") and tokens[pos + 2] in ("get", "contains", "has"):
                return True
            if pos + 1 < len(tokens) and tokens[pos + 1] == "[":
                return True
            # Ternary membership: X if X in ALLOWED else D / ALLOWED.contains(x) ? x : D
            if any(tokens[j] in ("in", "?", "??") for j in indices):
                return True

    # PHP/null-coalescing fallback: `something[...] ?? default` where the map
    # name itself contains an allowlist hint, including `$this->allowedSort`.
    for pos in indices:
        if tokens[pos] == "??":
            left = [tokens[j] for j in indices if j < pos]
            if "[" in left and any(_looks_like_allowlist_name(x) or _is_allowlist_identifier(x) for x in left if is_identifier(x)):
                return True

    # Python ternary explicit form.
    saw_if = saw_in = saw_else = False
    found_allowlist = False
    for pos in indices:
        t = tokens[pos]
        if t == "if":
            saw_if = True
        elif saw_if and t == "in":
            saw_in = True
        elif saw_in and t == "else":
            saw_else = True
        elif saw_in and not saw_else and (_is_allowlist_identifier(t) or _looks_like_allowlist_name(t)):
            found_allowlist = True
    return saw_if and saw_in and saw_else and found_allowlist


def _expr_has_db_fetch(tokens: list[str], indices: list[int]) -> bool:
    return any(_is_db_fetch_call(tokens, i) for i in indices)


def _expr_is_numeric_safe(tokens: list[str], indices: list[int], known_numeric: set[str]) -> bool:
    """Numeric-safe expression used for helper returns."""
    if not indices:
        return False
    saw_numeric = False
    allowed_punct = {",", "(", ")", "[", "]", "{", "}", ".", ":"}
    arith_ops = {"+", "-", "*", "/", "%", "//"}
    for pos in indices:
        t = tokens[pos]
        if t in allowed_punct or t in arith_ops:
            continue
        if t.isdigit() or (t.replace(".", "", 1).isdigit() and t.count(".") < 2):
            saw_numeric = True
            continue
        if t in _NUMERIC_FUNCS or t in _NUMERIC_NAMESPACES:
            saw_numeric = True
            continue
        if pos > 0 and tokens[pos - 1] == "." and pos >= 2 and tokens[pos - 2] in _NUMERIC_NAMESPACES:
            saw_numeric = True
            continue
        if is_identifier(t):
            if t in known_numeric:
                saw_numeric = True
                continue
            # Type hints / generic names in return annotations are not part of
            # the returned value once we are scanning after `return`; anything
            # else is a raw identifier and makes the expression unsafe.
            return False
        if t.startswith(('"', "'", "`")):
            return False
    return saw_numeric


def _candidate_function_ranges(tokens: list[str]) -> list[tuple[str, int, int]]:
    """Best-effort cross-language function/method ranges.

    Supports Python `def`, JS/PHP `function`, and Java-style methods such as
    `private String safeSort(...) { ... }`.  The ranges are intentionally used
    only for semantic helper propagation, not for parsing or security proofs.
    """
    ranges: list[tuple[str, int, int]] = []
    n = len(tokens)
    control = {"if", "for", "while", "switch", "catch", "return", "new", "class", "try", "with"}

    def matching_paren(open_idx: int) -> int | None:
        d = 0
        for j in range(open_idx, n):
            if tokens[j] == "(":
                d += 1
            elif tokens[j] == ")":
                d -= 1
                if d == 0:
                    return j
        return None

    def matching_brace(open_idx: int) -> int | None:
        d = 0
        for j in range(open_idx, n):
            if tokens[j] == "{":
                d += 1
            elif tokens[j] == "}":
                d -= 1
                if d == 0:
                    return j
        return None

    i = 0
    while i < n:
        name = None
        body_start = None
        body_end = None

        if tokens[i] in ("def", "function") and i + 2 < n and is_identifier(tokens[i + 1]) and tokens[i + 2] == "(":
            name = tokens[i + 1]
            close = matching_paren(i + 2)
            if close is not None:
                # Braced languages: function name(...) { ... }
                j = close + 1
                # PHP may have a return type between `)` and `{`, e.g.
                # `function f(): string { ... }`.  Skip through annotations
                # until the real body brace or a statement terminator.
                while j < n and tokens[j] not in ("{", ";"):
                    j += 1
                if j < n and tokens[j] == "{":
                    end = matching_brace(j)
                    if end is not None:
                        body_start, body_end = j + 1, end
                else:
                    # Python: until next def/class at top level (rough heuristic)
                    body_start = close + 1
                    end = body_start
                    while end < n:
                        if tokens[end] in ("def", "class") and end > body_start:
                            break
                        end += 1
                    body_end = end

        # Java/C#-style method: <modifiers/type> name(...) { ... }
        elif is_identifier(tokens[i]) and i + 1 < n and tokens[i + 1] == "(" and tokens[i] not in control:
            prev = tokens[i - 1] if i > 0 else None
            prev2 = tokens[i - 2] if i > 1 else None
            if prev not in (".", "->") and prev2 not in (".", "->"):
                close = matching_paren(i + 1)
                if close is not None:
                    j = close + 1
                    while j < n and tokens[j] not in ("{", ";"):
                        j += 1
                    if j < n and tokens[j] == "{":
                        end = matching_brace(j)
                        if end is not None:
                            name = tokens[i]
                            body_start, body_end = j + 1, end

        if name and body_start is not None and body_end is not None and body_start < body_end:
            ranges.append((name, body_start, body_end))
            # For Python-like unbraced ranges, body_end may be the next `def`;
            # do not skip over it.  For braced ranges body_end is `}`, so the
            # next token is correct.
            i = body_end if body_end < n and tokens[body_end] in ("def", "function") else body_end + 1
        else:
            i += 1
    return ranges


def _collect_lhs_positions(tokens: list[str], eq_idx: int) -> list[int]:
    """Collect variable identifiers assigned by the statement at `eq_idx`.

    Handles Python tuple assignment, JS destructuring (`const {a,b} = ...`),
    Java declarations (`String safeCol = ...`), and PHP variables (the `$` is
    not tokenized, so `$safeSort` appears as `safeSort`).
    """
    declaration_words = {
        "const", "let", "var", "final", "private", "public", "protected", "static",
        "String", "int", "long", "double", "float", "boolean", "bool", "array", "PDO",
        "List", "Map", "Set", "ResultSet", "PreparedStatement", "Connection",
    }

    if eq_idx <= 0:
        return []

    prev = tokens[eq_idx - 1]

    # JS/PHP destructuring: `const { safeCol, safeDir } = ...`.
    if prev in ("}", "]"):
        close_tok = prev
        open_tok = "{" if close_tok == "}" else "["
        d = 1
        j = eq_idx - 2
        while j >= 0:
            if tokens[j] == close_tok:
                d += 1
            elif tokens[j] == open_tok:
                d -= 1
                if d == 0:
                    break
            j -= 1
        if j >= 0:
            # Object/array destructuring if a declaration keyword appears just
            # before the opening brace/bracket.
            if j > 0 and tokens[j - 1] in declaration_words | {"const", "let", "var"}:
                return [
                    p for p in range(j + 1, eq_idx - 1)
                    if is_identifier(tokens[p]) and tokens[p] not in declaration_words
                    and not (p + 1 < eq_idx and tokens[p + 1] == ":")
                ]
            # Type annotation: `params: list[Any] = ...`. Walk back to colon,
            # then take the identifier immediately before it.
            k = j - 1
            while k >= 0 and tokens[k] not in (";", "{", "}", "def", "class", "function", ","):
                if tokens[k] == ":":
                    m = k - 1
                    while m >= 0 and not is_identifier(tokens[m]):
                        m -= 1
                    return [m] if m >= 0 and tokens[m] not in declaration_words else []
                k -= 1

    # Type annotation without generics: `x: int = ...`.
    # Guard against `if obj.attr: name = ...`, where the colon belongs to the
    # enclosing control statement and `name` is the real LHS.
    if prev and is_identifier(prev) and eq_idx >= 3 and tokens[eq_idx - 2] == ":":
        lhs_pos = eq_idx - 3
        if (
            lhs_pos >= 0
            and is_identifier(tokens[lhs_pos])
            and (lhs_pos == 0 or tokens[lhs_pos - 1] not in (".", "->"))
        ):
            return [lhs_pos]

    # Tuple / comma assignment: `a, b = ...`.  Only continue left if the
    # previous identifier is separated by a comma; this avoids collecting Java
    # type names (`String safeCol =`).
    positions: list[int] = []
    k = eq_idx - 1
    while k >= 0:
        if is_identifier(tokens[k]) and tokens[k] not in declaration_words:
            positions.append(k)
            k -= 1
            if k >= 0 and tokens[k] == ",":
                k -= 1
                continue
            break
        elif tokens[k] in (")",):
            k -= 1
            continue
        else:
            break
    return positions


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
        if t == "implode" and i + 1 < n and tokens[i + 1] == "(":
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
    "pdo", "mysqli", "stmt", "statement",
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


def _rhs_uses_db_loaded_var(tokens: list[str], eq_idx: int, db_loaded_vars: set[str]) -> bool:
    """Detect taint propagation: x = row[0] / x = row.field / x = helper(row)."""
    if not db_loaded_vars:
        return False
    n = len(tokens)
    depth = 0
    i = eq_idx + 1
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
            if i > eq_idx + 1 and t == "=":
                prev_t = tokens[i - 1] if i - 1 >= 0 else None
                next_t = tokens[i + 1] if i + 1 < n else None
                if prev_t not in ("=", "!", "<", ">", "+", "-", "*", "/", "%", "|", "&", "^") and next_t != "=":
                    break
            if i > eq_idx + 1 and t in stmt_boundary_kw:
                break
        if t in db_loaded_vars:
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
        if t == "join" or t == "implode":
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


def _detect_static_sql_assignment(tokens: list[str], eq_idx: int) -> bool:
    """Detect vars assigned from static SQL literals only.

    Safe examples:
      script = <triple-quoted CREATE TABLE literal>
      sql = "SELECT ..." + " FROM ..."

    Unsafe/non-static examples reject any identifier on the RHS.
    """
    n = len(tokens)
    i = eq_idx + 1
    depth = 0
    saw_sql = False
    saw_value = False
    prev_meaningful = ""
    allowed_ops = {"+", ".", "%"}
    structural = {"(", ")", "[", "]", "{", "}", ","}

    while i < n:
        t = tokens[i]

        # In this tokenizer newlines are not preserved.  After a complete RHS
        # value, a bare identifier at top level usually starts the next
        # statement (`script = "..." conn.executescript(script)`).  Stop before
        # consuming it unless the previous meaningful token was a concat op.
        if depth == 0 and saw_value and is_identifier(t) and prev_meaningful not in allowed_ops:
            break

        if t in ("(", "[", "{"):
            depth += 1
        elif t in (")", "]", "}"):
            depth -= 1
            if depth < 0:
                break

        if t in allowed_ops or t in structural:
            prev_meaningful = t if t in allowed_ops else prev_meaningful
            i += 1
            continue

        if is_sql_string(t):
            saw_sql = True
            saw_value = True
            prev_meaningful = "STRING"
            i += 1
            continue

        if is_string_literal(t) or (is_template_literal(t) and not _has_interpolation(t)):
            saw_value = True
            prev_meaningful = "STRING"
            i += 1
            continue

        if is_number(t):
            saw_value = True
            prev_meaningful = "NUMBER"
            i += 1
            continue

        if is_identifier(t):
            # If the identifier is connected by +/./%, it is part of the RHS
            # and therefore the assignment is not static.
            return False

        if t in {":", ";"}:
            break
        return False

    return saw_sql

def _detect_safe_sql_fragment_list_assignment(tokens: list[str], eq_idx: int) -> bool:
    """Detect variables that hold only static SQL predicate fragments.

    Examples:
      const where = ["tenant_id = ?"]
      sql_parts = ["SELECT ...", "FROM ...", "WHERE tenant_id = ?"]

    These containers are safe to interpolate via `${where.join(" AND ")}` if
    later mutations also add only literal SQL fragments or placeholder-list
    fragments. Raw value-bearing f-strings/templates will invalidate it in the
    mutation pass below.
    """
    n = len(tokens)
    i = eq_idx + 1
    depth = 0
    saw_array = False
    saw_string = False
    while i < n:
        t = tokens[i]
        if depth == 0:
            if t in (";", "\n"):
                break
            if i > eq_idx + 1 and t == "=":
                prev_t = tokens[i - 1] if i - 1 >= 0 else None
                next_t = tokens[i + 1] if i + 1 < n else None
                if prev_t not in ("=", "!", "<", ">", "+", "-", "*", "/", "%") and next_t != "=":
                    break
        if t == "[":
            saw_array = True
            depth += 1
        elif t in ("(", "{"):
            depth += 1
        elif t in ("]", ")", "}"):
            depth -= 1
            if depth < 0:
                break
        elif depth >= 1:
            if len(t) >= 2 and t[0] in '"\'`' and t[-1] in '"\'`':
                saw_string = True
            elif is_identifier(t):
                # Any non-keyword identifier inside the initial list means raw
                # runtime data entered the fragment container.
                if t.lower() not in LANGUAGE_KEYWORDS:
                    return False
        i += 1
    return saw_array and saw_string


def _validate_safe_sql_fragment_mutations(
    tokens: list[str],
    safe_fragment_vars: set[str],
    safe_interp_vars: set[str],
) -> set[str]:
    """Remove fragment-list vars that receive raw interpolated fragments."""
    if not safe_fragment_vars:
        return safe_fragment_vars
    invalid: set[str] = set()
    n = len(tokens)
    for i, t in enumerate(tokens):
        if t not in safe_fragment_vars:
            continue
        # where.push(...), sql_parts.append(...)
        if i + 3 >= n or tokens[i + 1] not in (".", "->") or tokens[i + 2] not in ("push", "append") or tokens[i + 3] != "(":
            continue
        depth = 1
        j = i + 4
        while j < n and depth > 0:
            tj = tokens[j]
            if tj in ("(", "[", "{"):
                depth += 1
            elif tj in (")", "]", "}"):
                depth -= 1
                if depth == 0:
                    break
            if is_fstring_sql(tj):
                interp = _extract_interpolated_vars(tj)
                if interp - safe_interp_vars:
                    invalid.add(t)
                    break
            j += 1
    return safe_fragment_vars - invalid


def _detect_second_order_flow(tokens: list[str], db_loaded_var_pos: dict[str, int]) -> bool:
    """Detect DB-loaded value reused later as SQL text/syntax.

    Second-order is not "any DB value". It specifically means a stored value
    becomes SQL syntax later: concatenated into SQL, interpolated into SQL, or
    passed as the SQL string to execute/query/executescript/executeQuery.
    """
    n = len(tokens)
    db_loaded_names = set(db_loaded_var_pos)

    exec_names = {
        "execute", "executescript", "executemany",
        "query", "raw", "run", "all", "get", "each",
        "executeQuery", "executeUpdate",
        "mysqli_query", "pg_query", "sqlsrv_query",
    }

    def _first_arg_indices(open_paren_idx: int) -> list[int]:
        depth = 1
        out: list[int] = []
        j = open_paren_idx + 1
        while j < n and depth > 0:
            tj = tokens[j]
            if tj in ("(", "[", "{"):
                depth += 1
            elif tj in (")", "]", "}"):
                depth -= 1
                if depth == 0:
                    break
            elif tj == "," and depth == 1:
                break
            out.append(j)
            j += 1
        return out

    def _is_exec_call(i: int) -> bool:
        if i >= n or tokens[i] not in exec_names:
            return False
        if i + 1 >= n or tokens[i + 1] != "(":
            return False
        if tokens[i] in {"all", "get", "run", "each", "query"}:
            if i >= 2 and tokens[i - 1] in (".", "->"):
                recv = tokens[i - 2].lower()
                return recv in _DB_LIKE_NAMES or recv in {"stmt", "statement"}
            return tokens[i] in {"mysqli_query", "pg_query", "sqlsrv_query"}
        return True

    # Cache/container taint: DB-loaded fragments stored into cache/map/array and
    # later retrieved into SQL construction: cache.set(... row.fragment),
    # cache.put(... rs.getString(...)), _CACHE[key] = row[0] then SQL + cache.get/key.
    tainted_containers: set[str] = set()
    db_vars = set(db_loaded_names)
    for i, t in enumerate(tokens):
        # Track variables assigned directly from DB fetch in this full-file scan.
        if t == "=":
            lhs_positions = _collect_lhs_positions(tokens, i)
            if _detect_db_loaded_assignment(tokens, i) or _rhs_uses_db_loaded_var(tokens, i, db_vars):
                for p in lhs_positions:
                    db_vars.add(tokens[p])
            # cache[key] = db_var / db fetch
            if i >= 2 and tokens[i - 1] == "]":
                j = i - 2
                depth = 1
                while j >= 0 and depth > 0:
                    if tokens[j] == "]": depth += 1
                    elif tokens[j] == "[": depth -= 1
                    j -= 1
                if j >= 0 and is_identifier(tokens[j]):
                    rhs = _first_arg_indices(i)  # not perfect for '=', but scans RHS until comma/end reasonably
                    # Use a bounded raw scan instead.
                    k = i + 1
                    while k < n and k < i + 25:
                        if tokens[k] in (";", "return", "def", "function", "class"):
                            break
                        if tokens[k] in db_vars or _is_db_fetch_call(tokens, k):
                            tainted_containers.add(tokens[j])
                            break
                        k += 1
        # cache.set(name, dbvar) / cache.put(name, dbfetch)
        if t in {"set", "put"} and i >= 2 and tokens[i - 1] in (".", "->") and is_identifier(tokens[i - 2]):
            container = tokens[i - 2]
            if i + 1 < n and tokens[i + 1] == "(":
                depth = 1
                j = i + 2
                while j < n and depth > 0:
                    tj = tokens[j]
                    if tj in ("(", "[", "{"):
                        depth += 1
                    elif tj in (")", "]", "}"):
                        depth -= 1
                        if depth == 0:
                            break
                    if tj in db_vars or _is_db_fetch_call(tokens, j):
                        tainted_containers.add(container)
                        break
                    j += 1

    if tainted_containers:
        for i, t in enumerate(tokens):
            if t not in tainted_containers:
                continue
            # Use through cache[key] or cache.get(key)
            uses_container_value = False
            if i + 1 < n and tokens[i + 1] == "[":
                uses_container_value = True
            if i + 3 < n and tokens[i + 1] in (".", "->") and tokens[i + 2] == "get" and tokens[i + 3] == "(":
                uses_container_value = True
            if not uses_container_value:
                continue
            lo = max(0, i - 12)
            hi = min(n, i + 12)
            window = tokens[lo:hi]
            if any(is_sql_string(x) or is_fstring_sql(x) for x in window) and any(x in {"+", ".", "%"} for x in window):
                return True

    # A direct DB fetch used as the SQL argument is second-order:
    #   executeQuery(rs.getString("sql_text"))
    #   query($stmt->fetchColumn())
    for i in range(n):
        if not _is_exec_call(i):
            continue
        first_arg = _first_arg_indices(i + 1)
        if not first_arg:
            continue
        # Prepared-statement parameter execution, e.g. $stmt->execute([$x]), is not a SQL-string sink.
        if tokens[i] == "execute" and first_arg and tokens[first_arg[0]] in {"[", "("}:
            continue
        for p in first_arg:
            if _is_db_fetch_call(tokens, p):
                return True
            if tokens[p] in db_loaded_names:
                return True

    if not db_loaded_var_pos:
        return False

    for name, load_pos in db_loaded_var_pos.items():
        for i in range(load_pos + 1, n):
            t = tokens[i]
            if is_fstring_sql(t) and name in _extract_interpolated_vars(t):
                return True
            if t != name:
                continue
            lo = max(load_pos + 1, i - 8)
            hi = min(n, i + 8)
            window = tokens[lo:hi]
            has_sql_text = any(is_sql_string(x) or is_fstring_sql(x) for x in window)
            prev_t = tokens[i - 1] if i > 0 else ""
            next_t = tokens[i + 1] if i + 1 < n else ""
            adjacent_concat = prev_t in {"+", "%"} or next_t in {"+", "%"}
            php_dot_concat = prev_t == "." or next_t == "."
            nearby_concat = any(x in {"+", "%"} for x in window)
            if has_sql_text and (adjacent_concat or (php_dot_concat and nearby_concat)):
                return True
    return False

def _detect_boolean_sink(tokens: list[str]) -> bool:
    """Detect query-result reduced to a boolean decision.

    Covers direct and indirect patterns across Python/JS/Java/PHP:
      - return cur.fetchone() is not None / count > 0
      - row = await db.get(sql); return !!row / Boolean(row)
      - return executeQuery(sql).next()
      - return (bool)$pdo->query($sql)->fetch()
    """
    n = len(tokens)
    bool_ops = {"==", "!=", ">", "<", ">=", "<=", "is"}
    bool_funcs = {"bool", "Boolean"}
    stmt_boundary_kw = {
        "def", "class", "return", "if", "elif", "else", "for", "while",
        "try", "except", "finally", "with", "import", "from", "raise",
        "yield", "pass", "break", "continue",
    }

    def _scan_stmt(start_idx: int) -> list[int]:
        depth = 0
        out: list[int] = []
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
            out.append(i)
            i += 1
        return out

    def _stmt_has_fetch(indices: list[int]) -> bool:
        for j in indices:
            if _is_db_fetch_call(tokens, j):
                return True
            if _is_db_bool_call(tokens, j):
                return True
            # Chained JDBC: executeQuery(sql).next(), where receiver before
            # next() is ')' rather than a named ResultSet var.
            if tokens[j] == "next" and j + 1 < n and tokens[j + 1] == "(":
                if any(tokens[k] == "executeQuery" for k in indices[:indices.index(j)]):
                    return True
        return False

    def _stmt_has_bool_context(indices: list[int]) -> bool:
        for pos, j in enumerate(indices):
            if tokens[j] in bool_ops or tokens[j] in bool_funcs or tokens[j] == "!":
                return True
            if _is_db_bool_call(tokens, j):
                return True
            if tokens[j] == "next" and j + 1 < n and tokens[j + 1] == "(":
                if any(tokens[k] == "executeQuery" for k in indices[:pos]):
                    return True
        return False

    bool_fetch_vars: set[str] = set()
    db_fetched_vars: set[str] = set()

    # Pre-pass: assignment facts.
    for idx in range(n):
        if tokens[idx] != "=":
            continue
        prev = tokens[idx - 1] if idx > 0 else None
        nxt = tokens[idx + 1] if idx + 1 < n else None
        if prev in ("=", "!", "<", ">", "+", "-", "*", "/", "%", "|", "&", "^") or nxt == "=":
            continue
        k = idx - 1
        while k >= 0 and tokens[k] in (",", "(", ")"):
            k -= 1
        if k < 0 or not is_identifier(tokens[k]):
            continue
        lhs = tokens[k]
        stmt = _scan_stmt(idx + 1)
        has_fetch = _stmt_has_fetch(stmt)
        has_bool = _stmt_has_bool_context(stmt)
        uses_db_var = any(tokens[j] in db_fetched_vars for j in stmt)
        if (has_fetch and has_bool) or (uses_db_var and has_bool):
            bool_fetch_vars.add(lhs)
        elif has_fetch:
            db_fetched_vars.add(lhs)

    # Main scan: return statements.
    for i, t in enumerate(tokens):
        if t != "return":
            continue
        stmt = _scan_stmt(i + 1)
        if not stmt:
            continue
        if _stmt_has_fetch(stmt) and _stmt_has_bool_context(stmt):
            return True
        if any(tokens[j] in bool_fetch_vars for j in stmt):
            return True
        has_db_var = any(tokens[j] in db_fetched_vars for j in stmt)
        if has_db_var and _stmt_has_bool_context(stmt):
            return True
        # Direct boolean-returning DB existence call without explicit op:
        #   return c.createStatement().executeQuery(sql).next()
        #   return rs.next()
        if any(_is_db_bool_call(tokens, j) for j in stmt):
            return True
        for j in stmt:
            if tokens[j] == "next" and j + 1 < n and tokens[j + 1] == "(":
                if any(tokens[k] == "executeQuery" for k in stmt if k < j):
                    return True
    return False


# ── Main normalizer ───────────────────────────────────────────────────────────

def _extract_helper_return_signals(tokens: list[str]) -> dict[str, set[str]]:
    """Infer what kind of safe/tainted value helper functions return.

    This is the file-level memory layer used to make chunked analysis behave
    more like a real file analysis.  It intentionally tracks only a few strong
    facts: whitelist-validated SQL identifiers, numeric-bounded paging values,
    and DB-loaded values for second-order flow.
    """
    signals_by_func: dict[str, set[str]] = {}
    ranges = _candidate_function_ranges(tokens)

    for fname, start, end in ranges:
        whitelisted_vars: set[str] = set()
        numeric_vars: set[str] = set()
        db_vars: set[str] = set()
        func_signals: set[str] = set()

        # Assignment facts inside the helper body.
        for idx in range(start, end):
            if tokens[idx] != "=":
                continue
            prev = tokens[idx - 1] if idx > 0 else None
            nxt = tokens[idx + 1] if idx + 1 < len(tokens) else None
            if prev in ("=", "!", "<", ">", "+", "-", "*", "/", "%", "|", "&", "^") or nxt == "=":
                continue
            lhs_positions = _collect_lhs_positions(tokens, idx)
            if not lhs_positions:
                continue
            if _detect_whitelist_assignment(tokens, idx):
                for p in lhs_positions:
                    whitelisted_vars.add(tokens[p])
                func_signals.add("WHITELIST_VAR")
            elif _detect_safe_numeric_assignment(tokens, idx, numeric_vars):
                for p in lhs_positions:
                    numeric_vars.add(tokens[p])
                func_signals.add("SAFE_NUMERIC_VAR")
            elif _detect_db_loaded_assignment(tokens, idx):
                for p in lhs_positions:
                    db_vars.add(tokens[p])
                func_signals.add("DB_LOADED_VAR")

        # Return facts.  This catches helpers like:
        #   return ALLOWED_COLUMNS.get(x, default)
        #   return SORT_COLUMNS.has(x) ? x : "created_at"
        #   return REPORT_TABLES[name] || "invoices"
        #   return db.get("SELECT ...", params)
        #   return safe_size, (safe_page - 1) * safe_size
        for idx in range(start, end):
            if tokens[idx] != "return":
                continue
            expr = _return_expr_indices(tokens, idx)
            expr_names = {tokens[p] for p in expr if is_identifier(tokens[p])}
            if _expr_has_allowlist_lookup(tokens, expr) or (expr_names and expr_names <= whitelisted_vars):
                func_signals.add("WHITELIST_VAR")
            if _expr_has_db_fetch(tokens, expr) or (expr_names and bool(expr_names & db_vars)):
                func_signals.add("DB_LOADED_VAR")
            if _expr_is_numeric_safe(tokens, expr, numeric_vars):
                func_signals.add("SAFE_NUMERIC_VAR")

        if func_signals:
            signals_by_func.setdefault(fname, set()).update(func_signals)

    # Transitive closure: helper A returns helper B(...).  Keep the semantics
    # from B if A is just a thin wrapper around it.
    for _ in range(3):
        added_any = False
        for fname, start, end in ranges:
            current = signals_by_func.setdefault(fname, set())
            before = set(current)
            for idx in range(start, end):
                if tokens[idx] != "return":
                    continue
                expr = _return_expr_indices(tokens, idx)
                for p in expr:
                    t = tokens[p]
                    if is_identifier(t) and t in signals_by_func and p + 1 < len(tokens) and tokens[p + 1] == "(":
                        current.update(signals_by_func[t])
            if current != before:
                added_any = True
        if not added_any:
            break

    return {name: sigs for name, sigs in signals_by_func.items() if sigs}


def extract_safe_returning_funcs(tokens: list[str]) -> set[str]:
    """Return helpers that produce whitelist-validated SQL identifiers."""
    return {
        name for name, sigs in _extract_helper_return_signals(tokens).items()
        if "WHITELIST_VAR" in sigs
    }


def extract_numeric_returning_funcs(tokens: list[str]) -> set[str]:
    """Return helpers that produce bounded numeric values (LIMIT/OFFSET)."""
    return {
        name for name, sigs in _extract_helper_return_signals(tokens).items()
        if "SAFE_NUMERIC_VAR" in sigs
    }


def extract_db_returning_funcs(tokens: list[str]) -> set[str]:
    """Return helpers that load values from the DB for later second-order flow."""
    return {
        name for name, sigs in _extract_helper_return_signals(tokens).items()
        if "DB_LOADED_VAR" in sigs
    }


def normalize_tokens(
    tokens: list[str],
    extra_safe_funcs: set[str] | None = None,
    extra_numeric_funcs: set[str] | None = None,
    extra_db_loaded_funcs: set[str] | None = None,
) -> list[str]:
    """
    Normalize a token list into a semantic sequence.
    Injects UNSAFE_EXEC, SAFE_EXEC, SQL_CONCAT signals where detected.
    Also injects flow signals: WHITELIST_VAR, DB_LOADED_VAR, BOOLEAN_SINK.

    extra_safe_funcs / extra_numeric_funcs / extra_db_loaded_funcs:
    file-level helper facts. Calls to these helpers on the RHS of an
    assignment propagate WHITELIST_VAR / SAFE_NUMERIC_VAR / DB_LOADED_VAR to
    the LHS. Used by the chunker to share context across helper chunks.
    """
    normalized: list[str] = []

    var_map: dict[str, str] = {}
    func_map: dict[str, str] = {}
    func_name_by_placeholder: dict[str, str] = {}
    property_map: dict[str, str] = {}

    var_counter = 0
    func_counter = 0
    property_counter = 0

    # ── Pre-scan: detect flow patterns over RAW tokens (Gap-A v2) ─────────
    # Map: position-of-`=` → flow signal to emit just BEFORE the assigned VAR.
    #
    # Why pre-scan: detectors look at raw tokens (need real method names like
    # "fetchone", real allowlist names like "ALLOWED_SORT_COLUMNS"). The first
    # pass below replaces those with placeholders, losing the information.
    flow_signal_at_pos: dict[int, str] = {}
    whitelisted_vars: set[str] = set()    # var names known to be allowlist-validated
    db_loaded_vars: set[str] = set()      # var names known to hold DB fetch result
    db_loaded_var_pos: dict[str, int] = {} # var name -> assignment position
    safe_placeholder_vars: set[str] = set()  # var = ",".join("?" for _ in xs)
    safe_numeric_vars: set[str] = set()      # var = int(x) / min(x, ...) / arithmetic
    safe_fragment_vars: set[str] = set()     # list/array of static SQL fragments with bound params
    static_sql_vars: set[str] = set()        # var assigned from static SQL literal/script only

    # ── Pre-scan: identify "safe-returning" helper functions ──────────────
    # A function is safe-returning if its body contains an assignment that
    # would fire WHITELIST_VAR (e.g. `col = pick_allowed(x, ALLOWED, default)`
    # or `return value if value in ALLOWED else default`). When such a
    # function is later called as RHS of an assignment, the LHS vars are
    # marked WHITELIST_VAR via propagation.
    #
    # We detect this in two waves: first find all `def <name>(...)` sites,
    # then for each, scan the body for whitelist patterns.
    safe_returning_funcs: set[str] = set(extra_safe_funcs) if extra_safe_funcs else set()
    numeric_returning_funcs: set[str] = set(extra_numeric_funcs) if extra_numeric_funcs else set()
    db_returning_funcs: set[str] = set(extra_db_loaded_funcs) if extra_db_loaded_funcs else set()
    n_tokens = len(tokens)
    for fi, ftok in enumerate(tokens):
        if ftok != "def" or fi + 1 >= n_tokens:
            continue
        fname = tokens[fi + 1]
        if not is_identifier(fname):
            continue
        # Scan body until next `def` or end of tokens, looking for
        # `return ... if ... in ALLOWLIST_NAME else ...` (Pattern A in return)
        # or any assignment that would fire _detect_whitelist_assignment.
        bj = fi + 2
        while bj < n_tokens:
            tj = tokens[bj]
            if tj == "def" and bj > fi + 2:
                break
            # Direct: `return X if X in ALLOWLIST_NAME else default`
            if tj == "return" and bj + 6 < n_tokens:
                # Look ahead for `if ... in <ALLOWLIST_NAME> else`
                k = bj + 1
                saw_if = saw_in = saw_else = False
                found_aw = False
                local_d = 0
                while k < n_tokens and k < bj + 30:
                    tk = tokens[k]
                    if tk in ("(", "[", "{"): local_d += 1
                    elif tk in (")", "]", "}"):
                        local_d -= 1
                        if local_d < 0: break
                    if local_d == 0:
                        if tk in (";", "\n"): break
                        if tk == "def" and k > bj + 1: break
                        if tk == "if": saw_if = True
                        elif saw_if and tk == "in": saw_in = True
                        elif saw_in and tk == "else": saw_else = True
                        elif saw_in and not saw_else and _is_allowlist_identifier(tk):
                            found_aw = True
                    k += 1
                if saw_if and saw_in and saw_else and found_aw:
                    safe_returning_funcs.add(fname)
                    break
            # Assignment with whitelist pattern (any inside body)
            if tj == "=":
                pv = tokens[bj - 1] if bj > 0 else None
                nv = tokens[bj + 1] if bj + 1 < n_tokens else None
                if pv not in ("=", "!", "<", ">", "+", "-", "*", "/", "%", "|", "&", "^") and nv != "=":
                    if _detect_whitelist_assignment(tokens, bj):
                        safe_returning_funcs.add(fname)
                        break
            bj += 1

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
        # Collect ALL LHS identifiers (tuple-unpack, JS destructuring, Java
        # declarations, PHP variables).  The old backwards scan lost
        # destructured values and often marked Java type names as variables.
        lhs_positions = _collect_lhs_positions(tokens, idx)
        if not lhs_positions:
            continue
        # Detection priority: most-specific first. Apply to ALL LHS vars.
        signal = None
        if _detect_safe_placeholder_list(tokens, idx):
            signal = "SAFE_PLACEHOLDER_LIST"
        elif _detect_whitelist_assignment(tokens, idx):
            signal = "WHITELIST_VAR"
        elif _detect_db_loaded_assignment(tokens, idx) or _rhs_uses_db_loaded_var(tokens, idx, db_loaded_vars):
            signal = "DB_LOADED_VAR"
        elif _detect_safe_sql_fragment_list_assignment(tokens, idx):
            signal = "SAFE_SQL_FRAGMENT_LIST"
        elif _detect_static_sql_assignment(tokens, idx):
            signal = "STATIC_SQL_VAR"
        elif _detect_safe_numeric_assignment(tokens, idx, safe_numeric_vars):
            signal = "SAFE_NUMERIC_VAR"
        else:
            # Pattern F: RHS starts with a call to a safe-returning helper
            # function, e.g. `safe_col, safe_dir = normalize_sort(...)` where
            # `normalize_sort` was identified as containing whitelist patterns
            # in its body. Propagates whitelist status across function calls.
            ji = idx + 1
            # Skip leading whitespace tokens (none here, but be safe)
            # Skip wrappers around RHS calls: `await helper(...)`, `this->helper(...)`.
            while ji < len(tokens) and tokens[ji] in ("await", "this", ".", "->"):
                ji += 1
            # Python/JavaScript instance calls: self.helper(...) / obj.helper(...)
            if ji + 2 < len(tokens) and tokens[ji] in ("self", "this") and tokens[ji + 1] in (".", "->"):
                ji += 2
            if ji < len(tokens) and is_identifier(tokens[ji]) and ji + 1 < len(tokens) and tokens[ji + 1] == "(":
                if tokens[ji] in safe_returning_funcs:
                    signal = "WHITELIST_VAR"
                elif tokens[ji] in numeric_returning_funcs:
                    signal = "SAFE_NUMERIC_VAR"
                elif tokens[ji] in db_returning_funcs:
                    signal = "DB_LOADED_VAR"
                elif _looks_like_allowlist_name(tokens[ji]) and any(
                    _looks_like_allowlist_name(tokens[p]) for p in lhs_positions
                ):
                    # Pragmatic helper-name propagation for idiomatic helpers
                    # like safeSort(), sortFor(), tableFor(), chooseMetric().
                    signal = "WHITELIST_VAR"
        if signal is None:
            continue
        # Mark ALL LHS positions and add ALL names to the appropriate set.
        # Emit signal at the FIRST (right-most in source) position so it
        # appears before the first VAR in the normalized stream.
        for pos in lhs_positions:
            name = tokens[pos]
            if signal == "SAFE_PLACEHOLDER_LIST":
                safe_placeholder_vars.add(name)
            elif signal == "SAFE_SQL_FRAGMENT_LIST":
                safe_fragment_vars.add(name)
            elif signal == "WHITELIST_VAR":
                whitelisted_vars.add(name)
            elif signal == "DB_LOADED_VAR":
                db_loaded_vars.add(name)
                db_loaded_var_pos[name] = idx
            elif signal == "SAFE_NUMERIC_VAR":
                safe_numeric_vars.add(name)
            elif signal == "STATIC_SQL_VAR":
                static_sql_vars.add(name)
        # Emit signal once, at the position of the first LHS var (left-most
        # in source = highest index in lhs_positions since we walked back).
        if signal not in {"SAFE_SQL_FRAGMENT_LIST", "STATIC_SQL_VAR"}:
            flow_signal_at_pos[max(lhs_positions)] = signal

    # ── Pre-scan: identify f-strings that interpolate ONLY whitelisted vars ──
    # f"... {safe_col} ..."  →  if safe_col ∈ whitelisted_vars → safe
    # f"... {sort_by} ..."   →  if sort_by ∉ whitelisted_vars → raw injection
    # Mark the position of each FSTRING_SQL token with extra context.
    # All "safe" var sets are treated equivalently for interpolation safety.
    # Validate SQL-fragment containers after all assignment facts are known.
    # DB-loaded vars are intentionally NOT safe for interpolation — they are
    # second-order taint if they later enter SQL text.
    provisional_safe_interp = whitelisted_vars | safe_placeholder_vars | safe_numeric_vars | safe_fragment_vars
    safe_fragment_vars = _validate_safe_sql_fragment_mutations(tokens, safe_fragment_vars, provisional_safe_interp)

    safe_interp_vars = whitelisted_vars | safe_placeholder_vars | safe_numeric_vars | safe_fragment_vars
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
        elif raw_left and (whitelisted_vars or safe_placeholder_vars or safe_numeric_vars or safe_fragment_vars):
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
                # numeric / safe SQL-fragment list). Treat this as a static SQL string —
                # the f-string brackets just hold safe values.
                raw_norm.append("SQL_STRING")
            elif _extract_interpolated_vars(token) & db_loaded_vars:
                # DB-loaded value embedded in a later SQL string: second-order
                # injection source. Do NOT treat DB_LOADED_VAR as safe.
                raw_norm.append("FSTRING_SQL")
                raw_norm.append("SECOND_ORDER_FLOW")
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
                            "sqlite", "cur", "cursor", "stmt", "pdo", "mysqli",
                        }:
                            should_classify = True
                    # await within 4 tokens behind
                    if not should_classify:
                        for j in range(max(0, i - 5), i):
                            if tokens[j] == "await":
                                should_classify = True
                                break

            if should_classify:
                signal = _classify_execute_call(tokens, i, static_sql_vars)
                if signal:
                    raw_norm.append(signal)
                ph, func_counter = get_or_create_placeholder(
                    token, func_map, func_counter, "FUNC", MAX_FUNC_TOKENS, "FUNC_OTHER"
                )
                func_name_by_placeholder[ph] = token
                raw_norm.append(ph)
                continue

            if after_dot and before_paren:
                ph, func_counter = get_or_create_placeholder(
                    token, func_map, func_counter, "FUNC", MAX_FUNC_TOKENS, "FUNC_OTHER"
                )
                func_name_by_placeholder[ph] = token
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
                func_name_by_placeholder[ph] = token
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

    db_loaded_placeholders: set[str] = set()
    for name in db_loaded_vars:
        if name in var_map:
            db_loaded_placeholders.add(var_map[name])
        if name in property_map:
            db_loaded_placeholders.add(property_map[name])

    def _is_safe_var(idx: int) -> bool:
        """Token at raw_norm[idx] is a safe-flagged VAR/PROPERTY placeholder."""
        if idx < 0 or idx >= len(raw_norm):
            return False
        return raw_norm[idx] in safe_var_placeholders

    def _is_db_loaded_var(idx: int) -> bool:
        """Token at raw_norm[idx] is a DB-loaded VAR/PROPERTY placeholder."""
        if idx < 0 or idx >= len(raw_norm):
            return False
        return raw_norm[idx] in db_loaded_placeholders

    def _append_concat_signal(var_idx: int | None = None) -> None:
        normalized.append("SQL_CONCAT")
        if var_idx is not None and _is_db_loaded_var(var_idx):
            normalized.append("SECOND_ORDER_FLOW")

    for i, tok in enumerate(raw_norm):
        normalized.append(tok)

        if tok in ("SQL_STRING", "FSTRING_SQL"):
            next_tok = raw_norm[i + 1] if i + 1 < len(raw_norm) else None
            next2    = raw_norm[i + 2] if i + 2 < len(raw_norm) else None

            # + concatenation:  SQL_STRING + ...
            if next_tok == "+":
                if next2 == "SQL_STRING":
                    pass  # static SQL literal split across lines
                elif not _is_safe_var(i + 2):
                    _append_concat_signal(i + 2)

            # % format injection:  SQL_STRING % VAR / SQL_STRING % (a, b)
            # Suppress only when the formatting values are all known-safe
            # numeric/whitelist/placeholder vars, e.g. safe LIMIT/OFFSET:
            #   "... LIMIT %d OFFSET %d" % (limit, offset)
            if next_tok == "%":
                safe_percent_tuple = False
                if next2 == "(":
                    depth = 1
                    j = i + 3
                    saw_value = False
                    all_values_safe = True
                    while j < len(raw_norm) and depth > 0:
                        tj = raw_norm[j]
                        if tj == "(":
                            depth += 1
                        elif tj == ")":
                            depth -= 1
                            if depth == 0:
                                break
                        elif depth >= 1:
                            if tj in {",", "NUMBER", "STRING", "SQL_STRING"}:
                                pass
                            elif tj.startswith("VAR") or tj.startswith("PROPERTY"):
                                saw_value = True
                                if tj not in safe_var_placeholders:
                                    all_values_safe = False
                                    break
                            elif tj in safe_var_placeholders:
                                saw_value = True
                            else:
                                # punctuation from indexing/calls is not proof of safety
                                if tj not in {"[", "]", ".", "+", "-", "*", "/", "%"}:
                                    all_values_safe = False
                                    break
                        j += 1
                    safe_percent_tuple = saw_value and all_values_safe
                if not safe_percent_tuple and not _is_safe_var(i + 2):
                    _append_concat_signal(i + 2)

            # .format() injection:  SQL_STRING . format(...)
            # Do not treat safe fragment-list joins such as PHP
            # `"WHERE " . implode(" AND ", $where)` as SQLi by default.
            if next_tok == "." and next2 is not None and next2.startswith("FUNC"):
                fname = func_name_by_placeholder.get(next2, "")
                if fname in {"format", "sprintf"}:
                    _append_concat_signal(None)

            # PHP dot concat:  SQL_STRING . VAR_n / SQL_STRING . PROPERTY_n / SQL_STRING . SQL_STRING
            if next_tok == "." and next2 is not None and (
                next2.startswith("VAR")
                or next2.startswith("PROPERTY")
                or next2 == "FSTRING_SQL"
            ):
                if not _is_safe_var(i + 2):
                    _append_concat_signal(i + 2)

        # Reverse: + SQL_STRING / % SQL_STRING / . SQL_STRING
        if tok in ("+", "%", "."):
            next_tok = raw_norm[i + 1] if i + 1 < len(raw_norm) else None
            if next_tok in ("SQL_STRING", "FSTRING_SQL"):
                # Static string literal split across concatenated strings, e.g.
                # Java: "SELECT ..." + "FROM ..." + "WHERE ...".  The
                # tokenizer may classify one side as STRING and the other as
                # SQL_STRING depending on which fragment contains SQL keywords.
                if next_tok == "SQL_STRING" and i > 0 and raw_norm[i - 1] in ("SQL_STRING", "STRING"):
                    continue

                # PHP safe fragment join:
                #   " WHERE " . implode(" AND ", $where) . " ORDER BY ..."
                # The dot after the function call has `)` immediately before
                # it, so look back to recover the function placeholder/name.
                if tok == "." and i > 0:
                    if raw_norm[i - 1].startswith("FUNC"):
                        continue
                    if raw_norm[i - 1] == ")":
                        depth = 1
                        j = i - 2
                        while j >= 0 and depth > 0:
                            if raw_norm[j] == ")":
                                depth += 1
                            elif raw_norm[j] == "(":
                                depth -= 1
                            j -= 1
                        func_ph = raw_norm[j] if j >= 0 and raw_norm[j].startswith("FUNC") else ""
                        if func_name_by_placeholder.get(func_ph, "") in {"implode", "join"}:
                            continue

                if i > 0 and _is_safe_var(i - 1):
                    continue
                _append_concat_signal(i - 1 if i > 0 else None)

    # ── Third pass: inject BOOLEAN_SINK once if any return-bool pattern found ─
    # Scanned over RAW tokens — not placeholders — because we need real
    # method names (`fetchone`, `bool`).
    if _detect_boolean_sink(tokens):
        normalized.append("BOOLEAN_SINK")

    if _detect_second_order_flow(tokens, db_loaded_var_pos):
        normalized.append("SECOND_ORDER_FLOW")

    return normalized
