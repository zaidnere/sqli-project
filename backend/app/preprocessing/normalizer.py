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
  UNSAFE_EXEC   — execute(single_var) with no parameter tuple (vulnerable)
  SAFE_EXEC     — execute(var, params_tuple) (parameterized, safe)
  SQL_CONCAT    — SQL_STRING followed by + operator (dangerous concatenation)

These signals give the CNN+BiLSTM strong local features to learn from.
"""

from app.core.constants import (
    LANGUAGE_KEYWORDS,
    SQL_PATTERNS,
    SQL_FRAGMENT_KEYWORDS,
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
    """True for plain string literals (not f-strings)."""
    return (
        len(token) >= 2
        and (
            (token[0] == '"' and token[-1] == '"')
            or (token[0] == "'" and token[-1] == "'")
        )
    )


def is_fstring(token: str) -> bool:
    """True for f-string tokens (captured as f"..." or f'...' by tokenizer)."""
    return len(token) >= 3 and token[0].lower() == 'f' and token[1] in ('"', "'")


def _contains_sql(content: str) -> bool:
    """Check if a string body contains SQL keywords."""
    normalized = " ".join(content.lower().split())
    for first, second in SQL_PATTERNS:
        if first in normalized and second in normalized:
            return True
    for fragment in SQL_FRAGMENT_KEYWORDS:
        if fragment in normalized:
            return True
    return False


def is_sql_string(token: str) -> bool:
    """Plain string literal that contains SQL."""
    if not is_string_literal(token):
        return False
    return _contains_sql(token[1:-1])


def is_fstring_sql(token: str) -> bool:
    """F-string that contains SQL — this is a dangerous interpolation pattern."""
    if not is_fstring(token):
        return False
    # Strip f prefix and outer quotes
    body = token[1:]   # remove leading f/F
    if len(body) < 2:
        return False
    inner = body[1:-1]  # strip outer quotes
    return _contains_sql(inner)


def is_identifier(token: str) -> bool:
    return token.isidentifier()


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
      UNSAFE_EXEC  — only one argument (no parameter tuple)
      SAFE_EXEC    — has a second argument (parameterized)
      None         — cannot determine

    Called when tokens[exec_idx] == 'execute' and tokens[exec_idx+1] == '('
    """
    if exec_idx + 1 >= len(tokens) or tokens[exec_idx + 1] != '(':
        return None

    # Scan for matching closing paren, counting commas at depth 1
    depth = 0
    commas_at_depth1 = 0
    i = exec_idx + 1
    while i < len(tokens):
        t = tokens[i]
        if t in ('(', '[', '{'):
            depth += 1
        elif t in (')', ']', '}'):
            depth -= 1
            if depth == 0:
                break
        elif t == ',' and depth == 1:
            commas_at_depth1 += 1
        i += 1

    # If there's at least one comma inside execute(…), it's parameterized
    if commas_at_depth1 >= 1:
        return 'SAFE_EXEC'
    return 'UNSAFE_EXEC'


# ── Main normalizer ───────────────────────────────────────────────────────────

def normalize_tokens(tokens: list[str]) -> list[str]:
    """
    Normalize a token list into a semantic sequence.
    Injects UNSAFE_EXEC, SAFE_EXEC, SQL_CONCAT signals where detected.
    """
    normalized: list[str] = []

    var_map: dict[str, str] = {}
    func_map: dict[str, str] = {}
    property_map: dict[str, str] = {}

    var_counter = 0
    func_counter = 0
    property_counter = 0

    # First pass: build normalized sequence
    raw_norm: list[str] = []

    for i, token in enumerate(tokens):
        lower = token.lower()

        # ── Language keywords ──────────────────────────────────────────────
        if lower in LANGUAGE_KEYWORDS:
            raw_norm.append(lower)
            continue

        # ── F-string SQL (dangerous: interpolated variables in SQL) ────────
        if is_fstring_sql(token):
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

            # Check for execute() pattern — inject semantic signal
            if token == "execute" and before_paren:
                signal = _classify_execute_call(tokens, i)
                # Add the signal BEFORE the FUNC placeholder
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
    #   SQL_STRING + VAR          → concatenation injection        (+)
    #   VAR + SQL_STRING          → concatenation injection        (+)
    #   SQL_STRING % VAR          → % format injection             (%)
    #   SQL_STRING . FUNC ( VAR ) → .format() injection            (. FUNC)
    #   FSTRING_SQL (any context) → f-string injection             (already flagged)
    #
    # All of these produce SQL_CONCAT so the hard-override rule fires.
    for i, tok in enumerate(raw_norm):
        normalized.append(tok)

        if tok in ("SQL_STRING", "FSTRING_SQL"):
            next_tok = raw_norm[i + 1] if i + 1 < len(raw_norm) else None
            next2    = raw_norm[i + 2] if i + 2 < len(raw_norm) else None

            # + concatenation:  SQL_STRING + ...
            if next_tok == "+":
                normalized.append("SQL_CONCAT")

            # % format injection:  SQL_STRING % VAR
            if next_tok == "%":
                normalized.append("SQL_CONCAT")

            # .format() injection:  SQL_STRING . FUNC_n ( ...
            if next_tok == "." and next2 is not None and next2.startswith("FUNC"):
                normalized.append("SQL_CONCAT")

        # Reverse: + SQL_STRING or % SQL_STRING
        if tok in ("+", "%"):
            next_tok = raw_norm[i + 1] if i + 1 < len(raw_norm) else None
            if next_tok in ("SQL_STRING", "FSTRING_SQL"):
                normalized.append("SQL_CONCAT")

    return normalized
