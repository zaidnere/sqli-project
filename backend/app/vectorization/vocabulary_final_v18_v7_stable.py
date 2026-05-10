import json
from pathlib import Path

from app.core.constants import (
    LANGUAGE_KEYWORDS,
    MAX_VAR_TOKENS,
    MAX_FUNC_TOKENS,
    MAX_PROPERTY_TOKENS,
)

PAD_TOKEN = "PAD"
UNK_TOKEN = "UNK"

STRING_TOKEN = "STRING"
SQL_STRING_TOKEN = "SQL_STRING"
FSTRING_SQL_TOKEN = "FSTRING_SQL"   # NEW
NUMBER_TOKEN = "NUMBER"

# Semantic signal tokens (injected by normalizer)
UNSAFE_EXEC_TOKEN = "UNSAFE_EXEC"  # execute(var)         — no params tuple
SAFE_EXEC_TOKEN   = "SAFE_EXEC"    # execute(var, params) — parameterized
SQL_CONCAT_TOKEN  = "SQL_CONCAT"   # SQL_STRING + VAR or FSTRING_SQL + VAR

# Data-flow signal tokens (Gap-A v2: distinguish attack types semantically)
WHITELIST_VAR_TOKEN     = "WHITELIST_VAR"      # var = X if X in ALLOWED_X else default
DB_LOADED_VAR_TOKEN     = "DB_LOADED_VAR"      # var = cursor.fetchone()/.fetchall()/...
BOOLEAN_SINK_TOKEN      = "BOOLEAN_SINK"       # function returns boolean of fetch result
FSTRING_SQL_RAW_TOKEN   = "FSTRING_SQL_RAW"    # f-string interpolates RAW (non-validated) var
SAFE_PLACEHOLDER_LIST_TOKEN = "SAFE_PLACEHOLDER_LIST"  # placeholders="?,?,?" + execute(sql, vals)
SAFE_NUMERIC_VAR_TOKEN  = "SAFE_NUMERIC_VAR"   # var derived from int(x)/min/max/arithmetic
SECOND_ORDER_FLOW_TOKEN = "SECOND_ORDER_FLOW"  # stored/config/db-loaded SQL fragment reaches SQL syntax
STORED_SQL_FRAGMENT_TOKEN = "STORED_SQL_FRAGMENT"  # variable/property holds SQL syntax loaded from DB/config/cache
SQL_FRAGMENT_TO_SYNTAX_TOKEN = "SQL_FRAGMENT_TO_SYNTAX"  # stored fragment is interpolated/concatenated into SQL
SAVED_SEGMENT_TOKEN = "SAVED_SEGMENT"  # saved segment/filter object used as SQL fragment source

VAR_OTHER_TOKEN      = "VAR_OTHER"
FUNC_OTHER_TOKEN     = "FUNC_OTHER"
PROPERTY_OTHER_TOKEN = "PROPERTY_OTHER"

PUNCTUATION_AND_OPERATORS = [
    "=", "+", "-", "*", "/", "%", ".", ",", ":", ";",
    "(", ")", "{", "}", "[", "]", "<", ">", "!",
    "==", "!=", "<=", ">=", "->", "=>", "++", "--", "?", "??", "|", "&", "||", "&&",
]


def build_fixed_vocabulary() -> dict[str, int]:
    tokens: list[str] = []

    # Special tokens
    tokens.extend([PAD_TOKEN, UNK_TOKEN])

    # Placeholders
    for i in range(MAX_VAR_TOKENS):
        tokens.append(f"VAR_{i}")
    tokens.append(VAR_OTHER_TOKEN)

    for i in range(MAX_FUNC_TOKENS):
        tokens.append(f"FUNC_{i}")
    tokens.append(FUNC_OTHER_TOKEN)

    for i in range(MAX_PROPERTY_TOKENS):
        tokens.append(f"PROPERTY_{i}")
    tokens.append(PROPERTY_OTHER_TOKEN)

    # String tokens
    tokens.extend([STRING_TOKEN, SQL_STRING_TOKEN, FSTRING_SQL_TOKEN, NUMBER_TOKEN])

    # Semantic signal tokens
    tokens.extend([UNSAFE_EXEC_TOKEN, SAFE_EXEC_TOKEN, SQL_CONCAT_TOKEN])

    # Data-flow signal tokens (Gap-A v2)
    tokens.extend([WHITELIST_VAR_TOKEN, DB_LOADED_VAR_TOKEN, BOOLEAN_SINK_TOKEN])
    tokens.extend([FSTRING_SQL_RAW_TOKEN, SAFE_PLACEHOLDER_LIST_TOKEN, SAFE_NUMERIC_VAR_TOKEN])
    tokens.extend([SECOND_ORDER_FLOW_TOKEN, STORED_SQL_FRAGMENT_TOKEN, SQL_FRAGMENT_TO_SYNTAX_TOKEN, SAVED_SEGMENT_TOKEN])

    # Keywords
    tokens.extend(sorted(LANGUAGE_KEYWORDS))

    # Operators
    tokens.extend(PUNCTUATION_AND_OPERATORS)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for t in tokens:
        if t not in seen:
            unique.append(t)
            seen.add(t)

    return {token: idx for idx, token in enumerate(unique)}


def save_vocabulary(vocabulary: dict[str, int], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(vocabulary, f, ensure_ascii=False, indent=2)


def load_vocabulary(path: str) -> dict[str, int]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
