ALLOWED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".php": "php",
    ".java": "java",
}


LANGUAGE_KEYWORDS = {
    "def", "return", "if", "else", "elif", "for", "while", "try", "except",
    "finally", "class", "import", "from", "with", "as", "pass", "break",
    "continue", "lambda", "true", "false", "null", "none", "new", "public",
    "private", "protected", "static", "void", "function",
}


SQL_PATTERNS = [
    ("select", "from"),
    ("insert", "into"),
    ("update", "set"),
    ("delete", "from"),
    ("drop", "table"),
    ("create", "table"),
    ("alter", "table"),
]


SQL_FRAGMENT_KEYWORDS = {
    "where",
    "order by",
    "group by",
    "limit",
    "values",
    "having",
    "join",
}

# Used by _contains_sql for fragment detection. Each entry is a list of
# tokens that must ALL be present in the candidate string for it to count
# as a SQL fragment. Two-feature requirement avoids false positives like
# the string "Please log in and try again" (which contains "and" but
# nothing else SQL-like).
SQL_FRAGMENT_COMBOS = [
    [" and ", "="],
    [" and ", " like "],
    [" and ", " in ("],
    [" and ", " is null"],
    [" and ", " is not null"],
    [" or ",  "="],
    [" or ",  " like "],
    [" or ",  " in ("],
    [" or ",  " is null"],
    [" like ", "%"],
    [" like ", "?"],
    [" between ", " and "],
    [" exists ", "select"],
    [" in (", "select"],
    ["lower(", "="],
    ["lower(", " like "],
    ["upper(", "="],
    ["upper(", " like "],
    ["coalesce(", "="],
    ["coalesce(", " like "],
]


MAX_VAR_TOKENS = 48
MAX_FUNC_TOKENS = 32
MAX_PROPERTY_TOKENS = 24
MAX_SEQUENCE_LENGTH = 2048
