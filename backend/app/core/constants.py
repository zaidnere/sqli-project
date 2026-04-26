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


MAX_VAR_TOKENS = 48
MAX_FUNC_TOKENS = 32
MAX_PROPERTY_TOKENS = 24
MAX_SEQUENCE_LENGTH = 2048
