import re


TOKEN_PATTERN = r"""
    [A-Za-z_][A-Za-z0-9_]*     |  # identifiers / keywords
    \d+\.\d+                   |  # float
    \d+                        |  # int
    "(?:\\.|[^"])*"            |  # double quoted string
    '(?:\\.|[^'])*'            |  # single quoted string
    ==|!=|<=|>=|\+\+|--|\|\||&&|->|=> |
    [{}()\[\];,.:=+\-*/%<>!]
"""


def tokenize_code(code: str) -> list[str]:
    tokens = re.findall(TOKEN_PATTERN, code, flags=re.VERBOSE)
    return tokens