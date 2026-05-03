import re

# ──────────────────────────────────────────────────────────────────────────────
# Tokenizer regex — order matters, longer patterns first
# ──────────────────────────────────────────────────────────────────────────────
TOKEN_REGEX = re.compile(
    r'''
    # ── F-strings (must come BEFORE plain strings) ───────────────────────────
    # Triple-quoted f-strings
    f\"\"\"[\s\S]*?\"\"\"                   |
    f\'\'\'[\s\S]*?\'\'\'                   |
    # Single-quoted f-strings
    f\"(?:\\.|[^\"\\])*\"                   |
    f\'(?:\\.|[^\'\\])*\'                   |

    # ── JavaScript template literals (backtick strings) ─────────────────────
    # Capture entire template literal as single token. The normalizer treats
    # this analogously to a Python f-string: if it contains ${...} AND SQL
    # keywords, it gets tagged FSTRING_SQL.
    \`(?:\\.|[^\`\\])*\`                    |

    # ── Triple-quoted plain strings ───────────────────────────────────────────
    \"\"\"[\s\S]*?\"\"\"                    |
    \'\'\'[\s\S]*?\'\'\'                    |

    # ── Plain strings ─────────────────────────────────────────────────────────
    \"(?:\\.|[^\"\\])*\"                    |
    \'(?:\\.|[^\'\\])*\'                    |

    # ── Numbers ───────────────────────────────────────────────────────────────
    \b\d+(?:\.\d+)?\b                       |

    # ── Identifiers / keywords ────────────────────────────────────────────────
    [A-Za-z_][A-Za-z0-9_]*                 |

    # ── Multi-char operators ──────────────────────────────────────────────────
    ==|!=|<=|>=|->|=>|\+\+|--|\?\?         |

    # ── Single-char operators and punctuation ─────────────────────────────────
    [=+\-*/%<>!.,:;?(){}\[\]]
    ''',
    re.VERBOSE,
)


def tokenize_code(cleaned_code: str) -> list[str]:
    """
    Tokenize source code into a list of string tokens.

    F-strings (f"..." / f'...') are returned as a single token including
    the f prefix so the normalizer can detect them as interpolated strings.
    """
    return TOKEN_REGEX.findall(cleaned_code)
