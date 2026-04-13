SQL_KEYWORDS = {
    "select", "insert", "update", "delete", "drop", "union",
    "where", "from", "into", "values", "join", "or", "and"
}

LANGUAGE_KEYWORDS = {
    "def", "return", "if", "else", "for", "while", "class", "import",
    "function", "public", "private", "protected", "static", "void",
    "new", "try", "catch", "finally", "true", "false", "null"
}

BUILTIN_FUNCTIONS = {
    "input", "print", "len", "str", "int", "float"
}

INPUT_SOURCES = {
    "input", "request", "req", "params", "get", "post", "query"
}

DB_SINKS = {
    "execute", "query", "exec", "run", "raw", "cursor"
}

OUTPUT_SINKS = {
    "print", "echo", "console", "log"
}


def is_sql_string(content: str) -> bool:
    return any(word in content for word in SQL_KEYWORDS)


def is_input_source(name: str) -> bool:
    return any(keyword in name for keyword in [
        "input", "read", "fetch", "get", "param", "request"
    ])


def is_db_sink(name: str) -> bool:
    return any(keyword in name for keyword in [
        "query", "exec", "execute", "sql", "cursor"
    ])


def is_output_sink(name: str) -> bool:
    return any(keyword in name for keyword in [
        "print", "log", "echo", "write"
    ])


def normalize_tokens(tokens: list[str]) -> list[str]:
    normalized = []

    var_map = {}
    var_counter = 1

    i = 0
    while i < len(tokens):
        token = tokens[i]
        lower = token.lower()

        if token.startswith('"') or token.startswith("'"):
            content = token.strip("\"'").lower()
            if is_sql_string(content):
                normalized.append("SQL_STRING")
            else:
                normalized.append("STRING")

        elif token.replace(".", "", 1).isdigit():
            normalized.append("NUMBER")

        elif lower in SQL_KEYWORDS:
            normalized.append(f"SQL_{lower.upper()}")

        elif lower in LANGUAGE_KEYWORDS:
            normalized.append(lower)

        elif (
            i + 1 < len(tokens)
            and tokens[i + 1] == "("
            and token.isidentifier()
        ):
            name = lower

            if name in INPUT_SOURCES or is_input_source(name):
                normalized.append("INPUT_SOURCE")

            elif name in DB_SINKS or is_db_sink(name):
                normalized.append("DB_SINK")

            elif name in OUTPUT_SINKS or is_output_sink(name):
                normalized.append("OUTPUT_SINK")

            elif name in BUILTIN_FUNCTIONS:
                normalized.append(f"FUNC_{name.upper()}")

            else:
                normalized.append("FUNC_CALL")

        elif token.isidentifier():
            if token not in var_map:
                var_map[token] = f"VAR_{var_counter}"
                var_counter += 1

            normalized.append(var_map[token])

        else:
            normalized.append(token)

        i += 1

    return normalized