import re


def remove_block_comments(code: str) -> str:
    return re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)


def clean_code(raw_code: str) -> str:
    code = remove_block_comments(raw_code)

    cleaned_lines = []

    for line in code.splitlines():
        stripped = line.strip()

        if not stripped:
            continue

        if stripped.startswith("#"):
            continue

        if stripped.startswith("//"):
            continue

        cleaned_lines.append(line.rstrip())

    return "\n".join(cleaned_lines)