import re


def clean_code(raw_code: str) -> str:
    code = raw_code

    # remove multiline comments: /* ... */
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)

    # remove python triple quotes
    code = re.sub(r"'''[\s\S]*?'''", "", code)
    code = re.sub(r'"""[\s\S]*?"""', "", code)

    # remove single-line comments
    code = re.sub(r"#.*", "", code)
    code = re.sub(r"//.*", "", code)

    # strip trailing spaces per line
    lines = [line.rstrip() for line in code.splitlines()]

    # remove empty lines
    lines = [line for line in lines if line.strip()]

    return "\n".join(lines).strip()