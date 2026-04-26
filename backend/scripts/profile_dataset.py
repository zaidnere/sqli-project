from pathlib import Path
from statistics import mean, median

from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.core.constants import LANGUAGE_KEYWORDS


DATASET_DIR = Path("../../datasets/juliet_java_cwe89")

def is_identifier(token: str) -> bool:
    return token.isidentifier()


def percentile(values: list[int], p: float) -> int:
    if not values:
        return 0

    values = sorted(values)
    index = int((len(values) - 1) * p)
    return values[index]


def classify_identifiers(tokens: list[str]) -> tuple[int, int, int]:
    vars_seen = set()
    funcs_seen = set()
    props_seen = set()

    for i, token in enumerate(tokens):
        lower = token.lower()

        if lower in LANGUAGE_KEYWORDS:
            continue

        if not is_identifier(token):
            continue

        prev_token = tokens[i - 1] if i > 0 else None
        next_token = tokens[i + 1] if i < len(tokens) - 1 else None

        is_after_dot = prev_token == "."
        is_before_open_paren = next_token == "("

        if is_after_dot and is_before_open_paren:
            funcs_seen.add(token)
        elif is_after_dot and not is_before_open_paren:
            props_seen.add(token)
        elif is_before_open_paren:
            funcs_seen.add(token)
        else:
            vars_seen.add(token)

    return len(vars_seen), len(funcs_seen), len(props_seen)


def profile_file(file_path: Path) -> dict:
    raw_code = file_path.read_text(encoding="utf-8", errors="ignore")
    cleaned = clean_code(raw_code)
    tokens = tokenize_code(cleaned)

    var_count, func_count, prop_count = classify_identifiers(tokens)

    return {
        "file": str(file_path),
        "vars": var_count,
        "funcs": func_count,
        "props": prop_count,
        "sequence_length": len(tokens),
    }


def summarize(results: list[dict]) -> None:
    vars_list = [r["vars"] for r in results]
    funcs_list = [r["funcs"] for r in results]
    props_list = [r["props"] for r in results]
    seq_list = [r["sequence_length"] for r in results]

    def print_stats(title: str, values: list[int]) -> None:
        print(f"\n{title}")
        print(f"  files: {len(values)}")
        print(f"  mean: {mean(values):.2f}")
        print(f"  median: {median(values):.2f}")
        print(f"  p90: {percentile(values, 0.90)}")
        print(f"  p95: {percentile(values, 0.95)}")
        print(f"  max: {max(values)}")

    print_stats("VARIABLE COUNTS", vars_list)
    print_stats("FUNCTION COUNTS", funcs_list)
    print_stats("PROPERTY COUNTS", props_list)
    print_stats("SEQUENCE LENGTHS", seq_list)


def main():
    if not DATASET_DIR.exists():
        print(f"Dataset folder not found: {DATASET_DIR.resolve()}")
        return

    files = list(DATASET_DIR.rglob("*.java"))

    if not files:
        print("No .java files found.")
        return

    print(f"Found {len(files)} Java files")

    results = []
    for file_path in files:
        try:
            results.append(profile_file(file_path))
        except Exception as exc:
            print(f"Failed on {file_path}: {exc}")

    summarize(results)


if __name__ == "__main__":
    main()