import argparse
import shutil
import subprocess
from pathlib import Path


def discover_zip_suites(suite_dir: Path) -> list[Path]:
    """
    Finds only .zip files inside the suite directory.
    Example:
    backend/test_suites/*.zip
    """
    if not suite_dir.exists():
        raise FileNotFoundError(f"Suite directory not found: {suite_dir}")

    if not suite_dir.is_dir():
        raise NotADirectoryError(f"Suite path is not a directory: {suite_dir}")

    zip_files = sorted(suite_dir.glob("*.zip"))

    if not zip_files:
        raise FileNotFoundError(f"No .zip suite files found in: {suite_dir}")

    return zip_files


def suite_name_from_path(suite_path: Path) -> str:
    """
    Example:
    test_suites/mega_sqli_debug_suite.zip
    -> mega_sqli_debug_suite
    """
    return suite_path.stem


def save_named_results(suite_name: str, output_dir: Path) -> bool:
    """
    Existing runner writes:
    outputs/sqli_test_results/test_results.md
    outputs/sqli_test_results/test_results.csv

    This saves copies in the SAME directory as:
    outputs/sqli_test_results/<suite_name>_test_results.md
    outputs/sqli_test_results/<suite_name>_test_results.csv

    Running the same suite again overwrites only that suite's named files.

    Returns True if at least the Markdown results file was saved.
    """
    source_md = output_dir / "test_results.md"
    source_csv = output_dir / "test_results.csv"

    target_md = output_dir / f"{suite_name}_test_results.md"
    target_csv = output_dir / f"{suite_name}_test_results.csv"

    if not source_md.exists():
        print(f"WARNING: Missing result file: {source_md}")
        return False

    shutil.copy2(source_md, target_md)
    print(f"Saved: {target_md}")

    if source_csv.exists():
        shutil.copy2(source_csv, target_csv)
        print(f"Saved: {target_csv}")
    else:
        print(f"WARNING: Missing CSV result file: {source_csv}")

    return True


def run_suite(
    suite_path: Path,
    email: str,
    password: str,
    python_cmd: str,
    output_dir: Path,
) -> dict:
    suite_name = suite_name_from_path(suite_path)

    print()
    print("=" * 80)
    print(f"Running suite: {suite_name}")
    print(f"Suite file: {suite_path}")
    print("=" * 80)

    cmd = [
        python_cmd,
        "scripts/run_sqli_test_suite.py",
        "--suite",
        str(suite_path),
        "--email",
        email,
        "--password",
        password,
    ]

    result = subprocess.run(cmd)

    # Important:
    # The original runner may return exit code 1 when tests fail.
    # That is NOT a reason to stop this wrapper.
    # We still save the result files and continue to the next ZIP suite.
    saved = save_named_results(suite_name, output_dir)

    if result.returncode == 0:
        status = "PASS_OR_NO_RUNNER_ERROR"
        print(f"Suite finished with exit code 0: {suite_name}")
    else:
        status = "TEST_FAILURES_OR_RUNNER_NONZERO_EXIT"
        print(
            f"Suite returned non-zero exit code {result.returncode}: {suite_name}. "
            "Results were still saved if result files existed."
        )

    return {
        "suite_name": suite_name,
        "suite_path": str(suite_path),
        "exit_code": result.returncode,
        "results_saved": saved,
        "status": status,
    }


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Run SQLi ZIP suites from test_suites and save named result files "
            "in the same output folder. The script continues even when a suite "
            "has failing tests."
        )
    )

    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)

    parser.add_argument(
        "--suite-dir",
        default="test_suites",
        help="Folder containing suite .zip files. Default: test_suites",
    )

    parser.add_argument(
        "--output-dir",
        default="outputs/sqli_test_results",
        help="Folder where the existing runner writes test_results.md/csv.",
    )

    parser.add_argument(
        "--python-cmd",
        default="py",
        help="Python command. On Windows usually: py",
    )

    parser.add_argument(
        "--suites",
        nargs="*",
        default=None,
        help=(
            "Optional specific .zip suite names to run. "
            "If omitted, the script runs all .zip files inside --suite-dir."
        ),
    )

    args = parser.parse_args()

    suite_dir = Path(args.suite_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.suites:
        suite_paths: list[Path] = []

        for suite in args.suites:
            suite_path = Path(suite)

            if suite_path.suffix.lower() != ".zip":
                print(f"Skipping non-zip suite argument: {suite_path}")
                continue

            if not suite_path.is_absolute() and suite_path.parent == Path("."):
                suite_path = suite_dir / suite_path

            if not suite_path.exists():
                raise FileNotFoundError(f"Suite not found: {suite_path}")

            suite_paths.append(suite_path)

        if not suite_paths:
            raise FileNotFoundError("No valid .zip suites were provided.")
    else:
        suite_paths = discover_zip_suites(suite_dir)

    print()
    print("=" * 80)
    print("SQLi suite runner")
    print(f"Suite directory: {suite_dir}")
    print("ZIP suites to run:")
    for suite_path in suite_paths:
        print(f"- {suite_path.name}")
    print("=" * 80)

    summaries = []

    for suite_path in suite_paths:
        try:
            summary = run_suite(
                suite_path=suite_path,
                email=args.email,
                password=args.password,
                python_cmd=args.python_cmd,
                output_dir=output_dir,
            )
            summaries.append(summary)
        except Exception as exc:
            suite_name = suite_name_from_path(suite_path)
            print()
            print(f"ERROR while running suite {suite_name}: {exc}")
            summaries.append(
                {
                    "suite_name": suite_name,
                    "suite_path": str(suite_path),
                    "exit_code": None,
                    "results_saved": False,
                    "status": f"WRAPPER_ERROR: {exc}",
                }
            )

    print()
    print("=" * 80)
    print("All requested ZIP suites finished.")
    print("Named results are in:")
    print(output_dir)
    print()
    print("Summary:")
    for item in summaries:
        print(
            f"- {item['suite_name']}: "
            f"exit_code={item['exit_code']}, "
            f"results_saved={item['results_saved']}, "
            f"status={item['status']}"
        )
    print("=" * 80)

    # Exit code behavior:
    # Return 0 because this wrapper's job is to run all suites and save outputs.
    # The actual pass/fail status is inside the named result files.
    raise SystemExit(0)


if __name__ == "__main__":
    main()
