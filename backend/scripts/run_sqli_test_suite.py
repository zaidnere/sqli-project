#!/usr/bin/env python3
"""
run_sqli_test_suite.py

Automatic test runner for the SQLi detector backend.

What it does:
1. Reads a test suite folder or ZIP.
2. Reads manifest.csv / manifest.json with expected results.
3. Uploads every code file to POST /api/scans/upload-and-scan.
4. Compares actual verdict/type against expected verdict/type.
5. Writes:
   - test_results.csv
   - test_results.md

Recommended location:
    backend/scripts/run_sqli_test_suite.py

Example:
    python scripts/run_sqli_test_suite.py ^
      --suite test_suites/flow_tokens_model_retest ^
      --base-url http://127.0.0.1:8000 ^
      --email test@example.com ^
      --password 123456

You can also pass a token directly:
    python scripts/run_sqli_test_suite.py --suite test_suites/flow_tokens_model_retest --token YOUR_JWT_TOKEN
"""

from __future__ import annotations

import argparse
import csv
import json
import mimetypes
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print("Missing dependency: requests")
    print("Install it with: pip install requests")
    sys.exit(1)


DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_SCAN_ENDPOINT = "/api/scans/upload-and-scan"
DEFAULT_LOGIN_ENDPOINT = "/api/user/login"


SUPPORTED_CODE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".java",
    ".php",
    ".cs",
    ".cpp",
    ".c",
}


@dataclass
class ExpectedCase:
    file: str
    expected_verdict: str
    expected_type: str
    notes: str = ""


@dataclass
class ActualResult:
    ok_http: bool
    status_code: int
    raw_error: str
    actual_verdict: str
    actual_type: str
    risk_score: Optional[float]
    patterns: str
    explanation: str
    scan_id: str


def normalize_verdict(value: Any) -> str:
    if value is None:
        return "UNKNOWN"

    text = str(value).strip().upper()
    text = text.replace("-", "_").replace(" ", "_")

    aliases = {
        "SAFE": "SAFE",
        "בטוח": "SAFE",
        "VULN": "VULNERABLE",
        "VULNERABLE": "VULNERABLE",
        "פגיע": "VULNERABLE",
        "DANGEROUS": "VULNERABLE",
        "SUSPICIOUS": "SUSPICIOUS",
        "חשוד": "SUSPICIOUS",
    }
    return aliases.get(text, text)


def normalize_type(value: Any) -> str:
    if value is None:
        return "NONE"

    text = str(value).strip().upper()
    text = text.replace("-", "_").replace(" ", "_")

    aliases = {
        "": "NONE",
        "NULL": "NONE",
        "NONE": "NONE",
        "SAFE": "NONE",
        "NO_SQLI": "NONE",
        "INBAND": "IN_BAND",
        "IN_BAND": "IN_BAND",
        "IN-BAND": "IN_BAND",
        "IN BAND": "IN_BAND",
        "BLIND": "BLIND",
        "SECONDORDER": "SECOND_ORDER",
        "SECOND_ORDER": "SECOND_ORDER",
        "SECOND-ORDER": "SECOND_ORDER",
        "SECOND ORDER": "SECOND_ORDER",
        "SQL_INJECTION": "SQL_INJECTION",
        "SQLI": "SQL_INJECTION",
    }
    return aliases.get(text, text)


def get_nested(data: Dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = data
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


GENERIC_TYPE_VALUES = {
    "SQL_INJECTION",
    "SQLI",
    "VULNERABILITY",
    "VULNERABLE",
    "DANGEROUS",
}


PRECISE_TYPE_KEYS = (
    "attackType",
    "attack_type",
    "sqlInjectionType",
    "sql_injection_type",
    "sqliType",
    "sqli_type",
    "injectionType",
    "injection_type",
    "classificationType",
    "classification_type",
    "subtype",
    "subType",
    "attackSubtype",
    "attack_subtype",
)


GENERIC_TYPE_KEYS = (
    "vulnerabilityType",
    "vulnerability_type",
    "type",
)


def recursive_find_key(data: Any, key_names: tuple[str, ...]) -> Optional[Any]:
    """Find the first value for any key name in a nested JSON object."""
    if isinstance(data, dict):
        for key in key_names:
            if key in data and data[key] not in (None, ""):
                return data[key]
        for value in data.values():
            found = recursive_find_key(value, key_names)
            if found not in (None, ""):
                return found
    elif isinstance(data, list):
        for item in data:
            found = recursive_find_key(item, key_names)
            if found not in (None, ""):
                return found
    return None


def is_generic_attack_type(value: Any) -> bool:
    return normalize_type(value) in GENERIC_TYPE_VALUES


def extract_precise_attack_type(data: Dict[str, Any], detection: Dict[str, Any]) -> Any:
    """
    Prefer precise SQLi attack type fields over generic vulnerabilityType.

    Old bug:
        The script read detection.vulnerabilityType first.
        Backend often returns vulnerabilityType = SQL_INJECTION,
        while the precise type is stored elsewhere as attackType/sqlInjectionType.
        That made the report show VULNERABLE / SQL_INJECTION instead of
        VULNERABLE / IN_BAND, BLIND, or SECOND_ORDER.
    """
    # 1. Check common precise keys directly in detection and root.
    for container in (detection, data):
        if isinstance(container, dict):
            for key in PRECISE_TYPE_KEYS:
                value = container.get(key)
                if value not in (None, "") and not is_generic_attack_type(value):
                    return value

    # 2. Recursively search precise keys anywhere in the response.
    value = recursive_find_key(data, PRECISE_TYPE_KEYS)
    if value not in (None, "") and not is_generic_attack_type(value):
        return value

    # 3. Fallback to generic keys only if no precise type exists.
    for container in (detection, data):
        if isinstance(container, dict):
            for key in GENERIC_TYPE_KEYS:
                value = container.get(key)
                if value not in (None, ""):
                    return value

    value = recursive_find_key(data, GENERIC_TYPE_KEYS)
    if value not in (None, ""):
        return value

    return None


def extract_actual_result(response: requests.Response) -> ActualResult:
    status_code = response.status_code

    try:
        data = response.json()
    except Exception:
        return ActualResult(
            ok_http=False,
            status_code=status_code,
            raw_error=response.text[:1000],
            actual_verdict="ERROR",
            actual_type="ERROR",
            risk_score=None,
            patterns="",
            explanation="",
            scan_id="",
        )

    if not response.ok:
        return ActualResult(
            ok_http=False,
            status_code=status_code,
            raw_error=json.dumps(data, ensure_ascii=False)[:1500],
            actual_verdict="ERROR",
            actual_type="ERROR",
            risk_score=None,
            patterns="",
            explanation="",
            scan_id=str(data.get("scanId", "")),
        )

    detection = data.get("detection", {}) if isinstance(data, dict) else {}

    actual_verdict = (
        detection.get("label")
        or detection.get("verdict")
        or data.get("label")
        or data.get("verdict")
        or "UNKNOWN"
    )

    actual_type = extract_precise_attack_type(data, detection)

    risk_score = (
        detection.get("riskScore")
        or detection.get("score")
        or data.get("riskScore")
        or data.get("score")
    )
    try:
        risk_score = float(risk_score) if risk_score is not None else None
    except Exception:
        risk_score = None

    raw_patterns = detection.get("suspiciousPatterns") or data.get("suspiciousPatterns") or []
    pattern_names: List[str] = []
    if isinstance(raw_patterns, list):
        for item in raw_patterns:
            if isinstance(item, dict):
                pattern_names.append(str(item.get("pattern") or item.get("name") or item))
            else:
                pattern_names.append(str(item))
    else:
        pattern_names.append(str(raw_patterns))

    explanation = str(detection.get("explanation") or data.get("explanation") or "")

    return ActualResult(
        ok_http=True,
        status_code=status_code,
        raw_error="",
        actual_verdict=normalize_verdict(actual_verdict),
        actual_type=normalize_type(actual_type),
        risk_score=risk_score,
        patterns=" | ".join(pattern_names),
        explanation=explanation.replace("\n", " ").strip(),
        scan_id=str(data.get("scanId", "")),
    )


def load_suite_path(suite_path: Path) -> Tuple[Path, Optional[tempfile.TemporaryDirectory]]:
    if suite_path.is_dir():
        return suite_path, None

    if suite_path.is_file() and suite_path.suffix.lower() == ".zip":
        tmp = tempfile.TemporaryDirectory(prefix="sqli_suite_")
        with zipfile.ZipFile(suite_path, "r") as zf:
            zf.extractall(tmp.name)

        root = Path(tmp.name)

        # If ZIP contains one root folder, use it.
        children = [p for p in root.iterdir()]
        dirs = [p for p in children if p.is_dir()]
        files = [p for p in children if p.is_file()]
        if len(dirs) == 1 and not any(f.name.startswith("manifest.") for f in files):
            return dirs[0], tmp

        return root, tmp

    raise FileNotFoundError(f"Suite path does not exist or is not a folder/zip: {suite_path}")


def load_manifest(suite_dir: Path) -> List[ExpectedCase]:
    csv_path = suite_dir / "manifest.csv"
    json_path = suite_dir / "manifest.json"

    cases: List[ExpectedCase] = []

    if csv_path.exists():
        with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cases.append(
                    ExpectedCase(
                        file=row.get("file", "").strip(),
                        expected_verdict=normalize_verdict(row.get("expected_verdict", "")),
                        expected_type=normalize_type(row.get("expected_type", "NONE")),
                        notes=row.get("notes", "").strip(),
                    )
                )
        return [c for c in cases if c.file]

    if json_path.exists():
        raw = json.loads(json_path.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and "expected_results" in raw:
            for file_name, expected in raw["expected_results"].items():
                # Supports older expected_results.json shape where value is only verdict.
                if isinstance(expected, dict):
                    verdict = expected.get("expected_verdict") or expected.get("verdict")
                    typ = expected.get("expected_type") or expected.get("type") or "NONE"
                    notes = expected.get("notes", "")
                else:
                    verdict = expected
                    typ = "NONE"
                    notes = ""
                cases.append(ExpectedCase(file=file_name, expected_verdict=normalize_verdict(verdict), expected_type=normalize_type(typ), notes=notes))
            return cases

        if isinstance(raw, list):
            for row in raw:
                cases.append(
                    ExpectedCase(
                        file=str(row.get("file", "")).strip(),
                        expected_verdict=normalize_verdict(row.get("expected_verdict", "")),
                        expected_type=normalize_type(row.get("expected_type", "NONE")),
                        notes=str(row.get("notes", "")).strip(),
                    )
                )
            return [c for c in cases if c.file]

    # Fallback: no manifest. Run every code file, expected is UNKNOWN.
    for p in sorted(suite_dir.rglob("*")):
        if p.is_file() and p.suffix.lower() in SUPPORTED_CODE_EXTENSIONS:
            cases.append(ExpectedCase(file=str(p.relative_to(suite_dir)), expected_verdict="UNKNOWN", expected_type="UNKNOWN", notes="No manifest found"))

    if not cases:
        raise FileNotFoundError(f"No manifest.csv/json and no code files found in: {suite_dir}")

    return cases


def login(base_url: str, login_endpoint: str, email: str, password: str) -> str:
    url = base_url.rstrip("/") + login_endpoint
    response = requests.post(url, json={"email": email, "password": password}, timeout=30)

    if not response.ok:
        raise RuntimeError(f"Login failed: HTTP {response.status_code}: {response.text[:1000]}")

    data = response.json()
    token = data.get("access_token") or data.get("accessToken") or data.get("token")
    if not token:
        raise RuntimeError(f"Login response did not contain access_token: {data}")

    return str(token)


def scan_file(
    base_url: str,
    scan_endpoint: str,
    token: str,
    file_path: Path,
    timeout: int,
) -> ActualResult:
    url = base_url.rstrip("/") + scan_endpoint
    headers = {"Authorization": f"Bearer {token}"}

    mime = mimetypes.guess_type(str(file_path))[0] or "text/plain"

    try:
        with file_path.open("rb") as f:
            files = {"file": (file_path.name, f, mime)}
            response = requests.post(url, headers=headers, files=files, timeout=timeout)
        return extract_actual_result(response)
    except requests.RequestException as exc:
        return ActualResult(
            ok_http=False,
            status_code=0,
            raw_error=str(exc),
            actual_verdict="ERROR",
            actual_type="ERROR",
            risk_score=None,
            patterns="",
            explanation="Request failed before receiving a response.",
            scan_id="",
        )


def verdict_matches(expected: str, actual: str, accept_suspicious_as_vulnerable: bool) -> bool:
    expected = normalize_verdict(expected)
    actual = normalize_verdict(actual)

    if expected == "UNKNOWN":
        return True

    if expected == actual:
        return True

    if accept_suspicious_as_vulnerable and expected == "VULNERABLE" and actual == "SUSPICIOUS":
        return True

    return False


def type_matches(expected: str, actual: str, expected_verdict: str, actual_verdict: str) -> bool:
    expected = normalize_type(expected)
    actual = normalize_type(actual)

    if expected == "UNKNOWN":
        return True

    # If expected is SAFE, type should be NONE. Some APIs return null/None, normalized to NONE.
    if normalize_verdict(expected_verdict) == "SAFE":
        return actual == "NONE"

    return expected == actual


def write_outputs(results: List[Dict[str, Any]], output_dir: Path) -> Tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    csv_out = output_dir / "test_results.csv"
    md_out = output_dir / "test_results.md"

    fieldnames = [
        "file",
        "expected_verdict",
        "actual_verdict",
        "verdict_pass",
        "expected_type",
        "actual_type",
        "type_pass",
        "overall_pass",
        "risk_score",
        "patterns",
        "notes",
        "explanation",
        "scan_id",
        "http_status",
        "error",
    ]

    with csv_out.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    total = len(results)
    passed = sum(1 for r in results if r["overall_pass"] == "YES")
    failed = total - passed

    lines: List[str] = []
    lines.append("# SQLi Test Suite Results")
    lines.append("")
    lines.append(f"- Total: **{total}**")
    lines.append(f"- Passed: **{passed}**")
    lines.append(f"- Failed: **{failed}**")
    lines.append("")
    lines.append("| # | File | Expected | Actual | Risk | Pass |")
    lines.append("|---:|---|---|---|---:|---|")

    for i, r in enumerate(results, 1):
        expected = f"{r['expected_verdict']} / {r['expected_type']}"
        actual = f"{r['actual_verdict']} / {r['actual_type']}"
        mark = "✅" if r["overall_pass"] == "YES" else "❌"
        risk = "" if r["risk_score"] is None else str(r["risk_score"])
        lines.append(f"| {i} | `{r['file']}` | {expected} | {actual} | {risk} | {mark} |")

    if failed:
        lines.append("")
        lines.append("## Failures")
        lines.append("")
        for r in results:
            if r["overall_pass"] == "NO":
                lines.append(f"### `{r['file']}`")
                lines.append("")
                lines.append(f"- Expected: `{r['expected_verdict']} / {r['expected_type']}`")
                lines.append(f"- Actual: `{r['actual_verdict']} / {r['actual_type']}`")
                lines.append(f"- Risk score: `{r['risk_score']}`")
                if r["patterns"]:
                    lines.append(f"- Patterns: `{r['patterns']}`")
                if r["explanation"]:
                    lines.append(f"- Explanation: {r['explanation']}")
                if r["error"]:
                    lines.append(f"- Error: `{r['error']}`")
                lines.append("")

    md_out.write_text("\n".join(lines), encoding="utf-8")

    return csv_out, md_out


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SQLi detector test suite against the FastAPI backend.")
    parser.add_argument("--suite", required=True, help="Path to a test suite folder or ZIP containing manifest.csv/json and code files.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"Backend base URL. Default: {DEFAULT_BASE_URL}")
    parser.add_argument("--scan-endpoint", default=DEFAULT_SCAN_ENDPOINT, help=f"Scan endpoint. Default: {DEFAULT_SCAN_ENDPOINT}")
    parser.add_argument("--login-endpoint", default=DEFAULT_LOGIN_ENDPOINT, help=f"Login endpoint. Default: {DEFAULT_LOGIN_ENDPOINT}")
    parser.add_argument("--email", help="User email for login. Alternative: use --token.")
    parser.add_argument("--password", help="User password for login. Alternative: use --token.")
    parser.add_argument("--token", help="JWT bearer token. If provided, login is skipped.")
    parser.add_argument("--output-dir", default="outputs/sqli_test_results", help="Where to write CSV/MD results.")
    parser.add_argument("--timeout", type=int, default=60, help="HTTP timeout per file in seconds.")
    parser.add_argument("--accept-suspicious-as-vulnerable", action="store_true", help="Treat SUSPICIOUS as pass when expected verdict is VULNERABLE.")
    parser.add_argument("--stop-on-fail", action="store_true", help="Stop after first failed test.")
    args = parser.parse_args()

    suite_path = Path(args.suite).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()

    suite_dir, tmp = load_suite_path(suite_path)

    try:
        cases = load_manifest(suite_dir)

        if args.token:
            token = args.token
        else:
            if not args.email or not args.password:
                print("You must provide either --token OR both --email and --password.")
                return 2
            token = login(args.base_url, args.login_endpoint, args.email, args.password)

        print(f"Suite: {suite_dir}")
        print(f"Cases: {len(cases)}")
        print(f"Backend: {args.base_url.rstrip('/') + args.scan_endpoint}")
        print()

        results: List[Dict[str, Any]] = []

        for i, case in enumerate(cases, 1):
            file_path = suite_dir / case.file
            if not file_path.exists():
                row = {
                    "file": case.file,
                    "expected_verdict": case.expected_verdict,
                    "actual_verdict": "ERROR",
                    "verdict_pass": "NO",
                    "expected_type": case.expected_type,
                    "actual_type": "ERROR",
                    "type_pass": "NO",
                    "overall_pass": "NO",
                    "risk_score": None,
                    "patterns": "",
                    "notes": case.notes,
                    "explanation": "",
                    "scan_id": "",
                    "http_status": "",
                    "error": f"File not found: {file_path}",
                }
                results.append(row)
                print(f"{i:02d}. {case.file}: ❌ file not found")
                if args.stop_on_fail:
                    break
                continue

            actual = scan_file(args.base_url, args.scan_endpoint, token, file_path, args.timeout)

            verdict_ok = actual.ok_http and verdict_matches(
                case.expected_verdict,
                actual.actual_verdict,
                args.accept_suspicious_as_vulnerable,
            )
            type_ok = actual.ok_http and type_matches(
                case.expected_type,
                actual.actual_type,
                case.expected_verdict,
                actual.actual_verdict,
            )

            overall_ok = verdict_ok and type_ok

            row = {
                "file": case.file,
                "expected_verdict": case.expected_verdict,
                "actual_verdict": actual.actual_verdict,
                "verdict_pass": "YES" if verdict_ok else "NO",
                "expected_type": case.expected_type,
                "actual_type": actual.actual_type,
                "type_pass": "YES" if type_ok else "NO",
                "overall_pass": "YES" if overall_ok else "NO",
                "risk_score": actual.risk_score,
                "patterns": actual.patterns,
                "notes": case.notes,
                "explanation": actual.explanation,
                "scan_id": actual.scan_id,
                "http_status": actual.status_code,
                "error": actual.raw_error,
            }
            results.append(row)

            mark = "✅" if overall_ok else "❌"
            print(
                f"{i:02d}. {case.file}: {mark} "
                f"expected={case.expected_verdict}/{case.expected_type} "
                f"actual={actual.actual_verdict}/{actual.actual_type} "
                f"risk={actual.risk_score}"
            )

            if args.stop_on_fail and not overall_ok:
                break

        csv_out, md_out = write_outputs(results, output_dir)

        total = len(results)
        passed = sum(1 for r in results if r["overall_pass"] == "YES")
        failed = total - passed

        print()
        print("=" * 72)
        print(f"Passed: {passed}/{total}")
        print(f"Failed: {failed}/{total}")
        print(f"CSV: {csv_out}")
        print(f"Markdown: {md_out}")
        print("=" * 72)

        return 0 if failed == 0 else 1

    finally:
        if tmp is not None:
            tmp.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
