# MODEL2_FIX_CASES_DIRECT_ZIP_OUTPUTS_BY_TYPE_MARKER
r"""
Direct runner for Model 2 Fix Recommendation cases.

Supports:
  1) A single JSON file containing either a list of cases or {"cases": [...]}.
  2) A ZIP file containing one or more .json suite files.
  3) --only <name> to run a specific JSON suite inside the ZIP, for example quick or diagnostic.

Output naming policy:
  Each test type gets its own stable output files.
  Running the same test type again overwrites only that test type's outputs.

Examples:
  All suites in ZIP:
    outputs/model2_fix_cases_all_results.csv
    outputs/model2_fix_cases_all_summary.json

  Only diagnostic:
    outputs/model2_fix_cases_diagnostic_results.csv
    outputs/model2_fix_cases_diagnostic_summary.json

  Only quick:
    outputs/model2_fix_cases_quick_results.csv
    outputs/model2_fix_cases_quick_summary.json

Run from backend folder:
  set PYTHONPATH=.
  python scripts\run_model2_fix_cases_direct.py --cases test_suites\model2_fix_cases.zip
  python scripts\run_model2_fix_cases_direct.py --cases test_suites\model2_fix_cases.zip --only quick
  python scripts\run_model2_fix_cases_direct.py --cases test_suites\model2_fix_cases.zip --only diagnostic
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import traceback
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Project imports. This script is intended to run from backend/ with PYTHONPATH=.
from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.preprocessing.normalizer import normalize_tokens
from app.vectorization.vocabulary import build_fixed_vocabulary
from app.vectorization.vectorizer import vectorize_tokens
from app.model.fix_model_inference import run_fix_inference
from app.fix_engine.fix_generator import generate_fix


def _safe_slug(value: str) -> str:
    value = (value or "").strip().lower()
    value = re.sub(r"[^a-z0-9_-]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value or "default"


def _default_output_paths(cases_path: Path, only: Optional[str], output_name: Optional[str]) -> Tuple[Path, Path, str]:
    """Return CSV path, JSON path and output type label."""
    if output_name:
        suite_type = _safe_slug(output_name)
    elif only:
        suite_type = _safe_slug(only)
    elif cases_path.suffix.lower() == ".zip":
        suite_type = "all"
    else:
        suite_type = _safe_slug(cases_path.stem)

    base = f"model2_fix_cases_{suite_type}"
    return Path("outputs") / f"{base}_results.csv", Path("outputs") / f"{base}_summary.json", suite_type


def _read_json_text(text: str, source_name: str) -> List[Dict[str, Any]]:
    data = json.loads(text)
    if isinstance(data, list):
        cases = data
    elif isinstance(data, dict) and isinstance(data.get("cases"), list):
        cases = data["cases"]
    else:
        raise ValueError(f"{source_name}: JSON must be a list or an object with a 'cases' list")

    cleaned: List[Dict[str, Any]] = []
    for idx, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            raise ValueError(f"{source_name}: case #{idx} is not an object")
        c = dict(case)
        c.setdefault("suiteSource", source_name)
        c.setdefault("id", f"{Path(source_name).stem}_{idx:03d}")
        cleaned.append(c)
    return cleaned


def _decode_json_bytes(raw: bytes, name: str) -> str:
    for enc in ("utf-8-sig", "utf-8"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("utf-8", raw, 0, 1, f"Could not decode {name} as UTF-8/UTF-8-SIG")


def _load_cases(path: Path, only: Optional[str] = None) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Cases file not found: {path}")

    only_norm = only.lower().strip() if only else None

    if path.suffix.lower() == ".zip":
        all_cases: List[Dict[str, Any]] = []
        with zipfile.ZipFile(path, "r") as zf:
            names = [n for n in zf.namelist() if n.lower().endswith(".json") and not n.endswith("/")]
            names.sort()
            if only_norm:
                names = [n for n in names if only_norm in Path(n).stem.lower() or only_norm in n.lower()]
            if not names:
                raise ValueError(f"No JSON suite files found in ZIP {path}" + (f" matching --only {only}" if only else ""))

            for name in names:
                text = _decode_json_bytes(zf.read(name), name)
                all_cases.extend(_read_json_text(text, name))
        return all_cases

    text = path.read_text(encoding="utf-8-sig")
    cases = _read_json_text(text, str(path))
    if only_norm:
        filtered = [
            c for c in cases
            if only_norm in str(c.get("suiteSource", "")).lower()
            or only_norm in str(c.get("id", "")).lower()
        ]
        return filtered if filtered else cases
    return cases


def _to_token_ids(vectorized: Any) -> List[int]:
    if isinstance(vectorized, dict):
        if "tokenIds" in vectorized:
            return vectorized["tokenIds"]
        if "token_ids" in vectorized:
            return vectorized["token_ids"]
    return vectorized


def _get_attr_or_key(obj: Any, name: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _infer_final_fix_type(fixed_code: str, fix_obj: Any = None) -> str:
    explicit = (
        _get_attr_or_key(fix_obj, "fixType")
        or _get_attr_or_key(fix_obj, "fix_type")
        or _get_attr_or_key(fix_obj, "type")
        or _get_attr_or_key(fix_obj, "strategy")
    )
    if explicit in {"A", "B", "C", "D"}:
        return explicit

    text = (fixed_code or "").lower()

    if (
        "allowed_columns" in text
        or "allowed_tables" in text
        or "whitelist" in text
        or "invalid sort column" in text
        or "invalid table name" in text
    ):
        return "B"

    if (
        "second-order" in text
        or "second order" in text
        or ("stored" in text and ("validate" in text or "parameter" in text))
        or "re-validate" in text
        or "revalidate" in text
    ):
        return "D"

    if (
        "orm" in text
        or "query builder" in text
        or "sqlalchemy" in text
        or ".filter(" in text
        or "sequelize" in text
        or "createquerybuilder" in text
    ):
        return "C"

    if (
        "parameterized query" in text
        or "cursor.execute(query," in text
        or "execute(query," in text
        or "?" in text
        or "%s" in text
    ):
        return "A"

    return "UNKNOWN"


def _contains_all(text: str, needles: Iterable[str]) -> Tuple[bool, List[str]]:
    lower = (text or "").lower()
    missing: List[str] = []
    for needle in needles or []:
        if str(needle).lower() not in lower:
            missing.append(str(needle))
    return (len(missing) == 0), missing


def _contains_none(text: str, needles: Iterable[str]) -> Tuple[bool, List[str]]:
    lower = (text or "").lower()
    present: List[str] = []
    for needle in needles or []:
        if str(needle).lower() in lower:
            present.append(str(needle))
    return (len(present) == 0), present


def _run_case(case: Dict[str, Any]) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "suiteSource": case.get("suiteSource", ""),
        "id": case.get("id", ""),
        "language": case.get("language", "python"),
        "attackType": case.get("attack_type") or case.get("attackType") or "IN_BAND",
        "expectedModelFixType": case.get("expected_model_fix_type") or case.get("expectedModelFixType") or case.get("expected_fix_type") or case.get("expectedFixType") or "",
        "expectedFinalFixType": case.get("expected_final_fix_type") or case.get("expectedFinalFixType") or case.get("expected_fix_type") or case.get("expectedFixType") or "",
        "modelFixType": "",
        "finalFixType": "",
        "modelPass": "",
        "finalPass": "",
        "contentPass": "",
        "passed": False,
        "confidence": "",
        "allProbabilities": "",
        "missingMustContain": "",
        "presentMustNotContain": "",
        "error": "",
        "fixedCode": "",
    }

    try:
        code = case.get("code", "")
        if not isinstance(code, str) or not code.strip():
            raise ValueError("case has no non-empty 'code' string")

        language = row["language"]
        attack_type = row["attackType"]

        cleaned = clean_code(code)
        tokens = tokenize_code(cleaned)
        normalized_tokens = normalize_tokens(tokens)
        vocab = build_fixed_vocabulary()
        vec = vectorize_tokens(normalized_tokens, vocab)
        token_ids = _to_token_ids(vec)

        pred = run_fix_inference(
            token_ids,
            language=language,
            attack_type=attack_type,
            normalized_tokens=normalized_tokens,
            raw_code=code,
        )

        model_fix_type = pred.get("fixType", "UNKNOWN") if isinstance(pred, dict) else "UNKNOWN"
        confidence = pred.get("confidence", "") if isinstance(pred, dict) else ""
        all_probs = pred.get("allProbabilities", {}) if isinstance(pred, dict) else {}

        fix_obj = generate_fix(
            code,
            language,
            normalized_tokens,
            preferred_fix_type=model_fix_type,
            model_prediction=pred,
        )
        fixed_code = _get_attr_or_key(fix_obj, "fixed_code", "") or _get_attr_or_key(fix_obj, "fixedCode", "") or ""
        final_fix_type = _infer_final_fix_type(fixed_code, fix_obj)

        row["modelFixType"] = model_fix_type
        row["finalFixType"] = final_fix_type
        row["confidence"] = confidence
        row["allProbabilities"] = json.dumps(all_probs, ensure_ascii=False)
        row["fixedCode"] = fixed_code.replace("\r\n", "\n")

        expected_model = row["expectedModelFixType"]
        expected_final = row["expectedFinalFixType"]

        model_pass: Optional[bool] = None
        final_pass: Optional[bool] = None
        content_pass: Optional[bool] = None

        if expected_model:
            model_pass = model_fix_type == expected_model
            row["modelPass"] = model_pass

        if expected_final:
            final_pass = final_fix_type == expected_final
            row["finalPass"] = final_pass

        must_contain = case.get("must_contain") or case.get("mustContain") or []
        must_not_contain = case.get("must_not_contain") or case.get("mustNotContain") or []

        contains_ok, missing = _contains_all(fixed_code, must_contain)
        excludes_ok, present = _contains_none(fixed_code, must_not_contain)
        if must_contain or must_not_contain:
            content_pass = contains_ok and excludes_ok
            row["contentPass"] = content_pass
            row["missingMustContain"] = " | ".join(missing)
            row["presentMustNotContain"] = " | ".join(present)

        checked = [x for x in (model_pass, final_pass, content_pass) if x is not None]
        row["passed"] = all(checked) if checked else True
        return row

    except Exception as exc:
        row["passed"] = False
        row["error"] = f"{type(exc).__name__}: {exc}"
        row["traceback"] = traceback.format_exc()
        return row


def _write_csv(rows: List[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "suiteSource",
        "id",
        "language",
        "attackType",
        "expectedModelFixType",
        "modelFixType",
        "modelPass",
        "expectedFinalFixType",
        "finalFixType",
        "finalPass",
        "contentPass",
        "passed",
        "confidence",
        "allProbabilities",
        "missingMustContain",
        "presentMustNotContain",
        "error",
        "fixedCode",
    ]
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _build_summary(rows: List[Dict[str, Any]], csv_path: Path, json_path: Path, suite_type: str) -> Dict[str, Any]:
    total = len(rows)
    crashed = sum(1 for r in rows if r.get("error"))
    checked = sum(1 for r in rows if r.get("expectedModelFixType") or r.get("expectedFinalFixType") or r.get("contentPass") != "")
    passed = sum(1 for r in rows if r.get("passed") is True)
    failed = total - passed

    model_checked = sum(1 for r in rows if r.get("expectedModelFixType"))
    model_passed = sum(1 for r in rows if r.get("expectedModelFixType") and r.get("modelPass") is True)
    final_checked = sum(1 for r in rows if r.get("expectedFinalFixType"))
    final_passed = sum(1 for r in rows if r.get("expectedFinalFixType") and r.get("finalPass") is True)
    content_checked = sum(1 for r in rows if r.get("contentPass") != "")
    content_passed = sum(1 for r in rows if r.get("contentPass") is True)

    return {
        "suite": "model2_fix_cases_direct_zip_v4_output_by_type",
        "suiteType": suite_type,
        "totalCases": total,
        "checkedCases": checked,
        "passedChecked": passed,
        "failedChecked": failed,
        "crashedCases": crashed,
        "modelExpectedChecked": model_checked,
        "modelExpectedPassed": model_passed,
        "modelExpectedFailed": model_checked - model_passed,
        "finalExpectedChecked": final_checked,
        "finalExpectedPassed": final_passed,
        "finalExpectedFailed": final_checked - final_passed,
        "contentChecked": content_checked,
        "contentPassed": content_passed,
        "contentFailed": content_checked - content_passed,
        "modelFixTypeCounts": dict(Counter(str(r.get("modelFixType", "UNKNOWN")) for r in rows)),
        "finalFixTypeCounts": dict(Counter(str(r.get("finalFixType", "UNKNOWN")) for r in rows)),
        "suiteSources": dict(Counter(str(r.get("suiteSource", "")) for r in rows)),
        "csv": str(csv_path),
        "json": str(json_path),
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run Model 2 fix recommendation cases directly, from JSON or ZIP.")
    parser.add_argument("--cases", required=True, help="Path to model2_fix_cases.json or model2_fix_cases.zip")
    parser.add_argument("--only", default=None, help="When --cases is ZIP, run only JSON files whose names contain this text, e.g. quick or diagnostic")
    parser.add_argument("--output-name", default=None, help="Optional output type name, e.g. regression, hardcases, quick. Controls output filenames.")
    parser.add_argument("--csv", default=None, help="Optional explicit CSV output path. Overrides automatic naming.")
    parser.add_argument("--json", default=None, help="Optional explicit JSON summary output path. Overrides automatic naming.")
    args = parser.parse_args(argv)

    cases_path = Path(args.cases)
    csv_path, json_path, suite_type = _default_output_paths(cases_path, args.only, args.output_name)
    if args.csv:
        csv_path = Path(args.csv)
    if args.json:
        json_path = Path(args.json)

    cases = _load_cases(cases_path, only=args.only)
    rows = [_run_case(case) for case in cases]

    _write_csv(rows, csv_path)
    summary = _build_summary(rows, csv_path=csv_path, json_path=json_path, suite_type=suite_type)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print("Model 2 Fix Cases Direct ZIP V4")
    print("--------------------------------")
    print(f"Cases source:          {cases_path}")
    if args.only:
        print(f"Only filter:           {args.only}")
    print(f"Output type:           {suite_type}")
    print(f"Total cases:           {summary['totalCases']}")
    print(f"Passed checked:        {summary['passedChecked']}")
    print(f"Failed checked:        {summary['failedChecked']}")
    print(f"Crashed cases:         {summary['crashedCases']}")
    print(f"Model expected:        {summary['modelExpectedPassed']}/{summary['modelExpectedChecked']}")
    print(f"Final expected:        {summary['finalExpectedPassed']}/{summary['finalExpectedChecked']}")
    print(f"Content checks:        {summary['contentPassed']}/{summary['contentChecked']}")
    print(f"Model fix counts:      {summary['modelFixTypeCounts']}")
    print(f"Final fix counts:      {summary['finalFixTypeCounts']}")
    print(f"Suite sources:         {summary['suiteSources']}")
    print(f"CSV:                   {csv_path}")
    print(f"JSON:                  {json_path}")

    return 0 if summary["failedChecked"] == 0 and summary["crashedCases"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
