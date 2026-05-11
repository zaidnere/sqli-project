# MODEL2_ON_DETECTION_SUITES_RUNNER_MARKER
"""
Run Model 2 Fix Recommendation against existing Model 1 detection suites.

Purpose:
- These suites were originally created for detection, not fix recommendation.
- SAFE cases are skipped by default because Model 2 should run only after Model 1 finds a vulnerability.
- For vulnerable cases, expected fix type is inferred from expected attack type + code structure.
- This is a broad stress/regression test, not a replacement for a dedicated Model 2 suite with explicit labels.

Outputs are separated by test type/name, and each run overwrites only its own output files.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

# Make the script runnable from backend without requiring PYTHONPATH=.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.preprocessing.normalizer import normalize_tokens
from app.vectorization.vocabulary import build_fixed_vocabulary
from app.vectorization.vectorizer import vectorize_tokens
from app.model.fix_model_inference import run_fix_inference, fix_model_is_loaded
from app.fix_engine.fix_generator import generate_fix

DEFAULT_OUTPUT_PREFIX = "model2_detection_suites"


@dataclass
class CaseResult:
    suite: str
    source_zip: str
    file: str
    language: str
    expected_verdict: str
    expected_attack_type: str
    expected_fix_type: str
    expected_reason: str
    model_fix_type: str
    final_fix_type: str
    model_pass: bool
    final_pass: bool
    content_pass: bool
    skipped: bool
    skip_reason: str
    crashed: bool
    error: str
    confidence: Any
    all_probabilities: Any
    fixed_code_preview: str


def _safe_name(value: str) -> str:
    value = (value or "all").strip().lower()
    value = re.sub(r"[^a-z0-9_-]+", "_", value)
    return value.strip("_") or "all"


def _decode_bytes(data: bytes) -> str:
    for enc in ("utf-8", "utf-8-sig", "cp1255", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _find_manifest(zf: zipfile.ZipFile) -> str | None:
    manifests = [n for n in zf.namelist() if n.lower().endswith("manifest.csv")]
    if not manifests:
        return None
    # Prefer root-ish manifest if multiple exist.
    return sorted(manifests, key=lambda x: (x.count("/"), len(x)))[0]


def _infer_language(row: dict[str, str], file_path: str) -> str:
    lang = (row.get("language") or "").strip().lower()
    if lang:
        return lang
    ext = Path(file_path).suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript",
        ".java": "java",
        ".php": "php",
    }.get(ext, "unknown")


def _strip_comments(code: str, language: str) -> str:
    if language == "python":
        return re.sub(r"#.*", "", code)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    return re.sub(r"//[^\n\r]*", "", code)


def _rx(pattern: str, text: str, flags: int = re.I | re.S) -> bool:
    return re.search(pattern, text, flags) is not None


def _detect_identifier_context(code: str, language: str) -> bool:
    c = _strip_comments(code, language)
    order_by = _rx(
        r"\bORDER\s+BY\s*(?:"
        r"[\"'`]\s*(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r"|\$\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r")",
        c,
    )
    table_name = _rx(
        r"\b(?:FROM|JOIN|UPDATE|INTO)\s*(?:"
        r"[\"'`]\s*(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|(?:\+|\.)\s*\$?[A-Za-z_$]\w*"
        r"|\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r"|\$\{\s*\$?[A-Za-z_$]\w*\s*\}"
        r")",
        c,
    )
    return bool(order_by or table_name)


def _detect_complex_builder_context(code: str, language: str) -> bool:
    c = _strip_comments(code, language)
    # Complex builder families: loops/maps/criteria build dynamic WHERE clauses, or helper returns SQL.
    loop_builder = _rx(
        r"\b(?:for|foreach)\b[\s\S]{0,220}(?:filters|criteria|whereMap|searchFields|params|Object\.keys|keySet|items\s*\(|implode|join)",
        c,
    ) and _rx(r"(?:sql|query|where|parts|where_parts)[\s\S]{0,260}(?:\+=|\.=|\.append\s*\(|\.push\s*\(|\.add\s*\(|join\s*\(|implode\s*\()", c)
    helper_builder = _rx(
        r"\b(?:build|make|compose|create|assemble|render)[A-Za-z0-9_]*(?:sql|query|where|filter|search|report)[A-Za-z0-9_]*\s*\(",
        c,
    )
    querybuilder_name = _rx(r"\b(?:QueryBuilder|queryBuilder|criteriaBuilder|createQueryBuilder|knex|sequelize|sqlalchemy)\b", c)
    dynamic_where_parts = _rx(r"(?:where_parts|parts|clauses|conditions)\s*=\s*\[", c) and _rx(r"\.join\s*\(|implode\s*\(", c)
    return bool(loop_builder or helper_builder or querybuilder_name or dynamic_where_parts)


def _infer_expected_fix(expected_type: str, code: str, language: str, row: dict[str, str]) -> tuple[str, str]:
    t = (expected_type or "NONE").strip().upper()
    category = " ".join(str(row.get(k, "")) for k in ("category", "focus_area", "description", "notes")).lower()

    if t == "SECOND_ORDER":
        return "D", "expected attack type is SECOND_ORDER"

    # Explicit category/focus hints from detection suites.
    if any(x in category for x in ("second_order", "second-order", "stored sql", "saved filter")):
        return "D", "manifest describes stored/second-order SQL fragment"
    if any(x in category for x in ("query builder", "builder", "orm", "criteria", "dynamic where", "filters")):
        return "C", "manifest describes complex builder/ORM-style case"

    if _detect_complex_builder_context(code, language):
        return "C", "code contains complex dynamic query-builder/helper context"
    if _detect_identifier_context(code, language):
        return "B", "code contains dynamic SQL identifier context (ORDER BY/table name)"
    return "A", "default vulnerable value injection repair is parameterized query"


def _content_check(expected_fix: str, fixed_code: str) -> bool:
    text = fixed_code or ""
    lower = text.lower()
    if expected_fix == "A":
        return ("?" in text or "prepare" in lower or "parameterized" in lower or "bound" in lower) and not ("allowed_columns" in lower or "allowedtables" in lower)
    if expected_fix == "B":
        return "allowed" in lower or "whitelist" in lower or "allowlist" in lower
    if expected_fix == "C":
        return "orm" in lower or "query builder" in lower or "builder" in lower
    if expected_fix == "D":
        return "second" in lower or "stored" in lower or "trusted" in lower or "static template" in lower
    return False


def _read_manifest_rows(zip_path: Path) -> tuple[list[dict[str, str]], str, str]:
    with zipfile.ZipFile(zip_path) as zf:
        manifest_name = _find_manifest(zf)
        if not manifest_name:
            raise ValueError(f"manifest.csv not found in {zip_path}")
        text = _decode_bytes(zf.read(manifest_name))
        rows = list(csv.DictReader(text.splitlines()))
        root = manifest_name.rsplit("/", 1)[0] if "/" in manifest_name else ""
        return rows, manifest_name, root


def _read_code_from_zip(zip_path: Path, root: str, rel_file: str) -> str:
    rel_file = rel_file.replace("\\", "/")
    candidates = []
    if root:
        candidates.append(f"{root}/{rel_file}")
    candidates.append(rel_file)
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
        for name in candidates:
            if name in names:
                return _decode_bytes(zf.read(name))
        # Fallback: match suffix.
        matches = [n for n in names if n.endswith("/" + rel_file) or n == rel_file]
        if matches:
            return _decode_bytes(zf.read(sorted(matches, key=len)[0]))
    raise FileNotFoundError(f"{rel_file} not found in {zip_path}")


def _discover_suites(args: argparse.Namespace) -> list[Path]:
    paths: list[Path] = []
    if args.suite:
        paths.extend(Path(p) for p in args.suite)
    if args.suites:
        paths.extend(Path(p) for p in args.suites)
    if args.dir:
        base = Path(args.dir)
        if base.exists():
            paths.extend(sorted(base.glob(args.pattern)))

    out: list[Path] = []
    seen = set()
    for p in paths:
        if not p.exists() or not p.is_file() or p.suffix.lower() != ".zip":
            continue
        if p.name == "model2_fix_cases.zip":
            continue
        key = str(p.resolve())
        if key not in seen:
            seen.add(key)
            out.append(p)
    if args.only:
        needles = [_safe_name(x) for x in args.only]
        out = [p for p in out if any(n in _safe_name(p.stem) for n in needles)]
    return out


def _run_case(zip_path: Path, suite_name: str, root: str, row: dict[str, str], vocab: dict[str, int]) -> CaseResult:
    rel_file = (row.get("file") or row.get("path") or row.get("filename") or "").strip()
    expected_verdict = (row.get("expected_verdict") or row.get("verdict") or "").strip().upper()
    expected_type = (row.get("expected_type") or row.get("attack_type") or row.get("type") or "NONE").strip().upper()
    language = _infer_language(row, rel_file)

    if expected_verdict in {"SAFE", "NONE", "CLEAN"} or expected_type == "NONE":
        return CaseResult(
            suite=suite_name,
            source_zip=zip_path.name,
            file=rel_file,
            language=language,
            expected_verdict=expected_verdict,
            expected_attack_type=expected_type,
            expected_fix_type="NONE",
            expected_reason="SAFE/NONE cases are skipped because Model 2 runs only after Model 1 detects a vulnerability",
            model_fix_type="",
            final_fix_type="",
            model_pass=True,
            final_pass=True,
            content_pass=True,
            skipped=True,
            skip_reason="safe_or_none",
            crashed=False,
            error="",
            confidence="",
            all_probabilities="",
            fixed_code_preview="",
        )

    try:
        code = _read_code_from_zip(zip_path, root, rel_file)
        expected_fix, reason = _infer_expected_fix(expected_type, code, language, row)
        cleaned = clean_code(code)
        tokens = tokenize_code(cleaned)
        normalized = normalize_tokens(tokens)
        vec = vectorize_tokens(normalized, vocab)
        pred = run_fix_inference(
            vec["tokenIds"],
            language=language,
            attack_type=expected_type,
            normalized_tokens=normalized,
            raw_code=code,
        ) or {}
        model_fix = (pred.get("fixType") or "").upper()
        fix = generate_fix(
            code,
            language,
            normalized,
            preferred_fix_type=model_fix,
            model_prediction=pred,
        )
        final_fix = (getattr(fix, "fix_type", "") or "").upper()
        fixed_code = getattr(fix, "fixed_code", "") or ""
        return CaseResult(
            suite=suite_name,
            source_zip=zip_path.name,
            file=rel_file,
            language=language,
            expected_verdict=expected_verdict,
            expected_attack_type=expected_type,
            expected_fix_type=expected_fix,
            expected_reason=reason,
            model_fix_type=model_fix,
            final_fix_type=final_fix,
            model_pass=(model_fix == expected_fix),
            final_pass=(final_fix == expected_fix),
            content_pass=_content_check(expected_fix, fixed_code),
            skipped=False,
            skip_reason="",
            crashed=False,
            error="",
            confidence=pred.get("confidence", ""),
            all_probabilities=json.dumps(pred.get("allProbabilities", {}), ensure_ascii=False),
            fixed_code_preview=fixed_code.replace("\r", "").replace("\n", "\\n")[:500],
        )
    except Exception as exc:
        return CaseResult(
            suite=suite_name,
            source_zip=zip_path.name,
            file=rel_file,
            language=language,
            expected_verdict=expected_verdict,
            expected_attack_type=expected_type,
            expected_fix_type="",
            expected_reason="",
            model_fix_type="",
            final_fix_type="",
            model_pass=False,
            final_pass=False,
            content_pass=False,
            skipped=False,
            skip_reason="",
            crashed=True,
            error=repr(exc),
            confidence="",
            all_probabilities="",
            fixed_code_preview="",
        )


def _summarize(results: list[CaseResult], suites: list[Path], csv_path: str, json_path: str) -> dict[str, Any]:
    checked = [r for r in results if not r.skipped]
    failed = [r for r in checked if not (r.model_pass and r.final_pass and r.content_pass)]
    by_suite: dict[str, Any] = {}
    for suite in sorted({r.suite for r in results}):
        items = [r for r in results if r.suite == suite]
        suite_checked = [r for r in items if not r.skipped]
        suite_failed = [r for r in suite_checked if not (r.model_pass and r.final_pass and r.content_pass)]
        by_suite[suite] = {
            "totalRows": len(items),
            "safeSkipped": sum(1 for r in items if r.skipped),
            "vulnerableChecked": len(suite_checked),
            "passedChecked": len(suite_checked) - len(suite_failed),
            "failedChecked": len(suite_failed),
            "modelExpectedPassed": sum(1 for r in suite_checked if r.model_pass),
            "finalExpectedPassed": sum(1 for r in suite_checked if r.final_pass),
            "contentPassed": sum(1 for r in suite_checked if r.content_pass),
            "crashedCases": sum(1 for r in suite_checked if r.crashed),
        }
    return {
        "suite": "model2_on_detection_suites_v1",
        "note": "Detection suites do not contain explicit Model 2 labels; expected fix types are inferred. SAFE/NONE cases are skipped by default.",
        "sourceSuites": [p.name for p in suites],
        "totalRows": len(results),
        "safeSkipped": sum(1 for r in results if r.skipped),
        "vulnerableChecked": len(checked),
        "passedChecked": len(checked) - len(failed),
        "failedChecked": len(failed),
        "modelExpectedChecked": len(checked),
        "modelExpectedPassed": sum(1 for r in checked if r.model_pass),
        "modelExpectedFailed": sum(1 for r in checked if not r.model_pass),
        "finalExpectedChecked": len(checked),
        "finalExpectedPassed": sum(1 for r in checked if r.final_pass),
        "finalExpectedFailed": sum(1 for r in checked if not r.final_pass),
        "contentChecked": len(checked),
        "contentPassed": sum(1 for r in checked if r.content_pass),
        "contentFailed": sum(1 for r in checked if not r.content_pass),
        "crashedCases": sum(1 for r in checked if r.crashed),
        "modelFixTypeCounts": {k: sum(1 for r in checked if r.model_fix_type == k) for k in ["A", "B", "C", "D", ""]},
        "finalFixTypeCounts": {k: sum(1 for r in checked if r.final_fix_type == k) for k in ["A", "B", "C", "D", ""]},
        "bySuite": by_suite,
        "csv": csv_path,
        "json": json_path,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", action="append", help="Specific detection suite ZIP. Can be repeated.")
    ap.add_argument("--suites", nargs="*", help="List of detection suite ZIP files.")
    ap.add_argument("--dir", default="test_suites", help="Directory to scan for ZIP suites when no explicit suite is provided.")
    ap.add_argument("--pattern", default="*.zip", help="Glob pattern inside --dir.")
    ap.add_argument("--only", action="append", help="Run only suite names containing this substring. Can be repeated.")
    ap.add_argument("--output-name", default="", help="Output basename without extension. Default is based on --only/all.")
    ap.add_argument("--csv", default="", help="Override CSV output path.")
    ap.add_argument("--json", default="", help="Override JSON output path.")
    args = ap.parse_args()

    if not fix_model_is_loaded():
        raise SystemExit("ERROR: Model 2 or shared Model 1 embedding did not load.")

    suites = _discover_suites(args)
    if not suites:
        raise SystemExit("ERROR: No detection suite ZIPs found. Put them under test_suites or pass --suite.")

    out_tag = _safe_name(args.output_name or ("_".join(args.only) if args.only else "all_detection_suites"))
    out_dir = Path("outputs")
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.csv or str(out_dir / f"{DEFAULT_OUTPUT_PREFIX}_{out_tag}_results.csv")
    json_path = args.json or str(out_dir / f"{DEFAULT_OUTPUT_PREFIX}_{out_tag}_summary.json")

    vocab = build_fixed_vocabulary()
    results: list[CaseResult] = []
    for suite_zip in suites:
        rows, manifest_name, root = _read_manifest_rows(suite_zip)
        suite_name = suite_zip.stem
        for row in rows:
            results.append(_run_case(suite_zip, suite_name, root, row, vocab))

    fields = list(CaseResult.__dataclass_fields__.keys())
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))

    summary = _summarize(results, suites, csv_path, json_path)
    Path(json_path).write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print("Model 2 on Detection Suites V1")
    print("--------------------------------")
    print(f"Suites:             {len(suites)}")
    print(f"Total manifest rows:{summary['totalRows']}")
    print(f"SAFE skipped:       {summary['safeSkipped']}")
    print(f"Vulnerable checked: {summary['vulnerableChecked']}")
    print(f"Passed checked:     {summary['passedChecked']}")
    print(f"Failed checked:     {summary['failedChecked']}")
    print(f"Model expected:     {summary['modelExpectedPassed']}/{summary['modelExpectedChecked']}")
    print(f"Final expected:     {summary['finalExpectedPassed']}/{summary['finalExpectedChecked']}")
    print(f"Content checks:     {summary['contentPassed']}/{summary['contentChecked']}")
    print(f"Crashed cases:      {summary['crashedCases']}")
    print(f"CSV:                {csv_path}")
    print(f"JSON:               {json_path}")
    return 0 if summary["failedChecked"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
