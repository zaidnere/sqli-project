# MODEL2_ALL_SUITES_EVALUATION_RUNNER_MARKER
"""Run all Model 2 evaluation suites and build one combined report.

This runner does not modify Model 1, Model 2, weights, suites, or fix_generator.
It orchestrates the existing test runners and consolidates their outputs.

It is intended for the SQLi project workflow:
1. Fix-generator language regression.
2. Dedicated Model 2 fix suites.
3. Full pipeline strict check using official Model 1 outputs.
4. Combined summary + failure review CSV.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = PROJECT_ROOT / "outputs"


def _run(cmd: list[str], *, label: str, allow_missing: bool = False) -> dict[str, Any]:
    print(f"\n=== {label} ===")
    print(" ".join(cmd))
    env = os.environ.copy()
    env["PYTHONPATH"] = "." + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    p = subprocess.run(cmd, cwd=str(PROJECT_ROOT), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(p.stdout)
    if p.returncode != 0 and not allow_missing:
        raise SystemExit(f"FAILED: {label} exited with {p.returncode}")
    return {"label": label, "returncode": p.returncode, "output": p.stdout}


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"_error": f"failed to read {path}: {exc}"}


def _pct(num: int | float, den: int | float) -> float:
    try:
        return round((float(num) / float(den)) * 100.0, 2) if den else 0.0
    except Exception:
        return 0.0


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in {"1", "true", "yes", "y", "pass", "passed"}


def _first(row: dict[str, str], names: list[str], default: str = "") -> str:
    for n in names:
        if n in row and row[n] not in {None, ""}:
            return row[n]
    return default


def _collect_failures(full_csv: Path, out_csv: Path) -> dict[str, Any]:
    if not full_csv.exists():
        return {"error": f"Full pipeline CSV not found: {full_csv}"}

    failures: list[dict[str, str]] = []
    by_stage = Counter()
    by_suite = Counter()
    by_language = Counter()
    by_expected_predicted = Counter()
    by_expected_final = Counter()

    with full_csv.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        for row in reader:
            expected_verdict = _first(row, ["expected_verdict", "expectedVerdict", "manifest_expected_verdict"]).upper()
            if expected_verdict in {"SAFE", "NONE"}:
                continue

            # Try several possible column names from our runner versions.
            full_pass = _truthy(_first(row, [
                "full_pipeline_strict_pass", "fullSystemStrictPass", "full_system_strict_pass",
                "end_to_end_strict_pass", "passed_checked", "passedChecked",
            ], "true"))
            model_pass = _truthy(_first(row, ["model2_model_fix_pass", "model_fix_pass", "modelExpectedPass", "model2ModelPass"], "true"))
            final_pass = _truthy(_first(row, ["model2_final_fix_pass", "final_fix_pass", "finalExpectedPass", "model2FinalPass"], "true"))
            strict_pass = _truthy(_first(row, ["strict_fix_pass", "strictFixPass", "model2_strict_fix_pass", "strict_validation_pass"], "true"))

            if full_pass and model_pass and final_pass and strict_pass:
                continue

            stage = _first(row, ["failure_stage", "failureStage"], "")
            if not stage:
                if not model_pass:
                    stage = "model2_fix_classification"
                elif not final_pass:
                    stage = "fix_generator_final_type"
                elif not strict_pass:
                    stage = "strict_fix_validation"
                else:
                    stage = "unknown"

            suite = _first(row, ["suite", "suite_name", "suiteName"])
            lang = _first(row, ["language", "lang"])
            expected_fix = _first(row, ["expected_fix_type", "expectedFixType", "expected_model_fix_type", "expectedFinalFixType"])
            model_fix = _first(row, ["model2_fix_type", "modelFixType", "predicted_fix_type", "model_fix_type"])
            final_fix = _first(row, ["final_fix_type", "finalFixType"])

            by_stage[stage] += 1
            if suite: by_suite[suite] += 1
            if lang: by_language[lang] += 1
            if expected_fix or model_fix: by_expected_predicted[f"{expected_fix}->{model_fix}"] += 1
            if expected_fix or final_fix: by_expected_final[f"{expected_fix}->{final_fix}"] += 1

            failures.append({
                "stage": stage,
                "suite": suite,
                "case_id": _first(row, ["id", "case_id", "file", "path", "relative_path", "source_path"]),
                "language": lang,
                "expected_verdict": expected_verdict,
                "model1_verdict": _first(row, ["model1_verdict", "actual_verdict", "model1ActualVerdict"]),
                "model1_attack_type": _first(row, ["model1_attack_type", "actual_type", "model1ActualType"]),
                "expected_fix_type": expected_fix,
                "model2_fix_type": model_fix,
                "final_fix_type": final_fix,
                "strict_reason": _first(row, ["strict_reason", "strictFixReason", "strict_validation_reason", "content_reason"]),
                "model2_confidence": _first(row, ["model2_confidence", "confidence"]),
                "probabilities": _first(row, ["model2_probabilities", "all_probabilities", "probabilities"]),
                "fixed_code_preview": _first(row, ["fixed_code_preview", "fixed_preview", "fixed_code"] )[:1200].replace("\r", ""),
            })

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8-sig", newline="") as f:
        fields = [
            "stage", "suite", "case_id", "language", "expected_verdict", "model1_verdict",
            "model1_attack_type", "expected_fix_type", "model2_fix_type", "final_fix_type",
            "strict_reason", "model2_confidence", "probabilities", "fixed_code_preview",
        ]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(failures)

    return {
        "totalFailures": len(failures),
        "byStage": dict(by_stage),
        "bySuite": dict(by_suite),
        "byLanguage": dict(by_language),
        "byExpectedToModel": dict(by_expected_predicted),
        "byExpectedToFinal": dict(by_expected_final),
        "csv": str(out_csv.relative_to(PROJECT_ROOT)),
    }


def _write_report(summary: dict[str, Any], path: Path) -> None:
    lines = []
    lines.append("# Model 2 All-Suites Evaluation Report")
    lines.append("")
    lines.append("This report consolidates the language-aware fix-generator regression, dedicated Model 2 fix suites, and full pipeline strict evaluation using official Model 1 outputs.")
    lines.append("")

    full = summary.get("fullPipelineStrict") or {}
    if full:
        lines.append("## Full Pipeline Strict")
        lines.append(f"- Model 1 official: {full.get('model1OfficialPassed')}/{full.get('totalRows')} ({full.get('model1OfficialAccuracyPct')}%)")
        lines.append(f"- Model 2 classification: {full.get('model2ModelFixPassed')}/{full.get('model2EvaluatedExpectedVulnerable')} ({full.get('model2ModelFixAccuracyPct')}%)")
        lines.append(f"- Model 2 final fix type: {full.get('model2FinalFixPassed')}/{full.get('model2EvaluatedExpectedVulnerable')} ({full.get('model2FinalFixAccuracyPct')}%)")
        lines.append(f"- Strict generated-fix validation: {full.get('model2StrictFixPassed')}/{full.get('model2EvaluatedExpectedVulnerable')} ({full.get('model2StrictFixAccuracyPct')}%)")
        lines.append(f"- Full pipeline strict: {full.get('fullPipelineStrictPassed')}/{full.get('totalRows')} ({full.get('fullPipelineStrictAccuracyPct')}%)")
        lines.append("")

    reg = summary.get("languageRegression") or {}
    if reg:
        lines.append("## Fix Generator Language Regression")
        lines.append(f"- Passed: {reg.get('passed')}/{reg.get('totalCases')} ({reg.get('accuracyPct', reg.get('accuracy'))}%)")
        lines.append("")

    failures = summary.get("failureReview") or {}
    if failures:
        lines.append("## Failure Review")
        lines.append(f"- Total failures: {failures.get('totalFailures')}")
        lines.append(f"- By stage: `{json.dumps(failures.get('byStage', {}), ensure_ascii=False)}`")
        lines.append(f"- By language: `{json.dumps(failures.get('byLanguage', {}), ensure_ascii=False)}`")
        lines.append(f"- Failure CSV: `{failures.get('csv')}`")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model1-results-zip", default="sqli_test_results.zip")
    ap.add_argument("--detection-suites-dir", default="test_suites_model2_detection")
    ap.add_argument("--fix-cases", default="test_suites/model2_fix_cases.zip")
    ap.add_argument("--skip-language-regression", action="store_true")
    ap.add_argument("--skip-fix-cases", action="store_true")
    ap.add_argument("--skip-full-pipeline", action="store_true")
    args = ap.parse_args()

    OUTPUTS.mkdir(exist_ok=True)
    runs = []

    if not args.skip_language_regression and (PROJECT_ROOT / "scripts" / "run_fix_generator_language_regression.py").exists():
        runs.append(_run([sys.executable, "scripts/run_fix_generator_language_regression.py"], label="Fix generator language regression"))

    if not args.skip_fix_cases and (PROJECT_ROOT / args.fix_cases).exists() and (PROJECT_ROOT / "scripts" / "run_model2_fix_cases_direct.py").exists():
        runs.append(_run([sys.executable, "scripts/run_model2_fix_cases_direct.py", "--cases", args.fix_cases], label="Dedicated Model 2 fix cases - all"))
        runs.append(_run([sys.executable, "scripts/run_model2_fix_cases_direct.py", "--cases", args.fix_cases, "--only", "diagnostic"], label="Dedicated Model 2 fix cases - diagnostic"))

    if not args.skip_full_pipeline:
        runs.append(_run([
            sys.executable,
            "scripts/run_full_pipeline_from_model1_results.py",
            "--model1-results-zip", args.model1_results_zip,
            "--suites-dir", args.detection_suites_dir,
            "--include-fixed-code",
        ], label="Full pipeline strict from official Model 1 results"))

    language_reg = _load_json(OUTPUTS / "fix_generator_language_regression_summary.json")
    fix_all = _load_json(OUTPUTS / "model2_fix_cases_all_summary.json")
    fix_diag = _load_json(OUTPUTS / "model2_fix_cases_diagnostic_summary.json")
    full = _load_json(OUTPUTS / "full_pipeline_from_model1_results_official_model1_results_strict_summary.json")
    failure_review = _collect_failures(
        OUTPUTS / "full_pipeline_from_model1_results_official_model1_results_strict_results.csv",
        OUTPUTS / "model2_all_suites_failure_review.csv",
    )

    combined = {
        "suite": "model2_all_suites_evaluation_v1",
        "note": "Combined evaluation. Does not modify models/suites; uses existing runners and official Model 1 output for full pipeline.",
        "runs": [{"label": r["label"], "returncode": r["returncode"]} for r in runs],
        "languageRegression": language_reg,
        "dedicatedModel2FixAll": fix_all,
        "dedicatedModel2FixDiagnostic": fix_diag,
        "fullPipelineStrict": full,
        "failureReview": failure_review,
        "outputs": {
            "summary": "outputs\\model2_all_suites_evaluation_summary.json",
            "report": "outputs\\model2_all_suites_evaluation_report.md",
            "failureReviewCsv": "outputs\\model2_all_suites_failure_review.csv",
        },
    }
    (OUTPUTS / "model2_all_suites_evaluation_summary.json").write_text(json.dumps(combined, indent=2, ensure_ascii=False), encoding="utf-8")
    _write_report(combined, OUTPUTS / "model2_all_suites_evaluation_report.md")

    print("\nModel 2 All-Suites Evaluation")
    print("-----------------------------")
    if language_reg:
        print(f"Language regression: {language_reg.get('passed')}/{language_reg.get('totalCases')}")
    if fix_all:
        print(f"Dedicated Model2 all: {fix_all.get('passedChecked')}/{fix_all.get('totalCases')}")
    if fix_diag:
        print(f"Dedicated Model2 diagnostic: {fix_diag.get('passedChecked')}/{fix_diag.get('totalCases')}")
    if full:
        print(f"Full pipeline strict: {full.get('fullPipelineStrictPassed')}/{full.get('totalRows')} ({full.get('fullPipelineStrictAccuracyPct')}%)")
        print(f"Model2 strict fix: {full.get('model2StrictFixPassed')}/{full.get('model2EvaluatedExpectedVulnerable')} ({full.get('model2StrictFixAccuracyPct')}%)")
    print(f"Failures: {failure_review.get('totalFailures')}")
    print("JSON: outputs\\model2_all_suites_evaluation_summary.json")
    print("CSV:  outputs\\model2_all_suites_failure_review.csv")
    print("MD:   outputs\\model2_all_suites_evaluation_report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
