r"""
Run ML-only evaluation on all SQLi ZIP suites and compare current results to
previous baseline metrics.

Run from backend/:
    set PYTHONPATH=%CD%
    venv\Scripts\python.exe scripts\run_ml_only_all_suites_compare.py

Optional:
    venv\Scripts\python.exe scripts\run_ml_only_all_suites_compare.py ^
      --threshold 0.52 ^
      --debug-preprocess-failures

Outputs:
    outputs/ml95_full_sweep/<suite_name>/ml_only_results.csv
    outputs/ml95_full_sweep/<suite_name>/ml_only_summary.json
    outputs/ml95_full_sweep/<suite_name>/ml_only_summary.md
    outputs/ml95_full_sweep/_comparison/ml_only_comparison.csv
    outputs/ml95_full_sweep/_comparison/ml_only_comparison.md
    outputs/ml95_full_sweep/_comparison/ml_only_comparison.json
"""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parents[1]

# suite filename, old baseline metrics filename

# Fallback legacy baseline from the pre-V18-ML95 sweep, used only when the
# individual baseline JSON files are not present in outputs/. This prevents the
# comparison table from showing misleading 0.00% baselines.
LEGACY_BASELINE_BY_SUITE: dict[str, dict[str, Any]] = {
    "targeted_next_debug_suite": {"binary_accuracy": 0.75},
    "enterprise_realistic_sqli_final_suite": {"binary_accuracy": 0.775},
    "final_framework_obfuscation_stability_suite": {"binary_accuracy": 0.8125},
    "adversarial_real_world_sqli_challenge_suite": {"binary_accuracy": 0.75},
    "v18_remaining_edge_focused_suite": {"binary_accuracy": 0.6786},
    "unseen_generalization_suite_latest_fixed": {"binary_accuracy": 1.0, "binary_correct": 128},
}
LEGACY_AGGREGATE_BASELINE: dict[str, Any] = {
    "total": 594,
    "binary_correct": 502,
    "binary_accuracy": 502 / 594,
    "full_correct": 447,
    "full_accuracy": 447 / 594,
    "false_positives": 63,
    "false_negatives": 29,
}

SUITES: list[tuple[str, str]] = [
    ("targeted_next_debug_suite.zip", "ml_only_targeted_baseline_metrics.json"),
    ("mega_sqli_debug_suite.zip", "ml_only_mega_baseline_metrics.json"),
    ("realistic_long_sqli_suite.zip", "ml_only_realistic_baseline_metrics.json"),
    ("enterprise_realistic_sqli_final_suite.zip", "ml_only_enterprise_baseline_metrics.json"),
    ("final_framework_obfuscation_stability_suite.zip", "ml_only_framework_baseline_metrics.json"),
    ("adversarial_real_world_sqli_challenge_suite.zip", "ml_only_adversarial_baseline_metrics.json"),
    ("v18_remaining_edge_focused_suite.zip", "ml_only_v18_edge_baseline_metrics.json"),
    ("v18_provenance_overfit_guard_suite.zip", "ml_only_provenance_baseline_metrics.json"),
    ("unseen_generalization_suite_latest_fixed.zip", "ml_only_unseen_baseline_metrics.json"),
    ("hard_mixed_sqli_challenge_suite.zip", "ml_only_hard_baseline_metrics.json"),
    ("known_good_sqli_detection_suite.zip", "ml_only_known_good_baseline_metrics.json"),
    ("root_cause_attack_type_diagnostic_suite.zip", "ml_only_root_cause_baseline_metrics.json"),
    ("stable_expected_detection_suite.zip", "ml_only_stable_expected_baseline_metrics.json"),
]


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def metric_block_from_baseline(raw: dict[str, Any]) -> dict[str, Any]:
    return raw.get("metrics", raw)


def pct(x: Any) -> str:
    try:
        return f"{float(x) * 100:.2f}%"
    except Exception:
        return ""


def delta(current: Any, previous: Any) -> float | None:
    try:
        return float(current) - float(previous)
    except Exception:
        return None


def fmt_delta(value: float | None) -> str:
    if value is None:
        return ""
    sign = "+" if value >= 0 else ""
    return f"{sign}{value * 100:.2f}pp"


def run_one(
    suite_path: Path,
    out_dir: Path,
    python_cmd: str,
    threshold: float | None,
    debug_preprocess: bool,
) -> int:
    cmd = [
        python_cmd,
        "scripts/evaluate_ml_only_on_suite.py",
        "--suite",
        str(suite_path),
        "--out",
        str(out_dir),
        "--sequence-length",
        "256",
    ]
    if threshold is not None:
        cmd.extend(["--threshold", str(threshold)])
    if debug_preprocess:
        cmd.append("--debug-preprocess")

    print()
    print("=" * 100)
    print(f"Running ML-only suite: {suite_path.name}")
    print(" ".join(cmd))
    print("=" * 100)

    result = subprocess.run(cmd, cwd=BACKEND_DIR)
    return int(result.returncode)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite-dir", default="test_suites")
    ap.add_argument("--baseline-dir", default="outputs")
    ap.add_argument("--out-root", default="outputs/ml95_full_sweep")
    ap.add_argument("--python-cmd", default=sys.executable)
    ap.add_argument("--threshold", type=float, default=None, help="Override threshold. Default: evaluator reads metadata threshold.")
    ap.add_argument("--debug-preprocess", action="store_true", help="Write debug_preprocess.jsonl for every suite.")
    ap.add_argument(
        "--suites",
        nargs="*",
        default=None,
        help="Optional suite zip names/stems to run. Default: all known suites.",
    )
    args = ap.parse_args()

    suite_dir = (BACKEND_DIR / args.suite_dir).resolve()
    baseline_dir = (BACKEND_DIR / args.baseline_dir).resolve()
    out_root = (BACKEND_DIR / args.out_root).resolve()
    compare_dir = out_root / "_comparison"
    compare_dir.mkdir(parents=True, exist_ok=True)

    selected = SUITES
    if args.suites:
        wanted = {s.removesuffix(".zip") for s in args.suites}
        selected = [(zip_name, base_name) for zip_name, base_name in SUITES if zip_name.removesuffix(".zip") in wanted or zip_name in args.suites]
        if not selected:
            raise SystemExit(f"No matching suites found for: {args.suites}")

    records: list[dict[str, Any]] = []

    for suite_zip, baseline_metrics_name in selected:
        suite_path = suite_dir / suite_zip
        suite_name = suite_path.stem
        suite_out = out_root / suite_name

        if not suite_path.exists():
            print(f"WARNING: suite not found, skipping: {suite_path}")
            records.append({"suite": suite_name, "status": "MISSING_SUITE"})
            continue

        rc = run_one(
            suite_path=suite_path,
            out_dir=suite_out,
            python_cmd=args.python_cmd,
            threshold=args.threshold,
            debug_preprocess=args.debug_preprocess,
        )

        current = read_json(suite_out / "ml_only_summary.json")
        baseline_raw = read_json(baseline_dir / baseline_metrics_name)
        baseline = metric_block_from_baseline(baseline_raw)
        if not baseline:
            baseline = dict(LEGACY_BASELINE_BY_SUITE.get(suite_name, {}))
            if baseline.get("binary_accuracy") is not None and baseline.get("binary_correct") is None and current.get("total"):
                baseline["binary_correct"] = round(float(baseline["binary_accuracy"]) * int(current["total"]))

        current_binary = current.get("binary_accuracy")
        current_full = current.get("full_accuracy")
        baseline_binary = baseline.get("binary_accuracy")
        baseline_full = baseline.get("exact_accuracy", baseline.get("full_accuracy"))

        record = {
            "suite": suite_name,
            "status": "OK" if rc == 0 and current else f"RUN_ERROR_{rc}",
            "total": current.get("total", baseline.get("total")),
            "threshold": current.get("threshold"),
            "model_version": current.get("model_version"),
            "current_binary_correct": current.get("binary_correct"),
            "current_binary_accuracy": current_binary,
            "baseline_binary_correct": baseline.get("binary_pass", baseline.get("binary_correct")),
            "baseline_binary_accuracy": baseline_binary,
            "delta_binary_accuracy": delta(current_binary, baseline_binary),
            "current_full_correct": current.get("full_correct"),
            "current_full_accuracy": current_full,
            "baseline_full_correct": baseline.get("exact_pass", baseline.get("full_correct")),
            "baseline_full_accuracy": baseline_full,
            "delta_full_accuracy": delta(current_full, baseline_full),
            "current_fp": current.get("false_positives"),
            "baseline_fp": baseline.get("false_positives"),
            "current_fn": current.get("false_negatives"),
            "baseline_fn": baseline.get("false_negatives"),
            "current_precision": current.get("precision"),
            "baseline_precision": baseline.get("precision"),
            "current_recall": current.get("recall"),
            "baseline_recall": baseline.get("recall"),
            "current_f1": current.get("f1"),
            "baseline_f1": baseline.get("f1"),
        }
        records.append(record)

    # Aggregate rows with valid numeric totals.
    current_total = sum(int(r.get("total") or 0) for r in records if r.get("status") == "OK")
    current_bin_ok = sum(int(r.get("current_binary_correct") or 0) for r in records if r.get("status") == "OK")
    current_full_ok = sum(int(r.get("current_full_correct") or 0) for r in records if r.get("status") == "OK")
    base_bin_ok = sum(int(r.get("baseline_binary_correct") or 0) for r in records if r.get("baseline_binary_correct") is not None)
    base_full_ok = sum(int(r.get("baseline_full_correct") or 0) for r in records if r.get("baseline_full_correct") is not None)
    current_fp = sum(int(r.get("current_fp") or 0) for r in records if r.get("status") == "OK")
    current_fn = sum(int(r.get("current_fn") or 0) for r in records if r.get("status") == "OK")
    base_fp = sum(int(r.get("baseline_fp") or 0) for r in records if r.get("baseline_fp") is not None)
    base_fn = sum(int(r.get("baseline_fn") or 0) for r in records if r.get("baseline_fn") is not None)

    # If no individual baseline files were found, use the known aggregate legacy
    # baseline so the TOTAL row still compares against the real previous result.
    if base_bin_ok == 0 and base_full_ok == 0:
        base_bin_ok = int(LEGACY_AGGREGATE_BASELINE["binary_correct"])
        base_full_ok = int(LEGACY_AGGREGATE_BASELINE["full_correct"])
        base_fp = int(LEGACY_AGGREGATE_BASELINE["false_positives"])
        base_fn = int(LEGACY_AGGREGATE_BASELINE["false_negatives"])

    aggregate = {
        "suite": "__TOTAL__",
        "status": "OK",
        "total": current_total,
        "threshold": "mixed/metadata" if args.threshold is None else args.threshold,
        "model_version": records[0].get("model_version") if records else "",
        "current_binary_correct": current_bin_ok,
        "current_binary_accuracy": current_bin_ok / max(1, current_total),
        "baseline_binary_correct": base_bin_ok,
        "baseline_binary_accuracy": base_bin_ok / max(1, current_total),
        "delta_binary_accuracy": (current_bin_ok - base_bin_ok) / max(1, current_total),
        "current_full_correct": current_full_ok,
        "current_full_accuracy": current_full_ok / max(1, current_total),
        "baseline_full_correct": base_full_ok,
        "baseline_full_accuracy": base_full_ok / max(1, current_total),
        "delta_full_accuracy": (current_full_ok - base_full_ok) / max(1, current_total),
        "current_fp": current_fp,
        "baseline_fp": base_fp,
        "current_fn": current_fn,
        "baseline_fn": base_fn,
    }

    all_records = records + [aggregate]

    csv_path = compare_dir / "ml_only_comparison.csv"
    fieldnames = list(aggregate.keys())
    # Include any extra fields from regular records.
    for r in all_records:
        for k in r:
            if k not in fieldnames:
                fieldnames.append(k)
    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_records)

    json_path = compare_dir / "ml_only_comparison.json"
    json_path.write_text(json.dumps({"suites": records, "aggregate": aggregate}, ensure_ascii=False, indent=2), encoding="utf-8")

    md_lines: list[str] = []
    md_lines.append("# ML-only Full Suite Comparison\n\n")
    md_lines.append("This compares the current deployed ML-only weights against the previous baseline metrics files.\n\n")
    md_lines.append("| Suite | Total | Current binary | Baseline binary | Δ binary | Current full | Baseline full | Δ full | FP current/base | FN current/base |\n")
    md_lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
    for r in records:
        md_lines.append(
            f"| {r.get('suite')} | {r.get('total','')} | "
            f"{pct(r.get('current_binary_accuracy'))} | {pct(r.get('baseline_binary_accuracy'))} | {fmt_delta(r.get('delta_binary_accuracy'))} | "
            f"{pct(r.get('current_full_accuracy'))} | {pct(r.get('baseline_full_accuracy'))} | {fmt_delta(r.get('delta_full_accuracy'))} | "
            f"{r.get('current_fp','')}/{r.get('baseline_fp','')} | {r.get('current_fn','')}/{r.get('baseline_fn','')} |\n"
        )
    md_lines.append(
        f"| **TOTAL** | **{aggregate['total']}** | "
        f"**{pct(aggregate['current_binary_accuracy'])}** | **{pct(aggregate['baseline_binary_accuracy'])}** | **{fmt_delta(aggregate['delta_binary_accuracy'])}** | "
        f"**{pct(aggregate['current_full_accuracy'])}** | **{pct(aggregate['baseline_full_accuracy'])}** | **{fmt_delta(aggregate['delta_full_accuracy'])}** | "
        f"**{aggregate['current_fp']}/{aggregate['baseline_fp']}** | **{aggregate['current_fn']}/{aggregate['baseline_fn']}** |\n"
    )
    md_path = compare_dir / "ml_only_comparison.md"
    md_path.write_text("".join(md_lines), encoding="utf-8")

    print()
    print("=" * 100)
    print("ML-only full suite comparison complete")
    print(f"Wrote: {csv_path}")
    print(f"Wrote: {md_path}")
    print(f"Wrote: {json_path}")
    print("Aggregate:")
    print(f"  Current binary: {current_bin_ok}/{current_total} ({aggregate['current_binary_accuracy']*100:.2f}%)")
    print(f"  Baseline binary: {base_bin_ok}/{current_total} ({aggregate['baseline_binary_accuracy']*100:.2f}%)")
    print(f"  Current full: {current_full_ok}/{current_total} ({aggregate['current_full_accuracy']*100:.2f}%)")
    print(f"  Baseline full: {base_full_ok}/{current_total} ({aggregate['baseline_full_accuracy']*100:.2f}%)")
    print(f"  Current FP/FN: {current_fp}/{current_fn}")
    print(f"  Baseline FP/FN: {base_fp}/{base_fn}")
    print("=" * 100)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
