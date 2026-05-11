from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any

SUITE_ORDER = [
    "targeted_next_debug_suite",
    "mega_sqli_debug_suite",
    "realistic_long_sqli_suite",
    "enterprise_realistic_sqli_final_suite",
    "final_framework_obfuscation_stability_suite",
    "adversarial_real_world_sqli_challenge_suite",
    "v18_remaining_edge_focused_suite",
    "v18_provenance_overfit_guard_suite",
    "unseen_generalization_suite_latest_fixed",
    "hard_mixed_sqli_challenge_suite",
    "known_good_sqli_detection_suite",
    "root_cause_attack_type_diagnostic_suite",
    "stable_expected_detection_suite",
]


def _pct(value: float | int | None) -> str:
    if value is None:
        return ""
    return f"{float(value) * 100:.2f}%"


def _threshold_from_dir(path: Path) -> float:
    # Supports names like threshold_0_30, threshold_0_90
    m = re.search(r"threshold_(\d+)_(\d+)", path.name)
    if not m:
        raise ValueError(f"Cannot parse threshold from directory name: {path}")
    return float(f"{m.group(1)}.{m.group(2)}")


def _read_summary(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _collect_threshold(threshold_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    threshold = _threshold_from_dir(threshold_dir)
    rows: list[dict[str, Any]] = []

    agg = {
        "threshold": threshold,
        "total": 0,
        "binary_correct": 0,
        "full_correct": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "true_positives": 0,
        "true_negatives": 0,
        "safe_count": 0,
        "vulnerable_count": 0,
    }

    suite_dirs = []
    for suite in SUITE_ORDER:
        p = threshold_dir / suite
        if p.exists():
            suite_dirs.append(p)

    # Include any extra suite directories that were not in the known order.
    known = {p.name for p in suite_dirs}
    for p in sorted(threshold_dir.iterdir()):
        if p.is_dir() and p.name not in known and (p / "ml_only_summary.json").exists():
            suite_dirs.append(p)

    for suite_dir in suite_dirs:
        summary_path = suite_dir / "ml_only_summary.json"
        if not summary_path.exists():
            continue

        s = _read_summary(summary_path)
        row = {
            "threshold": threshold,
            "suite": suite_dir.name,
            "total": int(s.get("total", 0)),
            "binary_correct": int(s.get("binary_correct", 0)),
            "binary_accuracy": float(s.get("binary_accuracy", 0.0)),
            "full_correct": int(s.get("full_correct", 0)),
            "full_accuracy": float(s.get("full_accuracy", 0.0)),
            "false_positives": int(s.get("false_positives", 0)),
            "false_negatives": int(s.get("false_negatives", 0)),
            "true_positives": int(s.get("true_positives", 0)),
            "true_negatives": int(s.get("true_negatives", 0)),
            "precision": float(s.get("precision", 0.0)),
            "recall": float(s.get("recall", 0.0)),
            "specificity": float(s.get("specificity", 0.0)),
            "f1": float(s.get("f1", 0.0)),
            "model_version": s.get("model_version", ""),
            "threshold_source": s.get("threshold_source", ""),
        }
        rows.append(row)

        for k in [
            "total",
            "binary_correct",
            "full_correct",
            "false_positives",
            "false_negatives",
            "true_positives",
            "true_negatives",
            "safe_count",
            "vulnerable_count",
        ]:
            agg[k] += int(s.get(k, 0))

    total = max(agg["total"], 1)
    predicted_positive = agg["true_positives"] + agg["false_positives"]
    actual_positive = agg["true_positives"] + agg["false_negatives"]
    actual_negative = agg["true_negatives"] + agg["false_positives"]

    precision = (agg["true_positives"] / predicted_positive) if predicted_positive else 0.0
    recall = (agg["true_positives"] / actual_positive) if actual_positive else 0.0
    specificity = (agg["true_negatives"] / actual_negative) if actual_negative else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    agg_row = {
        "threshold": threshold,
        "total": agg["total"],
        "binary_correct": agg["binary_correct"],
        "binary_accuracy": agg["binary_correct"] / total,
        "full_correct": agg["full_correct"],
        "full_accuracy": agg["full_correct"] / total,
        "false_positives": agg["false_positives"],
        "false_negatives": agg["false_negatives"],
        "true_positives": agg["true_positives"],
        "true_negatives": agg["true_negatives"],
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "suite_count": len(rows),
    }

    return rows, agg_row


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect already-generated threshold sweep outputs into final comparison files."
    )
    parser.add_argument("--root", default="outputs/ml95_v2_threshold_sweep")
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        raise SystemExit(f"Output root does not exist: {root}")

    threshold_dirs = sorted(
        [p for p in root.iterdir() if p.is_dir() and p.name.startswith("threshold_")],
        key=_threshold_from_dir,
    )
    if not threshold_dirs:
        raise SystemExit(f"No threshold_* directories found under: {root}")

    all_rows: list[dict[str, Any]] = []
    aggregate_rows: list[dict[str, Any]] = []

    for threshold_dir in threshold_dirs:
        rows, agg = _collect_threshold(threshold_dir)
        if not rows:
            print(f"[warn] no suite summaries found under {threshold_dir}")
            continue
        all_rows.extend(rows)
        aggregate_rows.append(agg)
        print(
            f"threshold={agg['threshold']:.2f}: "
            f"binary={agg['binary_correct']}/{agg['total']} ({agg['binary_accuracy']*100:.2f}%), "
            f"full={agg['full_correct']}/{agg['total']} ({agg['full_accuracy']*100:.2f}%), "
            f"FP/FN={agg['false_positives']}/{agg['false_negatives']}, suites={agg['suite_count']}"
        )

    comparison_dir = root / "_comparison"
    comparison_dir.mkdir(parents=True, exist_ok=True)

    per_suite_csv = comparison_dir / "threshold_sweep_per_suite.csv"
    aggregate_csv = comparison_dir / "threshold_sweep_aggregate.csv"
    aggregate_json = comparison_dir / "threshold_sweep_aggregate.json"
    aggregate_md = comparison_dir / "threshold_sweep_aggregate.md"

    per_suite_fields = [
        "threshold",
        "suite",
        "total",
        "binary_correct",
        "binary_accuracy",
        "full_correct",
        "full_accuracy",
        "false_positives",
        "false_negatives",
        "true_positives",
        "true_negatives",
        "precision",
        "recall",
        "specificity",
        "f1",
        "model_version",
        "threshold_source",
    ]

    with per_suite_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=per_suite_fields)
        writer.writeheader()
        writer.writerows(all_rows)

    aggregate_fields = [
        "threshold",
        "total",
        "binary_correct",
        "binary_accuracy",
        "full_correct",
        "full_accuracy",
        "false_positives",
        "false_negatives",
        "true_positives",
        "true_negatives",
        "precision",
        "recall",
        "specificity",
        "f1",
        "suite_count",
    ]

    with aggregate_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=aggregate_fields)
        writer.writeheader()
        writer.writerows(aggregate_rows)

    aggregate_json.write_text(json.dumps(aggregate_rows, indent=2, ensure_ascii=False), encoding="utf-8")

    md_lines = [
        "# ML-only V18-ML95-v2 External Threshold Sweep",
        "",
        "| Threshold | Binary | Full/type | FP | FN | Precision | Recall | Specificity | F1 | Suites |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for row in aggregate_rows:
        md_lines.append(
            f"| {row['threshold']:.2f} | "
            f"{row['binary_correct']}/{row['total']} ({_pct(row['binary_accuracy'])}) | "
            f"{row['full_correct']}/{row['total']} ({_pct(row['full_accuracy'])}) | "
            f"{row['false_positives']} | {row['false_negatives']} | "
            f"{_pct(row['precision'])} | {_pct(row['recall'])} | "
            f"{_pct(row['specificity'])} | {_pct(row['f1'])} | {row['suite_count']} |"
        )

    best_by_binary = max(
        aggregate_rows,
        key=lambda r: (r["binary_accuracy"], r["full_accuracy"], -r["false_negatives"], -r["false_positives"]),
    )
    best_by_f1 = max(aggregate_rows, key=lambda r: (r["f1"], r["binary_accuracy"]))

    md_lines.extend(
        [
            "",
            f"Best by binary accuracy: threshold **{best_by_binary['threshold']:.2f}** "
            f"with **{best_by_binary['binary_correct']}/{best_by_binary['total']} "
            f"({_pct(best_by_binary['binary_accuracy'])})**.",
            f"Best by F1: threshold **{best_by_f1['threshold']:.2f}** "
            f"with **{_pct(best_by_f1['f1'])}**.",
            "",
            "Files:",
            f"- `{per_suite_csv}`",
            f"- `{aggregate_csv}`",
            f"- `{aggregate_json}`",
            f"- `{per_suite_csv}`",
        ]
    )
    aggregate_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print()
    print("Wrote:")
    print(f"  {aggregate_md}")
    print(f"  {aggregate_json}")
    print(f"  {aggregate_csv}")
    print(f"  {per_suite_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
