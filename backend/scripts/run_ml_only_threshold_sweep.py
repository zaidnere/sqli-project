from __future__ import annotations

# This wrapper keeps the original workflow but delegates final collection to the collector.
# Prefer using collect_ml_only_threshold_sweep_results.py when the threshold run already completed.

import argparse
import subprocess
import sys
from pathlib import Path

SUITES = [
    "targeted_next_debug_suite.zip",
    "mega_sqli_debug_suite.zip",
    "realistic_long_sqli_suite.zip",
    "enterprise_realistic_sqli_final_suite.zip",
    "final_framework_obfuscation_stability_suite.zip",
    "adversarial_real_world_sqli_challenge_suite.zip",
    "v18_remaining_edge_focused_suite.zip",
    "v18_provenance_overfit_guard_suite.zip",
    "unseen_generalization_suite_latest_fixed.zip",
    "hard_mixed_sqli_challenge_suite.zip",
    "known_good_sqli_detection_suite.zip",
    "root_cause_attack_type_diagnostic_suite.zip",
    "stable_expected_detection_suite.zip",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--thresholds", nargs="+", type=float, default=[0.30, 0.40, 0.50, 0.52, 0.60, 0.70, 0.80, 0.90])
    parser.add_argument("--sequence-length", type=int, default=256)
    parser.add_argument("--suite-dir", default="test_suites")
    parser.add_argument("--out", default="outputs/ml95_v2_threshold_sweep")
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()

    root = Path.cwd()
    suite_dir = root / args.suite_dir
    out_root = root / args.out
    out_root.mkdir(parents=True, exist_ok=True)

    for threshold in args.thresholds:
        threshold_key = f"{threshold:.2f}".replace(".", "_")
        threshold_dir = out_root / f"threshold_{threshold_key}"
        threshold_dir.mkdir(parents=True, exist_ok=True)

        print()
        print("=" * 100)
        print(f"Running all suites at threshold={threshold:.2f}")
        print("=" * 100)

        for suite_name in SUITES:
            suite_path = suite_dir / suite_name
            suite_stem = suite_name.removesuffix(".zip")
            suite_out = threshold_dir / suite_stem

            if (suite_out / "ml_only_summary.json").exists():
                print(f"[skip existing] threshold={threshold:.2f} {suite_name}")
                continue

            cmd = [
                args.python,
                "scripts/evaluate_ml_only_on_suite.py",
                "--suite", str(suite_path),
                "--out", str(suite_out),
                "--sequence-length", str(args.sequence_length),
                "--threshold", str(threshold),
            ]
            print(f"\n[threshold={threshold:.2f}] {suite_name}")
            subprocess.run(cmd, check=True)

    subprocess.run(
        [
            args.python,
            "scripts/collect_ml_only_threshold_sweep_results.py",
            "--root",
            args.out,
        ],
        check=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
