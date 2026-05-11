"""Model 1 Detection training workflow helper — V17 type-balanced-flow.

This file keeps the existing name so it can replace the previous
backend/scripts/train_detection_model.py.

V17 goal:
- Keep the V8 ability to recognise SAFE bound/allowlisted/prepared flows.
- Restore stronger vulnerable recall for raw ORDER BY, raw identifiers,
  alias execute, multi-query-one-unsafe, BLIND boolean flows and
  SECOND_ORDER stored/config fragments.
- Improve attack-type classification without copying benchmark suite files.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT / "colab_export"
WEIGHTS = ROOT / "app" / "model" / "weights"

print("Model 1 Detection training workflow — V17 type-balanced-flow")
print()
print("1. From backend, export V17 training data:")
print("   set PYTHONPATH=.")
print("   python scripts\\export_for_colab.py ^")
print("     --out colab_export ^")
print("     --sequence-length 256 ^")
print("     --generated-per-class 4 ^")
print("     --hardcase-per-family 10 ^")
print("     --safe-calibration-per-family 5 ^")
print("     --generated-seeds 20260531 20260601 20260602 ^")
print("     --audit-csv outputs\\model_audit_mega_after_v8.csv ^")
print("     --audit-csv outputs\\model_audit_realistic_after_v8.csv ^")
print("     --audit-csv outputs\\model_audit_framework_after_v8.csv ^")
print("     --audit-csv outputs\\model_audit_enterprise_after_v8.csv ^")
print("     --audit-csv outputs\\model_audit_hard_after_v8.csv ^")
print("     --audit-csv outputs\\model_audit_targeted_after_v8.csv")
print()
print("2. Open model1_detection_aligned.ipynb in Google Colab.")
print("3. Upload these files from:", EXPORT)
print("   - vocabulary.json")
print("   - training_data.npz")
print()
print("4. Run all cells. Download the generated artifacts:")
print("   - sqli_model.npz")
print("   - sqli_detection_model.npz")
print("   - sqli_detection_vocab.json")
print("   - sqli_detection_metadata.json")
print("   - sqli_detection_metrics.json")
print("   - sqli_detection_label_maps.json")
print("   - training_history.json")
print("   - dataset_profile.json")
print("   - split_info.json")
print()
print("5. Copy downloaded artifacts into:", WEIGHTS)
print("6. Restart backend, then rerun audit suites with --force-ml.")
