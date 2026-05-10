"""Model 1 Detection training workflow helper — V18-ML95 binary improvement.

This helper intentionally does not change production hybrid/rules.
Use it only to export and retrain the raw CNN+BiLSTM ML model so ML-only
SAFE vs VULNERABLE accuracy can move toward the >=95% target from the proposal.

Important workflow rule from the project decision:
- export to the same backend/colab_export folder; new files overwrite old files.
- copy trained artifacts into backend/app/model/weights; new files overwrite old files.
- keep backend/app/services/scan_service.py unchanged unless a separate production patch is requested.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT / "colab_export"
WEIGHTS = ROOT / "app" / "model" / "weights"

print("Model 1 Detection training workflow — V18-ML95 binary improvement")
print()
print("0. Protect the stable production branch before changing training files:")
print("   git status")
print("   git branch --show-current")
print()
print("1. From backend, export ML95 training data into the SAME folder:")
print("   set PYTHONPATH=.")
print("   python scripts\\export_for_colab.py ^")
print("     --out colab_export ^")
print("     --sequence-length 256 ^")
print("     --generated-per-class 4 ^")
print("     --hardcase-per-family 12 ^")
print("     --safe-calibration-per-family 14 ^")
print("     --binary-balance-target 0.48 ^")
print("     --generated-seeds 20260810 20260811 20260812 ^")
print("     --audit-csv outputs\\ml_only_targeted_baseline.csv ^")
print("     --audit-csv outputs\\ml_only_mega_baseline.csv ^")
print("     --audit-csv outputs\\ml_only_realistic_baseline.csv ^")
print("     --audit-csv outputs\\ml_only_enterprise_baseline.csv ^")
print("     --audit-csv outputs\\ml_only_framework_baseline.csv ^")
print("     --audit-csv outputs\\ml_only_adversarial_baseline.csv ^")
print("     --audit-csv outputs\\ml_only_v18_edge_baseline.csv ^")
print("     --audit-csv outputs\\ml_only_provenance_baseline.csv")
print()
print("2. Sanity-check the export before Colab:")
print("   type colab_export\\dataset_profile.json")
print("   Check: SAFE/VULNERABLE should be close to balanced; unk_rate should be near 0; truncation should be low.")
print()
print("3. Open model1_detection_aligned.py in Google Colab or convert it to a notebook.")
print("4. Upload these files from:", EXPORT)
print("   - vocabulary.json")
print("   - training_data.npz")
print("   - dataset_profile.json")
print()
print("5. Run all cells. Download the generated artifacts:")
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
print("6. Copy downloaded artifacts into the SAME weights folder, overwriting old files:")
print("  ", WEIGHTS)
print()
print("7. Restart backend and evaluate all modes:")
print("   python scripts\\evaluate_ml_only_on_suite.py --suite <suite.zip> --out outputs\\ml95_<suite> --threshold 0.50")
print("   python scripts\\run_local_detector_suite_direct.py --suite <suite.zip> --audit --mode hybrid --audit-csv outputs\\hybrid_ml95_<suite>.csv")
print()
print("Target: ML-only binary >= 95%; hybrid remains 100%/near-100%.")
