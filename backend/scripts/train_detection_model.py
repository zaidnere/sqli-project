"""Training entrypoint placeholder for production workflows.

The fully documented, from-scratch NumPy training implementation is in
model1_detection_aligned.ipynb. This script gives the backend repo a clear
place for future CI/Colab integration and documents the exact expected artifacts.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT / "colab_export"

print("Model 1 training workflow")
print("1. Run: python scripts/export_for_colab.py")
print("2. Open model1_detection_aligned.ipynb in Colab")
print("3. Upload:")
print("   -", EXPORT / "vocabulary.json")
print("   -", EXPORT / "training_data.npz")
print("4. Run all cells and download:")
print("   - sqli_detection_model.npz")
print("   - sqli_detection_vocab.json")
print("   - sqli_detection_metadata.json")
print("   - sqli_detection_metrics.json")
print("   - sqli_model.npz (legacy backend compatibility)")
