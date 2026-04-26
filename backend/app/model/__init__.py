"""
SQL Injection detection model package.

Contents:
  sqli_detector.py  — forward-pass NumPy CNN+BiLSTM (matches Colab architecture)
  inference.py      — singleton loader + run_inference() entry point
  weights/          — place sqli_model.npz here after Colab training

See weights/README.md for the full Colab → backend deployment workflow.
"""
