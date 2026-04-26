"""
Juliet CWE-89 Dataset Integration
===================================
Processes the NIST Juliet Test Suite for Java (CWE-89 SQL Injection)
and exports a merged dataset (Juliet + synthetic) for Colab training.

Usage:
    1. Download Juliet Java from https://samate.nist.gov/SARD/test-suites/111
       (or the GitHub mirror: https://github.com/NIST-Software-Assurance-Ref-Datasets/juliet-test-suite-c-cplusplus)
       For Java: https://github.com/NIST-Software-Assurance-Ref-Datasets/juliet-java

    2. Extract to:  datasets/juliet_java_cwe89/
       (or pass --juliet-dir to override)

    3. Run from backend/:
       python scripts/import_juliet.py
       python scripts/import_juliet.py --juliet-dir /path/to/juliet/CWE89

Output:
    colab_export/vocabulary.json        (same fixed vocab)
    colab_export/training_data.npz      (merged Juliet + synthetic)
    colab_export/export_info.json       (updated stats)

Juliet naming convention:
    *_good*.java or *Good*.java   → label 0 (safe)
    *_bad*.java  or *Bad*.java    → label 1 (vulnerable)
"""

import os
import sys
import json
import argparse
import re
import numpy as np
from pathlib import Path

BACKEND_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.vectorization.vocabulary import build_fixed_vocabulary, save_vocabulary
from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.preprocessing.normalizer import normalize_tokens

OUTPUT_DIR = BACKEND_DIR / "colab_export"
MODEL_SEQ_LEN = 256

# Default Juliet directory (relative to project root)
DEFAULT_JULIET_DIR = BACKEND_DIR.parent / "datasets" / "juliet_java_cwe89"


def preprocess_to_ids(code: str, vocab: dict) -> np.ndarray:
    try:
        cleaned = clean_code(code)
        tokens = tokenize_code(cleaned)
        norm = normalize_tokens(tokens)
        unk_id = vocab["UNK"]
        pad_id = vocab["PAD"]
        ids = [vocab.get(t, unk_id) for t in norm]
        if len(ids) >= MODEL_SEQ_LEN:
            return np.array(ids[:MODEL_SEQ_LEN], dtype=np.int32)
        return np.array(ids + [pad_id] * (MODEL_SEQ_LEN - len(ids)), dtype=np.int32)
    except Exception:
        return None


def is_vulnerable_file(path: Path) -> bool | None:
    """
    Determine label from Juliet naming convention.
    Returns True (vulnerable), False (safe), or None (skip).
    """
    name = path.name.lower()

    # Juliet Java convention: Bad = vulnerable, Good = safe
    if "_bad" in name or name.startswith("cwe") and "bad" in name:
        return True
    if "_good" in name or "good" in name:
        return False

    # Support alternative naming: bad.java / good.java suffixes
    if name.endswith("bad.java"):
        return True
    if name.endswith("good.java"):
        return False

    # Files with "Base" are driver/helper files — skip
    if "base" in name or "helper" in name or "support" in name:
        return None

    return None


def load_juliet(juliet_dir: Path, vocab: dict, max_per_class: int = 500) -> tuple:
    """
    Walk the Juliet CWE-89 directory, classify files, preprocess, and vectorize.
    Returns (X, y) arrays.
    """
    java_files = list(juliet_dir.rglob("*.java"))
    print(f"  Found {len(java_files)} Java files in {juliet_dir}")

    vulnerable, safe = [], []

    for f in java_files:
        label = is_vulnerable_file(f)
        if label is None:
            continue

        try:
            code = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # Skip very short files (likely just imports/stubs)
        if len(code.strip()) < 50:
            continue

        ids = preprocess_to_ids(code, vocab)
        if ids is None:
            continue

        if label:
            vulnerable.append(ids)
        else:
            safe.append(ids)

    print(f"  Juliet processed: {len(vulnerable)} vulnerable, {len(safe)} safe")

    # Balance: cap each class
    rng = np.random.default_rng(42)
    if len(vulnerable) > max_per_class:
        idx = rng.choice(len(vulnerable), max_per_class, replace=False)
        vulnerable = [vulnerable[i] for i in idx]
    if len(safe) > max_per_class:
        idx = rng.choice(len(safe), max_per_class, replace=False)
        safe = [safe[i] for i in idx]

    print(f"  After balancing:  {len(vulnerable)} vulnerable, {len(safe)} safe")

    X = np.array(vulnerable + safe, dtype=np.int32)
    y = np.array([1.0] * len(vulnerable) + [0.0] * len(safe), dtype=np.float32)

    return X, y


def load_synthetic(vocab: dict) -> tuple:
    """Load the synthetic dataset from export_for_colab.py."""
    # Import the existing synthetic builder
    from scripts.export_for_colab import build_dataset
    return build_dataset(vocab)


def merge_and_export(juliet_dir: Path):
    OUTPUT_DIR.mkdir(exist_ok=True)

    vocab = build_fixed_vocabulary()
    vocab_path = OUTPUT_DIR / "vocabulary.json"
    save_vocabulary(vocab, str(vocab_path))
    print(f"[1] Vocabulary: {len(vocab)} tokens → {vocab_path}")

    # Synthetic data (always included)
    print("[2] Loading synthetic training data...")
    X_syn, y_syn = load_synthetic(vocab)
    print(f"    Synthetic: {len(X_syn)} samples")

    # Juliet data (if directory exists)
    X_jul, y_jul = np.empty((0, MODEL_SEQ_LEN), dtype=np.int32), np.empty(0, dtype=np.float32)
    if juliet_dir.exists():
        print(f"[3] Loading Juliet CWE-89 from {juliet_dir}...")
        X_jul, y_jul = load_juliet(juliet_dir, vocab)
        print(f"    Juliet: {len(X_jul)} samples")
    else:
        print(f"[3] Juliet directory not found: {juliet_dir}")
        print(f"    Skipping Juliet — using synthetic data only.")
        print(f"    To include Juliet: place dataset at {juliet_dir}")

    # Merge
    if len(X_jul) > 0:
        X = np.concatenate([X_syn, X_jul], axis=0)
        y = np.concatenate([y_syn, y_jul], axis=0)
    else:
        X, y = X_syn, y_syn

    # Shuffle
    rng = np.random.default_rng(42)
    idx = rng.permutation(len(y))
    X, y = X[idx], y[idx]

    n_vuln = int(y.sum())
    n_safe = int((1 - y).sum())

    data_path = OUTPUT_DIR / "training_data.npz"
    np.savez(str(data_path), X=X, y=y)
    print(f"[4] Dataset saved: {len(X)} total ({n_vuln} vuln, {n_safe} safe) → {data_path}")

    info = {
        "vocab_size": len(vocab),
        "model_seq_len": MODEL_SEQ_LEN,
        "n_samples": len(X),
        "n_vulnerable": n_vuln,
        "n_safe": n_safe,
        "sources": {
            "synthetic": int(len(X_syn)),
            "juliet_cwe89": int(len(X_jul)),
        },
    }
    info_path = OUTPUT_DIR / "export_info.json"
    with open(info_path, "w") as f:
        json.dump(info, f, indent=2)
    print(f"[5] Export info → {info_path}")

    print()
    print("=" * 60)
    print("Dataset ready for Colab training.")
    print(f"  Upload: {vocab_path}")
    print(f"          {data_path}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Import Juliet CWE-89 + synthetic data")
    parser.add_argument(
        "--juliet-dir",
        type=Path,
        default=DEFAULT_JULIET_DIR,
        help=f"Path to Juliet CWE-89 Java directory (default: {DEFAULT_JULIET_DIR})",
    )
    args = parser.parse_args()
    merge_and_export(args.juliet_dir)


if __name__ == "__main__":
    main()
