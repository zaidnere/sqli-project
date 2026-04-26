"""
Validate that sqli_model.npz is present and has the correct structure.

Run from backend/ before starting the server after downloading from Colab:

    python scripts/validate_weights.py

Exit codes:
    0 — weights are valid
    1 — weights missing or malformed
"""

import sys
import os
import numpy as np

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEIGHTS_PATH = os.path.join(BACKEND_DIR, "app", "model", "weights", "sqli_model.npz")

# Must match app/model/sqli_detector.py constants
EXPECTED_SHAPES = {
    "emb_W":         (None, 64),     # (vocab_size, EMBED_DIM)
    "conv_W":        (64,   64, 3),  # (CONV_FILTERS, EMBED_DIM, KERNEL_SIZE)
    "conv_b":        (64,),
    "bilstm_fwd_W":  (128,  96),     # (4*H, EMBED_DIM+H)
    "bilstm_fwd_b":  (128,),
    "bilstm_bwd_W":  (128,  96),
    "bilstm_bwd_b":  (128,),
    "dense1_W":      (64,  128),     # (DENSE_HIDDEN, DENSE_IN)
    "dense1_b":      (64,),
    "dense2_W":      (1,    64),     # (1, DENSE_HIDDEN)
    "dense2_b":      (1,),
}


def shape_matches(actual: tuple, expected: tuple) -> bool:
    """Check shape match, treating None as wildcard dimension."""
    if len(actual) != len(expected):
        return False
    return all(e is None or a == e for a, e in zip(actual, expected))


def validate() -> bool:
    print(f"Checking: {WEIGHTS_PATH}")

    if not os.path.isfile(WEIGHTS_PATH):
        print(f"  ERROR  File not found.")
        print()
        print("  To deploy the model:")
        print("    1. Run:  python scripts/export_for_colab.py")
        print("    2. Upload colab_export/ files to Google Colab")
        print("    3. Train with sqli_colab_training.ipynb")
        print("    4. Download sqli_model.npz")
        print("    5. Copy to:  backend/app/model/weights/sqli_model.npz")
        return False

    try:
        weights = dict(np.load(WEIGHTS_PATH, allow_pickle=False))
    except Exception as exc:
        print(f"  ERROR  Cannot load file: {exc}")
        return False

    ok = True

    # Check all required keys are present
    missing = set(EXPECTED_SHAPES) - set(weights)
    if missing:
        for key in sorted(missing):
            print(f"  ERROR  Missing key: {key}")
        ok = False

    extra = set(weights) - set(EXPECTED_SHAPES)
    if extra:
        for key in sorted(extra):
            print(f"  WARN   Unexpected key (ignored): {key}")

    # Check shapes of present keys
    for key, expected in EXPECTED_SHAPES.items():
        if key not in weights:
            continue
        actual = weights[key].shape
        if not shape_matches(actual, expected):
            print(f"  ERROR  {key}: expected shape {expected}, got {actual}")
            ok = False
        else:
            print(f"  OK     {key}: {actual}")

    # Check for NaN / Inf
    nan_keys = [k for k, v in weights.items() if k in EXPECTED_SHAPES
                and (np.any(np.isnan(v)) or np.any(np.isinf(v)))]
    if nan_keys:
        for key in nan_keys:
            print(f"  ERROR  {key} contains NaN or Inf values")
        ok = False

    # Quick forward-pass smoke test
    if ok:
        sys.path.insert(0, BACKEND_DIR)
        from app.model.sqli_detector import SQLiDetector
        det = SQLiDetector()
        det.load(WEIGHTS_PATH)
        score = det.forward([0] * 256)
        if not (0.0 <= score <= 1.0):
            print(f"  ERROR  Forward pass returned invalid score: {score}")
            ok = False
        else:
            print(f"  OK     Forward pass smoke test (score={score:.4f})")

    print()
    if ok:
        print("Weights are valid. Model is ready to deploy.")
        print("Restart the backend to load the new weights.")
    else:
        print("Weights validation FAILED. Re-train and re-download sqli_model.npz.")

    return ok


if __name__ == "__main__":
    sys.exit(0 if validate() else 1)
