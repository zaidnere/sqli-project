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
# REQUIRED keys are the shared backbone + the original vuln head.
# OPTIONAL keys are the Gap-A attack-type head; older weights without these
# still load (with the type head disabled).
REQUIRED_SHAPES = {
    "emb_W":         (None, 64),     # (vocab_size, EMBED_DIM)
    "conv_W":        (64,   64, 3),  # (CONV_FILTERS, EMBED_DIM, KERNEL_SIZE)
    "conv_b":        (64,),
    "bilstm_fwd_W":  (128,  96),     # (4*H, EMBED_DIM+H)
    "bilstm_fwd_b":  (128,),
    "bilstm_bwd_W":  (128,  96),
    "bilstm_bwd_b":  (128,),
    "dense1_W":      (64,  128),     # (DENSE_HIDDEN, DENSE_IN)
    "dense1_b":      (64,),
    "dense2_W":      (1,    64),     # vuln head:        (1, DENSE_HIDDEN)
    "dense2_b":      (1,),
}

OPTIONAL_SHAPES = {
    "dense2_type_W": (4,    64),     # attack-type head: (NUM_CLASSES, DENSE_HIDDEN)
    "dense2_type_b": (4,),
}

EXPECTED_SHAPES = {**REQUIRED_SHAPES, **OPTIONAL_SHAPES}


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
        print("    3. Train with model1_detection.ipynb")
        print("    4. Download sqli_model.npz")
        print("    5. Copy to:  backend/app/model/weights/sqli_model.npz")
        return False

    try:
        weights = dict(np.load(WEIGHTS_PATH, allow_pickle=False))
    except Exception as exc:
        print(f"  ERROR  Cannot load file: {exc}")
        return False

    ok = True

    # 1. REQUIRED keys must all be present
    missing_required = set(REQUIRED_SHAPES) - set(weights)
    if missing_required:
        for key in sorted(missing_required):
            print(f"  ERROR  Missing required key: {key}")
        ok = False

    # 2. OPTIONAL keys (Gap-A attack-type head) — note presence/absence
    optional_present = set(OPTIONAL_SHAPES) & set(weights)
    optional_missing = set(OPTIONAL_SHAPES) - set(weights)
    has_attack_type_head = (len(optional_missing) == 0)

    # 3. Unexpected keys — warn only
    extra = set(weights) - set(EXPECTED_SHAPES)
    if extra:
        for key in sorted(extra):
            print(f"  WARN   Unexpected key (ignored): {key}")

    # 4. Shape check on every present key
    for key, expected in EXPECTED_SHAPES.items():
        if key not in weights:
            continue
        actual = weights[key].shape
        if not shape_matches(actual, expected):
            print(f"  ERROR  {key}: expected shape {expected}, got {actual}")
            ok = False
        else:
            tag = "OK    " if key in REQUIRED_SHAPES else "OK+TYP"
            print(f"  {tag} {key}: {actual}")

    # 5. NaN / Inf check
    nan_keys = [k for k, v in weights.items()
                if k in EXPECTED_SHAPES and (np.any(np.isnan(v)) or np.any(np.isinf(v)))]
    if nan_keys:
        for key in nan_keys:
            print(f"  ERROR  {key} contains NaN or Inf values")
        ok = False

    # 6. Forward-pass smoke test (uses the new dual-head dict return)
    if ok:
        sys.path.insert(0, BACKEND_DIR)
        from app.model.sqli_detector import (
            SQLiDetector, MODEL_SEQ_LEN, ATTACK_TYPE_NUM_CLASSES,
        )
        det = SQLiDetector()
        det.load(WEIGHTS_PATH)
        out = det.forward([0] * MODEL_SEQ_LEN)
        score = out["riskScore"]
        probs = out["attackTypeProbs"]
        if not (0.0 <= score <= 1.0):
            print(f"  ERROR  Vuln head returned invalid score: {score}")
            ok = False
        elif probs.shape != (ATTACK_TYPE_NUM_CLASSES,):
            print(f"  ERROR  Attack-type head returned wrong shape: {probs.shape}")
            ok = False
        elif not np.isclose(probs.sum(), 1.0, atol=1e-4):
            print(f"  ERROR  Attack-type probs do not sum to 1.0: sum={probs.sum():.6f}")
            ok = False
        else:
            print(f"  OK     Forward pass smoke test")
            print(f"           vuln head score = {score:.4f}")
            print(f"           attack-type     = {out['attackTypeName']} "
                  f"(p={probs[out['attackTypeId']]:.4f})")

    print()
    if ok:
        print("Weights are valid. Model is ready to deploy.")

        # Check vocab-size consistency: old weights with new vocab → out-of-bounds
        try:
            import json
            from app.vectorization.vocabulary import build_fixed_vocabulary
            current_vocab_size = len(build_fixed_vocabulary())
            weights_vocab_size = weights["emb_W"].shape[0]
            if current_vocab_size != weights_vocab_size:
                print()
                print(f"WARNING: vocab size mismatch.")
                print(f"  Current vocabulary:  {current_vocab_size} tokens")
                print(f"  Weights expect:      {weights_vocab_size} tokens")
                print(f"  Token IDs >= {weights_vocab_size} will crash inference.")
                print(f"  Re-train Model 1 with the new vocabulary.")
        except Exception:
            pass

        if not has_attack_type_head:
            print()
            print("NOTE: This .npz predates Gap A — it lacks the attack-type head.")
            print("      The backend will run, but every prediction will report")
            print("      attackType=NONE. Re-train with the new notebook to fix.")
        print("Restart the backend to load the new weights.")
    else:
        print("Weights validation FAILED. Re-train and re-download sqli_model.npz.")

    return ok


if __name__ == "__main__":
    sys.exit(0 if validate() else 1)
