"""
Model 2 — Fix Recommendation Model (inference only).

Architecture (must match sqli_colab_training.ipynb Model 2 section):
    Embedding (shared with Model 1, frozen)
    → GlobalAvgPool  (mean over sequence)
    → Dense + ReLU   (EMBED_DIM → M2_HIDDEN=32)
    → Dense + Softmax (32 → 4 fix classes)

Fix classes:
    0 = A  Parameterized Query
    1 = B  Whitelist Validation
    2 = C  ORM Migration
    3 = D  Second-Order Mitigation

Weight keys in sqli_fix_model.npz:
    m2_dense1_W  (32, 64)
    m2_dense1_b  (32,)
    m2_dense2_W  (4, 32)
    m2_dense2_b  (4,)

Note: the embedding (emb_W) is shared with Model 1 (sqli_model.npz).
Model 2 uses it read-only during inference.
"""

import logging
import os
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

_WEIGHTS_DIR = os.path.join(os.path.dirname(__file__), "weights")
FIX_WEIGHTS_PATH = os.path.join(_WEIGHTS_DIR, "sqli_fix_model.npz")

FIX_CLASSES = {0: "A", 1: "B", 2: "C", 3: "D"}
FIX_LABELS  = {
    "A": "Parameterized Query",
    "B": "Whitelist Validation",
    "C": "ORM Migration",
    "D": "Second-Order Mitigation",
}

_fix_weights: Optional[dict] = None
_fix_load_attempted = False


def _load_fix_model() -> Optional[dict]:
    global _fix_weights, _fix_load_attempted
    if _fix_load_attempted:
        return _fix_weights
    _fix_load_attempted = True

    if not os.path.isfile(FIX_WEIGHTS_PATH):
        logger.warning(
            "Model 2 weights not found at %s. "
            "Train Model 2 in Colab and place sqli_fix_model.npz in app/model/weights/.",
            FIX_WEIGHTS_PATH,
        )
        return None

    try:
        w = dict(np.load(FIX_WEIGHTS_PATH, allow_pickle=False))
        _fix_weights = w
        logger.info("Model 2 (Fix) weights loaded from %s", FIX_WEIGHTS_PATH)
        return w
    except Exception as exc:
        logger.error("Failed to load Model 2 weights: %s", exc)
        return None


def _softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - x.max())
    return e / e.sum()


def _relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(0.0, x)


def run_fix_inference(token_ids: list[int], emb_W: np.ndarray) -> Optional[dict]:
    """
    Run Model 2 forward pass.

    Parameters
    ----------
    token_ids : list of ints, length MODEL_SEQ_LEN (from vectorizer)
    emb_W     : embedding matrix from Model 1 weights (shape: vocab_size × EMBED_DIM)

    Returns dict with fixType, fixStrategy, confidence — or None if weights not loaded.
    """
    w = _load_fix_model()
    if w is None:
        return None

    from app.model.sqli_detector import MODEL_SEQ_LEN
    ids = np.array(token_ids[:MODEL_SEQ_LEN], dtype=np.int32)
    emb = emb_W[ids]                                    # (seq_len, EMBED_DIM)
    pooled = emb.mean(axis=0)                           # (EMBED_DIM,)
    h = _relu(w["m2_dense1_W"] @ pooled + w["m2_dense1_b"])  # (M2_HIDDEN,)
    logits = w["m2_dense2_W"] @ h + w["m2_dense2_b"]   # (4,)
    probs = _softmax(logits)                            # (4,)

    best_idx = int(np.argmax(probs))
    fix_type = FIX_CLASSES[best_idx]

    return {
        "fixType": fix_type,
        "fixStrategy": FIX_LABELS[fix_type],
        "confidence": round(float(probs[best_idx]), 4),
        "allProbabilities": {FIX_CLASSES[i]: round(float(p), 4) for i, p in enumerate(probs)},
    }


def fix_model_is_loaded() -> bool:
    return _load_fix_model() is not None
