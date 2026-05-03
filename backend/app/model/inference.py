"""
Inference service for the SQL Injection detection model.

Behaviour:
- On first call, tries to load weights from WEIGHTS_PATH.
- If the file does not exist (model not yet trained in Colab), returns None
  so the rest of the pipeline can proceed gracefully.
- Once loaded, the model instance is reused for every subsequent request
  (singleton pattern — weights are loaded once at startup).

Integration:
    from app.model.inference import run_inference

    result = run_inference(token_ids)
    # result is None  →  model not yet deployed
    # result is dict with keys:
    #     riskScore, label, vulnerabilityType, recommendation, modelLoaded
    #     attackType, attackTypeId, attackTypeConfidence, attackTypeProbs,
    #     attackTypeAvailable
    #
    # The attack-type fields come from the Gap-A softmax head. If the loaded
    # weights predate Gap A, attackTypeAvailable=False and attackType="NONE".
"""

import os
import logging
from typing import Optional, List

from app.model.sqli_detector import SQLiDetector

logger = logging.getLogger(__name__)

# ── Path to the trained weights file ─────────────────────────────────────────
# User places sqli_model.npz here after training in Colab.
_WEIGHTS_DIR = os.path.join(os.path.dirname(__file__), "weights")
WEIGHTS_PATH = os.path.join(_WEIGHTS_DIR, "sqli_model.npz")

# ── Singleton ─────────────────────────────────────────────────────────────────
_detector: Optional[SQLiDetector] = None
_load_attempted: bool = False


def _load_model() -> Optional[SQLiDetector]:
    """
    Attempt to load the model weights once.
    Returns the detector if successful, None otherwise.
    """
    global _detector, _load_attempted
    if _load_attempted:
        return _detector

    _load_attempted = True

    if not os.path.isfile(WEIGHTS_PATH):
        logger.warning(
            "Model weights not found at %s. "
            "Train the model in Colab and place sqli_model.npz in app/model/weights/. "
            "Scans will return detection=None until the model is loaded.",
            WEIGHTS_PATH,
        )
        return None

    try:
        detector = SQLiDetector()
        detector.load(WEIGHTS_PATH)
        _detector = detector
        logger.info("SQLi detection model loaded from %s", WEIGHTS_PATH)
        return _detector
    except Exception as exc:
        logger.error("Failed to load model weights: %s", exc)
        return None


def run_inference(token_ids: List[int]) -> Optional[dict]:
    """
    Run the detection model on a list of token IDs.

    Returns:
        dict with keys:
            riskScore, label, vulnerabilityType, recommendation, modelLoaded,
            attackType, attackTypeId, attackTypeConfidence, attackTypeProbs,
            attackTypeAvailable
        — or —
        None if the model has not been trained / deployed yet.
    """
    detector = _load_model()
    if detector is None:
        return None
    return detector.predict(token_ids)


def model_is_loaded() -> bool:
    """Return True if the model weights have been successfully loaded."""
    return _load_model() is not None
