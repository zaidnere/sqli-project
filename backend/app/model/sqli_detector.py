"""
SQL Injection Detection Model — Forward Pass Only (Backend Inference).

This module is the backend counterpart of the Colab training notebook.
It defines the SAME architecture (same layer shapes, same weight key names)
so that weights saved in Colab (.npz) can be loaded here directly.

Architecture (must match model1_detection.ipynb exactly):

    Input (token_ids, length = MODEL_SEQ_LEN = 256)
        -> Embedding Layer          (vocab_size x EMBED_DIM=64)
        -> Conv1D + ReLU + MaxPool  (CONV_FILTERS=64, kernel=3)  -> (64,)
        -> Bi-LSTM                  (LSTM_HIDDEN=32 each dir)    -> (64,)
        -> Concatenate CNN + LSTM output                         -> (128,)
        -> Dense + ReLU             (DENSE_HIDDEN=64)            -> (64,)        [shared backbone ends here]
        ├─> Dense + Sigmoid         (1,)   -> riskScore           ∈ [0, 1]        [vuln head]
        └─> Dense + Softmax         (4,)   -> attackTypeProbs     ∈ ℝ⁴           [attack-type head]

Both heads share the dense hidden layer. The vulnerability head answers
"is this code vulnerable?" (binary). The attack-type head answers
"which kind of SQL injection?" (4-way: NONE, IN_BAND, BLIND, SECOND_ORDER).

The proposal (page 8, page 31) requires Model 1 to emit BOTH outputs.
Pre-Gap-A models had only the vulnerability head. New weight files include
the additional `dense2_type_W` and `dense2_type_b` tensors.

Weight keys in sqli_model.npz (from Colab training):
    emb_W              (vocab_size, 64)
    conv_W             (64, 64, 3)
    conv_b             (64,)
    bilstm_fwd_W       (128, 96)
    bilstm_fwd_b       (128,)
    bilstm_bwd_W       (128, 96)
    bilstm_bwd_b       (128,)
    dense1_W           (64, 128)
    dense1_b           (64,)
    dense2_W           (1, 64)            -- vuln head
    dense2_b           (1,)
    dense2_type_W      (4, 64)            -- attack-type head (NEW: Gap A)
    dense2_type_b      (4,)
"""

import numpy as np
from typing import Optional, List


EMBED_DIM = 64
CONV_FILTERS = 64
KERNEL_SIZE = 3
LSTM_HIDDEN = 32
DENSE_HIDDEN = 64
DENSE_IN = CONV_FILTERS + 2 * LSTM_HIDDEN   # = 128

# ML-primary v4 uses 256 tokens so the Bi-LSTM sees more context
# for source-to-sink, BLIND, and SECOND_ORDER patterns.
# Keep this value aligned with sqli_detection_metadata.json.
MODEL_SEQ_LEN = 256


# ─────────────────────────────────────────────────────────────────────────────
# Attack-type taxonomy — keep in sync with scripts/export_for_colab.py
# ─────────────────────────────────────────────────────────────────────────────
# Class IDs are the values produced by `category_to_attack_type()` at export
# time and consumed by the softmax head at inference. Order is fixed.
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_TYPE_NONE         = 0
ATTACK_TYPE_IN_BAND      = 1
ATTACK_TYPE_BLIND        = 2
ATTACK_TYPE_SECOND_ORDER = 3
ATTACK_TYPE_NUM_CLASSES  = 4

ATTACK_TYPE_NAMES = {
    ATTACK_TYPE_NONE:         "NONE",
    ATTACK_TYPE_IN_BAND:      "IN_BAND",
    ATTACK_TYPE_BLIND:        "BLIND",
    ATTACK_TYPE_SECOND_ORDER: "SECOND_ORDER",
}


# ─────────────────────────────────────────────────────────────────────────────
# Activation functions
# ─────────────────────────────────────────────────────────────────────────────

def _sigmoid(x: np.ndarray) -> np.ndarray:
    return np.where(x >= 0, 1.0 / (1.0 + np.exp(-x)), np.exp(x) / (1.0 + np.exp(x)))


def _relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(0.0, x)


def _softmax(x: np.ndarray) -> np.ndarray:
    """Numerically stable softmax for a 1-D logit vector."""
    shifted = x - np.max(x)
    exp = np.exp(shifted)
    return exp / np.sum(exp)


# ─────────────────────────────────────────────────────────────────────────────
# Detector
# ─────────────────────────────────────────────────────────────────────────────

class SQLiDetector:
    """Forward-pass-only SQL injection detector. Loads weights from Colab .npz.

    Two output heads (Gap A):
        - vulnerability score (sigmoid, scalar in [0, 1])
        - attack-type probability distribution (softmax, 4 classes)

    Both heads share the CNN+BiLSTM+Dense backbone.
    """

    def __init__(self) -> None:
        self._loaded = False
        # Backbone weights
        self.emb_W: Optional[np.ndarray] = None
        self.conv_W: Optional[np.ndarray] = None
        self.conv_b: Optional[np.ndarray] = None
        self.bilstm_fwd_W: Optional[np.ndarray] = None
        self.bilstm_fwd_b: Optional[np.ndarray] = None
        self.bilstm_bwd_W: Optional[np.ndarray] = None
        self.bilstm_bwd_b: Optional[np.ndarray] = None
        self.dense1_W: Optional[np.ndarray] = None
        self.dense1_b: Optional[np.ndarray] = None
        # Vuln head (binary, sigmoid)
        self.dense2_W: Optional[np.ndarray] = None
        self.dense2_b: Optional[np.ndarray] = None
        # Attack-type head (multiclass, softmax) — new in Gap A
        self.dense2_type_W: Optional[np.ndarray] = None
        self.dense2_type_b: Optional[np.ndarray] = None

    # ── Loading ──────────────────────────────────────────────────────────────

    def load(self, path: str) -> None:
        """
        Load weights from a Colab-trained .npz file.

        Backwards compatibility: a single-head .npz from before Gap A is
        accepted, but the attack-type head will be marked as missing and
        every prediction will return NONE for `attackType`. This allows
        running the new backend with old weights as a degraded fallback.
        """
        d = dict(np.load(path, allow_pickle=False))
        self.emb_W        = d["emb_W"].astype(np.float32)
        self.conv_W       = d["conv_W"].astype(np.float32)
        self.conv_b       = d["conv_b"].astype(np.float32)
        self.bilstm_fwd_W = d["bilstm_fwd_W"].astype(np.float32)
        self.bilstm_fwd_b = d["bilstm_fwd_b"].astype(np.float32)
        self.bilstm_bwd_W = d["bilstm_bwd_W"].astype(np.float32)
        self.bilstm_bwd_b = d["bilstm_bwd_b"].astype(np.float32)
        self.dense1_W     = d["dense1_W"].astype(np.float32)
        self.dense1_b     = d["dense1_b"].astype(np.float32)
        self.dense2_W     = d["dense2_W"].astype(np.float32)
        self.dense2_b     = d["dense2_b"].astype(np.float32)

        # Attack-type head — present in Gap A weights, absent in older weights.
        if "dense2_type_W" in d and "dense2_type_b" in d:
            self.dense2_type_W = d["dense2_type_W"].astype(np.float32)
            self.dense2_type_b = d["dense2_type_b"].astype(np.float32)
        else:
            self.dense2_type_W = None
            self.dense2_type_b = None

        self._loaded = True

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def has_attack_type_head(self) -> bool:
        """True if the loaded weights include the Gap-A attack-type head."""
        return self.dense2_type_W is not None and self.dense2_type_b is not None

    # ── Layer ops ────────────────────────────────────────────────────────────

    def _embedding(self, token_ids: np.ndarray) -> np.ndarray:
        return self.emb_W[token_ids]

    def _conv1d_maxpool(self, emb: np.ndarray) -> np.ndarray:
        seq_len = emb.shape[0]
        k = KERNEL_SIZE
        out_len = max(1, seq_len - k + 1)
        W_flat = self.conv_W.reshape(CONV_FILTERS, -1)   # (F, k*in_ch)
        conv_out = np.zeros((out_len, CONV_FILTERS), dtype=np.float32)
        for pos in range(out_len):
            patch = emb[pos: pos + k].flatten()
            conv_out[pos] = W_flat @ patch + self.conv_b
        return np.max(_relu(conv_out), axis=0)

    def _lstm_step(self, x_t, h, c, W, b):
        H = LSTM_HIDDEN
        gates = W @ np.concatenate([x_t, h]) + b
        f = _sigmoid(gates[0 * H: 1 * H])
        i = _sigmoid(gates[1 * H: 2 * H])
        o = _sigmoid(gates[2 * H: 3 * H])
        g = np.tanh (gates[3 * H: 4 * H])
        c_new = f * c + i * g
        h_new = o * np.tanh(c_new)
        return h_new, c_new

    def _bilstm(self, emb: np.ndarray) -> np.ndarray:
        H = LSTM_HIDDEN
        seq_len = emb.shape[0]
        # Forward direction
        h = np.zeros(H, dtype=np.float32)
        c = np.zeros(H, dtype=np.float32)
        for t in range(seq_len):
            h, c = self._lstm_step(emb[t], h, c, self.bilstm_fwd_W, self.bilstm_fwd_b)
        h_fwd = h
        # Backward direction
        h = np.zeros(H, dtype=np.float32)
        c = np.zeros(H, dtype=np.float32)
        for t in reversed(range(seq_len)):
            h, c = self._lstm_step(emb[t], h, c, self.bilstm_bwd_W, self.bilstm_bwd_b)
        return np.concatenate([h_fwd, h])

    def _prepare_input(self, token_ids: List[int]) -> np.ndarray:
        ids = np.array(token_ids, dtype=np.int32)
        if len(ids) >= MODEL_SEQ_LEN:
            return ids[:MODEL_SEQ_LEN]
        return np.concatenate([ids, np.zeros(MODEL_SEQ_LEN - len(ids), dtype=np.int32)])

    # ── Forward pass ─────────────────────────────────────────────────────────

    def forward(self, token_ids: List[int]) -> dict:
        """
        Run a single forward pass.

        Returns a dict with:
            riskScore         : float in [0, 1]  — vuln head (sigmoid)
            attackTypeProbs   : np.ndarray (4,)  — softmax over the 4 classes
                                                   (zeros + NONE=1 if head missing)
            attackTypeId      : int 0..3         — argmax of probs
            attackTypeName    : str              — human-readable class name
        """
        seq      = self._prepare_input(token_ids)
        emb      = self._embedding(seq)
        cnn_out  = self._conv1d_maxpool(emb)
        lstm_out = self._bilstm(emb)
        combined = np.concatenate([cnn_out, lstm_out])

        # Shared backbone — computed once, used by both heads
        h = _relu(self.dense1_W @ combined + self.dense1_b)

        # Head 1: vulnerability (binary, sigmoid)
        risk_score = float(_sigmoid(self.dense2_W @ h + self.dense2_b)[0])

        # Head 2: attack type (4-way, softmax). Falls back to NONE if the
        # loaded weights predate Gap A.
        if self.has_attack_type_head:
            type_logits = self.dense2_type_W @ h + self.dense2_type_b
            type_probs  = _softmax(type_logits)
        else:
            type_probs = np.zeros(ATTACK_TYPE_NUM_CLASSES, dtype=np.float32)
            type_probs[ATTACK_TYPE_NONE] = 1.0

        type_id   = int(np.argmax(type_probs))
        type_name = ATTACK_TYPE_NAMES[type_id]

        return {
            "riskScore":       risk_score,
            "attackTypeProbs": type_probs,
            "attackTypeId":    type_id,
            "attackTypeName":  type_name,
        }

    # ── User-facing prediction ───────────────────────────────────────────────

    def predict(self, token_ids: List[int]) -> dict:
        """
        Convenience wrapper that returns a structured prediction including
        verdict label, recommendation text, and attack-type info.

        The verdict label is driven solely by the vuln head's risk score.
        The attack-type head is reported alongside but does NOT alter the
        Vulnerable / Suspicious / Safe verdict — that contract is preserved
        from before Gap A.
        """
        if not self._loaded:
            raise RuntimeError("Model weights not loaded.")

        out = self.forward(token_ids)
        score = out["riskScore"]

        if score >= 0.70:
            label = "Vulnerable"
            vuln_type = "SQL Injection"
            recommendation = (
                "Use parameterized queries (prepared statements) instead of "
                "string concatenation. Never build SQL queries from user-controlled "
                "input directly. Consider using an ORM such as SQLAlchemy."
            )
        elif score >= 0.45:
            label = "Suspicious"
            vuln_type = "Possible SQL Injection"
            recommendation = (
                "Manual review recommended. The code shows patterns associated "
                "with SQL injection risk. Verify that all user input is properly "
                "parameterized before reaching the database layer."
            )
        else:
            label = "Safe"
            vuln_type = None
            recommendation = (
                "No SQL injection pattern detected. Continue using parameterized "
                "queries and input validation as best practice."
            )

        # Build human-readable per-class probabilities. Always emit all 4
        # entries so the API contract is stable regardless of which weights
        # are loaded.
        probs = out["attackTypeProbs"]
        attack_type_probs_dict = {
            ATTACK_TYPE_NAMES[cid]: round(float(probs[cid]), 4)
            for cid in range(ATTACK_TYPE_NUM_CLASSES)
        }

        return {
            "riskScore":           round(score, 4),
            "label":               label,
            "vulnerabilityType":   vuln_type,
            "recommendation":      recommendation,
            "attackType":          out["attackTypeName"],
            "attackTypeId":        out["attackTypeId"],
            "attackTypeConfidence": round(float(probs[out["attackTypeId"]]), 4),
            "attackTypeProbs":     attack_type_probs_dict,
            "attackTypeAvailable": self.has_attack_type_head,
            "modelLoaded":         True,
        }
