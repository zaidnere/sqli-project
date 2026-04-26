"""
SQL Injection Detection Model — Forward Pass Only (Backend Inference).

This module is the backend counterpart of the Colab training notebook.
It defines the SAME architecture (same layer shapes, same weight key names)
so that weights saved in Colab (.npz) can be loaded here directly.

Architecture (must match sqli_colab_training.ipynb exactly):
    Input (token_ids, length = MODEL_SEQ_LEN = 256)
    -> Embedding Layer          (vocab_size x EMBED_DIM=64)
    -> Conv1D + ReLU + MaxPool  (CONV_FILTERS=64, kernel=3)  -> (64,)
    -> Bi-LSTM                  (LSTM_HIDDEN=32 each dir)    -> (64,)
    -> Concatenate CNN + LSTM output                         -> (128,)
    -> Dense + ReLU             (DENSE_HIDDEN=64)            -> (64,)
    -> Dense + Sigmoid          (1,)                         -> risk score

Weight keys in sqli_model.npz:
    emb_W              (vocab_size, 64)
    conv_W             (64, 64, 3)
    conv_b             (64,)
    bilstm_fwd_W       (128, 96)
    bilstm_fwd_b       (128,)
    bilstm_bwd_W       (128, 96)
    bilstm_bwd_b       (128,)
    dense1_W           (64, 128)
    dense1_b           (64,)
    dense2_W           (1, 64)
    dense2_b           (1,)
"""

import numpy as np
from typing import Optional, List


EMBED_DIM = 64
CONV_FILTERS = 64
KERNEL_SIZE = 3
LSTM_HIDDEN = 32
DENSE_HIDDEN = 64
DENSE_IN = CONV_FILTERS + 2 * LSTM_HIDDEN   # = 128
MODEL_SEQ_LEN = 256


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return np.where(x >= 0, 1.0 / (1.0 + np.exp(-x)), np.exp(x) / (1.0 + np.exp(x)))


def _relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(0.0, x)


class SQLiDetector:
    """Forward-pass-only SQL injection detector. Loads weights from Colab .npz."""

    def __init__(self) -> None:
        self._loaded = False
        self.emb_W: Optional[np.ndarray] = None
        self.conv_W: Optional[np.ndarray] = None
        self.conv_b: Optional[np.ndarray] = None
        self.bilstm_fwd_W: Optional[np.ndarray] = None
        self.bilstm_fwd_b: Optional[np.ndarray] = None
        self.bilstm_bwd_W: Optional[np.ndarray] = None
        self.bilstm_bwd_b: Optional[np.ndarray] = None
        self.dense1_W: Optional[np.ndarray] = None
        self.dense1_b: Optional[np.ndarray] = None
        self.dense2_W: Optional[np.ndarray] = None
        self.dense2_b: Optional[np.ndarray] = None

    def load(self, path: str) -> None:
        d = dict(np.load(path, allow_pickle=False))
        self.emb_W = d["emb_W"].astype(np.float32)
        self.conv_W = d["conv_W"].astype(np.float32)
        self.conv_b = d["conv_b"].astype(np.float32)
        self.bilstm_fwd_W = d["bilstm_fwd_W"].astype(np.float32)
        self.bilstm_fwd_b = d["bilstm_fwd_b"].astype(np.float32)
        self.bilstm_bwd_W = d["bilstm_bwd_W"].astype(np.float32)
        self.bilstm_bwd_b = d["bilstm_bwd_b"].astype(np.float32)
        self.dense1_W = d["dense1_W"].astype(np.float32)
        self.dense1_b = d["dense1_b"].astype(np.float32)
        self.dense2_W = d["dense2_W"].astype(np.float32)
        self.dense2_b = d["dense2_b"].astype(np.float32)
        self._loaded = True

    @property
    def is_loaded(self) -> bool:
        return self._loaded

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
        f = _sigmoid(gates[0*H: 1*H])
        i = _sigmoid(gates[1*H: 2*H])
        o = _sigmoid(gates[2*H: 3*H])
        g = np.tanh(gates[3*H: 4*H])
        c_new = f * c + i * g
        h_new = o * np.tanh(c_new)
        return h_new, c_new

    def _bilstm(self, emb: np.ndarray) -> np.ndarray:
        H = LSTM_HIDDEN
        seq_len = emb.shape[0]
        h = np.zeros(H, dtype=np.float32)
        c = np.zeros(H, dtype=np.float32)
        for t in range(seq_len):
            h, c = self._lstm_step(emb[t], h, c, self.bilstm_fwd_W, self.bilstm_fwd_b)
        h_fwd = h
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

    def forward(self, token_ids: List[int]) -> float:
        seq = self._prepare_input(token_ids)
        emb = self._embedding(seq)
        cnn_out = self._conv1d_maxpool(emb)
        lstm_out = self._bilstm(emb)
        combined = np.concatenate([cnn_out, lstm_out])
        h = _relu(self.dense1_W @ combined + self.dense1_b)
        score = _sigmoid(self.dense2_W @ h + self.dense2_b)
        return float(score[0])

    def predict(self, token_ids: List[int]) -> dict:
        if not self._loaded:
            raise RuntimeError("Model weights not loaded.")
        score = self.forward(token_ids)
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
        return {
            "riskScore": round(score, 4),
            "label": label,
            "vulnerabilityType": vuln_type,
            "recommendation": recommendation,
            "modelLoaded": True,
        }
