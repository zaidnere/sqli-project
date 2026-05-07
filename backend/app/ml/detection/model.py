"""Hybrid CNN + BiLSTM SQL Injection detection model.

This module is intentionally NumPy-only. It implements the production forward
pass for the same architecture trained in model1_detection_aligned.ipynb:
    token_ids -> Embedding -> Conv1D -> BiLSTM -> Dense -> sigmoid/softmax heads
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping

import numpy as np

ATTACK_TYPE_NAMES = {0: "NONE", 1: "IN_BAND", 2: "BLIND", 3: "SECOND_ORDER"}
ATTACK_TYPE_NUM_CLASSES = 4


@dataclass(frozen=True)
class DetectionModelConfig:
    sequence_length: int = 128
    embed_dim: int = 64
    conv_filters: int = 64
    kernel_size: int = 3
    lstm_hidden: int = 32
    dense_hidden: int = 64
    threshold: float = 0.50
    pad_id: int = 0
    model_version: str = "model1-cnn-bilstm-dual-head-v2"


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return np.where(x >= 0, 1.0 / (1.0 + np.exp(-x)), np.exp(x) / (1.0 + np.exp(x)))


def _relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(0.0, x)


def _softmax(x: np.ndarray) -> np.ndarray:
    shifted = x - np.max(x)
    exp = np.exp(shifted)
    return exp / np.sum(exp)


class HybridCNNBiLSTMDetector:
    """Forward-pass detector used by backend inference.

    The object exposes raw ML prediction only. Evidence-aware fusion remains in
    scan_service/fusion code. This separation makes it clear that Model 1 is a
    real ML component and not a rule engine.
    """

    REQUIRED_KEYS = (
        "emb_W", "conv_W", "conv_b",
        "bilstm_fwd_W", "bilstm_fwd_b", "bilstm_bwd_W", "bilstm_bwd_b",
        "dense1_W", "dense1_b", "dense2_W", "dense2_b",
        "dense2_type_W", "dense2_type_b",
    )

    def __init__(self, config: DetectionModelConfig | None = None) -> None:
        self.config = config or DetectionModelConfig()
        self.weights: Dict[str, np.ndarray] = {}
        self.loaded = False

    def load_npz(self, path: str) -> None:
        data = dict(np.load(path, allow_pickle=False))
        missing = [k for k in self.REQUIRED_KEYS if k not in data]
        if missing:
            raise ValueError(f"Model weights missing required tensors: {missing}")
        self.weights = {k: data[k].astype(np.float32) for k in self.REQUIRED_KEYS}
        self._validate_shapes()
        self.loaded = True

    def load_arrays(self, arrays: Mapping[str, np.ndarray]) -> None:
        missing = [k for k in self.REQUIRED_KEYS if k not in arrays]
        if missing:
            raise ValueError(f"Model arrays missing required tensors: {missing}")
        self.weights = {k: np.asarray(arrays[k], dtype=np.float32) for k in self.REQUIRED_KEYS}
        self._validate_shapes()
        self.loaded = True

    def _validate_shapes(self) -> None:
        c = self.config
        w = self.weights
        expected = {
            "conv_W": (c.conv_filters, c.embed_dim, c.kernel_size),
            "conv_b": (c.conv_filters,),
            "bilstm_fwd_W": (4 * c.lstm_hidden, c.embed_dim + c.lstm_hidden),
            "bilstm_fwd_b": (4 * c.lstm_hidden,),
            "bilstm_bwd_W": (4 * c.lstm_hidden, c.embed_dim + c.lstm_hidden),
            "bilstm_bwd_b": (4 * c.lstm_hidden,),
            "dense1_W": (c.dense_hidden, c.conv_filters + 2 * c.lstm_hidden),
            "dense1_b": (c.dense_hidden,),
            "dense2_W": (1, c.dense_hidden),
            "dense2_b": (1,),
            "dense2_type_W": (ATTACK_TYPE_NUM_CLASSES, c.dense_hidden),
            "dense2_type_b": (ATTACK_TYPE_NUM_CLASSES,),
        }
        for key, shape in expected.items():
            if w[key].shape != shape:
                raise ValueError(f"Shape mismatch for {key}: got {w[key].shape}, expected {shape}")
        if w["emb_W"].ndim != 2 or w["emb_W"].shape[1] != c.embed_dim:
            raise ValueError(f"Shape mismatch for emb_W: got {w['emb_W'].shape}, expected (*, {c.embed_dim})")

    def _prepare_input(self, token_ids: List[int] | np.ndarray) -> np.ndarray:
        ids = np.asarray(token_ids, dtype=np.int32)
        if len(ids) >= self.config.sequence_length:
            return ids[: self.config.sequence_length]
        pad = np.full(self.config.sequence_length - len(ids), self.config.pad_id, dtype=np.int32)
        return np.concatenate([ids, pad])

    def _embedding(self, ids: np.ndarray) -> np.ndarray:
        vocab_size = self.weights["emb_W"].shape[0]
        safe_ids = np.where((ids >= 0) & (ids < vocab_size), ids, 1).astype(np.int32)
        return self.weights["emb_W"][safe_ids]

    def _conv1d_maxpool(self, emb: np.ndarray) -> np.ndarray:
        c = self.config
        W = self.weights["conv_W"]
        b = self.weights["conv_b"]
        if emb.shape[0] < c.kernel_size:
            pad = np.zeros((c.kernel_size - emb.shape[0], emb.shape[1]), dtype=np.float32)
            emb = np.vstack([emb, pad])
        windows = np.lib.stride_tricks.sliding_window_view(emb, window_shape=c.kernel_size, axis=0)
        patches = windows.transpose(0, 2, 1).reshape(windows.shape[0], -1)
        W_flat = W.reshape(c.conv_filters, -1)
        conv_out = patches @ W_flat.T + b
        return np.max(_relu(conv_out), axis=0)

    def _lstm_step(self, x_t: np.ndarray, h: np.ndarray, cell: np.ndarray, W: np.ndarray, b: np.ndarray):
        H = self.config.lstm_hidden
        gates = W @ np.concatenate([x_t, h]) + b
        f = _sigmoid(gates[0 * H : 1 * H])
        i = _sigmoid(gates[1 * H : 2 * H])
        o = _sigmoid(gates[2 * H : 3 * H])
        g = np.tanh(gates[3 * H : 4 * H])
        c_new = f * cell + i * g
        h_new = o * np.tanh(c_new)
        return h_new, c_new

    def _bilstm(self, emb: np.ndarray) -> np.ndarray:
        H = self.config.lstm_hidden
        h = np.zeros(H, dtype=np.float32)
        cell = np.zeros(H, dtype=np.float32)
        for t in range(emb.shape[0]):
            h, cell = self._lstm_step(emb[t], h, cell, self.weights["bilstm_fwd_W"], self.weights["bilstm_fwd_b"])
        h_fwd = h
        h = np.zeros(H, dtype=np.float32)
        cell = np.zeros(H, dtype=np.float32)
        for t in reversed(range(emb.shape[0])):
            h, cell = self._lstm_step(emb[t], h, cell, self.weights["bilstm_bwd_W"], self.weights["bilstm_bwd_b"])
        return np.concatenate([h_fwd, h])

    def forward(self, token_ids: List[int] | np.ndarray) -> Dict[str, Any]:
        if not self.loaded:
            raise RuntimeError("Detection model weights are not loaded")
        ids = self._prepare_input(token_ids)
        emb = self._embedding(ids)
        cnn_out = self._conv1d_maxpool(emb)
        lstm_out = self._bilstm(emb)
        combined = np.concatenate([cnn_out, lstm_out])
        h = _relu(self.weights["dense1_W"] @ combined + self.weights["dense1_b"])
        risk = float(_sigmoid(self.weights["dense2_W"] @ h + self.weights["dense2_b"])[0])
        type_probs = _softmax(self.weights["dense2_type_W"] @ h + self.weights["dense2_type_b"])
        type_id = int(np.argmax(type_probs))
        return {
            "ml_risk_score": round(risk, 4),
            "ml_predicted_verdict": "VULNERABLE" if risk >= self.config.threshold else "SAFE",
            "ml_predicted_attack_type": ATTACK_TYPE_NAMES[type_id],
            "ml_attack_type_id": type_id,
            "ml_attack_type_confidence": round(float(type_probs[type_id]), 4),
            "ml_attack_type_probs": {ATTACK_TYPE_NAMES[i]: round(float(type_probs[i]), 4) for i in range(ATTACK_TYPE_NUM_CLASSES)},
            "model_version": self.config.model_version,
            "sequence_length": self.config.sequence_length,
        }
