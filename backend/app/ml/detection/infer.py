"""Production inference engine for raw Model 1 ML predictions."""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from .metadata import load_json, validate_compatibility
from .model import DetectionModelConfig, HybridCNNBiLSTMDetector

class DetectionInferenceEngine:
    def __init__(self, weights_path: str, vocab_path: str, metadata_path: Optional[str] = None):
        self.weights_path = Path(weights_path)
        self.vocab_path = Path(vocab_path)
        self.metadata_path = Path(metadata_path) if metadata_path else None
        self.vocab = load_json(self.vocab_path)
        self.metadata = load_json(self.metadata_path) if self.metadata_path and self.metadata_path.exists() else {}
        seq_len = int(self.metadata.get("sequence_length", 128))
        pad_id = int(self.metadata.get("pad_id", self.vocab.get("PAD", 0)))
        threshold = float(self.metadata.get("threshold", 0.5))
        version = str(self.metadata.get("model_version", "model1-cnn-bilstm-dual-head-v2"))
        validate_compatibility(self.metadata, self.vocab, seq_len)
        self.model = HybridCNNBiLSTMDetector(DetectionModelConfig(sequence_length=seq_len, pad_id=pad_id, threshold=threshold, model_version=version))
        self.model.load_npz(str(self.weights_path))

    def predict_token_ids(self, token_ids: List[int]):
        return self.model.forward(token_ids)
