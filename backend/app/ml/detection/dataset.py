"""Dataset loading, profiling, splitting and class-weight calculation."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from typing import Dict, Tuple

import numpy as np

ATTACK_TYPE_NAMES = {0: "NONE", 1: "IN_BAND", 2: "BLIND", 3: "SECOND_ORDER"}

class DetectionDataset:
    def __init__(self, training_npz: str, vocabulary_json: str):
        self.training_npz = Path(training_npz)
        self.vocabulary_json = Path(vocabulary_json)
        self.vocab = json.loads(self.vocabulary_json.read_text(encoding="utf-8"))
        self.pad_id = int(self.vocab.get("PAD", 0))
        self.unk_id = int(self.vocab.get("UNK", 1))
        payload = json.dumps(self.vocab, sort_keys=True, ensure_ascii=False).encode("utf-8")
        self.vocab_hash = hashlib.sha256(payload).hexdigest()
        data = np.load(self.training_npz, allow_pickle=True)
        self.X = data["X"].astype(np.int32)
        self.y = data["y"].astype(np.float32)
        self.y_type = data["y_type"].astype(np.int32)
        self.languages = data["language"].astype(str) if "language" in data.files else np.array(["unknown"] * len(self.X))
        self.paths = data["path"].astype(str) if "path" in data.files else np.array([f"sample_{i}" for i in range(len(self.X))])
        self.truncated = data["truncated"].astype(bool) if "truncated" in data.files else np.zeros(len(self.X), dtype=bool)

    def profile(self) -> Dict:
        lengths = np.sum(self.X != self.pad_id, axis=1)
        unk_counts = np.sum(self.X == self.unk_id, axis=1)
        duplicates = len(self.X) - len({tuple(row.tolist()) for row in self.X})
        return {
            "n_samples": int(len(self.X)),
            "sequence_length": int(self.X.shape[1]),
            "vocab_size": int(len(self.vocab)),
            "vocabulary_sha256": self.vocab_hash,
            "verdict_counts": {"SAFE": int(np.sum(self.y == 0)), "VULNERABLE": int(np.sum(self.y == 1))},
            "attack_type_counts": {ATTACK_TYPE_NAMES[i]: int(np.sum(self.y_type == i)) for i in range(4)},
            "language_counts": dict(Counter(self.languages.tolist())),
            "avg_non_pad_length": float(np.mean(lengths)),
            "max_non_pad_length": int(np.max(lengths)),
            "truncated_samples": int(np.sum(self.truncated)),
            "truncation_rate": float(np.mean(self.truncated)),
            "unk_rate": float(np.sum(unk_counts) / max(1, np.sum(lengths))),
            "duplicate_sequence_count": int(duplicates),
        }

    def split(self, seed=42, train_ratio=0.70, val_ratio=0.15):
        rng = np.random.default_rng(seed)
        groups = defaultdict(list)
        for i, (typ, lang) in enumerate(zip(self.y_type, self.languages)):
            groups[(int(typ), str(lang))].append(i)
        train, val, test = [], [], []
        for idxs in groups.values():
            idxs = np.array(idxs, dtype=np.int32)
            rng.shuffle(idxs)
            n = len(idxs)
            if n < 3:
                train.extend(idxs.tolist())
                continue
            n_train = max(1, int(round(n * train_ratio)))
            n_val = max(1, int(round(n * val_ratio)))
            if n_train + n_val >= n:
                n_train = max(1, n - 2); n_val = 1
            train.extend(idxs[:n_train]); val.extend(idxs[n_train:n_train+n_val]); test.extend(idxs[n_train+n_val:])
        return np.array(train, dtype=np.int32), np.array(val, dtype=np.int32), np.array(test, dtype=np.int32)

    @staticmethod
    def class_weights(labels, n_classes):
        labels = np.asarray(labels).astype(int)
        counts = np.bincount(labels, minlength=n_classes).astype(np.float32)
        counts = np.maximum(counts, 1.0)
        weights = counts.sum() / (n_classes * counts)
        return weights.astype(np.float32)
