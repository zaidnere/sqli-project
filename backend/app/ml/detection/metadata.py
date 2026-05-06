"""Metadata helpers for detection model artifact compatibility checks."""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Mapping

def vocabulary_hash(vocab: Mapping[str, int]) -> str:
    return hashlib.sha256(json.dumps(vocab, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()

def load_json(path: str | Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def validate_compatibility(metadata: Mapping, vocab: Mapping[str, int], sequence_length: int) -> None:
    expected_hash = metadata.get("vocabulary_sha256")
    actual_hash = vocabulary_hash(vocab)
    if expected_hash and expected_hash != actual_hash:
        raise ValueError(f"Vocabulary hash mismatch: metadata={expected_hash}, runtime={actual_hash}")
    expected_len = int(metadata.get("sequence_length", sequence_length))
    if expected_len != int(sequence_length):
        raise ValueError(f"Sequence length mismatch: metadata={expected_len}, runtime={sequence_length}")
    labels = metadata.get("architecture", {}).get("heads", {}).get("attack_type_head", {}).get("classes")
    if labels and sorted(map(int, labels.keys())) != [0, 1, 2, 3]:
        raise ValueError(f"Attack label map mismatch: {labels}")
