"""Artifact export helpers for Model 1."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Mapping, Any

class ModelExporter:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save_json(self, name: str, payload: Mapping[str, Any]) -> Path:
        path = self.output_dir / name
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def deployment_manifest(self, metadata, metrics, vocab_hash) -> dict:
        return {
            "model_version": metadata.get("model_version"),
            "weights_file": metadata.get("weights_file"),
            "metadata_file": "sqli_detection_metadata.json",
            "metrics_file": "sqli_detection_metrics.json",
            "vocab_file": "sqli_detection_vocab.json",
            "vocabulary_sha256": vocab_hash,
            "test_metrics": metrics.get("test", {}),
        }
