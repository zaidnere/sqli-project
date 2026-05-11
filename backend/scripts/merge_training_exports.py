#!/usr/bin/env python3
"""
Merge the original broad SQLi detection training export with a newer ML-primary
augmentation export.

Why this exists:
- The original dataset is broad, but usually seq_len=128.
- The new ML-primary generated dataset is targeted and seq_len=256.
- Training only on the small targeted export can cause forgetting.
- This script pads/truncates both datasets to the same sequence length, verifies
  the vocabulary, concatenates them, and writes a combined Colab export.

Expected input structure:
  old_export/training_data.npz
  old_export/vocabulary.json
  colab_export/training_data.npz
  colab_export/vocabulary.json

Required NPZ keys:
  X       token ID matrix, shape [n_samples, seq_len]
  y       binary verdict labels, 0=SAFE, 1=VULNERABLE
  y_type  attack type labels, 0=NONE, 1=IN_BAND, 2=BLIND, 3=SECOND_ORDER

Optional NPZ keys, preserved or filled:
  language, file_path, suite_name, sample_id
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

import numpy as np


ATTACK_TYPE_NAMES = {
    0: "NONE",
    1: "IN_BAND",
    2: "BLIND",
    3: "SECOND_ORDER",
}

VERDICT_NAMES = {
    0: "SAFE",
    1: "VULNERABLE",
}


def read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def sha256_json(data: Any) -> str:
    payload = json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def sha256_array(arr: np.ndarray) -> str:
    return hashlib.sha256(np.ascontiguousarray(arr).tobytes()).hexdigest()


def load_training_npz(path: Path) -> Dict[str, np.ndarray]:
    if not path.exists():
        raise FileNotFoundError(f"Training data not found: {path}")

    data = np.load(path, allow_pickle=True)
    out = {key: data[key] for key in data.files}

    required = ["X", "y", "y_type"]
    missing = [key for key in required if key not in out]
    if missing:
        raise ValueError(f"{path} is missing required keys: {missing}. Found keys: {data.files}")

    if out["X"].ndim != 2:
        raise ValueError(f"{path}: X must be 2D [samples, seq_len], got shape {out['X'].shape}")

    n = out["X"].shape[0]
    if out["y"].shape[0] != n or out["y_type"].shape[0] != n:
        raise ValueError(
            f"{path}: X/y/y_type sample counts mismatch: "
            f"X={out['X'].shape}, y={out['y'].shape}, y_type={out['y_type'].shape}"
        )

    return out


def normalize_sequence_length(X: np.ndarray, target_len: int, pad_id: int) -> Tuple[np.ndarray, int, int]:
    """Return X with exactly target_len columns, plus (padded_count, truncated_count)."""
    X = X.astype(np.int32, copy=False)
    n, current_len = X.shape

    if current_len == target_len:
        non_pad = (X != pad_id).sum(axis=1)
        padded_count = int(np.sum(non_pad < target_len))
        truncated_count = 0
        return X.copy(), padded_count, truncated_count

    if current_len < target_len:
        out = np.full((n, target_len), pad_id, dtype=np.int32)
        out[:, :current_len] = X
        padded_count = int(n)
        truncated_count = 0
        return out, padded_count, truncated_count

    # current_len > target_len
    out = X[:, :target_len].copy()
    truncated_count = int(np.sum(np.any(X[:, target_len:] != pad_id, axis=1)))
    non_pad = (out != pad_id).sum(axis=1)
    padded_count = int(np.sum(non_pad < target_len))
    return out, padded_count, truncated_count


def as_str_array(values: Iterable[str]) -> np.ndarray:
    return np.array(list(values), dtype=object)


def get_optional_or_default(data: Dict[str, np.ndarray], key: str, n: int, default: str) -> np.ndarray:
    if key in data:
        arr = data[key]
        if arr.shape[0] == n:
            return arr.astype(object)
    return as_str_array([default] * n)


def align_optional_fields(
    old: Dict[str, np.ndarray],
    new: Dict[str, np.ndarray],
    old_name: str,
    new_name: str,
) -> Dict[str, np.ndarray]:
    old_n = old["X"].shape[0]
    new_n = new["X"].shape[0]

    optional = {}

    optional["language"] = np.concatenate([
        get_optional_or_default(old, "language", old_n, "unknown_legacy"),
        get_optional_or_default(new, "language", new_n, "unknown_generated"),
    ])

    optional["file_path"] = np.concatenate([
        get_optional_or_default(old, "file_path", old_n, f"{old_name}/unknown"),
        get_optional_or_default(new, "file_path", new_n, f"{new_name}/unknown"),
    ])

    optional["suite_name"] = np.concatenate([
        get_optional_or_default(old, "suite_name", old_n, old_name),
        get_optional_or_default(new, "suite_name", new_n, new_name),
    ])

    old_ids = [f"{old_name}_{i:06d}" for i in range(old_n)]
    new_ids = [f"{new_name}_{i:06d}" for i in range(new_n)]
    optional["sample_id"] = np.concatenate([
        get_optional_or_default(old, "sample_id", old_n, "").astype(object),
        get_optional_or_default(new, "sample_id", new_n, "").astype(object),
    ])

    # Replace empty IDs with generated stable IDs.
    for i, value in enumerate(optional["sample_id"]):
        if not str(value):
            optional["sample_id"][i] = old_ids[i] if i < old_n else new_ids[i - old_n]

    return optional


def count_labels(y: np.ndarray, names: Dict[int, str]) -> Dict[str, int]:
    ints = y.astype(int)
    counts = Counter(int(v) for v in ints)
    return {names.get(k, str(k)): int(counts.get(k, 0)) for k in sorted(set(names) | set(counts))}


def top_token_counts(X: np.ndarray, id_to_token: Dict[int, str], pad_id: int, top_n: int = 25) -> list:
    flat = X.reshape(-1)
    flat = flat[flat != pad_id]
    counts = Counter(int(v) for v in flat)
    return [[id_to_token.get(k, str(k)), int(v)] for k, v in counts.most_common(top_n)]


def build_profile(
    X: np.ndarray,
    y: np.ndarray,
    y_type: np.ndarray,
    vocab: Dict[str, int],
    optional: Dict[str, np.ndarray],
    old_count: int,
    new_count: int,
    old_seq_len: int,
    new_seq_len: int,
    padded_count: int,
    truncated_count: int,
    pad_id: int,
    unk_id: int,
) -> Dict[str, Any]:
    id_to_token = {int(v): str(k) for k, v in vocab.items()}
    non_pad_lengths = (X != pad_id).sum(axis=1)
    total_non_pad = int(non_pad_lengths.sum())
    unk_count = int(np.sum(X == unk_id))

    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "n_samples": int(X.shape[0]),
        "sequence_length": int(X.shape[1]),
        "vocabulary_size": int(len(vocab)),
        "vocabulary_sha256": sha256_json(vocab),
        "pad_id": int(pad_id),
        "unk_id": int(unk_id),
        "source_counts": {
            "legacy_broad": int(old_count),
            "generated_ml_primary": int(new_count),
        },
        "source_sequence_lengths": {
            "legacy_broad_original": int(old_seq_len),
            "generated_ml_primary_original": int(new_seq_len),
            "combined": int(X.shape[1]),
        },
        "verdict_counts": count_labels(y, VERDICT_NAMES),
        "attack_type_counts": count_labels(y_type, ATTACK_TYPE_NAMES),
        "language_counts": {str(k): int(v) for k, v in Counter(map(str, optional["language"])).items()},
        "suite_counts": {str(k): int(v) for k, v in Counter(map(str, optional["suite_name"])).items()},
        "avg_non_pad_length": float(np.mean(non_pad_lengths)) if X.shape[0] else 0.0,
        "max_non_pad_length": int(np.max(non_pad_lengths)) if X.shape[0] else 0,
        "min_non_pad_length": int(np.min(non_pad_lengths)) if X.shape[0] else 0,
        "padded_samples": int(padded_count),
        "truncated_samples": int(truncated_count),
        "truncation_rate": float(truncated_count / max(1, X.shape[0])),
        "unk_token_count": int(unk_count),
        "unk_rate": float(unk_count / max(1, total_non_pad)),
        "duplicate_sequence_count": int(X.shape[0] - len({tuple(row.tolist()) for row in X})),
        "top_tokens": top_token_counts(X, id_to_token, pad_id),
        "x_sha256": sha256_array(X),
        "y_sha256": sha256_array(y.astype(np.float32)),
        "y_type_sha256": sha256_array(y_type.astype(np.int32)),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge old and new SQLi detection training exports.")
    parser.add_argument("--old-data", required=True, help="Path to old broad training_data.npz")
    parser.add_argument("--old-vocab", required=True, help="Path to old vocabulary.json")
    parser.add_argument("--new-data", required=True, help="Path to new ML-primary training_data.npz")
    parser.add_argument("--new-vocab", required=True, help="Path to new ML-primary vocabulary.json")
    parser.add_argument("--out", required=True, help="Output directory for combined Colab export")
    parser.add_argument("--sequence-length", type=int, default=256, help="Combined sequence length")
    parser.add_argument("--allow-vocab-mismatch", action="store_true", help="Do not fail on vocabulary mismatch")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    old_data_path = Path(args.old_data)
    old_vocab_path = Path(args.old_vocab)
    new_data_path = Path(args.new_data)
    new_vocab_path = Path(args.new_vocab)
    out_dir = Path(args.out)

    old_vocab = read_json(old_vocab_path)
    new_vocab = read_json(new_vocab_path)

    old_vocab_hash = sha256_json(old_vocab)
    new_vocab_hash = sha256_json(new_vocab)

    if old_vocab != new_vocab:
        message = (
            "Vocabulary mismatch detected.\n"
            f"old_vocab_sha256={old_vocab_hash}\n"
            f"new_vocab_sha256={new_vocab_hash}\n"
            "Do not merge different token ID maps unless you know exactly what changed."
        )
        if not args.allow_vocab_mismatch:
            raise ValueError(message)
        print("WARNING:", message)
        vocab = new_vocab
    else:
        vocab = old_vocab

    pad_id = int(vocab.get("PAD", 0))
    unk_id = int(vocab.get("UNK", 1))

    print("[1/5] Loading old broad export...")
    old = load_training_npz(old_data_path)
    print(f"      old X shape: {old['X'].shape}")

    print("[2/5] Loading new ML-primary export...")
    new = load_training_npz(new_data_path)
    print(f"      new X shape: {new['X'].shape}")

    print(f"[3/5] Normalizing sequence length to {args.sequence_length}...")
    old_seq_len = int(old["X"].shape[1])
    new_seq_len = int(new["X"].shape[1])

    old_X, old_padded, old_truncated = normalize_sequence_length(old["X"], args.sequence_length, pad_id)
    new_X, new_padded, new_truncated = normalize_sequence_length(new["X"], args.sequence_length, pad_id)

    X = np.concatenate([old_X, new_X], axis=0).astype(np.int32)
    y = np.concatenate([old["y"], new["y"]], axis=0).astype(np.float32)
    y_type = np.concatenate([old["y_type"], new["y_type"]], axis=0).astype(np.int32)

    optional = align_optional_fields(old, new, "legacy_broad", "generated_ml_primary")

    print("[4/5] Writing combined training export...")
    out_dir.mkdir(parents=True, exist_ok=True)

    np.savez_compressed(
        out_dir / "training_data.npz",
        X=X,
        y=y,
        y_type=y_type,
        language=optional["language"],
        file_path=optional["file_path"],
        suite_name=optional["suite_name"],
        sample_id=optional["sample_id"],
    )

    write_json(out_dir / "vocabulary.json", vocab)

    profile = build_profile(
        X=X,
        y=y,
        y_type=y_type,
        vocab=vocab,
        optional=optional,
        old_count=old_X.shape[0],
        new_count=new_X.shape[0],
        old_seq_len=old_seq_len,
        new_seq_len=new_seq_len,
        padded_count=old_padded + new_padded,
        truncated_count=old_truncated + new_truncated,
        pad_id=pad_id,
        unk_id=unk_id,
    )
    write_json(out_dir / "dataset_profile.json", profile)

    export_info = {
        "created_at": profile["created_at"],
        "purpose": "combined_legacy_broad_plus_ml_primary_augmented_training_data",
        "old_data": str(old_data_path),
        "old_vocab": str(old_vocab_path),
        "old_vocab_sha256": old_vocab_hash,
        "new_data": str(new_data_path),
        "new_vocab": str(new_vocab_path),
        "new_vocab_sha256": new_vocab_hash,
        "output_dir": str(out_dir),
        "sequence_length": int(args.sequence_length),
        "n_samples": int(X.shape[0]),
        "notes": [
            "Old 128-token samples are padded to 256 using PAD_ID.",
            "New ML-primary samples are preserved at 256 tokens.",
            "Vocabulary equality is enforced by default to prevent token ID mismatch.",
            "Legacy samples without language metadata are marked as unknown_legacy.",
        ],
    }
    write_json(out_dir / "export_info.json", export_info)

    print("[5/5] Done.")
    print(f"Output dir: {out_dir.resolve()}")
    print(json.dumps({
        "n_samples": profile["n_samples"],
        "sequence_length": profile["sequence_length"],
        "source_counts": profile["source_counts"],
        "verdict_counts": profile["verdict_counts"],
        "attack_type_counts": profile["attack_type_counts"],
        "language_counts": profile["language_counts"],
        "truncation_rate": profile["truncation_rate"],
        "unk_rate": profile["unk_rate"],
        "duplicate_sequence_count": profile["duplicate_sequence_count"],
    }, indent=2, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
