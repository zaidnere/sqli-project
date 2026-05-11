r"""
Evaluate the raw ML model without final fusion/rule overrides.

Run from backend/:
    set PYTHONPATH=%CD%
    venv\Scripts\python.exe scripts\evaluate_ml_only_on_suite.py ^
      --suite test_suites\unseen_generalization_suite_latest_fixed.zip ^
      --out outputs\ml95_full_sweep\unseen_generalization_suite_latest_fixed ^
      --sequence-length 256

V18-ML95 evaluation notes:
- Uses the same chunk + semantic-normalization path used by the ML pipeline.
- Propagates file-level helper context into chunk-level normalization.
- Reads the calibrated binary threshold from app/model/weights/sqli_detection_metadata.json
  unless --threshold is explicitly provided.
- Can write per-file preprocessing/debug traces with --debug-preprocess.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
import zipfile
from collections import Counter
from pathlib import Path
from typing import Optional, Tuple, Any

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.preprocessing.normalizer import (
    normalize_tokens,
    extract_safe_returning_funcs,
    extract_numeric_returning_funcs,
    extract_db_returning_funcs,
)
from app.preprocessing.chunker import split_into_chunks
from app.vectorization.vocabulary import build_fixed_vocabulary
from app.vectorization.vectorizer import vectorize_tokens
from app.model.inference import run_inference, WEIGHTS_PATH

EXT_TO_LANG = {".py": "python", ".js": "javascript", ".java": "java", ".php": "php"}
ATTACKS = {"NONE", "IN_BAND", "BLIND", "SECOND_ORDER"}
SEMANTIC_TOKENS_TO_TRACK = [
    "UNSAFE_EXEC",
    "SAFE_EXEC",
    "SQL_CONCAT",
    "WHITELIST_VAR",
    "SAFE_NUMERIC_VAR",
    "SAFE_PLACEHOLDER_LIST",
    "DB_LOADED_VAR",
    "BOOLEAN_SINK",
    "FSTRING_SQL_RAW",
    "STORED_SQL_FRAGMENT",
    "SQL_FRAGMENT_TO_SYNTAX",
    "SECOND_ORDER_FLOW",
    "SAVED_SEGMENT",
]


def infer_expected(path: str) -> Optional[Tuple[str, str]]:
    p = path.replace("\\", "/").upper()
    name = Path(path).name.upper()
    if "SECOND_ORDER" in p:
        return "VULNERABLE", "SECOND_ORDER"
    if "BLIND" in p:
        return "VULNERABLE", "BLIND"
    if "IN_BAND" in p:
        return "VULNERABLE", "IN_BAND"
    if "SAFE" in p or "NONE" in name:
        return "SAFE", "NONE"
    return None


def read_manifest(root: Path) -> dict[str, Tuple[str, str]]:
    out: dict[str, Tuple[str, str]] = {}
    mf = root / "manifest.csv"
    if not mf.exists():
        return out
    with mf.open("r", encoding='utf-8-sig', newline="") as f:
        for row in csv.DictReader(f):
            rel = row.get("file") or row.get("path") or row.get("relative_path")
            label = (row.get("expected_label") or row.get("label") or "").strip().upper()
            attack = (row.get("expected_attack_type") or row.get("attack_type") or "").strip().upper()
            if rel and label and attack:
                out[rel.replace("\\", "/")] = (label, attack)
    return out


def _safe_read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding='utf-8-sig'))
    except Exception:
        return {}


def resolve_metadata_path(metadata_path_arg: str | None = None) -> Path:
    if metadata_path_arg:
        return Path(metadata_path_arg)
    weights_dir = Path(WEIGHTS_PATH).resolve().parent
    return weights_dir / "sqli_detection_metadata.json"


def resolve_threshold(metadata: dict[str, Any], cli_threshold: float | None) -> tuple[float, str]:
    if cli_threshold is not None:
        return float(cli_threshold), "cli"
    for key in ("threshold", "selected_threshold"):
        value = metadata.get(key)
        if isinstance(value, (int, float)):
            return float(value), f"metadata.{key}"
    arch = metadata.get("architecture") if isinstance(metadata.get("architecture"), dict) else {}
    value = arch.get("threshold")
    if isinstance(value, (int, float)):
        return float(value), "metadata.architecture.threshold"
    return 0.50, "default_0.50"


def _semantic_tokens_present(tokens: list[str]) -> list[str]:
    token_set = set(tokens)
    return [tok for tok in SEMANTIC_TOKENS_TO_TRACK if tok in token_set]


def ml_predict_code(
    code: str,
    filename: str,
    sequence_length: int,
    threshold: float,
    debug: bool = False,
) -> dict[str, Any]:
    vocab = build_fixed_vocabulary()
    language = EXT_TO_LANG.get(Path(filename).suffix.lower(), "python")

    # File-level helper facts: detect safe/numeric/db-returning helpers once on
    # the full source, then propagate those facts into per-function chunks.
    full_cleaned = clean_code(code)
    full_raw_tokens = tokenize_code(full_cleaned)
    file_safe_funcs = extract_safe_returning_funcs(full_raw_tokens)
    file_numeric_funcs = extract_numeric_returning_funcs(full_raw_tokens)
    file_db_loaded_funcs = extract_db_returning_funcs(full_raw_tokens)

    chunks = split_into_chunks(code, language)
    if not chunks:
        chunks = [("__file__", code)]

    best: dict[str, Any] | None = None
    chunk_debug: list[dict[str, Any]] = []

    for idx, chunk_item in enumerate(chunks):
        if isinstance(chunk_item, tuple):
            chunk_name, chunk_code = chunk_item
        else:
            chunk_name, chunk_code = f"chunk_{idx}", chunk_item

        cleaned = clean_code(chunk_code)
        raw_tokens = tokenize_code(cleaned)
        tokens = normalize_tokens(
            raw_tokens,
            extra_safe_funcs=file_safe_funcs,
            extra_numeric_funcs=file_numeric_funcs,
            extra_db_loaded_funcs=file_db_loaded_funcs,
        )
        vec = vectorize_tokens(tokens, vocab, max_length=sequence_length)
        pred = run_inference(vec["tokenIds"])
        if pred is None:
            return {
                "ml_available": False,
                "ml_verdict": "NO_MODEL",
                "ml_attack_type": "NONE",
                "ml_risk": None,
                "chunk_index": idx,
                "chunk_name": chunk_name,
                "debug_chunks": chunk_debug,
            }

        risk = float(pred.get("riskScore", 0.0))
        attack = str(pred.get("attackType") or "NONE").upper()
        if attack not in ATTACKS:
            attack = "NONE"

        one = {
            "ml_available": True,
            "ml_verdict": "VULNERABLE" if risk >= threshold else "SAFE",
            "ml_attack_type": attack if risk >= threshold else "NONE",
            "ml_risk": risk,
            "chunk_index": idx,
            "chunk_name": chunk_name,
            "ml_attack_type_confidence": pred.get("attackTypeConfidence"),
            "ml_attack_type_probs": pred.get("attackTypeProbs"),
        }

        if debug:
            chunk_debug.append({
                "chunk_index": idx,
                "chunk_name": chunk_name,
                "risk": risk,
                "raw_pred_attack_type": attack,
                "attack_type_probs": pred.get("attackTypeProbs"),
                "semantic_tokens_present": _semantic_tokens_present(tokens),
                "normalized_tokens": tokens,
            })

        # Same existing suite policy: use the riskiest chunk as the file-level ML decision.
        if best is None or risk > float(best["ml_risk"]):
            best = one

    if best is None:
        best = {
            "ml_available": False,
            "ml_verdict": "NO_MODEL",
            "ml_attack_type": "NONE",
            "ml_risk": None,
            "chunk_index": 0,
            "chunk_name": "__file__",
        }
    if debug:
        best["debug_chunks"] = chunk_debug
        best["file_level_context"] = {
            "safe_returning_funcs": sorted(file_safe_funcs),
            "numeric_returning_funcs": sorted(file_numeric_funcs),
            "db_returning_funcs": sorted(file_db_loaded_funcs),
        }
    return best


def _bool_from_csv(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sequence-length", type=int, default=256)
    ap.add_argument("--threshold", type=float, default=None, help="Override ML-only binary threshold. If omitted, read from metadata.")
    ap.add_argument("--metadata-path", default=None, help="Optional explicit path to sqli_detection_metadata.json.")
    ap.add_argument("--debug-preprocess", action="store_true", help="Write per-file normalized tokens and probabilities to debug_preprocess.jsonl.")
    args = ap.parse_args()

    metadata_path = resolve_metadata_path(args.metadata_path)
    metadata = _safe_read_json(metadata_path)
    threshold, threshold_source = resolve_threshold(metadata, args.threshold)

    weights_path = Path(WEIGHTS_PATH).resolve()
    model_version = metadata.get("model_version", "UNKNOWN")
    vocabulary_sha256 = metadata.get("vocabulary_sha256", "UNKNOWN")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("ML-only suite evaluation")
    print(f"Suite: {args.suite}")
    print(f"Output dir: {out_dir}")
    print(f"Loaded weights path: {weights_path}")
    print(f"Loaded metadata path: {metadata_path.resolve()}")
    print(f"Model version: {model_version}")
    print(f"Vocabulary SHA256: {vocabulary_sha256}")
    print(f"Selected threshold: {threshold:.4f} ({threshold_source})")
    print("=" * 80)

    rows: list[dict[str, Any]] = []
    debug_records: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        with zipfile.ZipFile(args.suite, "r") as zf:
            zf.extractall(root)
        manifest = read_manifest(root)
        for f in sorted(root.rglob("*")):
            if not f.is_file() or f.name.lower() == "manifest.csv":
                continue
            if f.suffix.lower() not in EXT_TO_LANG:
                continue
            rel = f.relative_to(root).as_posix()
            expected = manifest.get(rel) or infer_expected(rel)
            if not expected:
                continue
            exp_label, exp_attack = expected
            code = f.read_text(encoding='utf-8-sig', errors="replace")
            pred = ml_predict_code(
                code=code,
                filename=f.name,
                sequence_length=args.sequence_length,
                threshold=threshold,
                debug=args.debug_preprocess,
            )
            ml_label = pred["ml_verdict"]
            ml_attack = pred["ml_attack_type"]
            binary_ok = (ml_label == exp_label)
            full_ok = binary_ok and (ml_attack == exp_attack)
            row = {
                "file": rel,
                "expected_label": exp_label,
                "expected_attack_type": exp_attack,
                "ml_label": ml_label,
                "ml_attack_type": ml_attack,
                "ml_risk": pred.get("ml_risk"),
                "ml_attack_type_confidence": pred.get("ml_attack_type_confidence"),
                "ml_attack_type_probs": json.dumps(pred.get("ml_attack_type_probs"), ensure_ascii=False, sort_keys=True),
                "chunk_index": pred.get("chunk_index"),
                "chunk_name": pred.get("chunk_name"),
                "binary_pass": binary_ok,
                "full_pass": full_ok,
            }
            rows.append(row)

            if args.debug_preprocess:
                debug_records.append({
                    "file": rel,
                    "expected_label": exp_label,
                    "expected_attack_type": exp_attack,
                    "predicted_label": ml_label,
                    "predicted_attack_type": ml_attack,
                    "binary_pass": binary_ok,
                    "full_pass": full_ok,
                    "selected_chunk_index": pred.get("chunk_index"),
                    "selected_chunk_name": pred.get("chunk_name"),
                    "file_level_context": pred.get("file_level_context", {}),
                    "chunks": pred.get("debug_chunks", []),
                })

    total = len(rows)
    bin_ok = sum(1 for r in rows if _bool_from_csv(r["binary_pass"]))
    full_ok = sum(1 for r in rows if _bool_from_csv(r["full_pass"]))
    by_exp = Counter(r["expected_attack_type"] for r in rows)
    by_pred = Counter(r["ml_attack_type"] for r in rows)

    tp = sum(1 for r in rows if r["expected_label"] == "VULNERABLE" and r["ml_label"] == "VULNERABLE")
    tn = sum(1 for r in rows if r["expected_label"] == "SAFE" and r["ml_label"] == "SAFE")
    fp = sum(1 for r in rows if r["expected_label"] == "SAFE" and r["ml_label"] == "VULNERABLE")
    fn = sum(1 for r in rows if r["expected_label"] == "VULNERABLE" and r["ml_label"] == "SAFE")
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    specificity = tn / max(1, tn + fp)
    f1 = (2 * precision * recall) / max(1e-12, precision + recall)

    csv_path = out_dir / "ml_only_results.csv"
    with csv_path.open("w", encoding='utf-8-sig', newline="") as f:
        fieldnames = list(rows[0].keys()) if rows else ["file"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if rows:
            writer.writeheader()
            writer.writerows(rows)

    summary = {
        "suite": Path(args.suite).name,
        "mode": "ml-only",
        "model_version": model_version,
        "weights_path": str(weights_path),
        "metadata_path": str(metadata_path.resolve()),
        "vocabulary_sha256": vocabulary_sha256,
        "threshold": threshold,
        "threshold_source": threshold_source,
        "total": total,
        "safe_count": sum(1 for r in rows if r["expected_label"] == "SAFE"),
        "vulnerable_count": sum(1 for r in rows if r["expected_label"] == "VULNERABLE"),
        "binary_correct": bin_ok,
        "binary_accuracy": bin_ok / max(1, total),
        "full_correct": full_ok,
        "full_accuracy": full_ok / max(1, total),
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "false_positives": fp,
        "false_negatives": fn,
        "true_positives": tp,
        "true_negatives": tn,
        "expected_attack_distribution": dict(by_exp),
        "ml_attack_distribution": dict(by_pred),
    }

    md: list[str] = []
    md.append("# ML-only Suite Evaluation\n")
    md.append(f"- Suite: **{Path(args.suite).name}**\n")
    md.append(f"- Model version: **{model_version}**\n")
    md.append(f"- Weights: `{weights_path}`\n")
    md.append(f"- Metadata: `{metadata_path.resolve()}`\n")
    md.append(f"- Threshold: **{threshold:.4f}** from `{threshold_source}`\n")
    md.append(f"- Total: **{total}**\n")
    md.append(f"- Binary ML accuracy: **{bin_ok}/{total}** ({(bin_ok / max(1, total)) * 100:.2f}%)\n")
    md.append(f"- Full ML label+type accuracy: **{full_ok}/{total}** ({(full_ok / max(1, total)) * 100:.2f}%)\n")
    md.append(f"- Precision / Recall / F1: **{precision:.4f} / {recall:.4f} / {f1:.4f}**\n")
    md.append(f"- FP / FN: **{fp} / {fn}**\n")
    md.append(f"- Expected attack distribution: `{dict(by_exp)}`\n")
    md.append(f"- ML attack distribution: `{dict(by_pred)}`\n\n")
    md.append("## Failures\n\n")
    for r in rows:
        if not _bool_from_csv(r["full_pass"]):
            md.append(
                f"- `{r['file']}` expected `{r['expected_label']} / {r['expected_attack_type']}` "
                f"got `{r['ml_label']} / {r['ml_attack_type']}` risk `{r['ml_risk']}`\n"
            )

    (out_dir / "ml_only_summary.md").write_text("".join(md), encoding='utf-8-sig')
    (out_dir / "ml_only_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8-sig')

    if args.debug_preprocess:
        debug_path = out_dir / "debug_preprocess.jsonl"
        with debug_path.open("w", encoding='utf-8-sig') as f:
            for record in debug_records:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"Wrote debug preprocess: {debug_path}")

    print(f"ML-only binary accuracy: {bin_ok}/{total} ({(bin_ok / max(1, total)) * 100:.2f}%)")
    print(f"ML-only full accuracy: {full_ok}/{total} ({(full_ok / max(1, total)) * 100:.2f}%)")
    print(f"FP/FN: {fp}/{fn}")
    print(f"Wrote: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

