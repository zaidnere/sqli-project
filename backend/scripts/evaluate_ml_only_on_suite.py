r"""
Evaluate the raw ML model without final fusion/rule overrides.

Run from backend/:
    set PYTHONPATH=%CD%
    venv\Scripts\python.exe scripts\evaluate_ml_only_on_suite.py ^
      --suite test_suites\unseen_generalization_suite_v5.zip ^
      --out outputs\ml_only_unseen_v5 ^
      --sequence-length 256

Purpose:
- prove whether Model 1 itself is learning SAFE/VULNERABLE and attack type;
- separate ML performance from evidence-aware fusion;
- support the ML-primary requirement for the final project.
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
from typing import Optional, Tuple

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.preprocessing.normalizer import normalize_tokens
from app.preprocessing.chunker import split_into_chunks
from app.vectorization.vocabulary import build_fixed_vocabulary
from app.vectorization.vectorizer import vectorize_tokens
from app.model.inference import run_inference

EXT_TO_LANG = {".py":"python", ".js":"javascript", ".java":"java", ".php":"php"}
ATTACKS = {"NONE", "IN_BAND", "BLIND", "SECOND_ORDER"}


def infer_expected(path: str) -> Optional[Tuple[str, str]]:
    p = path.replace('\\','/').upper()
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
    out = {}
    mf = root / "manifest.csv"
    if not mf.exists():
        return out
    with mf.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            rel = row.get("file") or row.get("path") or row.get("relative_path")
            label = (row.get("expected_label") or row.get("label") or "").strip().upper()
            attack = (row.get("expected_attack_type") or row.get("attack_type") or "").strip().upper()
            if rel and label and attack:
                out[rel.replace('\\','/')] = (label, attack)
    return out


def ml_predict_code(code: str, filename: str, sequence_length: int) -> dict:
    vocab = build_fixed_vocabulary()

    # split_into_chunks expects a language name and returns tuples:
    #     [(chunk_name, chunk_code), ...]
    # Older versions of this script passed the filename and then sent the
    # whole tuple into clean_code(), causing:
    #     TypeError: expected string or bytes-like object, got 'tuple'
    language = EXT_TO_LANG.get(Path(filename).suffix.lower(), "python")
    chunks = split_into_chunks(code, language)
    if not chunks:
        chunks = [("__file__", code)]

    best = None
    for idx, chunk_item in enumerate(chunks):
        if isinstance(chunk_item, tuple):
            chunk_name, chunk_code = chunk_item
        else:
            chunk_name, chunk_code = f"chunk_{idx}", chunk_item

        cleaned = clean_code(chunk_code)
        tokens = normalize_tokens(tokenize_code(cleaned))
        vec = vectorize_tokens(tokens, vocab, max_length=sequence_length)
        pred = run_inference(vec["tokenIds"])
        if pred is None:
            return {"ml_available": False, "ml_verdict": "NO_MODEL", "ml_attack_type": "NONE", "ml_risk": None, "chunk_index": idx, "chunk_name": chunk_name}
        risk = float(pred.get("riskScore", 0.0))
        if best is None or risk > best["ml_risk"]:
            attack = str(pred.get("attackType") or "NONE").upper()
            if attack not in ATTACKS:
                attack = "NONE"
            best = {
                "ml_available": True,
                "ml_verdict": "VULNERABLE" if risk >= 0.50 else "SAFE",
                "ml_attack_type": attack if risk >= 0.50 else "NONE",
                "ml_risk": risk,
                "chunk_index": idx,
                "chunk_name": chunk_name,
                "ml_attack_type_confidence": pred.get("attackTypeConfidence"),
                "ml_attack_type_probs": pred.get("attackTypeProbs"),
            }
    return best or {"ml_available": False, "ml_verdict":"NO_MODEL", "ml_attack_type":"NONE", "ml_risk":None, "chunk_index":0, "chunk_name":"__file__"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sequence-length", type=int, default=256)
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []

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
            code = f.read_text(encoding="utf-8", errors="replace")
            pred = ml_predict_code(code, f.name, args.sequence_length)
            ml_label = pred["ml_verdict"]
            ml_attack = pred["ml_attack_type"]
            binary_ok = (ml_label == exp_label)
            full_ok = binary_ok and (ml_attack == exp_attack)
            rows.append({
                "file": rel,
                "expected_label": exp_label,
                "expected_attack_type": exp_attack,
                "ml_label": ml_label,
                "ml_attack_type": ml_attack,
                "ml_risk": pred.get("ml_risk"),
                "ml_attack_type_confidence": pred.get("ml_attack_type_confidence"),
                "chunk_index": pred.get("chunk_index"),
                "chunk_name": pred.get("chunk_name"),
                "binary_pass": binary_ok,
                "full_pass": full_ok,
            })

    total = len(rows)
    bin_ok = sum(1 for r in rows if r["binary_pass"])
    full_ok = sum(1 for r in rows if r["full_pass"])
    by_exp = Counter(r["expected_attack_type"] for r in rows)
    by_pred = Counter(r["ml_attack_type"] for r in rows)

    csv_path = out_dir / "ml_only_results.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [])
        if rows:
            writer.writeheader(); writer.writerows(rows)

    md = []
    md.append("# ML-only Suite Evaluation\n")
    md.append(f"- Total: **{total}**\n")
    md.append(f"- Binary ML accuracy: **{bin_ok}/{total}** ({(bin_ok/max(1,total))*100:.2f}%)\n")
    md.append(f"- Full ML label+type accuracy: **{full_ok}/{total}** ({(full_ok/max(1,total))*100:.2f}%)\n")
    md.append(f"- Expected attack distribution: `{dict(by_exp)}`\n")
    md.append(f"- ML attack distribution: `{dict(by_pred)}`\n\n")
    md.append("## Failures\n\n")
    for r in rows:
        if not r["full_pass"]:
            md.append(f"- `{r['file']}` expected `{r['expected_label']} / {r['expected_attack_type']}` got `{r['ml_label']} / {r['ml_attack_type']}` risk `{r['ml_risk']}`\n")
    (out_dir / "ml_only_summary.md").write_text("".join(md), encoding="utf-8")
    (out_dir / "ml_only_summary.json").write_text(json.dumps({
        "total": total,
        "binary_correct": bin_ok,
        "binary_accuracy": bin_ok/max(1,total),
        "full_correct": full_ok,
        "full_accuracy": full_ok/max(1,total),
        "expected_attack_distribution": dict(by_exp),
        "ml_attack_distribution": dict(by_pred),
    }, indent=2), encoding="utf-8")

    print(f"ML-only binary accuracy: {bin_ok}/{total}")
    print(f"ML-only full accuracy: {full_ok}/{total}")
    print(f"Wrote: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
