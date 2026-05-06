r"""
ML-primary audit for the SQLi detector.

Purpose:
- Quantify whether final SAFE/VULNERABLE decisions are mostly supported by the ML model.
- Detect places where fusion overrides ML, and why.
- Run directly on ZIP suites without using the API.

Run from backend/:
    set PYTHONPATH=%CD%
    venv\Scripts\python.exe scripts\ml_primary_audit.py --suite test_suites\mega_sqli_debug_suite.zip --out outputs\ml_audit\mega

Multiple suites:
    venv\Scripts\python.exe scripts\ml_primary_audit.py --suite test_suites\targeted_next_debug_suite.zip --suite test_suites\mega_sqli_debug_suite.zip --out outputs\ml_audit\all
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# Project imports. This script must be run from backend/ with PYTHONPATH=%CD%.
from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.preprocessing.normalizer import (
    extract_db_returning_funcs,
    extract_numeric_returning_funcs,
    extract_safe_returning_funcs,
)
from app.preprocessing.chunker import split_into_chunks
from app.services.scan_service import _analyse_chunk, _build_detection

EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".java": "java",
    ".php": "php",
}

ATTACK_TYPES = ["NONE", "IN_BAND", "BLIND", "SECOND_ORDER"]


def infer_expected_from_path(path: str) -> Tuple[Optional[str], Optional[str]]:
    """Infer expected label/type from common suite filename conventions."""
    name = Path(path).name.upper()
    full = path.replace("\\", "/").upper()
    if "SECOND_ORDER" in name or "SECOND_ORDER" in full:
        return "VULNERABLE", "SECOND_ORDER"
    if "IN_BAND" in name or "IN_BAND" in full:
        return "VULNERABLE", "IN_BAND"
    if "BLIND" in name or "BLIND" in full:
        return "VULNERABLE", "BLIND"
    if "SAFE" in name or "_NONE_" in name or "/NONE" in full or "NONE_" in name:
        return "SAFE", "NONE"
    return None, None


def binary(label: Optional[str]) -> Optional[str]:
    if label is None:
        return None
    return "VULNERABLE" if label in {"VULNERABLE", "SUSPICIOUS"} else "SAFE"


def ml_label_from_score(score: Optional[float], threshold: float = 0.5) -> str:
    if score is None:
        return "NO_MODEL"
    return "VULNERABLE" if score >= threshold else "SAFE"


def read_manifest(extracted_root: Path) -> Dict[str, Tuple[str, str]]:
    """Read manifest.csv if generated suite has one."""
    manifest = extracted_root / "manifest.csv"
    out: Dict[str, Tuple[str, str]] = {}
    if not manifest.exists():
        return out
    with manifest.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rel = row.get("file") or row.get("path") or row.get("relative_path")
            if not rel:
                continue
            label = (row.get("expected_label") or row.get("label") or "").strip().upper()
            attack = (row.get("expected_attack_type") or row.get("attack_type") or "").strip().upper()
            if label and attack:
                out[rel.replace("\\", "/")] = (label, attack)
    return out


def analyse_file(raw_code: str, language: str) -> Dict[str, object]:
    """Run chunk-level analysis and collect ML/rule/fusion audit data."""
    chunks = split_into_chunks(raw_code, language)
    full_tokens = tokenize_code(clean_code(raw_code))
    safe_funcs = extract_safe_returning_funcs(full_tokens)
    numeric_funcs = extract_numeric_returning_funcs(full_tokens)
    db_funcs = extract_db_returning_funcs(full_tokens)

    chunk_rows = []
    for chunk_name, chunk_code in chunks:
        r = _analyse_chunk(
            chunk_code,
            chunk_name,
            extra_safe_funcs=safe_funcs,
            extra_numeric_funcs=numeric_funcs,
            extra_db_loaded_funcs=db_funcs,
        )
        chunk_rows.append(r)

    ml_scores = [r["mlScore"] for r in chunk_rows if r.get("mlScore") is not None]
    rule_scores = [float(r.get("ruleScore", 0.0)) for r in chunk_rows]
    fused_scores = [float(r.get("fusedScore", 0.0)) for r in chunk_rows]

    ml_max = max(ml_scores) if ml_scores else None
    rule_max = max(rule_scores) if rule_scores else None
    fused_max = max(fused_scores) if fused_scores else None

    worst = max(chunk_rows, key=lambda r: float(r.get("fusedScore", 0.0))) if chunk_rows else None
    source = worst.get("verdictSource") if worst else "NO_CHUNKS"
    worst_chunk = worst.get("chunkName") if worst else "NO_CHUNKS"
    worst_signals = sorted(list(worst.get("signals", set()))) if worst else []

    # Attack-type ML majority for vulnerable ML chunks (approximation only).
    type_votes = Counter()
    for r in chunk_rows:
        if r.get("mlScore") is not None and float(r["mlScore"]) >= 0.5:
            type_votes[str(r.get("attackType", "NONE"))] += 1
    ml_type_mode = type_votes.most_common(1)[0][0] if type_votes else "NONE"

    return {
        "n_chunks": len(chunks),
        "ml_max_score": ml_max,
        "rule_max_score": rule_max,
        "fused_max_score": fused_max,
        "worst_chunk": worst_chunk,
        "worst_verdict_source": source,
        "worst_signals": worst_signals,
        "ml_label_05": ml_label_from_score(ml_max, 0.5),
        "ml_label_07": ml_label_from_score(ml_max, 0.7),
        "ml_attack_type_mode": ml_type_mode,
        "chunk_source_counts": dict(Counter(str(r.get("verdictSource", "UNKNOWN")) for r in chunk_rows)),
        "chunk_ml_loaded_count": sum(1 for r in chunk_rows if r.get("mlScore") is not None),
    }


def iter_suite_files(suite_zip: Path):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        with zipfile.ZipFile(suite_zip, "r") as zf:
            zf.extractall(root)
        manifest = read_manifest(root)
        for file_path in sorted(root.rglob("*")):
            if not file_path.is_file():
                continue
            if file_path.name.lower() == "manifest.csv":
                continue
            ext = file_path.suffix.lower()
            if ext not in EXT_TO_LANG:
                continue
            rel = file_path.relative_to(root).as_posix()
            raw = file_path.read_text(encoding="utf-8", errors="replace")
            expected = manifest.get(rel) or infer_expected_from_path(rel)
            yield rel, raw, EXT_TO_LANG[ext], expected


def run_audit(suite_paths: List[Path], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    summary = {
        "suites": {},
        "overall": {},
    }
    global_counts = Counter()
    global_ml_support = Counter()

    for suite in suite_paths:
        suite_name = suite.stem
        suite_counts = Counter()
        suite_ml_support = Counter()
        for rel, raw, language, (expected_label, expected_type) in iter_suite_files(suite):
            try:
                det = _build_detection(raw, language)
                audit = analyse_file(raw, language)
            except Exception as exc:
                row = {
                    "suite": suite_name,
                    "file": rel,
                    "language": language,
                    "expected_label": expected_label or "UNKNOWN",
                    "expected_attack_type": expected_type or "UNKNOWN",
                    "final_label": "ERROR",
                    "final_attack_type": "ERROR",
                    "final_risk": "",
                    "error": repr(exc),
                }
                rows.append(row)
                suite_counts["errors"] += 1
                global_counts["errors"] += 1
                continue

            final_label = getattr(det, "label", None)
            final_type = getattr(det, "attackType", None)
            final_risk = getattr(det, "riskScore", None)
            final_binary = binary(final_label)
            expected_binary = binary(expected_label)
            ml_binary = audit["ml_label_05"]
            final_correct = (
                expected_label is not None
                and final_label == expected_label
                and (expected_type is None or final_type == expected_type)
            )
            ml_supports_final = (ml_binary == final_binary)
            final_differs_from_ml = not ml_supports_final

            suite_counts["total"] += 1
            suite_counts["correct"] += int(final_correct)
            suite_counts[f"source::{audit['worst_verdict_source']}"] += 1
            suite_counts[f"final::{final_binary}"] += 1
            suite_counts[f"ml::{ml_binary}"] += 1
            suite_ml_support["ml_supports_final"] += int(ml_supports_final)
            suite_ml_support["final_differs_from_ml"] += int(final_differs_from_ml)

            global_counts.update(suite_counts - suite_counts)  # no-op; keep explicit below
            global_counts["total"] += 1
            global_counts["correct"] += int(final_correct)
            global_counts[f"source::{audit['worst_verdict_source']}"] += 1
            global_counts[f"final::{final_binary}"] += 1
            global_counts[f"ml::{ml_binary}"] += 1
            global_ml_support["ml_supports_final"] += int(ml_supports_final)
            global_ml_support["final_differs_from_ml"] += int(final_differs_from_ml)

            row = {
                "suite": suite_name,
                "file": rel,
                "language": language,
                "expected_label": expected_label or "UNKNOWN",
                "expected_attack_type": expected_type or "UNKNOWN",
                "final_label": final_label,
                "final_attack_type": final_type,
                "final_binary": final_binary,
                "final_risk": final_risk,
                "final_correct": final_correct,
                "ml_max_score": audit["ml_max_score"],
                "ml_label_05": audit["ml_label_05"],
                "ml_label_07": audit["ml_label_07"],
                "ml_attack_type_mode": audit["ml_attack_type_mode"],
                "ml_supports_final": ml_supports_final,
                "rule_max_score": audit["rule_max_score"],
                "fused_max_score": audit["fused_max_score"],
                "verdict_source": audit["worst_verdict_source"],
                "n_chunks": audit["n_chunks"],
                "chunk_ml_loaded_count": audit["chunk_ml_loaded_count"],
                "worst_chunk": audit["worst_chunk"],
                "worst_signals": "|".join(audit["worst_signals"]),
                "chunk_source_counts": json.dumps(audit["chunk_source_counts"], sort_keys=True),
                "error": "",
            }
            rows.append(row)

        total = suite_counts.get("total", 0)
        summary["suites"][suite_name] = {
            "total": total,
            "correct": suite_counts.get("correct", 0),
            "accuracy": round(suite_counts.get("correct", 0) / total, 4) if total else 0.0,
            "ml_supports_final": suite_ml_support.get("ml_supports_final", 0),
            "ml_support_rate": round(suite_ml_support.get("ml_supports_final", 0) / total, 4) if total else 0.0,
            "source_counts": {k.replace("source::", ""): v for k, v in suite_counts.items() if k.startswith("source::")},
            "final_binary_counts": {k.replace("final::", ""): v for k, v in suite_counts.items() if k.startswith("final::")},
            "ml_binary_counts": {k.replace("ml::", ""): v for k, v in suite_counts.items() if k.startswith("ml::")},
        }

    total = global_counts.get("total", 0)
    summary["overall"] = {
        "total": total,
        "correct": global_counts.get("correct", 0),
        "accuracy": round(global_counts.get("correct", 0) / total, 4) if total else 0.0,
        "ml_supports_final": global_ml_support.get("ml_supports_final", 0),
        "ml_support_rate": round(global_ml_support.get("ml_supports_final", 0) / total, 4) if total else 0.0,
        "source_counts": {k.replace("source::", ""): v for k, v in global_counts.items() if k.startswith("source::")},
        "final_binary_counts": {k.replace("final::", ""): v for k, v in global_counts.items() if k.startswith("final::")},
        "ml_binary_counts": {k.replace("ml::", ""): v for k, v in global_counts.items() if k.startswith("ml::")},
    }

    csv_path = out_dir / "ml_primary_audit.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        if rows:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    json_path = out_dir / "ml_primary_audit_summary.json"
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    md_path = out_dir / "ml_primary_audit_summary.md"
    md_lines = ["# ML Primary Audit Summary", ""]
    md_lines.append("## Overall")
    o = summary["overall"]
    md_lines.append(f"- Total files: **{o['total']}**")
    md_lines.append(f"- Final detector correct: **{o['correct']}/{o['total']}** ({o['accuracy']:.2%})")
    md_lines.append(f"- ML binary prediction supports final binary verdict: **{o['ml_supports_final']}/{o['total']}** ({o['ml_support_rate']:.2%})")
    md_lines.append(f"- Verdict source counts: `{json.dumps(o['source_counts'], ensure_ascii=False)}`")
    md_lines.append(f"- ML binary counts: `{json.dumps(o['ml_binary_counts'], ensure_ascii=False)}`")
    md_lines.append("")
    md_lines.append("## By suite")
    for name, s in summary["suites"].items():
        md_lines.append(f"### {name}")
        md_lines.append(f"- Final detector correct: **{s['correct']}/{s['total']}** ({s['accuracy']:.2%})")
        md_lines.append(f"- ML supports final: **{s['ml_supports_final']}/{s['total']}** ({s['ml_support_rate']:.2%})")
        md_lines.append(f"- Source counts: `{json.dumps(s['source_counts'], ensure_ascii=False)}`")
        md_lines.append("")
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    print(f"Saved CSV: {csv_path}")
    print(f"Saved summary JSON: {json_path}")
    print(f"Saved summary MD: {md_path}")
    print(json.dumps(summary["overall"], indent=2, ensure_ascii=False))


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", action="append", required=True, help="Path to a ZIP suite. Can be passed multiple times.")
    ap.add_argument("--out", default="outputs/ml_primary_audit", help="Output directory.")
    args = ap.parse_args(argv)
    suites = [Path(s) for s in args.suite]
    missing = [str(s) for s in suites if not s.exists()]
    if missing:
        print(f"Missing suite(s): {missing}", file=sys.stderr)
        return 2
    run_audit(suites, Path(args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
