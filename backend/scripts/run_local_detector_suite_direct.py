#!/usr/bin/env python3
"""
Direct local SQLi suite runner.
Run from backend folder. It imports _build_detection directly, so it verifies
which backend code is currently active without needing FastAPI/Uvicorn/Postman.

Usage examples:
  python scripts/run_local_detector_suite_direct.py --suite test_suites/targeted_next_debug_suite.zip
  python scripts/run_local_detector_suite_direct.py --suite test_suites/mega_sqli_debug_suite.zip --audit
  python scripts/run_local_detector_suite_direct.py --suite test_suites/realistic_long_sqli_suite.zip --audit-csv outputs/audit.csv
"""
from __future__ import annotations

import argparse
import csv
import sys
import tempfile
import zipfile
import types
from collections import Counter
from pathlib import Path
from typing import Any

# Lightweight stubs so importing scan_service does not require MongoDB/bson.
try:
    import bson  # type: ignore
except Exception:
    bson = types.ModuleType("bson")
    class ObjectId(str):
        pass
    bson.ObjectId = ObjectId
    sys.modules["bson"] = bson

if "app.db.database" not in sys.modules:
    m = types.ModuleType("app.db.database")
    m.get_audit_logs_collection = lambda: None
    sys.modules["app.db.database"] = m
if "app.services.audit_log_service" not in sys.modules:
    m2 = types.ModuleType("app.services.audit_log_service")
    async def log_audit_event(*args, **kwargs):
        return "local-direct-scan"
    m2.log_audit_event = log_audit_event
    sys.modules["app.services.audit_log_service"] = m2

from app.services.scan_service import _build_detection

EXT_LANG = {".py": "python", ".js": "javascript", ".java": "java", ".php": "php"}


def norm_type(value: str | None) -> str:
    return (value or "NONE").strip().upper().replace("-", "_").replace(" ", "_")


def norm_label(value: str | None) -> str:
    v = (value or "").strip().upper()
    if v == "NONE":
        return "SAFE"
    return v


def unpack_if_zip(suite: Path) -> tuple[tempfile.TemporaryDirectory[str] | None, Path]:
    if suite.is_file() and suite.suffix.lower() == ".zip":
        tmp = tempfile.TemporaryDirectory()
        with zipfile.ZipFile(suite, "r") as zf:
            zf.extractall(tmp.name)
        return tmp, Path(tmp.name)
    return None, suite


def g(obj: Any, name: str, default: Any = None) -> Any:
    return getattr(obj, name, default)


def audit_record(rel: str, expected_v: str, expected_t: str, actual_v: str, actual_t: str, ok: bool, det: Any) -> dict[str, Any]:
    ml_verdict = norm_label(g(det, "mlPredictedVerdict")) if g(det, "mlPredictedVerdict") else ""
    ml_type = norm_type(g(det, "mlPredictedAttackType")) if g(det, "mlPredictedAttackType") else ""
    final_matches_ml_label = bool(ml_verdict and ml_verdict == actual_v)
    final_matches_ml_type = bool(actual_v == "SAFE" or (ml_type and ml_type == actual_t))
    return {
        "file": rel,
        "expected_verdict": expected_v,
        "expected_attack_type": expected_t,
        "final_verdict": actual_v,
        "final_attack_type": actual_t,
        "pass": ok,
        "final_risk_score": g(det, "riskScore"),
        "ml_executed": g(det, "mlExecuted", False),
        "ml_risk_score": g(det, "mlRiskScore"),
        "ml_predicted_verdict": ml_verdict,
        "ml_predicted_attack_type": ml_type,
        "rule_score": g(det, "ruleScore"),
        "verdict_source": g(det, "verdictSource", ""),
        "decision_source": g(det, "decisionSource", ""),
        "fusion_reason": g(det, "fusionReason", ""),
        "raw_evidence_override_applied": g(det, "rawEvidenceOverrideApplied", False),
        "pre_override_verdict": g(det, "preOverrideVerdict", ""),
        "pre_override_attack_type": g(det, "preOverrideAttackType", ""),
        "pre_override_risk_score": g(det, "preOverrideRiskScore", ""),
        "worst_chunk": g(det, "worstChunk", ""),
        "chunk_count": g(det, "chunkCount", 0),
        "model_version": g(det, "modelVersion", ""),
        "model_sequence_length": g(det, "modelSequenceLength", ""),
        "final_matches_ml_label": final_matches_ml_label,
        "final_matches_ml_type": final_matches_ml_type,
        "final_matches_ml_label_and_type": bool(final_matches_ml_label and final_matches_ml_type),
    }


def print_audit_summary(records: list[dict[str, Any]]) -> None:
    total = len(records)
    if not total:
        return
    def pct(n: int) -> str:
        return f"{n}/{total} ({(100*n/total):.1f}%)"

    ml_executed = sum(1 for r in records if str(r["ml_executed"]).lower() == "true" or r["ml_executed"] is True)
    raw_override = sum(1 for r in records if str(r["raw_evidence_override_applied"]).lower() == "true" or r["raw_evidence_override_applied"] is True)
    final_matches_ml_label = sum(1 for r in records if r["final_matches_ml_label"])
    final_matches_ml_both = sum(1 for r in records if r["final_matches_ml_label_and_type"])

    verdict_sources = Counter(str(r["verdict_source"] or "UNKNOWN") for r in records)
    decision_sources = Counter(str(r["decision_source"] or "UNKNOWN") for r in records)

    ml_primary_like = sum(
        c for src, c in decision_sources.items()
        if src in {"ml_primary", "ml_supported_by_evidence"}
    )
    rule_like = sum(
        c for src, c in decision_sources.items()
        if src in {"rule_primary", "semantic_safe_guard", "rule_safety_net", "rule_safety_net_no_model", "raw_evidence_override", "raw_evidence_fast_path"}
    )

    print("\nAudit summary")
    print("-------------")
    print(f"ML executed:                 {pct(ml_executed)}")
    print(f"Final label matches ML:      {pct(final_matches_ml_label)}")
    print(f"Final label+type matches ML: {pct(final_matches_ml_both)}")
    print(f"ML-primary/support bucket:   {pct(ml_primary_like)}")
    print(f"Rule/semantic/raw bucket:    {pct(rule_like)}")
    print(f"Raw override/fast path:      {pct(raw_override)}")

    print("\nDecision source counts:")
    for src, count in decision_sources.most_common():
        print(f"  {src}: {count}")

    print("\nExact verdictSource counts:")
    for src, count in verdict_sources.most_common():
        print(f"  {src}: {count}")


def write_audit_csv(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not records:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        writer.writeheader()
        writer.writerows(records)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", required=True, help="Suite folder or .zip containing manifest.csv")
    parser.add_argument("--audit", action="store_true", help="Print ML-vs-fusion audit summary")
    parser.add_argument("--audit-csv", default=None, help="Optional CSV path for detailed per-file audit output")
    parser.add_argument("--force-ml", action="store_true", help="Diagnostic mode: bypass raw fast-path so Model 1 runs before fusion when possible")
    args = parser.parse_args()

    suite_path = Path(args.suite).resolve()
    tmp, root = unpack_if_zip(suite_path)
    try:
        manifests = list(root.rglob("manifest.csv"))
        if not manifests:
            print(f"ERROR: manifest.csv not found under {root}")
            return 2
        manifest = manifests[0]
        base = manifest.parent
        rows = list(csv.DictReader(manifest.open(encoding="utf-8")))
        fails = []
        audit_rows: list[dict[str, Any]] = []

        for row in rows:
            rel = row["file"]
            path = base / rel
            code = path.read_text(encoding="utf-8")
            lang = EXT_LANG.get(path.suffix.lower(), "python")
            det = _build_detection(code, lang, force_ml=args.force_ml)
            actual_v = norm_label(det.label)
            actual_t = norm_type(det.attackType if actual_v != "SAFE" else "NONE")
            expected_v = norm_label(
                row.get("expected_verdict")
                or row.get("expected_label")
                or row.get("label")
                or ""
            )
            expected_t = norm_type(
                row.get("expected_type")
                or row.get("expected_attack_type")
                or row.get("attack_type")
                or "NONE"
            )
            ok = (actual_v, actual_t) == (expected_v, expected_t)
            audit_rows.append(audit_record(rel, expected_v, expected_t, actual_v, actual_t, ok, det))
            if not ok:
                patterns = " | ".join(p.pattern for p in det.suspiciousPatterns)
                fails.append((rel, expected_v, expected_t, actual_v, actual_t, det.riskScore, patterns, det.explanation, det.verdictSource))

        print(f"Suite: {suite_path.name}")
        print(f"Total: {len(rows)}")
        print(f"Passed: {len(rows) - len(fails)}")
        print(f"Failed: {len(fails)}")

        if args.audit or args.audit_csv:
            print_audit_summary(audit_rows)
        if args.audit_csv:
            out = Path(args.audit_csv)
            write_audit_csv(out, audit_rows)
            print(f"\nAudit CSV written to: {out}")

        for f in fails:
            print("\nFAIL:")
            print(f"  File: {f[0]}")
            print(f"  Expected: {f[1]} / {f[2]}")
            print(f"  Actual:   {f[3]} / {f[4]}")
            print(f"  Risk:     {f[5]}")
            print(f"  Patterns: {f[6]}")
            print(f"  Source:   {f[8]}")
            print(f"  Expl:     {f[7]}")
        return 1 if fails else 0
    finally:
        if tmp is not None:
            tmp.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
