#!/usr/bin/env python3
"""
Direct local SQLi suite runner.
Run from backend folder. It imports _build_detection directly, so it verifies
which backend code is currently active without needing FastAPI/Uvicorn/Postman.

Usage examples:
  python scripts/run_local_detector_suite_direct.py --suite test_suites/targeted_next_debug_suite.zip
  python scripts/run_local_detector_suite_direct.py --suite test_suites/mega_sqli_debug_suite.zip
  python scripts/run_local_detector_suite_direct.py --suite test_suites/realistic_long_sqli_suite.zip
"""
from __future__ import annotations
import argparse, csv, sys, tempfile, zipfile, types
from pathlib import Path

# Lightweight stubs so importing scan_service does not require MongoDB/bson.
try:
    import bson  # type: ignore
except Exception:
    bson = types.ModuleType("bson")
    class ObjectId(str): pass
    bson.ObjectId = ObjectId
    sys.modules["bson"] = bson

if "app.db.database" not in sys.modules:
    m = types.ModuleType("app.db.database")
    m.get_audit_logs_collection = lambda: None
    sys.modules["app.db.database"] = m
if "app.services.audit_log_service" not in sys.modules:
    m2 = types.ModuleType("app.services.audit_log_service")
    async def log_audit_event(*args, **kwargs): return "local-direct-scan"
    m2.log_audit_event = log_audit_event
    sys.modules["app.services.audit_log_service"] = m2

from app.services.scan_service import _build_detection

EXT_LANG = {".py": "python", ".js": "javascript", ".java": "java", ".php": "php"}

def norm_type(value: str | None) -> str:
    return (value or "NONE").strip().upper().replace("-", "_").replace(" ", "_")

def unpack_if_zip(suite: Path) -> tuple[tempfile.TemporaryDirectory[str] | None, Path]:
    if suite.is_file() and suite.suffix.lower() == ".zip":
        tmp = tempfile.TemporaryDirectory()
        with zipfile.ZipFile(suite, "r") as zf:
            zf.extractall(tmp.name)
        return tmp, Path(tmp.name)
    return None, suite

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", required=True, help="Suite folder or .zip containing manifest.csv")
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
        for row in rows:
            rel = row["file"]
            path = base / rel
            code = path.read_text(encoding="utf-8")
            lang = EXT_LANG.get(path.suffix.lower(), "python")
            det = _build_detection(code, lang)
            actual_v = det.label
            actual_t = norm_type(det.attackType if det.label != "SAFE" else "NONE")
            expected_v = row["expected_verdict"].strip().upper()
            expected_t = norm_type(row["expected_type"])
            ok = (actual_v, actual_t) == (expected_v, expected_t)
            if not ok:
                patterns = " | ".join(p.pattern for p in det.suspiciousPatterns)
                fails.append((rel, expected_v, expected_t, actual_v, actual_t, det.riskScore, patterns, det.explanation, det.verdictSource))
        print(f"Suite: {suite_path.name}")
        print(f"Total: {len(rows)}")
        print(f"Passed: {len(rows) - len(fails)}")
        print(f"Failed: {len(fails)}")
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
