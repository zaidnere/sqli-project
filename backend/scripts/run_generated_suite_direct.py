r"""
Run a generated suite ZIP with manifest.csv directly through _build_detection.

Run from backend/:
    set PYTHONPATH=%CD%
    venv\Scripts\python.exe scripts\run_generated_suite_direct.py --suite test_suites\unseen_generalization_suite.zip --out outputs\unseen_generalization_results
"""
from __future__ import annotations

import argparse
import csv
import json
import tempfile
import zipfile
from pathlib import Path

from app.services.scan_service import _build_detection

EXT_TO_LANG = {".py": "python", ".js": "javascript", ".java": "java", ".php": "php"}


def load_manifest(root: Path):
    path = root / "manifest.csv"
    if not path.exists():
        raise FileNotFoundError("generated suite must contain manifest.csv")
    out = {}
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            out[row["file"].replace("\\", "/")] = row
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    suite = Path(args.suite)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        with zipfile.ZipFile(suite, "r") as zf:
            zf.extractall(root)
        manifest = load_manifest(root)
        for rel, meta in sorted(manifest.items()):
            path = root / rel
            code = path.read_text(encoding="utf-8", errors="replace")
            lang = meta.get("language") or EXT_TO_LANG[path.suffix.lower()]
            expected_label = meta["expected_label"]
            expected_attack = meta["expected_attack_type"]
            try:
                det = _build_detection(code, lang)
                actual_label = det.label
                actual_attack = det.attackType
                risk = det.riskScore
                passed = (actual_label == expected_label and actual_attack == expected_attack)
                error = ""
            except Exception as exc:
                actual_label = "ERROR"
                actual_attack = "ERROR"
                risk = ""
                passed = False
                error = repr(exc)
            rows.append({
                "file": rel,
                "language": lang,
                "expected": f"{expected_label} / {expected_attack}",
                "actual": f"{actual_label} / {actual_attack}",
                "risk": risk,
                "pass": passed,
                "error": error,
            })

    total = len(rows)
    passed = sum(1 for r in rows if r["pass"])
    csv_path = out_dir / "generated_suite_results.csv"
    md_path = out_dir / "generated_suite_results.md"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    md = ["# Generated Unseen Generalization Suite Results", "", f"- Total: **{total}**", f"- Passed: **{passed}**", f"- Failed: **{total-passed}**", "", "| # | File | Expected | Actual | Risk | Pass |", "|---:|---|---|---|---:|---|"]
    for i, row in enumerate(rows, 1):
        mark = "✅" if row["pass"] else "❌"
        md.append(f"| {i} | `{row['file']}` | {row['expected']} | {row['actual']} | {row['risk']} | {mark} |")
    fails = [r for r in rows if not r["pass"]]
    if fails:
        md.extend(["", "## Failures", ""])
        for r in fails:
            md.append(f"### `{r['file']}`")
            md.append(f"- Expected: `{r['expected']}`")
            md.append(f"- Actual: `{r['actual']}`")
            md.append(f"- Risk: `{r['risk']}`")
            if r["error"]:
                md.append(f"- Error: `{r['error']}`")
            md.append("")
    md_path.write_text("\n".join(md), encoding="utf-8")

    print(f"Total: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {total-passed}")
    print(f"Saved: {csv_path}")
    print(f"Saved: {md_path}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
