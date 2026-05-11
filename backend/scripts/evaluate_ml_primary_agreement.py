#!/usr/bin/env python3
"""Summarize suite results and, when available, ML/fusion decision sources.

The current CSV reports may not include `verdictSource`. If you add that column
to the runner output, this script will calculate how many final decisions were
ML-driven vs deterministic overrides.
"""
from __future__ import annotations
import argparse, csv, json
from pathlib import Path
from collections import Counter


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('csv_files', nargs='+')
    ap.add_argument('--out', default='outputs/ml_primary_agreement.json')
    args = ap.parse_args()
    summary = {}
    source_counts = Counter()
    for path in args.csv_files:
        p = Path(path)
        with p.open(encoding='utf-8-sig', newline='') as f:
            rows = list(csv.DictReader(f))
        total = len(rows)
        pass_count = sum(1 for r in rows if str(r.get('Pass','')).strip() in {'✅','True','true','1','PASS','pass'})
        source_col = None
        for c in ['verdictSource','Verdict Source','source','Source']:
            if rows and c in rows[0]: source_col = c; break
        if source_col:
            source_counts.update(str(r.get(source_col,'unknown')) for r in rows)
        summary[p.name] = {'total': total, 'passed': pass_count, 'failed': total-pass_count}
    result = {'suite_summary': summary, 'verdict_source_counts': dict(source_counts)}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    if not source_counts:
        print('\nNOTE: No verdictSource column found. Add it to runner CSV output to prove ML-primary decision share.')

if __name__ == '__main__':
    main()
