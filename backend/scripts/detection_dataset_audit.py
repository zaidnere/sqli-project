#!/usr/bin/env python3
"""Dataset audit for Model 1 Detection.

Run from backend/ or project root:
    python backend/scripts/detection_dataset_audit.py --data backend/colab_export/training_data.npz --vocab backend/colab_export/vocabulary.json --out outputs/model1_audit

The script is intentionally defensive because different exports may contain
slightly different field names. It reports data size, class distribution,
language distribution, padding/truncation, UNK rate, and duplicate sequence
checks. This strengthens the Ministry requirements: data reliability, bias,
outliers, and imbalance.
"""
from __future__ import annotations
import argparse, json, hashlib, os, re
from collections import Counter
from pathlib import Path
import numpy as np

LANG_EXT = {'.py':'python','.js':'javascript','.jsx':'javascript','.ts':'javascript','.java':'java','.php':'php'}

def infer_language(name='', text=''):
    name = str(name or '').lower()
    text = str(text or '').lower()
    for ext, lang in LANG_EXT.items():
        if name.endswith(ext):
            return lang
    if '<?php' in text or '$_get' in text or '$_post' in text or '$this->' in text:
        return 'php'
    if 'public class' in text or 'preparedstatement' in text or 'resultset' in text:
        return 'java'
    if 'req.query' in text or 'const ' in text or 'db.all' in text or 'function ' in text:
        return 'javascript'
    if 'def ' in text or 'cursor.execute' in text or 'request.get' in text:
        return 'python'
    return 'unknown'

def get_first(data, names):
    for n in names:
        if n in data.files:
            return data[n]
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', required=True)
    ap.add_argument('--vocab', required=True)
    ap.add_argument('--out', default='outputs/model1_audit')
    args = ap.parse_args()
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    data = np.load(args.data, allow_pickle=True)
    vocab = json.load(open(args.vocab, encoding='utf-8'))
    X = get_first(data, ['X','x','sequences','token_ids'])
    if X is None:
        raise SystemExit(f'Could not find token sequence array. Available fields: {data.files}')
    yv = get_first(data, ['y_verdict','y_binary','y','labels'])
    yt = get_first(data, ['y_attack_type','y_type','attack_types','type_labels'])
    PAD_ID = int(vocab.get('PAD', vocab.get('<PAD>', 0)))
    UNK_ID = int(vocab.get('UNK', vocab.get('<UNK>', 1)))

    paths = get_first(data, ['file_paths','paths','filenames','names'])
    raw = get_first(data, ['raw_code','source_code','code'])
    langs = get_first(data, ['languages','language'])
    if langs is not None:
        lang_list = [str(x) for x in langs]
    elif paths is not None or raw is not None:
        paths_l = [str(x) for x in paths] if paths is not None else [''] * len(X)
        raw_l = [str(x) for x in raw] if raw is not None else [''] * len(X)
        lang_list = [infer_language(p, t) for p,t in zip(paths_l, raw_l)]
    else:
        lang_list = ['unknown'] * len(X)

    non_pad_lengths = np.array([(row != PAD_ID).sum() for row in X])
    unk_count = int((X == UNK_ID).sum())
    token_count = int((X != PAD_ID).sum())
    seq_hashes = [hashlib.sha256(','.join(map(str,[int(v) for v in row if int(v)!=PAD_ID])).encode()).hexdigest() for row in X]
    duplicate_count = len(seq_hashes) - len(set(seq_hashes))

    report = {
        'n_samples': int(len(X)),
        'sequence_length': int(X.shape[1]),
        'vocabulary_size': int(len(vocab)),
        'pad_id': PAD_ID,
        'unk_id': UNK_ID,
        'language_counts': dict(Counter(lang_list)),
        'avg_non_pad_length': float(non_pad_lengths.mean()),
        'max_non_pad_length': int(non_pad_lengths.max()),
        'min_non_pad_length': int(non_pad_lengths.min()),
        'padded_samples': int((non_pad_lengths < X.shape[1]).sum()),
        'truncated_samples_estimate': int((non_pad_lengths >= X.shape[1]).sum()),
        'unk_token_count': unk_count,
        'unk_rate': float(unk_count / max(token_count,1)),
        'duplicate_sequence_count': int(duplicate_count),
    }
    if yv is not None:
        report['verdict_counts_raw'] = {str(k): int(v) for k,v in Counter([int(x) for x in yv]).items()}
    if yt is not None:
        report['attack_type_counts_raw'] = {str(k): int(v) for k,v in Counter([int(x) for x in yt]).items()}
    (out/'dataset_audit_v3.json').write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if report['language_counts'] == {'unknown': len(X)}:
        print('\nWARNING: all languages are unknown. Update export_for_colab.py to export file_paths or language labels.')

if __name__ == '__main__':
    main()
