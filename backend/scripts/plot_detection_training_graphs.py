#!/usr/bin/env python3
"""Plot Model 1 Detection training history and metrics.

Usage:
    python backend/scripts/plot_detection_training_graphs.py --history training_history.json --metrics sqli_detection_metrics.json --out training_plots
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
import matplotlib.pyplot as plt


def plot_line(history, keys, title, path, ylabel=None):
    epochs = [h.get('epoch', i+1) for i,h in enumerate(history)]
    plt.figure(figsize=(9,5))
    for k in keys:
        ys = [h.get(k) for h in history]
        if any(v is not None for v in ys):
            plt.plot(epochs, ys, marker='o', label=k)
    plt.title(title); plt.xlabel('Epoch')
    if ylabel: plt.ylabel(ylabel)
    plt.grid(True, alpha=0.3); plt.legend(); plt.tight_layout()
    plt.savefig(path, dpi=160); plt.close()


def plot_cm(cm, labels, title, path):
    plt.figure(figsize=(7,6))
    plt.imshow(cm)
    plt.title(title)
    plt.xticks(range(len(labels)), labels, rotation=45, ha='right')
    plt.yticks(range(len(labels)), labels)
    for i,row in enumerate(cm):
        for j,val in enumerate(row):
            plt.text(j, i, str(val), ha='center', va='center')
    plt.xlabel('Predicted'); plt.ylabel('Actual')
    plt.tight_layout(); plt.savefig(path, dpi=160); plt.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--history', required=True)
    ap.add_argument('--metrics', required=True)
    ap.add_argument('--out', default='training_plots')
    args = ap.parse_args()
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    history = json.load(open(args.history, encoding='utf-8'))
    metrics = json.load(open(args.metrics, encoding='utf-8'))
    plot_line(history, ['train_loss_total','train_loss_bce','train_loss_cce'], 'Training losses', out/'loss_curves.png', 'Loss')
    plot_line(history, ['train_f1','val_f1'], 'F1 over epochs', out/'f1_curves.png', 'F1')
    plot_line(history, ['val_precision','val_recall'], 'Validation precision/recall', out/'precision_recall_curves.png', 'Score')
    plot_line(history, ['val_type_acc','val_type_macro_f1'], 'Attack-type metrics', out/'attack_type_metrics.png', 'Score')
    plot_line(history, ['lr'], 'Learning-rate schedule', out/'learning_rate.png', 'LR')
    test = metrics.get('test', {})
    binary_cm = [[test.get('tn',0), test.get('fp',0)], [test.get('fn',0), test.get('tp',0)]]
    plot_cm(binary_cm, ['SAFE','VULNERABLE'], 'Binary confusion matrix', out/'binary_confusion_matrix.png')
    type_cm = test.get('type_cm')
    if type_cm:
        plot_cm(type_cm, ['NONE','IN_BAND','BLIND','SECOND_ORDER'], 'Attack-type confusion matrix', out/'attack_type_confusion_matrix.png')
    print(f'Saved plots to {out}')

if __name__ == '__main__':
    main()
