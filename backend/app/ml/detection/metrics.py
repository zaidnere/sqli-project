"""Metrics for Model 1 binary and attack-type heads."""
from __future__ import annotations
import numpy as np

ATTACK_TYPE_NAMES = {0: "NONE", 1: "IN_BAND", 2: "BLIND", 3: "SECOND_ORDER"}

def classification_metrics(y_true, y_score, threshold=0.5):
    y_true = np.asarray(y_true).astype(int)
    y_pred = (np.asarray(y_score) >= threshold).astype(int)
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    acc = (tp + tn) / len(y_true) if len(y_true) else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "tp": tp, "tn": tn, "fp": fp, "fn": fn}

def attack_type_metrics(y_true_type, y_pred_type, n_classes=4):
    y_true_type = np.asarray(y_true_type).astype(int)
    y_pred_type = np.asarray(y_pred_type).astype(int)
    cm = np.zeros((n_classes, n_classes), dtype=int)
    for t, p in zip(y_true_type, y_pred_type):
        cm[t, p] += 1
    per_class = {}
    f1s = []
    for cid in range(n_classes):
        tp = int(cm[cid, cid])
        fp = int(cm[:, cid].sum() - tp)
        fn = int(cm[cid, :].sum() - tp)
        n = int(cm[cid, :].sum())
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        per_class[ATTACK_TYPE_NAMES.get(cid, str(cid))] = {"n": n, "precision": prec, "recall": rec, "f1": f1}
        if n:
            f1s.append(f1)
    return {
        "accuracy": float(np.mean(y_true_type == y_pred_type)) if len(y_true_type) else 0.0,
        "macro_f1": float(np.mean(f1s)) if f1s else 0.0,
        "confusion_matrix": cm.tolist(),
        "per_class": per_class,
    }
