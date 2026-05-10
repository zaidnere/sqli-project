# Auto-exported from model1_detection_aligned.ipynb — V18 semantic-flow-input
# Run in Google Colab after uploading vocabulary.json and training_data.npz.

# # Model 1 Detection — ML-primary v17
#
# This version focuses on stronger ML ownership of the final decision: sequence length 256, attack-type loss emphasis, live graphs, and training data enriched for Java safe builders, Python/PHP BLIND, and PHP SECOND_ORDER.

# # Model 1 — SQL Injection Detection Model (Proposal/Ministry aligned)
#
# This notebook is the upgraded academic/training notebook for **Model 1: Detection**.
# It keeps the required project architecture:
#
# `normalized token IDs → Embedding → Conv1D/CNN → Bi-LSTM → Dense → two output heads`
#
# Output heads:
# - **Vulnerability head**: Sigmoid, SAFE vs VULNERABLE.
# - **Attack-type head**: Softmax, `NONE / IN_BAND / BLIND / SECOND_ORDER`.
#
# The notebook is intentionally explicit: it shows data loading, dataset analysis, train/validation/test split, class imbalance handling, forward pass, loss, backpropagation, early stopping, metrics, export metadata, and inference proof.
#
# It is designed to satisfy the final project proposal and the Ministry requirements:
# - collect / prepare / analyze data;
# - inspect reliability, duplicates, imbalance, bias, padding/truncation and UNK rate;
# - train a real deep-learning model from scratch;
# - track metrics beyond accuracy;
# - export model, vocabulary, metadata and metrics;
# - prove that ML inference runs before fusion.

"""
MODEL 1 — SQL Injection Detection ML-Primary v17 ADVERSARIAL-FLOW (CNN + Bi-LSTM, dual-head)
============================================================
Architecture (matches project proposal page 8 + page 31 + Gap A review):
  Raw Code → Clean → Tokenize → Normalize → Vectorize
  → Embedding → CNN → Bi-LSTM → Dense
  ├─→ Sigmoid  → vulnerability score (binary)
  └─→ Softmax  → attack type        (NONE / IN_BAND / BLIND / SECOND_ORDER)

Both heads share the CNN+BiLSTM+Dense backbone.

V17 goal: keep V11 adversarial-flow learning while adding hard SAFE no-sink/comment-only/string-only examples, so SQL-looking text is not treated as SQLi without a real execution sink. It targets new-code failures without copying benchmark source files.

Loss: hardcase-weighted BCE(vuln_head) + λ·hardcase-weighted CCE(type_head), λ = 0.90
The vuln head is the proposal-defined primary classifier; the type head
is auxiliary (proposal page 8: "classify into vulnerable AND attack type").

HOW TO USE THIS FILE IN GOOGLE COLAB:
1. Upload this file to your Colab session
2. Upload vocabulary.json   (from backend/colab_export/)
3. Upload training_data.npz (from backend/colab_export/) — must contain X, y, y_type and V17 sample_weight_binary/sample_weight_type
4. Run all cells. Live training plots are displayed and saved to training_plots/.
   OR copy-paste each section into cells

After training, download sqli_model.npz and sqli_detection_* artifacts
Place it in: backend/app/model/weights/sqli_model.npz
"""


# ## Section 1 — Load data & vocabulary
#
# Loads the dataset and vocabulary that were exported by the backend's `scripts/export_for_colab.py`. Upload `vocabulary.json` and `training_data.npz` (which now contains X, y, AND y_type) to this Colab session before running. Prints class balance, attack-type distribution, and signal coverage so you can sanity-check the dataset shape before training begins.

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — Load data, vocabulary and dataset metadata
# ─────────────────────────────────────────────────────────────────────────────
import json
import time
import hashlib
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime

import numpy as np

VOCAB_PATH = Path("vocabulary.json")
DATA_PATH  = Path("training_data.npz")

if not VOCAB_PATH.exists():
    raise FileNotFoundError("Missing vocabulary.json. Export it from the backend and upload it to Colab.")
if not DATA_PATH.exists():
    raise FileNotFoundError("Missing training_data.npz. Export it from the backend and upload it to Colab.")

with VOCAB_PATH.open("r", encoding="utf-8") as f:
    vocab = json.load(f)
VOCAB_SIZE = len(vocab)
id_to_token = {int(v): k for k, v in vocab.items()}

# Stable hash proves that the backend and training notebook use the same vocabulary.
vocab_payload = json.dumps(vocab, sort_keys=True, ensure_ascii=False).encode("utf-8")
VOCAB_HASH = hashlib.sha256(vocab_payload).hexdigest()

npz = np.load(DATA_PATH, allow_pickle=True)
X      = npz["X"].astype(np.int32)       # (N, seq_len) token ID sequences
y      = npz["y"].astype(np.float32)     # (N,) 1=vulnerable, 0=safe
y_type = npz["y_type"].astype(np.int32)  # 0=NONE 1=IN_BAND 2=BLIND 3=SECOND_ORDER

# hardcase export may include per-sample weights.
# They let audit-derived hard variants influence training more without changing
# the production architecture or output tensor shapes. Older exports still work.
sample_weight_binary = npz["sample_weight_binary"].astype(np.float32) if "sample_weight_binary" in npz.files else np.ones(len(X), dtype=np.float32)
sample_weight_type   = npz["sample_weight_type"].astype(np.float32)   if "sample_weight_type"   in npz.files else np.ones(len(X), dtype=np.float32)
sample_family        = npz["sample_family"].astype(str) if "sample_family" in npz.files else np.array(["base"] * len(X))

# Optional metadata exported by newer pipelines. The notebook works even if these are missing.
languages = npz["language"].astype(str) if "language" in npz.files else np.array(["unknown"] * len(X))
source_ids = npz["source_id"].astype(str) if "source_id" in npz.files else np.array([f"sample_{i}" for i in range(len(X))])
raw_paths = npz["path"].astype(str) if "path" in npz.files else source_ids.copy()

ATTACK_TYPE_NAMES = {0: "NONE", 1: "IN_BAND", 2: "BLIND", 3: "SECOND_ORDER"}
ATTACK_NAME_TO_ID = {v: k for k, v in ATTACK_TYPE_NAMES.items()}

PAD_ID = vocab.get("PAD", 0)
UNK_ID = vocab.get("UNK", 1)

print(f"Vocabulary size: {VOCAB_SIZE}")
print(f"Vocabulary SHA256: {VOCAB_HASH[:16]}...")
print(f"Dataset: {len(X)} samples")
print(f"Sequence length: {X.shape[1]}")
print(f"PAD_ID={PAD_ID}  UNK_ID={UNK_ID}")

# ── Dataset analysis required by the Ministry guidelines ────────────────────
def count_dict(values):
    return dict(Counter([str(v) for v in values]))

non_pad_lengths = np.sum(X != PAD_ID, axis=1)
pad_counts = np.sum(X == PAD_ID, axis=1)
unk_counts = np.sum(X == UNK_ID, axis=1)
truncated_flags = npz["truncated"].astype(bool) if "truncated" in npz.files else np.zeros(len(X), dtype=bool)

verdict_counts = {"SAFE": int(np.sum(y == 0)), "VULNERABLE": int(np.sum(y == 1))}
type_counts = {ATTACK_TYPE_NAMES[i]: int(np.sum(y_type == i)) for i in range(4)}
language_counts = count_dict(languages)

duplicate_sequences = len(X) - len({tuple(row.tolist()) for row in X})
sample_family_counts = count_dict(sample_family)

# Token frequency analysis, excluding PAD.
token_counter = Counter()
for row in X:
    for tid in row:
        if int(tid) != PAD_ID:
            token_counter[id_to_token.get(int(tid), "<BAD_ID>")] += 1

total_non_pad = int(non_pad_lengths.sum())
total_unk = int(unk_counts.sum())
unk_rate = total_unk / total_non_pad if total_non_pad else 0.0

DATASET_PROFILE = {
    "created_at": datetime.utcnow().isoformat() + "Z",
    "n_samples": int(len(X)),
    "sequence_length": int(X.shape[1]),
    "vocabulary_size": int(VOCAB_SIZE),
    "vocabulary_sha256": VOCAB_HASH,
    "pad_id": int(PAD_ID),
    "unk_id": int(UNK_ID),
    "verdict_counts": verdict_counts,
    "attack_type_counts": type_counts,
    "language_counts": language_counts,
    "sample_family_counts": sample_family_counts,
    "avg_sample_weight_binary": float(np.mean(sample_weight_binary)),
    "avg_sample_weight_type": float(np.mean(sample_weight_type)),
    "max_sample_weight_binary": float(np.max(sample_weight_binary)),
    "max_sample_weight_type": float(np.max(sample_weight_type)),
    "avg_non_pad_length": float(np.mean(non_pad_lengths)),
    "max_non_pad_length": int(np.max(non_pad_lengths)),
    "min_non_pad_length": int(np.min(non_pad_lengths)),
    "padded_samples": int(np.sum(pad_counts > 0)),
    "truncated_samples": int(np.sum(truncated_flags)),
    "truncation_rate": float(np.mean(truncated_flags)),
    "unk_token_count": total_unk,
    "unk_rate": float(unk_rate),
    "duplicate_sequence_count": int(duplicate_sequences),
    "top_tokens": token_counter.most_common(25),
}

print("\nDATASET PROFILE")
print("-" * 70)
print(json.dumps(DATASET_PROFILE, indent=2, ensure_ascii=False))

with open("dataset_profile.json", "w", encoding="utf-8") as f:
    json.dump(DATASET_PROFILE, f, indent=2, ensure_ascii=False)
print("\nSaved dataset_profile.json")


# ## Section 2 — Architecture constants
#
# Architecture constants — they MUST match `backend/app/model/sqli_detector.py` exactly. Includes Gap A constants `NUM_TYPE_CLASSES = 4` and `LAMBDA_TYPE = 0.5` for the attack-type head.

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — Architecture constants and training hyperparameters
# CRITICAL: architecture values must match backend inference.
# ─────────────────────────────────────────────────────────────────────────────
MODEL_VERSION = "model1-cnn-bilstm-dual-head-v18-ml95-binary"
NORMALIZER_VERSION = "semantic-normalizer-v18-ml95-flow"  # update if backend normalizer semantics change
DATASET_VERSION = DATASET_PROFILE.get("vocabulary_sha256", "unknown")[:12]

EMBED_DIM        = 64
CONV_FILTERS     = 64
KERNEL_SIZE      = 3
LSTM_HIDDEN      = 32    # per direction; BiLSTM output = 2 × 32 = 64
DENSE_HIDDEN     = 64
DENSE_IN         = CONV_FILTERS + 2 * LSTM_HIDDEN   # = 128
MODEL_SEQ_LEN    = int(X.shape[1])                  # ML-primary v17 should be 256; saved in metadata

NUM_TYPE_CLASSES = 4     # NONE, IN_BAND, BLIND, SECOND_ORDER
LAMBDA_TYPE      = 1.30   # V17: strong but less overconfident type head; evidence should help separate direct IN_BAND from SECOND_ORDER

EPOCHS   = 155
LR_INIT  = 0.0042
LR_DECAY = 0.966
PATIENCE = 32
SEED     = 42
BATCH_SIZE_NOTE = "Per-sample SGD in NumPy; batch size effectively 1."
CLIP     = 5.0
THRESHOLD = 0.50

MODEL_WEIGHTS_FILE = "sqli_detection_model.npz"
LEGACY_WEIGHTS_FILE = "sqli_model.npz"  # kept for current backend compatibility

ARCHITECTURE = {
    "model_version": MODEL_VERSION,
    "input": {"shape": ["batch", MODEL_SEQ_LEN], "type": "token_id_sequence"},
    "embedding": {"vocab_size": VOCAB_SIZE, "embed_dim": EMBED_DIM, "pad_id": PAD_ID},
    "cnn": {"filters": CONV_FILTERS, "kernel_size": KERNEL_SIZE, "activation": "ReLU", "pooling": "global_max"},
    "bilstm": {"hidden_per_direction": LSTM_HIDDEN, "directions": 2},
    "dense": {"hidden": DENSE_HIDDEN, "activation": "ReLU"},
    "heads": {
        "vulnerability_head": "sigmoid_binary",
        "attack_type_head": {"activation": "softmax", "classes": ATTACK_TYPE_NAMES},
    },
    "loss": "sample_weighted_BCE + lambda_type * sample_weighted_CCE",
    "lambda_type": LAMBDA_TYPE,
    "hardcase_training": "V18-ML95 focuses the raw ML binary head on SAFE/VULNERABLE accuracy using hard SAFE counterexamples, vulnerable recall families, helper/provenance context, binary balancing, and threshold calibration",
    "threshold": THRESHOLD_CALIBRATED if "THRESHOLD_CALIBRATED" in globals() else THRESHOLD,
}

print(json.dumps(ARCHITECTURE, indent=2, ensure_ascii=False))

PLOT_EVERY = 1
PLOT_OUT_DIR = "training_plots"
BEST_SCORE_TYPE_WEIGHT = 0.34
BEST_SCORE_SAFE_WEIGHT = 0.31
BEST_SCORE_BALANCED_WEIGHT = 0.35  # V17 checkpoint favors balanced SAFE/VULN behavior and attack-type accuracy, while reducing SECOND_ORDER overclassification


# ## Section 2b — Stratified train/validation/test split and class weights
#
# This section creates a true **70/15/15** split. It stratifies by attack type and language when possible, calculates class weights for the binary vulnerability head and the attack-type head, and saves the split metadata for reproducibility.

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2b — Split and imbalance handling
# ─────────────────────────────────────────────────────────────────────────────
def stratified_split_indices(y_type_arr, languages_arr, seed=42, train_ratio=0.70, val_ratio=0.15):
    """Simple dependency-free stratification by (attack_type, language)."""
    rng = np.random.default_rng(seed)
    groups = defaultdict(list)
    for i, (t, lang) in enumerate(zip(y_type_arr, languages_arr)):
        groups[(int(t), str(lang))].append(i)

    train, val, test = [], [], []
    for _, idxs in groups.items():
        idxs = np.array(idxs, dtype=np.int32)
        rng.shuffle(idxs)
        n = len(idxs)
        if n < 3:
            # Keep tiny rare groups represented without forcing impossible ratios.
            train.extend(idxs.tolist())
            continue
        n_train = max(1, int(round(n * train_ratio)))
        n_val = max(1, int(round(n * val_ratio)))
        if n_train + n_val >= n:
            n_train = max(1, n - 2)
            n_val = 1
        train.extend(idxs[:n_train].tolist())
        val.extend(idxs[n_train:n_train+n_val].tolist())
        test.extend(idxs[n_train+n_val:].tolist())

    rng.shuffle(train); rng.shuffle(val); rng.shuffle(test)
    return np.array(train, dtype=np.int32), np.array(val, dtype=np.int32), np.array(test, dtype=np.int32)

idx_train, idx_val, idx_test = stratified_split_indices(y_type, languages, seed=SEED)
X_train, y_train, yt_train = X[idx_train], y[idx_train], y_type[idx_train]
X_val,   y_val,   yt_val   = X[idx_val],   y[idx_val],   y_type[idx_val]
X_test,  y_test,  yt_test  = X[idx_test],  y[idx_test],  y_type[idx_test]

# V6 hardcase sample weights travel with the split.
sw_bin_train, sw_type_train = sample_weight_binary[idx_train], sample_weight_type[idx_train]
sw_bin_val,   sw_type_val   = sample_weight_binary[idx_val],   sample_weight_type[idx_val]
sw_bin_test,  sw_type_test  = sample_weight_binary[idx_test],  sample_weight_type[idx_test]
family_train, family_val, family_test = sample_family[idx_train], sample_family[idx_val], sample_family[idx_test]

print(f"Train: {len(X_train)} ({len(X_train)/len(X):.1%})")
print(f"Val:   {len(X_val)} ({len(X_val)/len(X):.1%})")
print(f"Test:  {len(X_test)} ({len(X_test)/len(X):.1%})")

# Binary class weights: inverse frequency, normalized around 1.0.
def inverse_freq_weights(labels, n_classes):
    counts = np.bincount(labels.astype(int), minlength=n_classes).astype(np.float32)
    counts = np.maximum(counts, 1.0)
    weights = counts.sum() / (n_classes * counts)
    return weights.astype(np.float32), counts.astype(int)

BIN_CLASS_WEIGHTS, bin_counts = inverse_freq_weights(y_train.astype(int), 2)
TYPE_CLASS_WEIGHTS, type_counts_train = inverse_freq_weights(yt_train.astype(int), NUM_TYPE_CLASSES)

# V17: V7 became too aggressive and marked many SAFE files as VULNERABLE.
# We therefore boost SAFE/NONE learning while keeping vulnerable classes strong enough
# for high recall. This is training-time calibration, not runtime rule memorization.
TYPE_HARDCASE_BOOST = np.array([1.25, 1.55, 1.76, 0.95], dtype=np.float32)  # V17: boost IN_BAND/BLIND, reduce SECOND_ORDER over-prediction
TYPE_CLASS_WEIGHTS = (TYPE_CLASS_WEIGHTS * TYPE_HARDCASE_BOOST).astype(np.float32)
BIN_HARDCASE_BOOST = np.array([1.16, 1.22], dtype=np.float32)  # balance SAFE specificity with vulnerable recall
BIN_CLASS_WEIGHTS = (BIN_CLASS_WEIGHTS * BIN_HARDCASE_BOOST).astype(np.float32)

print("\nBinary train counts [SAFE, VULNERABLE]:", bin_counts.tolist())
print("Binary class weights [SAFE, VULNERABLE]:", np.round(BIN_CLASS_WEIGHTS, 4).tolist())
print("Attack-type train counts:", {ATTACK_TYPE_NAMES[i]: int(type_counts_train[i]) for i in range(NUM_TYPE_CLASSES)})
print("Attack-type class weights:", {ATTACK_TYPE_NAMES[i]: float(round(TYPE_CLASS_WEIGHTS[i], 4)) for i in range(NUM_TYPE_CLASSES)})

SPLIT_INFO = {
    "strategy": "stratified_by_attack_type_and_language_when_available",
    "seed": SEED,
    "train_count": int(len(idx_train)),
    "val_count": int(len(idx_val)),
    "test_count": int(len(idx_test)),
    "train_indices_sha256": hashlib.sha256(idx_train.tobytes()).hexdigest(),
    "val_indices_sha256": hashlib.sha256(idx_val.tobytes()).hexdigest(),
    "test_indices_sha256": hashlib.sha256(idx_test.tobytes()).hexdigest(),
    "binary_class_weights": {"SAFE": float(BIN_CLASS_WEIGHTS[0]), "VULNERABLE": float(BIN_CLASS_WEIGHTS[1])},
    "attack_type_class_weights": {ATTACK_TYPE_NAMES[i]: float(TYPE_CLASS_WEIGHTS[i]) for i in range(NUM_TYPE_CLASSES)},
    "type_hardcase_boost": {ATTACK_TYPE_NAMES[i]: float(TYPE_HARDCASE_BOOST[i]) for i in range(NUM_TYPE_CLASSES)},
    "binary_hardcase_boost": {"SAFE": float(BIN_HARDCASE_BOOST[0]), "VULNERABLE": float(BIN_HARDCASE_BOOST[1])},
    "sample_weight_summary": {
        "train_binary_mean": float(np.mean(sw_bin_train)),
        "train_type_mean": float(np.mean(sw_type_train)),
        "train_binary_max": float(np.max(sw_bin_train)),
        "train_type_max": float(np.max(sw_type_train)),
    },
    "train_family_counts": count_dict(family_train),
}
with open("split_info.json", "w", encoding="utf-8") as f:
    json.dump(SPLIT_INFO, f, indent=2, ensure_ascii=False)
print("\nSaved split_info.json")


# ## Section 3 — Activation functions
#
# Plain NumPy activations: sigmoid, relu, tanh, plus a numerically stable softmax for the new attack-type head.

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — Activation functions
# ─────────────────────────────────────────────────────────────────────────────
def sigmoid(x):
    # Numerically stable
    return np.where(x >= 0, 1.0 / (1.0 + np.exp(-x)), np.exp(x) / (1.0 + np.exp(x)))

def sigmoid_grad(s):
    return s * (1.0 - s)

def relu(x):
    return np.maximum(0.0, x)

def relu_grad(x):
    return (x > 0).astype(np.float32)

def tanh_grad(t):
    return 1.0 - t * t

def softmax(x):
    """Numerically stable softmax over a 1-D logit vector."""
    z = x - np.max(x)
    e = np.exp(z)
    return e / e.sum()


# ## Section 4 — Weight initialisation (dual-head)
#
# He initialisation for all layers. The dual-head architecture adds `dense2_type_W (4, 64)` and `dense2_type_b (4,)` for the attack-type softmax head. Both heads share the dense hidden layer.

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 — Weight initialisation (now includes the attack-type head)
# ─────────────────────────────────────────────────────────────────────────────
rng = np.random.default_rng(SEED)

def he(shape):
    """He (Kaiming) initialisation — best for ReLU layers."""
    fan_in = shape[-1] if len(shape) > 1 else shape[0]
    return rng.normal(0, np.sqrt(2.0 / fan_in), shape).astype(np.float32)

# Embedding layer
emb_W = rng.normal(0, 0.05, (VOCAB_SIZE, EMBED_DIM)).astype(np.float32)

# CNN — 1D convolution
conv_W = he((CONV_FILTERS, EMBED_DIM, KERNEL_SIZE))
conv_b = np.zeros(CONV_FILTERS, dtype=np.float32)

# Bi-LSTM — forward and backward directions
bilstm_fwd_W = he((4 * LSTM_HIDDEN, EMBED_DIM + LSTM_HIDDEN))
bilstm_fwd_b = np.zeros(4 * LSTM_HIDDEN, dtype=np.float32)
bilstm_bwd_W = he((4 * LSTM_HIDDEN, EMBED_DIM + LSTM_HIDDEN))
bilstm_bwd_b = np.zeros(4 * LSTM_HIDDEN, dtype=np.float32)

# Shared dense hidden layer
dense1_W = he((DENSE_HIDDEN, DENSE_IN))
dense1_b = np.zeros(DENSE_HIDDEN, dtype=np.float32)

# Vulnerability head — sigmoid scalar
dense2_W = he((1, DENSE_HIDDEN))
dense2_b = np.zeros(1, dtype=np.float32)

# Attack-type head — softmax over 4 classes (NEW: Gap A)
dense2_type_W = he((NUM_TYPE_CLASSES, DENSE_HIDDEN))
dense2_type_b = np.zeros(NUM_TYPE_CLASSES, dtype=np.float32)

print("Weights initialised:")
print(f"  emb_W:         {emb_W.shape}")
print(f"  conv_W:        {conv_W.shape}")
print(f"  bilstm_fwd_W:  {bilstm_fwd_W.shape}")
print(f"  bilstm_bwd_W:  {bilstm_bwd_W.shape}")
print(f"  dense1_W:      {dense1_W.shape}")
print(f"  dense2_W:      {dense2_W.shape}        (vuln head)")
print(f"  dense2_type_W: {dense2_type_W.shape}        (attack-type head — Gap A)")


# ## Section 5 — Forward pass (dual-head)
#
# Forward pass: token IDs → embedding → CNN → BiLSTM → shared dense → (sigmoid for vuln) AND (softmax for attack type). Returns both outputs plus a cache for backprop.

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5 — Forward pass (dual-head)
# ─────────────────────────────────────────────────────────────────────────────
def fwd_embedding(ids):
    return emb_W[ids]   # (seq_len, EMBED_DIM)


def fwd_conv1d_maxpool(emb):
    """Conv1D + ReLU + Global Max Pool — detects local dangerous patterns."""
    seq_len = emb.shape[0]
    out_len = max(1, seq_len - KERNEL_SIZE + 1)
    W_flat = conv_W.reshape(CONV_FILTERS, -1)
    conv_out = np.zeros((out_len, CONV_FILTERS), dtype=np.float32)
    for pos in range(out_len):
        patch = emb[pos: pos + KERNEL_SIZE].flatten()
        conv_out[pos] = W_flat @ patch + conv_b
    act = relu(conv_out)
    pool_idx = np.argmax(act, axis=0)
    pooled = act[pool_idx, np.arange(CONV_FILTERS)]
    return pooled, act, pool_idx, conv_out


def lstm_step(x_t, h, c, W, b):
    """Single LSTM cell step."""
    H = LSTM_HIDDEN
    concat = np.concatenate([x_t, h])
    gates = W @ concat + b
    f = sigmoid(gates[0 * H: 1 * H])    # forget gate
    i = sigmoid(gates[1 * H: 2 * H])    # input gate
    o = sigmoid(gates[2 * H: 3 * H])    # output gate
    g = np.tanh(gates[3 * H: 4 * H])    # cell update
    c_new   = f * c + i * g
    tanh_c  = np.tanh(c_new)
    h_new   = o * tanh_c
    return h_new, c_new, (x_t, h, c, f, i, o, g, c_new, tanh_c, concat)


def fwd_lstm_direction(emb, W, b, reverse=False):
    """Run LSTM across the full sequence in one direction."""
    H = LSTM_HIDDEN
    seq_len = emb.shape[0]
    h = np.zeros(H, dtype=np.float32)
    c = np.zeros(H, dtype=np.float32)
    caches = []
    order = range(seq_len) if not reverse else reversed(range(seq_len))
    for t in order:
        h, c, cache = lstm_step(emb[t], h, c, W, b)
        caches.append(cache)
    if reverse:
        caches.reverse()
    return h, caches


def fwd_dense(x, W, b, activation):
    pre = W @ x + b
    if activation == "relu":
        out = relu(pre)
    elif activation == "sigmoid":
        out = sigmoid(pre)
    elif activation == "softmax":
        out = softmax(pre)
    elif activation == "linear":
        out = pre
    else:
        raise ValueError(f"unknown activation: {activation}")
    return out, pre


def forward(ids):
    """
    Full forward pass: ids → (vuln_score, type_probs, cache).

    cache contains everything backward needs.
    """
    emb = fwd_embedding(ids)
    cnn_out, cnn_act, pool_idx, conv_pre = fwd_conv1d_maxpool(emb)
    h_fwd, fwd_caches = fwd_lstm_direction(emb, bilstm_fwd_W, bilstm_fwd_b, reverse=False)
    h_bwd, bwd_caches = fwd_lstm_direction(emb, bilstm_bwd_W, bilstm_bwd_b, reverse=True)
    lstm_out = np.concatenate([h_fwd, h_bwd])
    combined = np.concatenate([cnn_out, lstm_out])
    h1, pre1 = fwd_dense(combined, dense1_W, dense1_b, "relu")

    # Vuln head (sigmoid)
    score, _ = fwd_dense(h1, dense2_W, dense2_b, "sigmoid")

    # Attack-type head (softmax)
    type_probs, type_logits = fwd_dense(h1, dense2_type_W, dense2_type_b, "softmax")

    cache = (
        emb, ids, cnn_act, pool_idx, conv_pre,
        fwd_caches, bwd_caches, combined, h1, pre1,
        score, type_probs, type_logits,
    )
    return float(score[0]), type_probs, cache


# ## Section 6 — Backward pass (dual-head joint loss)
#
# Joint backprop. The total loss is `BCE(vuln) + λ·CCE(type)` with λ = 0.5. Gradients from BOTH heads are summed at the shared dense hidden layer, then propagated through the shared backbone (CNN, BiLSTM, embedding) once.

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6 — Backward pass (dual-head joint loss)
# ─────────────────────────────────────────────────────────────────────────────
# Loss = BCE(vuln_head, y_binary) + LAMBDA_TYPE · CCE(type_head, y_type)
#
# Backprop accumulates gradients from BOTH heads at the shared dense
# hidden layer h1, then continues through the shared backbone (CNN, BiLSTM,
# embedding) once with the summed gradient.
#
# This is the standard multi-task learning pattern: the auxiliary loss
# regularises the embedding space to cluster similar attack types together,
# which proposal page 23 says Model 2 will reuse.
# ─────────────────────────────────────────────────────────────────────────────
CLIP = float(CLIP)  # defined in Section 2

def clip(g):
    return np.clip(g, -CLIP, CLIP)


def bwd_lstm_direction(caches, d_h_last, W, b, reversed_iter=True):
    """BPTT for one LSTM direction."""
    H = LSTM_HIDDEN
    dW = np.zeros_like(W)
    db = np.zeros_like(b)
    d_h = d_h_last.copy()
    d_c = np.zeros(H, dtype=np.float32)
    seq_len = len(caches)
    d_x_seq = [None] * seq_len

    order = reversed(range(seq_len)) if reversed_iter else range(seq_len)
    for t in order:
        x_t, h_prev, c_prev, f, i_g, o, g, c_t, tanh_c, concat = caches[t]
        d_o  = d_h * tanh_c
        d_tc = d_h * o
        d_ct = d_c + d_tc * tanh_grad(tanh_c)
        d_f  = d_ct * c_prev
        d_i  = d_ct * g
        d_g  = d_ct * i_g
        d_c  = d_ct * f
        gates = np.concatenate([
            d_f * sigmoid_grad(f),
            d_i * sigmoid_grad(i_g),
            d_o * sigmoid_grad(o),
            d_g * tanh_grad(g),
        ])
        dW += np.outer(gates, concat)
        db += gates
        d_concat = W.T @ gates
        x_dim = x_t.shape[0]
        d_x_seq[t] = d_concat[:x_dim]
        d_h = d_concat[x_dim:]

    return d_x_seq, dW, db


def train_step(ids, label_binary, label_type, lr, sample_weight_binary_i=1.0, sample_weight_type_i=1.0):
    """
    One training step — forward + dual-head backward + weight update.

    Returns (binary_loss, type_loss, total_loss) for diagnostic logging.
    """
    global emb_W, conv_W, conv_b
    global bilstm_fwd_W, bilstm_fwd_b, bilstm_bwd_W, bilstm_bwd_b
    global dense1_W, dense1_b, dense2_W, dense2_b, dense2_type_W, dense2_type_b

    # ── Forward (shared backbone + both heads) ──
    emb = fwd_embedding(ids)
    cnn_out, cnn_act, pool_idx, conv_pre = fwd_conv1d_maxpool(emb)
    h_fwd, fwd_caches = fwd_lstm_direction(emb, bilstm_fwd_W, bilstm_fwd_b, reverse=False)
    h_bwd, bwd_caches = fwd_lstm_direction(emb, bilstm_bwd_W, bilstm_bwd_b, reverse=True)
    lstm_out = np.concatenate([h_fwd, h_bwd])
    combined = np.concatenate([cnn_out, lstm_out])
    h1, pre1 = fwd_dense(combined, dense1_W, dense1_b, "relu")
    score, _      = fwd_dense(h1, dense2_W,      dense2_b,      "sigmoid")
    type_probs, _ = fwd_dense(h1, dense2_type_W, dense2_type_b, "softmax")
    pred = float(score[0])

    # ── Losses ──
    eps = 1e-7
    # Binary cross-entropy
    p = np.clip(pred, eps, 1 - eps)
    bin_w = float(BIN_CLASS_WEIGHTS[int(label_binary)] * sample_weight_binary_i)
    type_w = float(TYPE_CLASS_WEIGHTS[int(label_type)] * sample_weight_type_i)
    bce = bin_w * (-(label_binary * np.log(p) + (1 - label_binary) * np.log(1 - p)))
    # Categorical cross-entropy on the true class
    cce = type_w * (-np.log(np.clip(type_probs[label_type], eps, 1.0)))
    total_loss = bce + LAMBDA_TYPE * cce

    # ── Backward — VULN head (sigmoid + BCE) ──
    # d/d_pre2 of BCE(σ(pre2)) = pred - label  (the standard simplification)
    d_score   = np.array([bin_w * (pred - label_binary)], dtype=np.float32)
    d_h1_vuln = dense2_W.T @ d_score
    dense2_W -= lr * clip(np.outer(d_score, h1))
    dense2_b -= lr * clip(d_score)

    # ── Backward — TYPE head (softmax + CCE) ──
    # d/d_logits of CCE(softmax(logits)) = probs - one_hot(target)
    d_logits = type_probs.copy()
    d_logits[label_type] -= 1.0          # one-hot subtraction
    d_logits *= (LAMBDA_TYPE * type_w)    # auxiliary loss + class weight
    d_h1_type = dense2_type_W.T @ d_logits
    dense2_type_W -= lr * clip(np.outer(d_logits, h1))
    dense2_type_b -= lr * clip(d_logits)

    # ── Sum gradients into the shared dense hidden layer ──
    d_h1 = clip(d_h1_vuln + d_h1_type)

    # ── Backward — Dense 1 (shared) ──
    d_pre1     = d_h1 * relu_grad(pre1)
    d_combined = clip(dense1_W.T @ d_pre1)
    dense1_W  -= lr * clip(np.outer(d_pre1, combined))
    dense1_b  -= lr * clip(d_pre1)

    # Split gradient for CNN and BiLSTM branches
    d_cnn   = d_combined[:CONV_FILTERS]
    d_lstm  = d_combined[CONV_FILTERS:]
    d_h_fwd = d_lstm[:LSTM_HIDDEN]
    d_h_bwd = d_lstm[LSTM_HIDDEN:]

    # ── Backward — BiLSTM ──
    d_x_fwd, dW_fwd, db_fwd = bwd_lstm_direction(fwd_caches, d_h_fwd, bilstm_fwd_W, bilstm_fwd_b, reversed_iter=True)
    d_x_bwd, dW_bwd, db_bwd = bwd_lstm_direction(bwd_caches, d_h_bwd, bilstm_bwd_W, bilstm_bwd_b, reversed_iter=False)
    bilstm_fwd_W -= lr * clip(dW_fwd);  bilstm_fwd_b -= lr * clip(db_fwd)
    bilstm_bwd_W -= lr * clip(dW_bwd);  bilstm_bwd_b -= lr * clip(db_bwd)

    # ── Backward — CNN ──
    seq_len = emb.shape[0]
    out_len = max(1, seq_len - KERNEL_SIZE + 1)
    d_act = np.zeros((out_len, CONV_FILTERS), dtype=np.float32)
    d_act[pool_idx, np.arange(CONV_FILTERS)] = d_cnn
    d_conv  = d_act * relu_grad(conv_pre)
    W_flat  = conv_W.reshape(CONV_FILTERS, -1)
    d_emb_cnn = np.zeros_like(emb)
    dW_conv   = np.zeros_like(W_flat)
    for pos in range(out_len):
        patch = emb[pos: pos + KERNEL_SIZE].flatten()
        dW_conv += np.outer(d_conv[pos], patch)
        d_emb_cnn[pos: pos + KERNEL_SIZE] += (W_flat.T @ d_conv[pos]).reshape(KERNEL_SIZE, -1)
    conv_W -= lr * clip(dW_conv).reshape(conv_W.shape)
    conv_b -= lr * clip(d_conv.sum(axis=0))

    # ── Backward — Embedding ──
    d_emb_lstm = np.zeros_like(emb)
    for t in range(seq_len):
        if d_x_fwd[t] is not None: d_emb_lstm[t] += d_x_fwd[t]
        if d_x_bwd[t] is not None: d_emb_lstm[t] += d_x_bwd[t]
    np.add.at(emb_W, ids, -lr * clip(d_emb_cnn + d_emb_lstm))

    return float(bce), float(cce), float(total_loss)


# ## Section 7 — Evaluation metrics
#
# Evaluation produces both binary metrics (acc/prec/recall/F1) and attack-type metrics (per-class precision/recall/F1, macro-F1, 4×4 confusion matrix). The proposal page 28 emphasises Recall as the primary metric — it's reported alongside F1.

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7 — Evaluation metrics (binary head + attack-type head)
# ─────────────────────────────────────────────────────────────────────────────
def evaluate(Xs, ys, ys_type, threshold=0.5):
    """
    Returns binary metrics + attack-type metrics + macro-F1.
    """
    n = len(Xs)
    preds_bin  = np.zeros(n, dtype=np.float32)
    preds_type = np.zeros(n, dtype=np.int32)
    for i in range(n):
        s, tp, _ = forward(Xs[i])
        preds_bin[i]  = s
        preds_type[i] = int(np.argmax(tp))

    binary  = (preds_bin >= threshold).astype(int)
    labels  = ys.astype(int)
    labels_type = ys_type.astype(int)

    # Binary metrics
    tp = int(np.sum((binary == 1) & (labels == 1)))
    tn = int(np.sum((binary == 0) & (labels == 0)))
    fp = int(np.sum((binary == 1) & (labels == 0)))
    fn = int(np.sum((binary == 0) & (labels == 1)))
    acc  = (tp + tn) / n if n else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0  # SAFE recall / specificity
    bal_acc = 0.5 * (rec + spec)
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

    # Attack-type metrics — overall accuracy + per-class precision/recall/F1
    type_acc = float(np.mean(preds_type == labels_type))
    per_class = {}
    f1s = []
    for cid, name in ATTACK_TYPE_NAMES.items():
        tp_c = int(np.sum((preds_type == cid) & (labels_type == cid)))
        fp_c = int(np.sum((preds_type == cid) & (labels_type != cid)))
        fn_c = int(np.sum((preds_type != cid) & (labels_type == cid)))
        n_c  = int((labels_type == cid).sum())
        p_c  = tp_c / (tp_c + fp_c) if (tp_c + fp_c) > 0 else 0.0
        r_c  = tp_c / (tp_c + fn_c) if (tp_c + fn_c) > 0 else 0.0
        f1_c = 2 * p_c * r_c / (p_c + r_c) if (p_c + r_c) > 0 else 0.0
        per_class[name] = {"n": n_c, "prec": round(p_c, 4),
                           "rec": round(r_c, 4), "f1": round(f1_c, 4)}
        # macro-F1 averages over all classes that actually appear in the set
        if n_c > 0:
            f1s.append(f1_c)
    macro_f1 = float(np.mean(f1s)) if f1s else 0.0

    # 4×4 confusion matrix for the type head
    type_cm = np.zeros((NUM_TYPE_CLASSES, NUM_TYPE_CLASSES), dtype=int)
    for true_c, pred_c in zip(labels_type, preds_type):
        type_cm[true_c, pred_c] += 1

    return {
        # Binary
        "acc": round(acc, 4), "prec": round(prec, 4),
        "rec": round(rec, 4), "spec": round(spec, 4), "balanced_acc": round(bal_acc, 4), "f1": round(f1, 4),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        # Attack-type
        "type_acc": round(type_acc, 4),
        "type_macro_f1": round(macro_f1, 4),
        "per_class": per_class,
        "type_cm": type_cm,
    }


def calibrate_binary_threshold(Xs, ys, ys_type, thresholds=None):
    """Sweep thresholds on validation data and pick a balanced ML-only binary point.

    The project target is ML-only SAFE/VULNERABLE accuracy >= 95%, but this is
    still a security detector, so ties prefer higher recall and fewer false
    negatives. Attack-type metrics are reported but do not drive this threshold.
    """
    if thresholds is None:
        thresholds = np.round(np.arange(0.30, 0.701, 0.01), 2)
    rows = []
    best = None
    for th in thresholds:
        m = evaluate(Xs, ys, ys_type, threshold=float(th))
        score = (m["acc"] + m["f1"] + m["balanced_acc"]) / 3.0
        row = {"threshold": float(th), "selection_score": float(score), **m}
        rows.append(row)
        key = (score, m["rec"], -m["fn"], m["spec"], m["acc"])
        if best is None or key > best[0]:
            best = (key, row)
    return best[1], rows


# ## Section 8 — Training loop (joint loss)
#
# Per-sample SGD on the joint loss. Best-model selection uses the binary F1 (the proposal-defined primary metric); attack-type metrics are tracked but don't drive checkpointing.

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7b — Live training plots for Colab
# ─────────────────────────────────────────────────────────────────────────────
# These plots are updated during training and saved to training_plots/.
# They directly support the Ministry requirement to monitor metrics over epochs.
from pathlib import Path as _Path
import matplotlib.pyplot as plt
try:
    from IPython.display import clear_output, display
    _HAS_IPYTHON_DISPLAY = True
except Exception:
    _HAS_IPYTHON_DISPLAY = False

_Path(PLOT_OUT_DIR).mkdir(parents=True, exist_ok=True)

def _series(history, key):
    return [float(h.get(key, 0.0)) for h in history]

def render_live_training_plots(history, epoch, show=True):
    if not history:
        return
    epochs = [int(h["epoch"]) for h in history]
    fig, axes = plt.subplots(2, 3, figsize=(18, 9))

    axes[0, 0].plot(epochs, _series(history, "train_loss_total"), label="total")
    axes[0, 0].plot(epochs, _series(history, "train_loss_bce"), label="BCE vuln")
    axes[0, 0].plot(epochs, _series(history, "train_loss_cce"), label="CCE type")
    axes[0, 0].set_title("Training loss")
    axes[0, 0].set_xlabel("epoch")
    axes[0, 0].legend()

    axes[0, 1].plot(epochs, _series(history, "train_f1"), label="train F1")
    axes[0, 1].plot(epochs, _series(history, "val_f1"), label="val F1")
    axes[0, 1].set_title("Binary vulnerability F1")
    axes[0, 1].set_xlabel("epoch")
    axes[0, 1].set_ylim(0, 1.05)
    axes[0, 1].legend()

    axes[0, 2].plot(epochs, _series(history, "val_precision"), label="val precision")
    axes[0, 2].plot(epochs, _series(history, "val_recall"), label="val recall")
    axes[0, 2].plot(epochs, _series(history, "val_specificity"), label="SAFE specificity")
    axes[0, 2].plot(epochs, _series(history, "val_balanced_acc"), label="balanced acc")
    axes[0, 2].set_title("Validation precision / recall / SAFE specificity")
    axes[0, 2].set_xlabel("epoch")
    axes[0, 2].set_ylim(0, 1.05)
    axes[0, 2].legend()

    axes[1, 0].plot(epochs, _series(history, "val_type_acc"), label="type accuracy")
    axes[1, 0].plot(epochs, _series(history, "val_type_macro_f1"), label="type macro-F1")
    axes[1, 0].set_title("Attack-type head")
    axes[1, 0].set_xlabel("epoch")
    axes[1, 0].set_ylim(0, 1.05)
    axes[1, 0].legend()

    axes[1, 1].plot(epochs, _series(history, "lr"), label="learning rate")
    axes[1, 1].set_title("Learning-rate schedule")
    axes[1, 1].set_xlabel("epoch")
    axes[1, 1].legend()

    axes[1, 2].plot(epochs, _series(history, "ml_primary_score"), label="checkpoint score")
    axes[1, 2].plot(epochs, _series(history, "val_none_f1"), label="NONE F1")
    axes[1, 2].set_title("V17 balanced checkpoint score")
    axes[1, 2].set_xlabel("epoch")
    axes[1, 2].legend()

    fig.suptitle(f"Model 1 training progress — epoch {epoch}", fontsize=16)
    fig.tight_layout()
    out_path = _Path(PLOT_OUT_DIR) / f"training_progress_epoch_{epoch:03d}.png"
    fig.savefig(out_path, dpi=140, bbox_inches="tight")
    if show:
        if _HAS_IPYTHON_DISPLAY:
            clear_output(wait=True)
            display(fig)
        else:
            plt.show()
    plt.close(fig)

print(f"Live plots enabled. Output directory: {PLOT_OUT_DIR}")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8 — Training loop (dual-head, weighted joint loss)
# ─────────────────────────────────────────────────────────────────────────────
# Uses the 70/15/15 split from Section 2b.
# Per-sample SGD is intentionally explicit so the forward pass, loss,
# backpropagation and parameter update are visible for academic review.
# ─────────────────────────────────────────────────────────────────────────────
rng_train = np.random.default_rng(SEED)
print(f"Train: {len(X_train)}   Val: {len(X_val)}   Test: {len(X_test)}")
print("Class-weighted loss is active:")
print("  BCE weights:", np.round(BIN_CLASS_WEIGHTS, 4).tolist())
print("  CCE weights:", np.round(TYPE_CLASS_WEIGHTS, 4).tolist())
print()

lr          = LR_INIT
best_val_f1 = -1.0
best_ml_primary_score = -1.0
no_improve  = 0
history     = []

for epoch in range(1, EPOCHS + 1):
    perm           = rng_train.permutation(len(X_train))
    total_bce      = 0.0
    total_cce      = 0.0
    total_combined = 0.0
    t0             = time.time()

    for i in perm:
        bce_i, cce_i, total_i = train_step(
            X_train[i], float(y_train[i]), int(yt_train[i]), lr,
            sample_weight_binary_i=float(sw_bin_train[i]),
            sample_weight_type_i=float(sw_type_train[i]),
        )
        total_bce      += bce_i
        total_cce      += cce_i
        total_combined += total_i

    avg_bce      = total_bce      / max(1, len(perm))
    avg_cce      = total_cce      / max(1, len(perm))
    avg_combined = total_combined / max(1, len(perm))

    val_m = evaluate(X_val,   y_val,   yt_val, threshold=THRESHOLD)
    tr_m  = evaluate(X_train, y_train, yt_train, threshold=THRESHOLD)
    elapsed = time.time() - t0

    none_f1 = float(val_m["per_class"].get("NONE", {}).get("f1", 0.0))
    none_rec = float(val_m["per_class"].get("NONE", {}).get("rec", 0.0))
    checkpoint_score = (
        val_m["f1"]
        + BEST_SCORE_BALANCED_WEIGHT * val_m["balanced_acc"]
        + BEST_SCORE_SAFE_WEIGHT * none_f1
        + BEST_SCORE_TYPE_WEIGHT * val_m["type_macro_f1"]
    )

    history.append({
        "epoch": epoch,
        "lr": lr,
        "train_loss_total": avg_combined,
        "train_loss_bce": avg_bce,
        "train_loss_cce": avg_cce,
        "train_f1": tr_m["f1"], "train_recall": tr_m["rec"],
        "val_f1": val_m["f1"], "val_precision": val_m["prec"], "val_recall": val_m["rec"],
        "val_specificity": val_m["spec"], "val_balanced_acc": val_m["balanced_acc"],
        "val_none_f1": none_f1, "val_none_recall": none_rec,
        "val_acc": val_m["acc"],
        "val_type_acc": val_m["type_acc"], "val_type_macro_f1": val_m["type_macro_f1"],
        "ml_primary_score": checkpoint_score,
        "train_sample_weight_binary_mean": float(np.mean(sw_bin_train)),
        "train_sample_weight_type_mean": float(np.mean(sw_type_train)),
    })

    print(
        f"Epoch {epoch:02d}/{EPOCHS}  "
        f"loss={avg_combined:.4f} (bce={avg_bce:.4f} cce={avg_cce:.4f})  "
        f"val_f1={val_m['f1']:.3f} P={val_m['prec']:.3f} R={val_m['rec']:.3f} "
        f"SAFE_spec={val_m['spec']:.3f} balAcc={val_m['balanced_acc']:.3f} NONE_F1={none_f1:.3f}  "
        f"type_acc={val_m['type_acc']:.3f} type_macroF1={val_m['type_macro_f1']:.3f}  "
        f"score={history[-1]['ml_primary_score']:.3f}  lr={lr:.5f}  ({elapsed:.1f}s)"
    )

    # V17 checkpoint: binary F1 remains primary, but we explicitly reward
    # SAFE specificity / NONE F1 so the best checkpoint cannot be an
    # all-vulnerable model. Attack-type macro-F1 still matters for IN_BAND,
    # BLIND and SECOND_ORDER classification.
    current_score = history[-1]["ml_primary_score"]
    if current_score > best_ml_primary_score:
        best_val_f1 = val_m["f1"]
        best_ml_primary_score = current_score
        no_improve  = 0
        np.savez(
            MODEL_WEIGHTS_FILE,
            emb_W=emb_W,
            conv_W=conv_W,                  conv_b=conv_b,
            bilstm_fwd_W=bilstm_fwd_W,      bilstm_fwd_b=bilstm_fwd_b,
            bilstm_bwd_W=bilstm_bwd_W,      bilstm_bwd_b=bilstm_bwd_b,
            dense1_W=dense1_W,              dense1_b=dense1_b,
            dense2_W=dense2_W,              dense2_b=dense2_b,
            dense2_type_W=dense2_type_W,    dense2_type_b=dense2_type_b,
        )
        # Legacy filename for the existing backend path.
        np.savez(
            LEGACY_WEIGHTS_FILE,
            emb_W=emb_W,
            conv_W=conv_W,                  conv_b=conv_b,
            bilstm_fwd_W=bilstm_fwd_W,      bilstm_fwd_b=bilstm_fwd_b,
            bilstm_bwd_W=bilstm_bwd_W,      bilstm_bwd_b=bilstm_bwd_b,
            dense1_W=dense1_W,              dense1_b=dense1_b,
            dense2_W=dense2_W,              dense2_b=dense2_b,
            dense2_type_W=dense2_type_W,    dense2_type_b=dense2_type_b,
        )
        print(f"   ✓ Best model saved  (score={current_score:.3f}, val_f1={val_m['f1']:.3f}, "
              f"val_recall={val_m['rec']:.3f}, SAFE_spec={val_m['spec']:.3f}, "
              f"NONE_F1={none_f1:.3f}, type_macroF1={val_m['type_macro_f1']:.3f})")
    else:
        no_improve += 1
        if no_improve >= PATIENCE:
            print(f"   ⏹ Early stopping at epoch {epoch}")
            break

    if epoch % PLOT_EVERY == 0:
        render_live_training_plots(history, epoch, show=True)

    lr *= LR_DECAY

# Always save one final consolidated plot image.
render_live_training_plots(history, history[-1]["epoch"] if history else 0, show=True)

with open("training_history.json", "w", encoding="utf-8") as f:
    json.dump(history, f, indent=2, ensure_ascii=False)
print(f"\nTraining complete. Best val_F1 = {best_val_f1:.4f}; best ML-primary score = {best_ml_primary_score:.4f}")
print("Saved training_history.json")


# ## Section 9 — Final evaluation report
#
# Final report against the held-out validation split. Reports both heads independently. The 4×4 attack-type confusion matrix is the key academic-defense artifact for Gap A.

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 9 — Final held-out TEST evaluation report
# ─────────────────────────────────────────────────────────────────────────────
# Reload best checkpoint selected by validation F1, then evaluate ONCE on test.
best = np.load(MODEL_WEIGHTS_FILE)
emb_W         = best["emb_W"]
conv_W        = best["conv_W"];        conv_b        = best["conv_b"]
bilstm_fwd_W  = best["bilstm_fwd_W"];  bilstm_fwd_b  = best["bilstm_fwd_b"]
bilstm_bwd_W  = best["bilstm_bwd_W"];  bilstm_bwd_b  = best["bilstm_bwd_b"]
dense1_W      = best["dense1_W"];      dense1_b      = best["dense1_b"]
dense2_W      = best["dense2_W"];      dense2_b      = best["dense2_b"]
dense2_type_W = best["dense2_type_W"]; dense2_type_b = best["dense2_type_b"]

threshold_best, threshold_sweep = calibrate_binary_threshold(X_val, y_val, yt_val)
THRESHOLD_CALIBRATED = float(threshold_best["threshold"])
print("=" * 70)
print("VALIDATION THRESHOLD CALIBRATION")
print("=" * 70)
for row in threshold_sweep:
    if row["threshold"] in (0.30, 0.40, 0.50, 0.60, 0.70) or row["threshold"] == THRESHOLD_CALIBRATED:
        print(f"th={row['threshold']:.2f} acc={row['acc']:.4f} f1={row['f1']:.4f} recall={row['rec']:.4f} spec={row['spec']:.4f} fp={row['fp']} fn={row['fn']}")
print(f"Selected threshold: {THRESHOLD_CALIBRATED:.2f}")

test_m = evaluate(X_test, y_test, yt_test, threshold=THRESHOLD_CALIBRATED)
val_m  = evaluate(X_val,  y_val,  yt_val,  threshold=THRESHOLD_CALIBRATED)

print("=" * 70)
print("FINAL MODEL 1 EVALUATION (Held-out Test Set)")
print("=" * 70)
print()
print("VULNERABILITY HEAD (binary, sigmoid) — proposal-defined primary task")
print("-" * 70)
print(f"  Accuracy:  {test_m['acc']:.4f}")
print(f"  Precision: {test_m['prec']:.4f}")
print(f"  Recall:    {test_m['rec']:.4f}")
print(f"  F1 Score:  {test_m['f1']:.4f}")
print()
print("  Confusion Matrix:")
print("                    Pred SAFE   Pred VULN")
print(f"    Actual SAFE       {test_m['tn']:>6}      {test_m['fp']:>6}")
print(f"    Actual VULN       {test_m['fn']:>6}      {test_m['tp']:>6}")
print(f"    False Negatives (vulnerable missed): {test_m['fn']}  ← most critical")
print()

print("ATTACK-TYPE HEAD (softmax, 4 classes)")
print("-" * 70)
print(f"  Overall accuracy: {test_m['type_acc']:.4f}")
print(f"  Macro-F1:         {test_m['type_macro_f1']:.4f}")
print()
print(f"  {'class':<14s} {'n':>5s} {'prec':>7s} {'recall':>7s} {'F1':>7s}")
for name in ("NONE", "IN_BAND", "BLIND", "SECOND_ORDER"):
    pc = test_m["per_class"][name]
    flag = "  (no samples in test)" if pc["n"] == 0 else ""
    print(f"  {name:<14s} {pc['n']:>5d} {pc['prec']:>7.3f} {pc['rec']:>7.3f} {pc['f1']:>7.3f}{flag}")
print()
print("  Attack-type confusion matrix (rows=actual, cols=predicted):")
print(f"               {'NONE':>8s}  {'IN_BAND':>8s}  {'BLIND':>8s}  {'SECOND_ORDER':>13s}")
for cid, name in ATTACK_TYPE_NAMES.items():
    row = test_m["type_cm"][cid]
    print(f"  Actual {name:<10s} {row[0]:>8d}  {row[1]:>8d}  {row[2]:>8d}  {row[3]:>13d}")
print("=" * 70)

# Save machine-readable metrics for documentation and backend metadata.
MODEL_METRICS = {
    "selected_threshold": THRESHOLD_CALIBRATED,
    "threshold_sweep": [{k: (v.tolist() if hasattr(v, "tolist") else v) for k, v in row.items() if k != "type_cm"} for row in threshold_sweep],
    "validation": {k: (v.tolist() if hasattr(v, "tolist") else v) for k, v in val_m.items()},
    "test": {k: (v.tolist() if hasattr(v, "tolist") else v) for k, v in test_m.items()},
}
with open("sqli_detection_metrics.json", "w", encoding="utf-8") as f:
    json.dump(MODEL_METRICS, f, indent=2, ensure_ascii=False)
print("Saved sqli_detection_metrics.json")


# ## Section 10 — Smoke test by signal category
#
# Smoke test bucketing predictions by semantic signal. Confirms the binary head learned context, not just signal-token shortcuts.

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 9b — Save final confusion matrix plots
# ─────────────────────────────────────────────────────────────────────────────
# These are useful for the final project report.
import matplotlib.pyplot as plt
from pathlib import Path as _Path
_Path(PLOT_OUT_DIR).mkdir(parents=True, exist_ok=True)

def plot_matrix(cm, labels, title, filename):
    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(cm)
    ax.set_title(title)
    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.set_yticklabels(labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, str(int(cm[i][j])), ha="center", va="center")
    fig.colorbar(im, ax=ax)
    fig.tight_layout()
    path = _Path(PLOT_OUT_DIR) / filename
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.show()
    plt.close(fig)
    print("Saved", path)

binary_cm = [[test_m["tn"], test_m["fp"]], [test_m["fn"], test_m["tp"]]]
plot_matrix(binary_cm, ["SAFE", "VULNERABLE"], "Binary vulnerability confusion matrix", "binary_confusion_matrix.png")
plot_matrix(test_m["type_cm"], ["NONE", "IN_BAND", "BLIND", "SECOND_ORDER"], "Attack-type confusion matrix", "attack_type_confusion_matrix.png")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10 — SMOKE TEST: predictions broken down by signal category
# ─────────────────────────────────────────────────────────────────────────────
# (unchanged from previous version — answers "did the model truly learn,
# or just match signal tokens?")
# ─────────────────────────────────────────────────────────────────────────────
CATEGORY_SIGNALS = {
    "FSTRING_SQL (vuln)":            ("FSTRING_SQL", 1),
    "SQL_CONCAT  (vuln)":            ("SQL_CONCAT",  1),
    "UNSAFE_EXEC (vuln, no FS/CC)":  ("UNSAFE_EXEC", 1),
    "SAFE_EXEC   (safe)":            ("SAFE_EXEC",   0),
}

print()
print("=" * 70)
print("SMOKE TEST — vuln-head mean prediction per signal category")
print("=" * 70)
print(f"  {'category':32s} {'n':>4} {'mean':>7} {'>=0.5':>10}")
print("  " + "-" * 60)

for label, (signal_name, expected_class) in CATEGORY_SIGNALS.items():
    sid = vocab.get(signal_name, -1)
    if sid < 0:
        print(f"  {label:32s}  signal not in vocabulary")
        continue
    mask_signal = np.any(X == sid, axis=1)
    mask_class  = (y == expected_class) if expected_class == 1 else (y == 0)
    bucket_idx  = np.where(mask_signal & mask_class)[0]
    if len(bucket_idx) == 0:
        print(f"  {label:32s} {0:>4d}  (no matching samples)")
        continue
    preds = np.array([forward(X[i])[0] for i in bucket_idx])
    n_above = int((preds >= 0.5).sum())
    flag = "✓" if (expected_class == 1 and preds.mean() >= 0.5) or \
                  (expected_class == 0 and preds.mean() <  0.5) else "✗"
    print(f"  {label:32s} {len(bucket_idx):>4d} {preds.mean():>7.3f}  {n_above:>4d}/{len(bucket_idx):<3d} {flag}")

# Hard generalisation check: samples with NO semantic signal at all
print()
print("  ── samples WITHOUT any of {FSTRING_SQL, SQL_CONCAT, UNSAFE_EXEC, SAFE_EXEC} ──")
ids_arr = [vocab.get(n, -1) for n in ("FSTRING_SQL", "SQL_CONCAT", "UNSAFE_EXEC", "SAFE_EXEC")]
ids_arr = [s for s in ids_arr if s >= 0]
mask_no_signal = np.ones(len(X), dtype=bool)
for sid in ids_arr:
    mask_no_signal &= ~np.any(X == sid, axis=1)
for cls, name in [(1, "vuln, no signal"), (0, "safe, no signal")]:
    idx = np.where(mask_no_signal & (y == cls))[0]
    if len(idx) == 0:
        print(f"  {name:32s}    0  (no samples)")
        continue
    preds = np.array([forward(X[i])[0] for i in idx])
    print(f"  {name:32s} {len(idx):>4d} {preds.mean():>7.3f}")

# Attack-type breakdown — mean predicted probability of true class per type
print()
print("=" * 70)
print("ATTACK-TYPE HEAD — mean P(true class) per attack type")
print("=" * 70)
print("  A well-trained type head should give the true class high probability.")
print()
print(f"  {'attack_type':14s} {'n':>5} {'mean P(true)':>14} {'argmax-correct':>16}")
for cid, name in ATTACK_TYPE_NAMES.items():
    idx = np.where(y_type == cid)[0]
    if len(idx) == 0:
        print(f"  {name:14s} {0:>5}  (no samples)")
        continue
    probs_for_true = []
    n_correct = 0
    for i in idx:
        _, tp, _ = forward(X[i])
        probs_for_true.append(tp[cid])
        if int(np.argmax(tp)) == cid:
            n_correct += 1
    mean_p = float(np.mean(probs_for_true))
    print(f"  {name:14s} {len(idx):>5d} {mean_p:>14.3f} {n_correct:>10d}/{len(idx):<5d}")
print("=" * 70)


# ## Section 10b — Export vocabulary, metadata and label maps
#
# This section saves the artifacts required for deployment and reproducibility: weights, vocabulary, label maps, training split information, metrics, and metadata. The backend can use these fields to verify that the normalizer/vocabulary/sequence length match the trained model.

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10b — Export reproducibility metadata
# ─────────────────────────────────────────────────────────────────────────────
LABEL_MAPS = {
    "verdict_labels": {"SAFE": 0, "VULNERABLE": 1},
    "attack_type_labels": ATTACK_NAME_TO_ID,
    "attack_type_names": ATTACK_TYPE_NAMES,
}

MODEL_METADATA = {
    "model_version": MODEL_VERSION,
    "training_date_utc": datetime.utcnow().isoformat() + "Z",
    "dataset_version": DATASET_VERSION,
    "normalizer_version": NORMALIZER_VERSION,
    "vocabulary_sha256": VOCAB_HASH,
    "sequence_length": MODEL_SEQ_LEN,
    "pad_id": int(PAD_ID),
    "unk_id": int(UNK_ID),
    "architecture": ARCHITECTURE,
    "threshold": THRESHOLD_CALIBRATED if "THRESHOLD_CALIBRATED" in globals() else THRESHOLD,
    "class_weights": SPLIT_INFO["binary_class_weights"],
    "attack_type_class_weights": SPLIT_INFO["attack_type_class_weights"],
    "hardcase_training": {
        "uses_sample_weight_binary": bool("sample_weight_binary" in npz.files),
        "uses_sample_weight_type": bool("sample_weight_type" in npz.files),
        "type_hardcase_boost": SPLIT_INFO.get("type_hardcase_boost"),
        "binary_hardcase_boost": SPLIT_INFO.get("binary_hardcase_boost"),
        "target_problem": "V18-ML95: improve raw ML-only SAFE/VULNERABLE binary accuracy toward >=95% while preserving vulnerable recall and reducing SAFE false positives",
    },
    "split_info": SPLIT_INFO,
    "dataset_profile": DATASET_PROFILE,
    "weights_file": MODEL_WEIGHTS_FILE,
    "legacy_weights_file": LEGACY_WEIGHTS_FILE,
    "metrics_file": "sqli_detection_metrics.json",
}

with open("sqli_detection_vocab.json", "w", encoding="utf-8") as f:
    json.dump(vocab, f, indent=2, ensure_ascii=False)
with open("sqli_detection_label_maps.json", "w", encoding="utf-8") as f:
    json.dump(LABEL_MAPS, f, indent=2, ensure_ascii=False)
with open("sqli_detection_metadata.json", "w", encoding="utf-8") as f:
    json.dump(MODEL_METADATA, f, indent=2, ensure_ascii=False)

print("Saved:")
print("  -", MODEL_WEIGHTS_FILE)
print("  -", LEGACY_WEIGHTS_FILE)
print("  - sqli_detection_vocab.json")
print("  - sqli_detection_metadata.json")
print("  - sqli_detection_metrics.json")
print("  - sqli_detection_label_maps.json")


# ## Section 10c — Inference proof
#
# This cell demonstrates the full Model 1 inference chain: normalized token IDs enter the model, the CNN+BiLSTM network produces raw ML scores, and the final backend fusion layer may later adjust the decision with deterministic evidence. This is the proof that Model 1 is active and not replaced by rules.

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10c — Inference proof: token IDs → raw ML prediction
# ─────────────────────────────────────────────────────────────────────────────
def ml_predict_raw(token_ids, threshold=THRESHOLD_CALIBRATED if "THRESHOLD_CALIBRATED" in globals() else THRESHOLD):
    risk, type_probs, _ = forward(token_ids)
    type_id = int(np.argmax(type_probs))
    return {
        "ml_risk_score": round(float(risk), 4),
        "ml_predicted_verdict": "VULNERABLE" if risk >= threshold else "SAFE",
        "ml_predicted_attack_type": ATTACK_TYPE_NAMES[type_id],
        "ml_attack_type_probs": {ATTACK_TYPE_NAMES[i]: round(float(type_probs[i]), 4) for i in range(NUM_TYPE_CLASSES)},
        "model_version": MODEL_VERSION,
        "sequence_length": MODEL_SEQ_LEN,
    }

# Pick one vulnerable and one safe test sample for demonstration.
demo_indices = []
for desired in [1, 0]:
    matches = np.where(y_test.astype(int) == desired)[0]
    if len(matches):
        demo_indices.append(int(matches[0]))

for local_idx in demo_indices:
    token_ids = X_test[local_idx]
    true_verdict = "VULNERABLE" if int(y_test[local_idx]) == 1 else "SAFE"
    true_type = ATTACK_TYPE_NAMES[int(yt_test[local_idx])]
    non_pad = token_ids[token_ids != PAD_ID]
    tokens_preview = [id_to_token.get(int(t), "<BAD_ID>") for t in non_pad[:40]]
    print("=" * 70)
    print("Source sample:", raw_paths[idx_test[local_idx]])
    print("True:", true_verdict, "/", true_type)
    print("Normalized tokens preview:", tokens_preview)
    print("Token IDs preview:", non_pad[:40].tolist())
    print("Raw ML output:")
    print(json.dumps(ml_predict_raw(token_ids), indent=2, ensure_ascii=False))
    print("Fusion note: backend fusion may override ML only with explicit source/sink evidence.")


# ## Section 11 — Save & download weights
#
# Saves `sqli_model.npz` with both heads' weights and triggers a browser download. Place the file at `backend/app/model/weights/sqli_model.npz` and restart the backend.

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 11 — Download/export artifacts
# ─────────────────────────────────────────────────────────────────────────────
ARTIFACTS = [
    MODEL_WEIGHTS_FILE,
    LEGACY_WEIGHTS_FILE,
    "sqli_detection_vocab.json",
    "sqli_detection_metadata.json",
    "sqli_detection_metrics.json",
    "sqli_detection_label_maps.json",
    "dataset_profile.json",
    "split_info.json",
    "training_history.json",
]

print("Artifacts ready for backend deployment. Training plots are in training_plots/:")
for p in ARTIFACTS:
    print(" -", p)

try:
    from google.colab import files
    for p in ARTIFACTS:
        if Path(p).exists():
            files.download(p)
except Exception:
    print("Not running in Colab or download unavailable. Files are saved in the current directory.")

print("\nPlace model artifacts under something like:")
print("  backend/app/model/weights/sqli_detection_model.npz")
print("  backend/app/model/weights/sqli_detection_metadata.json")
print("  backend/app/model/weights/sqli_detection_vocab.json")
print("Current backend compatibility: also copy sqli_model.npz to backend/app/model/weights/sqli_model.npz")


