# Backend Scripts

Run all scripts from the `backend/` directory with the virtual environment activated.

---

## `export_for_colab.py` — Main export (run this first)

Generates the vocabulary and synthetic training dataset for Colab training.

```bash
python scripts/export_for_colab.py
```

**Outputs** (`backend/colab_export/`):

| File | Description |
|---|---|
| `vocabulary.json` | Fixed token→ID mapping (173 tokens incl. semantic signals) |
| `training_data.npz` | `X` (int32, N×256) + `y` (float32 labels), ~1200 samples |
| `export_info.json` | Dataset stats, signal coverage, architecture spec |

**Signal coverage report** (printed when run):
```
FSTRING_SQL_in_vuln    19/76   ← f-string SQL injection
UNSAFE_EXEC_in_vuln    48/76   ← execute(query) with no params
SQL_CONCAT_in_vuln     39/76   ← SQL_STRING + variable
SAFE_EXEC_in_safe      33/74   ← execute(query, (params,))
```

These four signals are the primary features the CNN+BiLSTM learns from.

---

## `import_juliet.py` — Optional Juliet CWE-89 integration

Merges the [NIST Juliet CWE-89](https://samate.nist.gov/SARD/test-suites/112) Java
benchmark with the synthetic dataset for a larger, more diverse training set.

**Step 1 — Download Juliet:**
- Go to: https://samate.nist.gov/SARD/test-suites/112
- Download: `Juliet_Test_Suite_v1.3_for_Java.zip`
- Extract and locate the `CWE89_SQL_Injection` folder

**Step 2 — Run:**
```bash
python scripts/import_juliet.py --juliet-dir /path/to/CWE89_SQL_Injection/
```

**Output:** Overwrites `colab_export/training_data.npz` with the merged dataset (~1,600 samples).

**Without Juliet:** The system works fine with the 1,200 synthetic samples alone.

---

## `validate_weights.py` — Verify trained model weights

After downloading `sqli_model.npz` from Colab, validate it before restarting:

```bash
python scripts/validate_weights.py
```

Checks:
- File exists at `app/model/weights/sqli_model.npz`
- All 11 weight arrays present with correct shapes
- No NaN / Inf values
- Forward pass returns a valid score in [0.0, 1.0]

Exit code: `0` = valid, `1` = missing or malformed.

---

## `profile_dataset.py` — Dataset analysis utility

Profiles sequence lengths and identifier counts in a Java dataset.
Used to calibrate `MAX_VAR_TOKENS`, `MAX_FUNC_TOKENS`, `MAX_SEQUENCE_LENGTH`.

```bash
python scripts/profile_dataset.py
```

Requires Juliet dataset at `../../datasets/juliet_java_cwe89/`.

---

## `generate_dataset.py` — **Deprecated**

Replaced by `export_for_colab.py`. Kept to avoid breaking cached references.

---

## `train_model.py` — **Moved to Colab**

Training is done in Google Colab. See `sqli_colab_training.ipynb` at the project root.

---

## Full workflow

```
1. python scripts/export_for_colab.py          # generate colab_export/
2. # (optional) python scripts/import_juliet.py --juliet-dir /path/
3. # Open sqli_colab_training.ipynb in Colab
4. # Upload vocabulary.json + training_data.npz
5. # Run all cells — download sqli_model.npz
6. # Copy sqli_model.npz → backend/app/model/weights/
7. python scripts/validate_weights.py          # verify before restarting
8. # Restart backend — model loads automatically
```
