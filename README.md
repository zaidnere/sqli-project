# SENTINEL.SQL — AI-Powered SQL Injection Detector

A full-stack SAST (Static Application Security Testing) system that detects
SQL Injection vulnerabilities in source code using a deep learning model
(CNN + Bi-LSTM, trained from scratch) plus a rule-based Fix Recommendation Engine.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Frontend  (React + TypeScript + Tailwind)               │
│  • Upload .py / .js / .php / .java file                  │
│  • View: vulnerability verdict (rule-based, always)      │
│  • View: AI risk score + label (after Colab training)    │
│  • View: corrected code with real variable names         │
│  • View: scan history with SAFE/SUSPICIOUS/VULNERABLE    │
└───────────────────────┬──────────────────────────────────┘
                        │ REST API
┌───────────────────────▼──────────────────────────────────┐
│  Backend  (FastAPI + Python)                             │
│                                                          │
│  Preprocessing pipeline:                                 │
│    Clean → Tokenize → Normalize → Vectorize              │
│                                                          │
│  Semantic signals injected by normalizer:                │
│    FSTRING_SQL   f"SELECT...{var}..."  ← always danger   │
│    UNSAFE_EXEC   execute(query)        ← no params       │
│    SAFE_EXEC     execute(query,(p,))   ← parameterized   │
│    SQL_CONCAT    SQL_STRING + var      ← concatenation   │
│                                                          │
│  Fix Recommendation Engine (rule-based, no ML needed):  │
│    Detects pattern → extracts real var names → fix code  │
│                                                          │
│  CNN+BiLSTM Inference (after Colab training):           │
│    Embedding → Conv1D+MaxPool → BiLSTM → Dense → score  │
│                                                          │
│  Auth: JWT    DB: MongoDB                               │
└───────────────────────┬──────────────────────────────────┘
                        │ .npz weights
┌───────────────────────▼──────────────────────────────────┐
│  AI Model  (trained in Google Colab)                     │
│  Vocab: 173 tokens  |  Seq len: 256  |  NumPy from scratch│
└──────────────────────────────────────────────────────────┘
```

---

## Quick Start (Windows)

```cmd
cd backend

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt

copy .env.example .env
REM Edit .env: set MONGODB_URL and JWT_SECRET_KEY

uvicorn app.main:app --reload
```

Second terminal:
```cmd
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** — the app is fully functional.  
The Fix Recommendation Engine works immediately (no ML model needed).

---

## What works without ML model training

When `sqli_model.npz` has not been deployed, the system still:

- ✅ Detects SQL injection via rule-based signals (FSTRING_SQL, UNSAFE_EXEC, SQL_CONCAT)
- ✅ Shows the **Fix Recommendation** panel with corrected code
- ✅ Colour-codes normalized tokens in the UI
- ✅ Stores scan history
- ⏳ Shows "Model not deployed" for the AI risk score panel

---

## AI Model Training (Colab)

### Option A — Synthetic data only (quick, ~5 min)

```bash
cd backend
python scripts/export_for_colab.py
```

### Option B — Synthetic + Juliet dataset (better, recommended)

1. Download Juliet Java CWE-89 from https://samate.nist.gov/SARD/test-suites/111
2. Extract to `datasets/juliet_java_cwe89/` (project root)
3. Run:
```bash
cd backend
python scripts/import_juliet.py
```

### Then in both cases:

1. Open `sqli_colab_training.ipynb` in Google Colab
2. Upload `backend/colab_export/vocabulary.json` and `backend/colab_export/training_data.npz`
3. Run all cells — prints Precision, Recall, F1, Confusion Matrix
4. Download `sqli_model.npz`
5. Deploy:
```bash
cp sqli_model.npz backend/app/model/weights/sqli_model.npz
python backend/scripts/validate_weights.py
# restart backend
```

---

## Supported file types

`.py` · `.js` · `.php` · `.java`

## Detection signals

| Signal | Meaning | Example |
|--------|---------|---------|
| `FSTRING_SQL` | F-string SQL interpolation | `f"SELECT...{username}"` |
| `UNSAFE_EXEC` | execute() with no params | `cursor.execute(query)` |
| `SAFE_EXEC` | Parameterized execute | `cursor.execute(q, (v,))` |
| `SQL_CONCAT` | SQL string + variable | `"SELECT..." + user_id` |

## Fix strategies

| Code | Strategy | When used |
|------|----------|-----------|
| A | Parameterized Query | F-string, concat, %, .format() injection |
| B | Whitelist Validation | Dynamic column/table names |
| C | ORM Migration | Complex query patterns |
| D | Second-Order Mitigation | Stored input re-used in SQL |

---

## API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | No | Server + model status |
| `POST` | `/api/user/register` | No | Create account |
| `POST` | `/api/user/login` | No | Get JWT token |
| `GET` | `/api/user/me` | Yes | Current user |
| `POST` | `/api/scans/upload-and-scan` | Yes | Upload + analyse |
| `GET` | `/api/scans/model-status` | No | Model deployment status |
| `GET` | `/api/scans/history` | Yes | Scan history |
| `GET` | `/api/scans/history/{id}` | Yes | Reopen past scan |
| `GET` | `/api/admin/dashboard-summary` | Admin | Platform stats |

---

## Project structure

```
sqli-project/
├── sqli_colab_training.ipynb      # Colab notebook (full backprop from scratch)
├── README.md
├── Makefile                       # make install / make dev-backend / make export-colab
├── start-backend.sh               # Linux/Mac startup
├── datasets/
│   └── juliet_java_cwe89/         # Place Juliet here (download separately)
├── backend/
│   ├── requirements.txt
│   ├── .env.example
│   ├── app/
│   │   ├── preprocessing/         # clean → tokenize → normalize (with signals)
│   │   ├── vectorization/         # vocab (173 tokens) + vectorizer
│   │   ├── fix_engine/            # fix_generator.py — rule-based fix recommender
│   │   ├── model/
│   │   │   ├── sqli_detector.py   # forward-pass NumPy CNN+BiLSTM
│   │   │   ├── inference.py       # singleton loader
│   │   │   └── weights/           # place sqli_model.npz here
│   │   ├── schemas/scan.py        # ScanResponse, ScanDetectionInfo, ScanFixRecommendation
│   │   └── services/scan_service.py
│   ├── scripts/
│   │   ├── export_for_colab.py    # generate synthetic dataset
│   │   ├── import_juliet.py       # merge Juliet CWE-89 + synthetic
│   │   └── validate_weights.py    # verify .npz before deployment
│   └── colab_export/              # generated output (upload to Colab)
└── frontend/src/
    ├── types/api.ts               # TypeScript types (zero any)
    ├── components/scan/
    │   ├── ScanResult.tsx         # detection + fix panel + normalized tokens
    │   ├── ScanHistory.tsx        # verdict badges
    │   └── FileUpload.tsx         # model status banner
    └── hooks/useModelStatus.ts
```
