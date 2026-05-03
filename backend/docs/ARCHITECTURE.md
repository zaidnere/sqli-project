# SQLi Scanner — Architecture & Decision Policy

> **Status**: stable for academic submission · **Last updated**: Gap A + Gap B alignment review

This document is the single source of truth for **how the system reaches a verdict**.
It exists because reviewers (and the academic supervisor) will ask:
*"You said deep learning replaces traditional Regex — but your code has a rule layer.
What's the relationship?"*

Short answer: **the trained model is the primary classifier. The rule layer is an
auxiliary explainability + safety-net component.** Long answer below.

---

## 1. One-line summary

The CNN+BiLSTM model decides. The rule layer **explains** and provides a
**failsafe** if the model is unavailable.

---

## 2. Pipeline overview

```
Raw uploaded file
   ↓
Preprocessing (deterministic)
   ├── Code Cleaning      (remove comments, normalize whitespace)
   ├── Tokenization       (split into ordered tokens)
   └── Semantic Normalization
         ↳ produces VAR_n, FUNC_n, SQL_STRING, FSTRING_SQL,
                    SQL_CONCAT, UNSAFE_EXEC, SAFE_EXEC, ...
   ↓
                ┌─── Vectorization ──→ tokenIds (int32, MODEL_SEQ_LEN=128)
                │            ↓
                │       CNN + BiLSTM + Dense  (the model)
                │            ↓
                │       Vuln head (sigmoid)  →  ml_score    ∈ [0, 1]
                │       Type head (softmax)  →  attack_type ∈ {NONE, IN_BAND, BLIND, SECOND_ORDER}
                │
                └─── Rule scorer ─────→ rule_score ∈ [0, 1] from signal heuristics
                             ↓
                     _fuse_scores(ml_score, rule_score, signals)
                             ↓
                     fused_score, verdict_source
                             ↓
                     {SAFE | SUSPICIOUS | VULNERABLE}
                     + attack type + suspicious patterns + verdictSource
```

The rule layer is a **second consumer** of the same preprocessing artifacts
that feed the model, not an independent system. The proposal (page 8) is
explicit: deterministic logic in preprocessing produces signals, then those
signals feed the probabilistic model. We added a parallel rule scorer on top
because we need (a) explainability for the user, (b) a fallback when the
model is unloaded, and (c) a sanity layer for production reliability.

---

## 3. Why a rule layer exists at all

### 3.1 Explainability for the user

When the model says "this code is 99.7% likely to be vulnerable," the user
asks "**why?**" The model itself can't answer — it's a black-box
function over token sequences. The rule layer translates the deterministic
signals (`FSTRING_SQL`, `SQL_CONCAT`, `UNSAFE_EXEC`) into human-readable
patterns:

> *"F-string SQL injection in 'get_user': user variable embedded directly
> in SQL via `f"...{var}..."`."*

This is the `suspiciousPatterns[]` field in the API response. It tells the
user *what* the dangerous shape is and *where* it appears. The model alone
could not produce that.

### 3.2 Safety net when the model is unavailable

The trained `sqli_model.npz` is a separate artifact. If a fresh deployment
spins up before weights are present, or if the file is corrupted, we want
the scanner to **degrade gracefully** rather than refuse to run. The rule
layer alone produces a defensible (though less accurate) verdict. The
response field `modelLoaded: false` tells the frontend to display a
"reduced-accuracy mode" banner. `verdictSource` is `"rule_safety_net"`.

### 3.3 Industry alignment

Real-world SAST tools combine ML with rules:

| Tool | ML component | Rule component |
|---|---|---|
| Semgrep | symbolic AST patterns | rule packs |
| CodeQL | dataflow analysis | query DSL |
| Snyk Code | learned classifier | curated signatures |

A pure-ML academic prototype is fine. A pure-ML *production* tool would be
fragile. We chose to ship the production-shaped architecture and document
the deviation, rather than gut the rule layer to be more "academically pure."

---

## 4. What the rule layer does NOT do

These are explicit non-goals. The rule layer is **not**:

1. **The headline academic accuracy metric.** The reported F1 = 1.000 on
   validation is the **vulnerability head's** F1, measured against the
   **binary labels** the head was trained to predict. The rule layer is
   not part of that measurement.
2. **An override of confident ML predictions.** When ML scores < 0.05 and
   no `SQL_CONCAT` signal is present, ML wins outright (`verdictSource =
   "ml"` or `"ml_overrides_rule"`), regardless of what the rule layer said.
3. **Reliable on its own.** The rule scorer is a hand-tuned heuristic; it
   was the entire detection mechanism in early prototypes and hit textbook
   weaknesses (false positives on whitelist guards, false negatives on
   builder patterns). The model fixes those. The rule layer is now the
   floor, not the ceiling.

---

## 5. Decision rule (`_fuse_scores`)

The exact policy implemented in `app/services/scan_service.py`:

```python
def _fuse_scores(ml_score, rule_score, signals) -> (fused_score, source_tag):
    # 1. Failsafe path
    if ml_score is None:
        if hard_rule_combo_present(signals):
            return max(0.90, rule_score), "rule_safety_net"
        return rule_score, "rule_safety_net"

    has_fstring = "FSTRING_SQL" in signals
    has_concat  = "SQL_CONCAT"  in signals

    # 2a. ML strongly says safe and rule has nothing dangerous
    if ml_score < 0.05 and not has_fstring and not has_concat:
        return ml_score, "ml"

    # 2b. ML strongly says safe; rule fired ONLY because of FSTRING_SQL.
    # F-strings can be safe (validated dynamic SQL); concat almost never can.
    if ml_score < 0.05 and has_fstring and not has_concat:
        return ml_score, "ml_overrides_rule"

    # 2c. Default: max-pool, with source tag based on which margin is larger
    fused = max(ml_score, rule_score)
    diff  = ml_score - rule_score
    if   diff >=  0.10: source = "ml"
    elif diff <= -0.10: source = "rule"
    else:               source = "ml+rule"
    return fused, source
```

**Why ml < 0.05 and not 0.20**: an earlier policy used `< 0.20`. Real-world
testing showed it allowed the model to override rule evidence on patterns
it had not generalised to (e.g. an f-string SQLi diluted by an unrelated
`if __name__ == "__main__":` block scoring 0.17). The 0.05 threshold
narrows the override to "the model is genuinely confident-safe."

**Why no override when SQL_CONCAT is present**: string concatenation
(`"SELECT ... " + var`) is almost always genuine injection. F-strings are
"could be either" — they're idiomatic Python and frequently appear in
safe builder code with whitelist-validated values. We picked which signal
to trust override on based on the ratio of safe-vs-vulnerable real-world
samples.

---

## 6. Worked examples

These show how the policy plays out across the four canonical situations.
Numbers are taken from the dual-head model trained on the post-Gap-A dataset.

### Example A — Plain f-string injection (ML wins, rule agrees)

```python
def get_user(name):
    sql = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(sql)
```

| Component | Value |
|---|---|
| `mlScore` | **0.997** |
| `ruleScore` | 0.90 (FSTRING_SQL + UNSAFE_EXEC = hard-vuln combo) |
| `fusedScore` | **0.997** |
| `verdictSource` | `"ml+rule"` (both agree, within 0.10 — actually difference is 0.097) |
| `verdict` | VULNERABLE |
| `attackType` | IN_BAND |

Both layers agree. The user sees a high-confidence VULNERABLE verdict with
the f-string pattern explained.

### Example B — Whitelist-validated f-string (ML overrides rule)

```python
ALLOWED = {"name", "price", "created_at"}
def list_products(sort_by):
    if sort_by not in ALLOWED:
        raise ValueError("invalid")
    cursor.execute(f"SELECT * FROM products ORDER BY {sort_by}")
```

| Component | Value |
|---|---|
| `mlScore` | **0.006** (model learned the whitelist context) |
| `ruleScore` | 0.90 (FSTRING_SQL → hard-vuln combo, naively) |
| `fusedScore` | **0.006** |
| `verdictSource` | `"ml_overrides_rule"` |
| `verdict` | SAFE |
| `attackType` | NONE |

The model correctly reads the whitelist guard. The rule layer (which
doesn't understand validation) would have flagged this as VULNERABLE.
Without the override, this would be a false positive.

### Example C — Builder helper with `SQL_CONCAT` (rule wins)

```python
def legacy_keyword_surface(self, keyword):
    clean = normalize_keyword(keyword)
    raw_fragment = (
        " AND (LOWER(r.customer_name) LIKE '%"
        + clean
        + "%' OR LOWER(r.reference_code) LIKE '%"
        + clean
        + "%')"
    )
    self.fragments.append(raw_fragment)   # later: cur.execute(sql, params)
```

| Component | Value |
|---|---|
| `mlScore` | 0.09 (model is confused — function appends, doesn't execute) |
| `ruleScore` | 0.90 (SQL_CONCAT alone is a hard-vuln combo) |
| `fusedScore` | **0.90** |
| `verdictSource` | `"rule"` (rule is 0.81 above ML) |
| `verdict` | VULNERABLE |
| `attackType` | IN_BAND (sanity rule kicks in: VULNERABLE + type-head-NONE → IN_BAND) |

The model has not seen builder-pattern helpers in training. The rule layer
correctly catches this real second-order vulnerability. Once we add such
samples to the training set, the model should agree directly.

### Example D — Model unavailable (failsafe)

```python
sql = "SELECT * FROM users WHERE id=" + uid
cursor.execute(sql)
```

| Component | Value |
|---|---|
| `mlScore` | None (weights file missing) |
| `ruleScore` | 0.90 (SQL_CONCAT + UNSAFE_EXEC → hard-vuln combo) |
| `fusedScore` | **0.90** |
| `verdictSource` | `"rule_safety_net"` |
| `verdict` | VULNERABLE |
| `modelLoaded` | false |

The frontend shows a "running in reduced-accuracy mode" banner. The user
still gets a verdict. After re-training and dropping `sqli_model.npz` into
`backend/app/model/weights/`, `verdictSource` returns to `"ml*"`.

---

## 7. What the API surfaces (the transparency contract)

Every scan response includes:

```json
{
  "detection": {
    "riskScore":      0.997,
    "label":          "VULNERABLE",
    "modelLoaded":    true,
    "verdictSource":  "ml+rule",      ← which layer drove the verdict (Gap B)

    "attackType":             "IN_BAND",
    "attackTypeConfidence":   0.94,
    "attackTypeProbs": {
      "NONE": 0.02, "IN_BAND": 0.94, "BLIND": 0.03, "SECOND_ORDER": 0.01
    },
    "attackTypeAvailable":    true,    ← false if running pre-Gap-A weights

    "suspiciousPatterns": [
      { "pattern": "FSTRING_SQL", "severity": "HIGH", "description": "..." }
    ],
    "explanation": "..."
  }
}
```

A reviewer or researcher reading the API output can answer:
- Did the ML model decide, or did the rule layer? → `verdictSource`
- What kind of attack? → `attackType` + `attackTypeProbs`
- Is the model running, or are we in failsafe? → `modelLoaded`
- Which deterministic signals fired? → `suspiciousPatterns`
- Does the trained model include the new attack-type head? → `attackTypeAvailable`

This separation is what makes the hybrid architecture defensible
academically. We are not hiding rule contributions inside an opaque "score";
we are reporting them.

---

## 8. Academic-submission framing (suggested writeup paragraph)

> *"The proposal (page 8) describes a pipeline in which deterministic
> preprocessing produces semantic labels (`VAR_0`, `STRING_SQL`,
> `USER_INPUT`, ...) which then feed a probabilistic CNN+BiLSTM
> classifier. The implementation realises this pipeline and adds a
> parallel deterministic scoring layer that consumes the same signals.
> The scoring layer serves three purposes orthogonal to classification:
> (1) it produces the `suspiciousPatterns[]` array shown to the user,
> (2) it provides a degraded-mode verdict when the trained model is
> unavailable, and (3) it acts as a sanity floor on the rare patterns
> the model has not generalised to (notably builder-pattern helpers
> with deferred execution). The reported headline metric (F1 = X.XXX) is
> measured against the binary head of the model alone; the rule layer
> does not contribute to it. The fusion policy is documented in
> `_fuse_scores` and exposed to the user via the `verdictSource` field
> in every API response."*

---

## 9. Where to look

| Concern | File |
|---|---|
| The fusion policy | `backend/app/services/scan_service.py` → `_fuse_scores` |
| Rule scoring | `backend/app/services/scan_service.py` → `_rule_score` |
| Hard-rule combos | `backend/app/services/scan_service.py` → `ALWAYS_VULNERABLE_COMBOS` |
| Signal generation | `backend/app/preprocessing/normalizer.py` |
| Model architecture | `backend/app/model/sqli_detector.py` |
| Training | `colab/model1_detection.ipynb` |
| API contract | `backend/app/schemas/scan.py` → `ScanDetectionInfo` |
