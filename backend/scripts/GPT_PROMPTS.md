# GPT_PROMPTS.md — Targeted dataset extension via ChatGPT (GPT‑Pro / Claude API)

The mutation framework in `dataset_mutations.py` covers the **broad space** of
SQL injection patterns (5 axes × 4 languages → ~350 base samples → ~2000 unique
training samples after structural augmentation).

This document is for **surgical extensions**: when real-world testing reveals
a specific pattern the model misclassifies, use a targeted prompt to generate
a small batch (10–25 samples) of that exact pattern, vet them, and add to
`VULNERABLE_BASE` or `SAFE_BASE` in `export_for_colab.py`.

---

## When to use a prompt vs. extend the mutation framework

| Situation | Use |
|---|---|
| 30+ misclassifications of one shape | extend mutation framework |
| 1–10 misclassifications of one shape | use a targeted prompt |
| Pattern is highly idiomatic (specific framework method) | use a targeted prompt |
| Pattern is mechanical (just a new SQL keyword) | extend mutation framework |

---

## How to use these prompts

1. Copy a prompt below into ChatGPT (any model with code-fluency works).
2. Paste the model's response into a Python list-of-tuples format matching
   `VULNERABLE_BASE` / `SAFE_BASE`.
3. **Verify each sample manually**:
   - For VULN: does the code actually have an injection? Does user input flow into a SQL string without parameterization?
   - For SAFE: is the input **actually** validated/parameterized? Watch for subtle holes (e.g. `validate(x)` returning `True` for any string).
4. Add to the appropriate list in `export_for_colab.py`.
5. Re-run `python scripts/export_for_colab.py`.
6. Re-train and confirm the misclassification is fixed.

**Manual verification is non-negotiable.** GPT models occasionally generate
"safe" code that's actually vulnerable, or "vulnerable" code that's actually
benign because it doesn't reach a sink.

---

## Prompt templates

### A. Vulnerable samples — specific framework

```
Generate 15 short Python code samples that contain a SQL injection
vulnerability. Each sample should:

- Use the {FRAMEWORK} web framework specifically
- Be 4-10 lines long
- Take user input from a request object
- Build a SQL query using {f-strings | string concatenation | .format() | %}
- Execute the query via {cursor.execute() | db.query() | session.execute()}
- NOT contain any validation, sanitization, parameterization, or ORM use

Output as a Python list of tuples in this exact format:

[
    ("python", "framework_attack_type", '''<code here>'''),
    ...
]

Do not add explanatory text. Do not add comments inside the code.
Each sample must be unique (different tables, columns, variable names).

{FRAMEWORK} = Django   (replace with FastAPI, Flask, Tornado, Bottle, Sanic, etc.)
```

### B. Safe samples — specific validation pattern

```
Generate 15 short Python code samples that USE user input in a database
query but are SAFE because of validation or parameterization.

Each sample should:

- Be 5-12 lines long
- Take user input from a request object
- Apply the validation pattern: {PATTERN}
- Either parameterize the query OR use the validated value safely
- Use a real database library (sqlite3, psycopg2, pymysql, SQLAlchemy)

Output as a Python list of tuples in this exact format:

[
    ("python", "safe_pattern_name", '''<code here>'''),
    ...
]

{PATTERN} options (use one per batch):

  - "set whitelist for ORDER BY column"
  - "regex validation matching ^[a-zA-Z0-9_]+$"
  - "dict mapping user keys to safe SQL fragments"
  - "type cast to int with try/except"
  - "Pydantic model validation"
  - "SQLAlchemy ORM with filter()"
  - "Django ORM with filter() / .objects.get()"
  - "stored procedure call (cursor.callproc)"
  - "named parameter binding (text(...) with :name)"

CRITICAL: each sample MUST actually be safe. Read each one and confirm
that no path exists for unvalidated user input to reach the SQL string.
```

### C. JavaScript / PHP / Java equivalents

Adapt prompts A and B by replacing the language and library names:

- JavaScript: `mysql`, `mysql2`, `pg`, `sequelize`, `prisma`, `knex`
- PHP: `mysqli`, `PDO`, `mysql_*` (legacy), `Doctrine`
- Java: `JDBC PreparedStatement`, `Hibernate`, `JPA`, `MyBatis`

---

## Example: filling a real gap

Suppose real-world testing reveals the model misses Django ORM `.extra(where=...)`
calls with f-string parameters (a real-but-rare misuse of the ORM). You'd:

1. Open ChatGPT.
2. Paste prompt A with `{FRAMEWORK} = Django ORM .extra(where=) misuse`.
3. Get 15 samples like:

```python
def by_score(req):
    threshold = req.GET["min_score"]
    return User.objects.extra(where=[f"score > {threshold}"])
```

4. **Manually verify** each is actually unsafe (`extra(where=)` does NOT parameterize raw SQL).
5. Add to `VULNERABLE_BASE`.
6. Re-export, re-train, confirm fix.

This is **surgical**. Don't generate 200 samples this way unless you can vet 200 samples this way.

---

## Why we don't generate everything via GPT

1. **Reproducibility.** The mutation framework produces the same dataset every run. GPT samples are a one-time artifact that examiners can't re-derive.
2. **Label noise.** Even careful GPT samples have a ~5% rate of subtle label errors, which compounds at scale.
3. **Bias amplification.** GPT tends to write idiomatic-but-narrow code that doesn't match real-world variation.
4. **Audit cost.** Vetting 200 samples takes 4-6 hours. Vetting 20 surgical samples takes 20 minutes.

The mutation framework + targeted prompts is the right balance. Don't drift toward "let GPT generate the whole training set."
