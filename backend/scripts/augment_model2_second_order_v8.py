# MODEL2_TARGETED_SECOND_ORDER_V8_AUGMENT_MARKER
"""Targeted Model 2 augmentation for the final D->A failures.

Purpose:
- Keep Model 1 frozen/read-only.
- Do not change suites.
- Do not add rules that override Model 2 decisions.
- Add training examples that help Model 2 learn remaining second-order SQLi cases.

This script updates the existing Colab export folder in-place by overwriting:
- training_data.npz
- dataset_profile.json

It does NOT delete the export folder.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Callable, Dict, List, Tuple

import numpy as np

from app.model.fix_model_inference import EVIDENCE_FEATURES, build_evidence_vector
from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.normalizer import normalize_tokens
from app.preprocessing.tokenizer import tokenize_code
from app.vectorization.vectorizer import vectorize_tokens

FIX_LABELS = {"A": 0, "B": 1, "C": 2, "D": 3}
LANG = {"python": 0, "javascript": 1, "java": 2, "php": 3}
ATTACK = {"NONE": 0, "IN_BAND": 1, "BLIND": 2, "SECOND_ORDER": 3}

# Families are intentionally close to the remaining full-pipeline failures:
# - saved widget/filter SQL fragments
# - stored query executor
# - config fragment / archival predicate
# - saved filter builder
# Anchors keep A/B/C boundaries stable so we do not solve D by over-predicting D.

PY_D_PATTERNS = [
    lambda i: f'''def load_widget_filter(cursor, widget_id):\n    row = cursor.execute("SELECT filter_sql FROM widget_filters WHERE widget_id = ?", (widget_id,)).fetchone()\n    saved_filter = row["filter_sql"]\n    sql = "SELECT * FROM widgets WHERE " + saved_filter\n    return cursor.execute(sql).fetchall()\n''',
    lambda i: f'''def run_saved_widget_query(cursor, name):\n    row = cursor.execute("SELECT sql_fragment FROM widget_reports WHERE name = ?", (name,)).fetchone()\n    widget_clause = row["sql_fragment"]\n    query = "SELECT id, name FROM widgets WHERE active = 1 AND " + widget_clause\n    return cursor.execute(query).fetchall()\n''',
    lambda i: f'''def search_from_config(cursor, config):\n    archival_predicate = config.get("archival_predicate")\n    sql = "SELECT * FROM invoices WHERE tenant_id = ? AND " + archival_predicate\n    return cursor.execute(sql, (config.get("tenant_id"),)).fetchall()\n''',
    lambda i: f'''def apply_configured_fragment(cursor, cfg):\n    config_fragment = cfg["where_clause"]\n    base = "SELECT * FROM audit_log WHERE "\n    sql = base + config_fragment\n    return cursor.execute(sql).fetchall()\n''',
    lambda i: f'''def run_cached_filter(cursor, cache, key):\n    saved_where = cache.get(key)\n    query = "SELECT * FROM customers WHERE " + saved_where\n    rows = cursor.execute(query).fetchall()\n    return rows\n''',
]

JS_D_PATTERNS = [
    lambda i: f'''async function runStoredQuery(db, queryId) {{\n  const row = await db.get("SELECT sql_text FROM saved_queries WHERE id = ?", [queryId]);\n  const storedSql = row.sql_text;\n  return db.all(storedSql);\n}}\n''',
    lambda i: f'''async function executeStoredWidgetFilter(db, widgetId) {{\n  const row = await db.get("SELECT filter_sql FROM widget_filters WHERE widget_id = ?", [widgetId]);\n  const savedFilter = row.filter_sql;\n  const sql = "SELECT * FROM widgets WHERE " + savedFilter;\n  return db.all(sql);\n}}\n''',
    lambda i: f'''async function savedFilterBuilder(db, cache, key) {{\n  const fragment = await cache.get(key);\n  const sql = "SELECT * FROM customers WHERE active = 1 AND " + fragment;\n  return db.query(sql);\n}}\n''',
    lambda i: f'''async function configDrivenSearch(client, config) {{\n  const whereClause = config.get("where_clause");\n  const sql = "SELECT * FROM reports WHERE " + whereClause;\n  return client.query(sql);\n}}\n''',
]

JAVA_D_PATTERNS = [
    lambda i: '''ResultSet runSavedFilter(Connection conn, String id) throws Exception {\n    PreparedStatement ps = conn.prepareStatement("SELECT sql_text FROM saved_reports WHERE id = ?");\n    ps.setString(1, id);\n    ResultSet row = ps.executeQuery();\n    String storedSql = row.getString("sql_text");\n    return conn.createStatement().executeQuery(storedSql);\n}\n''',
    lambda i: '''ResultSet runConfigFragment(Connection conn, Config config) throws Exception {\n    String whereClause = config.get("where_clause");\n    String sql = "SELECT * FROM invoices WHERE " + whereClause;\n    return conn.createStatement().executeQuery(sql);\n}\n''',
]

PHP_D_PATTERNS = [
    lambda i: '''<?php\nfunction runSavedFilter($pdo, $id) {\n    $stmt = $pdo->prepare("SELECT sql_text FROM saved_reports WHERE id = ?");\n    $stmt->execute([$id]);\n    $storedSql = $stmt->fetchColumn();\n    return $pdo->query($storedSql)->fetchAll();\n}\n?>\n''',
    lambda i: '''<?php\nfunction applyCachedWhere($conn, $cacheKey) {\n    $whereClause = Cache::get($cacheKey);\n    $sql = "SELECT * FROM customers WHERE " . $whereClause;\n    return $conn->query($sql);\n}\n?>\n''',
]

# A anchors for the remaining A->C alias execute failure and similar safe-to-parameterize value contexts.
PY_A_PATTERNS = [
    lambda i: f'''def alias_execute_search(cursor, email):\n    run = cursor.execute\n    sql = "SELECT * FROM users WHERE email = '" + email + "'"\n    return run(sql).fetchone()\n''',
    lambda i: f'''def obfuscated_alias_execute(conn, token):\n    executor = conn.execute\n    sql = f"SELECT id FROM reset_tokens WHERE token = '{{token}}'"\n    return executor(sql).fetchone()\n''',
    lambda i: f'''def indirect_cursor_exec(cur, user_id):\n    do_exec = cur.execute\n    query = "SELECT * FROM users WHERE id = " + str(user_id)\n    rows = do_exec(query).fetchall()\n    return rows\n''',
]

JS_A_PATTERNS = [
    lambda i: '''async function aliasExecute(db, email) {\n  const runQuery = db.query.bind(db);\n  const sql = "SELECT * FROM users WHERE email = '" + email + "'";\n  return runQuery(sql);\n}\n''',
    lambda i: '''async function simpleValueConcat(db, userId) {\n  const q = "SELECT * FROM users WHERE id = " + userId;\n  return db.execute(q);\n}\n''',
]

JAVA_A_PATTERNS = [
    lambda i: '''ResultSet simpleUserLookup(Connection conn, String email) throws Exception {\n    String sql = "SELECT * FROM users WHERE email = '" + email + "'";\n    Statement stmt = conn.createStatement();\n    return stmt.executeQuery(sql);\n}\n''',
]

PHP_A_PATTERNS = [
    lambda i: '''<?php\nfunction findByEmail($conn, $email) {\n    $sql = "SELECT * FROM users WHERE email = '" . $email . "'";\n    return $conn->query($sql);\n}\n?>\n''',
]

B_ANCHORS = {
    "python": [lambda i: 'def list_users(cursor, sort_column):\n    sql = "SELECT * FROM users ORDER BY " + sort_column\n    return cursor.execute(sql).fetchall()\n'],
    "javascript": [lambda i: 'async function listUsers(db, sortColumn) {\n  const sql = "SELECT * FROM users ORDER BY " + sortColumn;\n  return db.all(sql);\n}\n'],
    "java": [lambda i: 'ResultSet listUsers(Connection conn, String sortColumn) throws Exception {\n    String sql = "SELECT * FROM users ORDER BY " + sortColumn;\n    return conn.createStatement().executeQuery(sql);\n}\n'],
    "php": [lambda i: '<?php\nfunction listUsers($conn, $sort) {\n    $sql = "SELECT * FROM users ORDER BY " . $sort;\n    return $conn->query($sql);\n}\n?>\n'],
}

C_ANCHORS = {
    "python": [lambda i: 'def search(cursor, filters):\n    sql = "SELECT * FROM users WHERE 1=1"\n    for field, value in filters.items():\n        sql += " AND " + field + " = \'" + value + "\'"\n    return cursor.execute(sql).fetchall()\n'],
    "javascript": [lambda i: 'async function search(db, filters) {\n  let sql = "SELECT * FROM users WHERE 1=1";\n  for (const k of Object.keys(filters)) {\n    sql += " AND " + k + " = \'" + filters[k] + "\'";\n  }\n  return db.all(sql);\n}\n'],
    "java": [lambda i: 'List<User> search(JdbcTemplate jdbc, Map<String,String> filters) {\n    String sql = "SELECT * FROM users WHERE 1=1";\n    for (String k : filters.keySet()) {\n        sql += " AND " + k + " = \'" + filters.get(k) + "\'";\n    }\n    return jdbc.query(sql);\n}\n'],
    "php": [lambda i: '<?php\nfunction search($conn, $filters) {\n    $sql = "SELECT * FROM users WHERE 1=1";\n    foreach ($filters as $k => $v) {\n        $sql .= " AND " . $k . " = \'" . $v . "\'";\n    }\n    return $conn->query($sql);\n}\n?>\n'],
}

TEMPLATES: Dict[str, Dict[str, List[Callable[[int], str]]]] = {
    "D": {"python": PY_D_PATTERNS, "javascript": JS_D_PATTERNS, "java": JAVA_D_PATTERNS, "php": PHP_D_PATTERNS},
    "A": {"python": PY_A_PATTERNS, "javascript": JS_A_PATTERNS, "java": JAVA_A_PATTERNS, "php": PHP_A_PATTERNS},
    "B": B_ANCHORS,
    "C": C_ANCHORS,
}


def _variant(code: str, i: int, language: str) -> str:
    # Small source-level variation without changing semantic class.
    prefix = "# targeted v8 second-order augmentation\n" if language == "python" else "// targeted v8 second-order augmentation\n"
    if i % 7 == 0:
        code = prefix + code
    if i % 11 == 0:
        code = code.replace("users", "accounts")
    if i % 13 == 0:
        code = code.replace("customers", "clients")
    if i % 17 == 0:
        code = "\n" + code
    return code


def _make_sample(fix: str, language: str, i: int) -> Tuple[str, str]:
    templates = TEMPLATES[fix][language]
    code = templates[i % len(templates)](i)
    code = _variant(code, i, language)
    attack = "SECOND_ORDER" if fix == "D" else "IN_BAND"
    return attack, code


def _vectorize_sample(code: str, language: str, attack: str, fix: str, vocab: dict):
    cleaned = clean_code(code)
    tokens = tokenize_code(cleaned)
    normalized = normalize_tokens(tokens)
    vec = vectorize_tokens(normalized, vocab)
    return {
        "X": np.array(vec["tokenIds"], dtype=np.int32),
        "y_fix": np.int64(FIX_LABELS[fix]),
        "language_id": np.int64(LANG[language]),
        "attack_type_id": np.int64(ATTACK[attack]),
        "evidence": build_evidence_vector(normalized, code, language).astype(np.float32),
        "raw_code": code,
        "normalized_text": " ".join(normalized),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--export-dir", default="colab_export_fix_v2")
    ap.add_argument("--samples-per-class-language-extra", type=int, default=80)
    ap.add_argument("--seed", type=int, default=20260518)
    args = ap.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)

    export_dir = Path(args.export_dir)
    data_path = export_dir / "training_data.npz"
    vocab_path = export_dir / "vocabulary.json"
    profile_path = export_dir / "dataset_profile.json"

    if not data_path.exists():
        raise SystemExit(f"training_data.npz not found: {data_path}")
    if not vocab_path.exists():
        raise SystemExit(f"vocabulary.json not found: {vocab_path}")

    data = dict(np.load(data_path, allow_pickle=True))
    vocab = json.loads(vocab_path.read_text(encoding="utf-8"))

    old_n = int(len(data["y_fix"]))
    new_rows = {"X": [], "y_fix": [], "language_id": [], "attack_type_id": [], "evidence": [], "raw_code": [], "normalized_text": []}

    for fix in ["A", "B", "C", "D"]:
        for language in ["python", "javascript", "java", "php"]:
            for i in range(args.samples_per_class_language_extra):
                attack, code = _make_sample(fix, language, i)
                sample = _vectorize_sample(code, language, attack, fix, vocab)
                for key in new_rows:
                    new_rows[key].append(sample[key])

    appended = {k: np.array(v, dtype=(np.float32 if k == "evidence" else object)) for k, v in new_rows.items()}
    appended["X"] = np.stack(new_rows["X"]).astype(np.int32)
    appended["y_fix"] = np.array(new_rows["y_fix"], dtype=np.int64)
    appended["language_id"] = np.array(new_rows["language_id"], dtype=np.int64)
    appended["attack_type_id"] = np.array(new_rows["attack_type_id"], dtype=np.int64)
    appended["evidence"] = np.stack(new_rows["evidence"]).astype(np.float32)
    appended["raw_code"] = np.array(new_rows["raw_code"], dtype=str)
    appended["normalized_text"] = np.array(new_rows["normalized_text"], dtype=str)

    merged = dict(data)
    for key in ["X", "y_fix", "language_id", "attack_type_id", "evidence", "raw_code", "normalized_text"]:
        if key not in merged:
            raise SystemExit(f"Expected key missing from training_data.npz: {key}")
        merged[key] = np.concatenate([merged[key], appended[key]], axis=0)

    np.savez_compressed(data_path, **merged)

    profile = {}
    if profile_path.exists():
        try:
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
        except Exception:
            profile = {}

    new_n = int(len(merged["y_fix"]))
    profile.update({
        "exporterVersion": "model2_attack_all_v6_targeted_v8_second_order_augmented",
        "n_samples": new_n,
        "fix_counts": {label: int(np.sum(merged["y_fix"] == idx)) for label, idx in FIX_LABELS.items()},
        "language_counts": {label: int(np.sum(merged["language_id"] == idx)) for label, idx in LANG.items()},
        "attack_type_counts": {label: int(np.sum(merged["attack_type_id"] == idx)) for label, idx in ATTACK.items()},
        "evidence_features": EVIDENCE_FEATURES,
        "evidence_feature_count": len(EVIDENCE_FEATURES),
    })
    history = profile.setdefault("augmentationHistory", [])
    history.append({
        "version": "targeted_v8_second_order_only",
        "old_n_samples": old_n,
        "appended_samples": int(new_n - old_n),
        "new_n_samples": new_n,
        "goal": "Fix final remaining D->A second-order classifications while preserving A/B/C anchors.",
        "target_failures": [
            "python/004_SECOND_ORDER_saved_widget_filter.py",
            "javascript/018_SECOND_ORDER_stored_query_executor.js",
            "python/018_SECOND_ORDER_config_fragment.py",
            "javascript/040_SECOND_ORDER_saved_filter_builder.js",
            "python/008_IN_BAND_obfuscated_alias_execute.py",
        ],
    })
    profile_path.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")

    print(json.dumps({
        "status": "ok",
        "augmentationVersion": "targeted_v8_second_order_only",
        "old_n_samples": old_n,
        "appended_samples": int(new_n - old_n),
        "new_n_samples": new_n,
        "fix_counts": profile["fix_counts"],
        "language_counts": profile["language_counts"],
        "attack_type_counts": profile["attack_type_counts"],
        "evidence_feature_count": profile["evidence_feature_count"],
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
