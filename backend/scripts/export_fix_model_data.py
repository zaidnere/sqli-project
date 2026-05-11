# EXPORT_FIX_MODEL_DATA_MODEL2_CONTEXT_FEATURES_MARKER
"""
Export hard-case oriented training data for Model 2 Fix Recommendation.

This exporter is Model-2-only:
- It does not modify Model 1.
- It does not modify Model 1 weights/vocabulary.
- It uses the current preprocessing/vectorization path and Model 2 evidence builder.
- It overwrites the target export folder so the workflow stays in one folder.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import List, Tuple

import numpy as np

from app.model.fix_model_inference import EVIDENCE_FEATURES, build_evidence_vector
from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.normalizer import normalize_tokens
from app.preprocessing.tokenizer import tokenize_code
from app.vectorization.vectorizer import vectorize_tokens
from app.vectorization.vocabulary import build_fixed_vocabulary

FIX_LABELS = {"A": 0, "B": 1, "C": 2, "D": 3}
LANG = {"python": 0, "javascript": 1, "java": 2, "php": 3}
ATTACK = {"NONE": 0, "IN_BAND": 1, "BLIND": 2, "SECOND_ORDER": 3}

TABLES = ["users", "accounts", "customers", "orders", "reports"]
ID_COLUMNS = ["id", "user_id", "account_id", "customer_id", "order_id"]
VALUE_VARS = ["uid", "user_id", "id", "email", "name", "accountId", "customerId"]
SORT_VARS = ["sort_column", "sortColumn", "orderBy", "sort", "column", "field"]
TABLE_VARS = ["table", "tableName", "entity", "resource", "targetTable"]
FILTER_VARS = ["filters", "params", "criteria", "whereMap", "searchFields"]
SAVED_VARS = ["saved_sql", "stored_filter", "report_sql", "cached_where", "savedFilter", "sql_text"]


def _pick(items: List[str], i: int) -> str:
    return items[i % len(items)]


def _template_A(language: str, i: int) -> Tuple[str, str]:
    """Parameterized Query cases: user values belong in placeholders."""
    table = _pick(TABLES, i)
    col = _pick(ID_COLUMNS, i)
    var = _pick(VALUE_VARS, i)
    if language == "python":
        patterns = [
            ("IN_BAND", f'''def get_user(cursor, {var}):\n    query = "SELECT * FROM {table} WHERE {col} = " + {var}\n    return cursor.execute(query).fetchall()\n'''),
            ("IN_BAND", f'''def find_user(cursor, name):\n    query = f"SELECT * FROM {table} WHERE name = '{{name}}'"\n    return cursor.execute(query).fetchall()\n'''),
            ("IN_BAND", f'''def find_user_alt(cursor, name):\n    sql = f'SELECT * FROM {table} WHERE name = {{name}}'\n    return cursor.execute(sql).fetchone()\n'''),
            ("BLIND", f'''def exists_user(cursor, {var}):\n    query = "SELECT COUNT(*) AS c FROM {table} WHERE {col} = " + {var}\n    row = cursor.execute(query).fetchone()\n    return row["c"] > 0\n'''),
            ("IN_BAND", f'''def get_by_email(cursor, email):\n    sql = "SELECT * FROM {table} WHERE email = '" + email + "'"\n    return cursor.execute(sql).fetchone()\n'''),
        ]
    elif language == "javascript":
        patterns = [
            ("IN_BAND", f'''async function getUser(db, id) {{\n  const query = "SELECT * FROM {table} WHERE {col} = " + id;\n  return db.all(query);\n}}\n'''),
            ("IN_BAND", f'''async function findUser(db, email) {{\n  const query = `SELECT * FROM {table} WHERE email = '${{email}}'`;\n  return db.all(query);\n}}\n'''),
            ("IN_BAND", f'''async function findByName(db, name) {{\n  const sql = `SELECT * FROM {table} WHERE name = ${{name}}`;\n  return db.get(sql);\n}}\n'''),
            ("BLIND", f'''async function userExists(db, id) {{\n  const query = "SELECT COUNT(*) AS c FROM {table} WHERE {col} = " + id;\n  const row = await db.get(query);\n  return row.c > 0;\n}}\n'''),
            ("IN_BAND", f'''async function byName(db, name) {{\n  const sql = "SELECT * FROM {table} WHERE name = '" + name + "'";\n  return db.get(sql);\n}}\n'''),
        ]
    elif language == "java":
        patterns = [
            ("IN_BAND", f'''ResultSet getUser(Connection conn, String id) throws Exception {{\n    String sql = "SELECT * FROM {table} WHERE {col} = " + id;\n    return conn.createStatement().executeQuery(sql);\n}}\n'''),
            ("IN_BAND", f'''List<User> findUser(JdbcTemplate jdbc, String email) {{\n    String sql = "SELECT * FROM {table} WHERE email = '" + email + "'";\n    return jdbc.query(sql);\n}}\n'''),
            ("IN_BAND", f'''ResultSet findName(Connection conn, String name) throws Exception {{\n    String sql = "SELECT * FROM {table} WHERE name = '" + name + "'";\n    return conn.createStatement().executeQuery(sql);\n}}\n'''),
            ("BLIND", f'''boolean exists(Connection conn, String id) throws Exception {{\n    String sql = "SELECT COUNT(*) FROM {table} WHERE {col} = " + id;\n    ResultSet rs = conn.createStatement().executeQuery(sql);\n    return rs.next();\n}}\n'''),
        ]
    elif language == "php":
        patterns = [
            ("IN_BAND", f'''<?php\nfunction getUser($pdo, $id) {{\n    $sql = "SELECT * FROM {table} WHERE {col} = " . $id;\n    return $pdo->query($sql)->fetch();\n}}\n?>\n'''),
            ("IN_BAND", f'''<?php\nfunction findUser($pdo, $email) {{\n    $sql = "SELECT * FROM {table} WHERE email = '" . $email . "'";\n    return $pdo->query($sql)->fetch();\n}}\n?>\n'''),
            ("BLIND", f'''<?php\nfunction existsUser($pdo, $id) {{\n    $sql = "SELECT COUNT(*) AS c FROM {table} WHERE {col} = " . $id;\n    return $pdo->query($sql)->fetchColumn() > 0;\n}}\n?>\n'''),
        ]
    else:
        raise KeyError(language)
    return patterns[i % len(patterns)]


def _template_B(language: str, i: int) -> Tuple[str, str]:
    """Whitelist Validation cases: SQL identifiers cannot use placeholders."""
    sort = _pick(SORT_VARS, i)
    table_var = _pick(TABLE_VARS, i)
    if language == "python":
        patterns = [
            ("IN_BAND", f'''def list_users(cursor, {sort}):\n    query = "SELECT * FROM users ORDER BY " + {sort}\n    return cursor.execute(query).fetchall()\n'''),
            ("IN_BAND", f'''def read_table(cursor, {table_var}):\n    query = "SELECT * FROM " + {table_var}\n    return cursor.execute(query).fetchall()\n'''),
            ("IN_BAND", f'''def dynamic_join(cursor, {table_var}):\n    sql = f"SELECT * FROM {{{table_var}}} WHERE active = 1"\n    return cursor.execute(sql).fetchall()\n'''),
        ]
    elif language == "javascript":
        patterns = [
            ("IN_BAND", f'''async function listUsers(db, {sort}) {{\n  const sql = "SELECT * FROM users ORDER BY " + {sort};\n  return db.all(sql);\n}}\n'''),
            ("IN_BAND", f'''async function readTable(db, {table_var}) {{\n  const sql = "SELECT * FROM " + {table_var};\n  return db.all(sql);\n}}\n'''),
            ("IN_BAND", f'''async function readDynamic(db, {table_var}) {{\n  const sql = `SELECT * FROM ${{{table_var}}} WHERE active = 1`;\n  return db.all(sql);\n}}\n'''),
        ]
    elif language == "java":
        patterns = [
            ("IN_BAND", f'''ResultSet listUsers(Connection conn, String sortColumn) throws Exception {{\n    String sql = "SELECT * FROM users ORDER BY " + sortColumn;\n    return conn.createStatement().executeQuery(sql);\n}}\n'''),
            ("IN_BAND", f'''ResultSet readTable(Connection conn, String tableName) throws Exception {{\n    String sql = "SELECT * FROM " + tableName;\n    return conn.createStatement().executeQuery(sql);\n}}\n'''),
        ]
    elif language == "php":
        patterns = [
            ("IN_BAND", f'''<?php\nfunction listUsers($pdo, $sort) {{\n    $sql = "SELECT * FROM users ORDER BY " . $sort;\n    return $pdo->query($sql)->fetchAll();\n}}\n?>\n'''),
            ("IN_BAND", f'''<?php\nfunction readTable($pdo, $table) {{\n    $sql = "SELECT * FROM " . $table;\n    return $pdo->query($sql)->fetchAll();\n}}\n?>\n'''),
        ]
    else:
        raise KeyError(language)
    return patterns[i % len(patterns)]


def _template_C(language: str, i: int) -> Tuple[str, str]:
    """ORM / Query Builder cases: complex dynamic SQL construction."""
    filters = _pick(FILTER_VARS, i)
    if language == "python":
        patterns = [
            ("IN_BAND", f'''def search(cursor, {filters}):\n    sql = "SELECT * FROM users WHERE 1=1"\n    for field, value in {filters}.items():\n        sql += " AND " + field + " = '" + value + "'"\n    return cursor.execute(sql).fetchall()\n'''),
            ("IN_BAND", f'''def report(cursor, {filters}):\n    where_parts = []\n    for key, val in {filters}.items():\n        where_parts.append(key + " LIKE '%" + val + "%'")\n    query = "SELECT * FROM users WHERE " + " AND ".join(where_parts)\n    return cursor.execute(query).fetchall()\n'''),
        ]
    elif language == "javascript":
        patterns = [
            ("IN_BAND", f'''async function search(db, filters) {{\n  let sql = "SELECT * FROM users WHERE 1=1";\n  for (const k of Object.keys(filters)) {{\n    sql += " AND " + k + " = '" + filters[k] + "'";\n  }}\n  return db.all(sql);\n}}\n'''),
            ("IN_BAND", f'''async function report(db, criteria) {{\n  const parts = [];\n  for (const key in criteria) {{ parts.push(key + " LIKE '%" + criteria[key] + "%'"); }}\n  const sql = "SELECT * FROM users WHERE " + parts.join(" AND ");\n  return db.all(sql);\n}}\n'''),
        ]
    elif language == "java":
        patterns = [
            ("IN_BAND", f'''List<User> search(JdbcTemplate jdbc, Map<String,String> filters) {{\n    String sql = "SELECT * FROM users WHERE 1=1";\n    for (String k : filters.keySet()) {{\n        sql += " AND " + k + " = '" + filters.get(k) + "'";\n    }}\n    return jdbc.query(sql);\n}}\n'''),
            ("IN_BAND", f'''ResultSet report(Connection conn, Map<String,String> criteria) throws Exception {{\n    String where = "";\n    for (String key : criteria.keySet()) {{ where += " AND " + key + " LIKE '%" + criteria.get(key) + "%'"; }}\n    String sql = "SELECT * FROM users WHERE 1=1" + where;\n    return conn.createStatement().executeQuery(sql);\n}}\n'''),
        ]
    elif language == "php":
        patterns = [
            ("IN_BAND", f'''<?php\nfunction search($pdo, $filters) {{\n    $sql = "SELECT * FROM users WHERE 1=1";\n    foreach ($filters as $k => $v) {{\n        $sql .= " AND " . $k . " = '" . $v . "'";\n    }}\n    return $pdo->query($sql)->fetchAll();\n}}\n?>\n'''),
            ("IN_BAND", f'''<?php\nfunction report($pdo, $criteria) {{\n    $parts = [];\n    foreach ($criteria as $k => $v) {{ $parts[] = $k . " LIKE '%" . $v . "%'"; }}\n    $sql = "SELECT * FROM users WHERE " . implode(" AND ", $parts);\n    return $pdo->query($sql)->fetchAll();\n}}\n?>\n'''),
        ]
    else:
        raise KeyError(language)
    return patterns[i % len(patterns)]


def _template_D(language: str, i: int) -> Tuple[str, str]:
    """Second-order cases: SQL fragments loaded from DB/config/cache/storage."""
    saved = _pick(SAVED_VARS, i)
    if language == "python":
        patterns = [
            ("SECOND_ORDER", f'''def run_saved(cursor, report_id):\n    row = cursor.execute("SELECT sql_text FROM reports WHERE id = ?", (report_id,)).fetchone()\n    {saved} = row["sql_text"]\n    return cursor.execute({saved}).fetchall()\n'''),
            ("SECOND_ORDER", f'''def apply_saved_filter(cursor, user_id):\n    row = cursor.execute("SELECT saved_filter FROM users WHERE id = ?", (user_id,)).fetchone()\n    stored_filter = row["saved_filter"]\n    query = "SELECT * FROM users WHERE " + stored_filter\n    return cursor.execute(query).fetchall()\n'''),
            ("SECOND_ORDER", f'''def from_config(cursor, config):\n    cached_where = config.get("where_clause")\n    sql = "SELECT * FROM users WHERE " + cached_where\n    return cursor.execute(sql).fetchall()\n'''),
        ]
    elif language == "javascript":
        patterns = [
            ("SECOND_ORDER", f'''async function runSaved(db, id) {{\n  const row = await db.get("SELECT sql_text FROM reports WHERE id = ?", [id]);\n  const savedSql = row.sql_text;\n  return db.all(savedSql);\n}}\n'''),
            ("SECOND_ORDER", f'''async function applyCachedFilter(db, cacheKey) {{\n  const savedFilter = await cache.get(cacheKey);\n  const sql = "SELECT * FROM users WHERE " + savedFilter;\n  return db.all(sql);\n}}\n'''),
        ]
    elif language == "java":
        patterns = [
            ("SECOND_ORDER", f'''ResultSet runSaved(Connection conn, String id) throws Exception {{\n    PreparedStatement ps = conn.prepareStatement("SELECT sql_text FROM reports WHERE id = ?");\n    ps.setString(1, id);\n    ResultSet rs = ps.executeQuery();\n    String savedFilter = rs.getString("sql_text");\n    String sql = "SELECT * FROM users WHERE " + savedFilter;\n    return conn.createStatement().executeQuery(sql);\n}}\n'''),
            ("SECOND_ORDER", f'''ResultSet runConfigured(Connection conn, Config config) throws Exception {{\n    String cachedWhere = config.get("where_clause");\n    String sql = "SELECT * FROM users WHERE " + cachedWhere;\n    return conn.createStatement().executeQuery(sql);\n}}\n'''),
        ]
    elif language == "php":
        patterns = [
            ("SECOND_ORDER", f'''<?php\nfunction runSaved($pdo, $id) {{\n    $stmt = $pdo->prepare("SELECT sql_text FROM reports WHERE id = ?");\n    $stmt->execute([$id]);\n    $sql = $stmt->fetchColumn();\n    return $pdo->query($sql)->fetchAll();\n}}\n?>\n'''),
            ("SECOND_ORDER", f'''<?php\nfunction applyStoredFilter($pdo, $id) {{\n    $stmt = $pdo->prepare("SELECT saved_filter FROM users WHERE id = ?");\n    $stmt->execute([$id]);\n    $storedFilter = $stmt->fetchColumn();\n    $sql = "SELECT * FROM users WHERE " . $storedFilter;\n    return $pdo->query($sql)->fetchAll();\n}}\n?>\n'''),
        ]
    else:
        raise KeyError(language)
    return patterns[i % len(patterns)]


TEMPLATE_BY_FIX = {"A": _template_A, "B": _template_B, "C": _template_C, "D": _template_D}


def make_sample(language: str, fix: str, i: int) -> Tuple[str, str]:
    attack_type, code = TEMPLATE_BY_FIX[fix](language, i)
    if i % 5 == 0:
        code = code.replace("users", _pick(TABLES, i + 1))
    if i % 7 == 0:
        code = "\n" + code
    if i % 11 == 0:
        comment = "# generated context-feature hardcase variation\n" if language == "python" else "// generated context-feature hardcase variation\n"
        code = code + "\n" + comment
    return attack_type, code


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="colab_export_fix_v2")
    ap.add_argument("--samples-per-class-language", type=int, default=240)
    ap.add_argument("--seed", type=int, default=20260512)
    args = ap.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)

    vocab = build_fixed_vocabulary()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    X: list[list[int]] = []
    y_fix: list[int] = []
    language_id: list[int] = []
    attack_type_id: list[int] = []
    evidence: list[np.ndarray] = []
    raw_code: list[str] = []
    normalized_text: list[str] = []

    for language in LANG:
        for fix in FIX_LABELS:
            for i in range(args.samples_per_class_language):
                attack_type, code = make_sample(language, fix, i)
                cleaned = clean_code(code)
                tokens = tokenize_code(cleaned)
                normalized = normalize_tokens(tokens)
                vec = vectorize_tokens(normalized, vocab)
                X.append(vec["tokenIds"])
                y_fix.append(FIX_LABELS[fix])
                language_id.append(LANG[language])
                attack_type_id.append(ATTACK[attack_type])
                evidence.append(build_evidence_vector(normalized, code, language))
                raw_code.append(code)
                normalized_text.append(" ".join(normalized))

    np.savez_compressed(
        out / "training_data.npz",
        X=np.array(X, dtype=np.int32),
        y_fix=np.array(y_fix, dtype=np.int64),
        language_id=np.array(language_id, dtype=np.int64),
        attack_type_id=np.array(attack_type_id, dtype=np.int64),
        evidence=np.array(evidence, dtype=np.float32),
        raw_code=np.array(raw_code, dtype=str),
        normalized_text=np.array(normalized_text, dtype=str),
    )

    (out / "vocabulary.json").write_text(json.dumps(vocab, indent=2, ensure_ascii=False), encoding="utf-8")

    profile = {
        "exporterVersion": "model2_context_features_v3",
        "n_samples": len(X),
        "fix_counts": {k: int(sum(v == idx for v in y_fix)) for k, idx in FIX_LABELS.items()},
        "language_counts": {k: int(sum(v == idx for v in language_id)) for k, idx in LANG.items()},
        "attack_type_counts": {k: int(sum(v == idx for v in attack_type_id)) for k, idx in ATTACK.items()},
        "evidence_features": EVIDENCE_FEATURES,
        "evidence_feature_count": len(EVIDENCE_FEATURES),
        "output_files": ["training_data.npz", "vocabulary.json", "dataset_profile.json"],
        "notes": [
            "Balanced by language and fix class.",
            "Adds semantic context features for value parameters, identifiers, complex builders, and stored SQL fragments.",
            "Model 1 remains frozen/read-only; this export does not modify Model 1.",
        ],
    }
    (out / "dataset_profile.json").write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(profile, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
