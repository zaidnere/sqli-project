# MODEL2_TARGETED_FAILURE_AUGMENT_V7_MARKER
"""Append targeted Model 2 hard cases to an existing Colab export.

Purpose:
- Do not touch Model 1.
- Do not change any suites.
- Do not add rules that override Model 2.
- Strengthen Model 2 training data for the few remaining full-pipeline failures:
  * Second-order stored/config/cache SQL fragments should classify as D.
  * Obfuscated direct value execution should classify as A.
  * Keep B/C anchor cases so the extra export remains balanced.

This script overwrites only the existing files inside the export folder:
  training_data.npz
  vocabulary.json
  dataset_profile.json
It does not delete the export folder.
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
from app.vectorization.vocabulary import build_fixed_vocabulary

FIX_LABELS = {"A": 0, "B": 1, "C": 2, "D": 3}
LANG = {"python": 0, "javascript": 1, "java": 2, "php": 3}
ATTACK = {"NONE": 0, "IN_BAND": 1, "BLIND": 2, "SECOND_ORDER": 3}

TABLES = ["users", "customers", "widgets", "reports", "orders", "audit_logs"]
VALUE_VARS = ["uid", "user_id", "email", "token", "customer_id", "invoice_id", "resource_id"]
SORT_VARS = ["sort", "sortColumn", "orderBy", "column", "field"]
TABLE_VARS = ["table", "tableName", "entity", "resource", "targetTable"]
FILTER_VARS = ["filters", "criteria", "params", "whereMap", "searchFields"]
STORED_VARS = ["saved_filter", "savedSql", "config_fragment", "storedWhere", "cachedQuery", "widget_filter"]


def _pick(items: List[str], i: int) -> str:
    return items[i % len(items)]


def _a_case(language: str, i: int) -> Tuple[str, str]:
    """Hard A cases: direct value SQLi, including obfuscated execute aliases."""
    table = _pick(TABLES, i)
    var = _pick(VALUE_VARS, i)
    if language == "python":
        patterns = [
            ("IN_BAND", f'''def load_user(cursor, {var}):\n    sql = "SELECT * FROM {table} WHERE id = " + {var}\n    runner = cursor.execute\n    return runner(sql).fetchall()\n'''),
            ("IN_BAND", f'''def find_by_email(conn, email):\n    exec_fn = conn.execute\n    sql = f"SELECT * FROM {table} WHERE email = '{{email}}'"\n    return exec_fn(sql).fetchall()\n'''),
            ("BLIND", f'''def token_exists(cur, token):\n    q = "SELECT COUNT(*) FROM reset_tokens WHERE token = '" + token + "'"\n    run = cur.execute\n    row = run(q).fetchone()\n    return row[0] > 0\n'''),
            ("IN_BAND", f'''def search_customer(cur, q):\n    sql = "SELECT * FROM customers WHERE name LIKE '%" + q + "%'"\n    execute_sql = cur.execute\n    return execute_sql(sql).fetchall()\n'''),
        ]
    elif language == "javascript":
        patterns = [
            ("IN_BAND", f'''async function loadUser(db, {var}) {{\n  const sql = "SELECT * FROM {table} WHERE id = " + {var};\n  const run = db.query.bind(db);\n  return await run(sql);\n}}\n'''),
            ("IN_BAND", f'''async function findEmail(client, email) {{\n  const sql = `SELECT * FROM {table} WHERE email = '${{email}}'`;\n  const q = client.query.bind(client);\n  return await q(sql);\n}}\n'''),
            ("BLIND", f'''async function tokenExists(db, token) {{\n  const sql = "SELECT COUNT(*) AS c FROM reset_tokens WHERE token = '" + token + "'";\n  const [rows] = await db.query(sql);\n  return rows[0].c > 0;\n}}\n'''),
        ]
    elif language == "java":
        patterns = [
            ("IN_BAND", f'''ResultSet loadUser(Connection conn, String id) throws Exception {{\n    String sql = "SELECT * FROM {table} WHERE id = " + id;\n    Statement s = conn.createStatement();\n    return s.executeQuery(sql);\n}}\n'''),
            ("IN_BAND", f'''List<User> byEmail(JdbcTemplate jdbc, String email) {{\n    String sql = "SELECT * FROM {table} WHERE email = '" + email + "'";\n    return jdbc.query(sql);\n}}\n'''),
            ("BLIND", f'''boolean exists(Connection conn, String token) throws Exception {{\n    String sql = "SELECT COUNT(*) FROM reset_tokens WHERE token = '" + token + "'";\n    ResultSet rs = conn.createStatement().executeQuery(sql);\n    return rs.next();\n}}\n'''),
        ]
    elif language == "php":
        patterns = [
            ("IN_BAND", f'''<?php\nfunction loadUser($conn, $id) {{\n    $sql = "SELECT * FROM {table} WHERE id = " . $id;\n    return $conn->query($sql);\n}}\n?>\n'''),
            ("IN_BAND", f'''<?php\nfunction byEmail($conn, $email) {{\n    $sql = "SELECT * FROM {table} WHERE email = '" . $email . "'";\n    return mysqli_query($conn, $sql);\n}}\n?>\n'''),
            ("BLIND", f'''<?php\nfunction tokenExists($conn, $token) {{\n    $sql = "SELECT COUNT(*) AS c FROM reset_tokens WHERE token = '" . $token . "'";\n    return mysqli_query($conn, $sql);\n}}\n?>\n'''),
        ]
    else:
        raise KeyError(language)
    return patterns[i % len(patterns)]


def _b_case(language: str, i: int) -> Tuple[str, str]:
    """B anchors: identifiers require allowlists, not placeholders."""
    sort = _pick(SORT_VARS, i)
    table_var = _pick(TABLE_VARS, i)
    if language == "python":
        patterns = [
            ("IN_BAND", f'''def list_users(cur, {sort}):\n    sql = "SELECT * FROM users ORDER BY " + {sort}\n    return cur.execute(sql).fetchall()\n'''),
            ("IN_BAND", f'''def read_table(cur, {table_var}):\n    sql = "SELECT * FROM " + {table_var}\n    return cur.execute(sql).fetchall()\n'''),
        ]
    elif language == "javascript":
        patterns = [
            ("IN_BAND", f'''async function listUsers(db, {sort}) {{\n  const sql = "SELECT * FROM users ORDER BY " + {sort};\n  return db.all(sql);\n}}\n'''),
            ("IN_BAND", f'''async function readTable(db, {table_var}) {{\n  const sql = "SELECT * FROM " + {table_var};\n  return db.all(sql);\n}}\n'''),
        ]
    elif language == "java":
        patterns = [
            ("IN_BAND", '''ResultSet listUsers(Connection conn, String sortColumn) throws Exception {\n    String sql = "SELECT * FROM users ORDER BY " + sortColumn;\n    return conn.createStatement().executeQuery(sql);\n}\n'''),
            ("IN_BAND", '''ResultSet readTable(Connection conn, String tableName) throws Exception {\n    String sql = "SELECT * FROM " + tableName;\n    return conn.createStatement().executeQuery(sql);\n}\n'''),
        ]
    elif language == "php":
        patterns = [
            ("IN_BAND", '''<?php\nfunction listUsers($conn, $sort) {\n    $sql = "SELECT * FROM users ORDER BY " . $sort;\n    return $conn->query($sql);\n}\n?>\n'''),
            ("IN_BAND", '''<?php\nfunction readTable($conn, $table) {\n    $sql = "SELECT * FROM " . $table;\n    return mysqli_query($conn, $sql);\n}\n?>\n'''),
        ]
    else:
        raise KeyError(language)
    return patterns[i % len(patterns)]


def _c_case(language: str, i: int) -> Tuple[str, str]:
    """C anchors: truly complex builders / ORM migrations."""
    filters = _pick(FILTER_VARS, i)
    if language == "python":
        patterns = [
            ("IN_BAND", f'''def support_ticket_search(session, {filters}):\n    query_parts = []\n    for field, value in {filters}.items():\n        query_parts.append(field + " LIKE '%" + value + "%'" )\n    sql = "SELECT * FROM tickets WHERE " + " AND ".join(query_parts)\n    return session.execute(sql).fetchall()\n'''),
            ("IN_BAND", f'''def build_report(cur, {filters}):\n    sql = compose_report_query({filters})\n    return cur.execute(sql).fetchall()\n'''),
        ]
    elif language == "javascript":
        patterns = [
            ("IN_BAND", '''async function search(db, filters) {\n  let where = [];\n  for (const key of Object.keys(filters)) {\n    where.push(key + " LIKE '%" + filters[key] + "%'");\n  }\n  const sql = "SELECT * FROM users WHERE " + where.join(" AND ");\n  return db.all(sql);\n}\n'''),
            ("IN_BAND", '''async function report(db, criteria) {\n  const sql = buildDynamicReportSql(criteria);\n  return db.raw(sql);\n}\n'''),
        ]
    elif language == "java":
        patterns = [
            ("IN_BAND", '''List<User> search(EntityManager em, Map<String,String> filters) {\n    String where = "";\n    for (String key : filters.keySet()) {\n        where += " AND " + key + " LIKE '%" + filters.get(key) + "%'";\n    }\n    String sql = "SELECT * FROM users WHERE 1=1" + where;\n    return em.createNativeQuery(sql).getResultList();\n}\n'''),
            ("IN_BAND", '''ResultSet report(Connection conn, Map<String,String> criteria) throws Exception {\n    String sql = buildReportQuery(criteria);\n    return conn.createStatement().executeQuery(sql);\n}\n'''),
        ]
    elif language == "php":
        patterns = [
            ("IN_BAND", '''<?php\nfunction search($db, $filters) {\n    $parts = [];\n    foreach ($filters as $field => $value) {\n        $parts[] = $field . " LIKE '%" . $value . "%'";\n    }\n    $sql = "SELECT * FROM users WHERE " . implode(" AND ", $parts);\n    return $db->query($sql);\n}\n?>\n'''),
            ("IN_BAND", '''<?php\nfunction report($db, $criteria) {\n    $sql = buildDynamicReportSql($criteria);\n    return $db->query($sql);\n}\n?>\n'''),
        ]
    else:
        raise KeyError(language)
    return patterns[i % len(patterns)]


def _d_case(language: str, i: int) -> Tuple[str, str]:
    """Hard D cases: stored/config/cache fragments that must not be executed."""
    stored = _pick(STORED_VARS, i)
    if language == "python":
        patterns = [
            ("SECOND_ORDER", f'''def saved_widget_filter(cur, widget_id):\n    row = cur.execute("SELECT filter_sql FROM widget_filters WHERE id = ?", (widget_id,)).fetchone()\n    {stored} = row["filter_sql"]\n    sql = "SELECT * FROM widgets WHERE " + {stored}\n    return cur.execute(sql).fetchall()\n'''),
            ("SECOND_ORDER", f'''def config_fragment(cur, config):\n    config_fragment = config.get("where_clause")\n    sql = "SELECT * FROM customers WHERE " + config_fragment\n    return cur.execute(sql).fetchall()\n'''),
            ("SECOND_ORDER", f'''def run_saved_report(cur, report_id):\n    row = cur.execute("SELECT sql_text FROM reports WHERE id = ?", (report_id,)).fetchone()\n    saved_sql = row["sql_text"]\n    return cur.execute(saved_sql).fetchall()\n'''),
        ]
    elif language == "javascript":
        patterns = [
            ("SECOND_ORDER", '''async function storedQueryExecutor(db, id) {\n  const row = await db.get("SELECT sql_text FROM reports WHERE id = ?", [id]);\n  const savedSql = row.sql_text;\n  return db.all(savedSql);\n}\n'''),
            ("SECOND_ORDER", '''async function savedFilterBuilder(db, key) {\n  const savedFilter = await cache.get(key);\n  const sql = "SELECT * FROM customers WHERE " + savedFilter;\n  return db.query(sql);\n}\n'''),
            ("SECOND_ORDER", '''async function configOrder(db, config) {\n  const orderClause = config.get("order_clause");\n  const sql = "SELECT * FROM users " + orderClause;\n  return db.all(sql);\n}\n'''),
        ]
    elif language == "java":
        patterns = [
            ("SECOND_ORDER", '''ResultSet runSaved(Connection conn, String id) throws Exception {\n    PreparedStatement ps = conn.prepareStatement("SELECT sql_text FROM reports WHERE id = ?");\n    ps.setString(1, id);\n    ResultSet row = ps.executeQuery();\n    String savedSql = row.getString("sql_text");\n    return conn.createStatement().executeQuery(savedSql);\n}\n'''),
            ("SECOND_ORDER", '''ResultSet fromConfig(Connection conn, Config config) throws Exception {\n    String where = config.get("where_clause");\n    String sql = "SELECT * FROM users WHERE " + where;\n    return conn.createStatement().executeQuery(sql);\n}\n'''),
        ]
    elif language == "php":
        patterns = [
            ("SECOND_ORDER", '''<?php\nfunction runSaved($pdo, $id) {\n    $stmt = $pdo->prepare("SELECT sql_text FROM reports WHERE id = ?");\n    $stmt->execute([$id]);\n    $savedSql = $stmt->fetchColumn();\n    return $pdo->query($savedSql)->fetchAll();\n}\n?>\n'''),
            ("SECOND_ORDER", '''<?php\nfunction fromConfig($conn, $config) {\n    $where = $config->get("where_clause");\n    $sql = "SELECT * FROM users WHERE " . $where;\n    return $conn->query($sql);\n}\n?>\n'''),
        ]
    else:
        raise KeyError(language)
    return patterns[i % len(patterns)]


GENERATORS: Dict[str, Callable[[str, int], Tuple[str, str]]] = {
    "A": _a_case,
    "B": _b_case,
    "C": _c_case,
    "D": _d_case,
}


def _make_record(code: str, language: str, fix: str, attack_type: str, vocab: dict):
    cleaned = clean_code(code)
    tokens = tokenize_code(cleaned)
    normalized = normalize_tokens(tokens)
    vec = vectorize_tokens(normalized, vocab)
    return {
        "X": np.array(vec["tokenIds"], dtype=np.int32),
        "y_fix": np.int64(FIX_LABELS[fix]),
        "language_id": np.int64(LANG[language]),
        "attack_type_id": np.int64(ATTACK[attack_type]),
        "evidence": build_evidence_vector(normalized, code, language).astype(np.float32),
        "raw_code": code,
        "normalized_text": " ".join(normalized),
    }


def _load_npz(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"training_data.npz not found under {path.parent}")
    return dict(np.load(path, allow_pickle=True))


def _write_profile(export_dir: Path, profile: dict, arrays: dict, added: int, samples_per_class_language_extra: int):
    y = arrays["y_fix"].astype(int)
    lang = arrays["language_id"].astype(int)
    atk = arrays["attack_type_id"].astype(int)
    inv_fix = {v: k for k, v in FIX_LABELS.items()}
    inv_lang = {v: k for k, v in LANG.items()}
    inv_atk = {v: k for k, v in ATTACK.items()}
    profile.update(
        {
            "augmentationVersion": "model2_targeted_failure_v7",
            "n_samples": int(len(y)),
            "added_samples": int(added),
            "samples_per_class_language_extra": int(samples_per_class_language_extra),
            "fix_counts": {inv_fix[i]: int(np.sum(y == i)) for i in sorted(inv_fix)},
            "language_counts": {inv_lang[i]: int(np.sum(lang == i)) for i in sorted(inv_lang)},
            "attack_type_counts": {inv_atk[i]: int(np.sum(atk == i)) for i in sorted(inv_atk)},
            "evidence_features": EVIDENCE_FEATURES,
            "evidence_feature_count": len(EVIDENCE_FEATURES),
            "targeted_failure_families": [
                "Second-order saved widget/config/cache/query fragments should classify as D",
                "Obfuscated execute aliases with direct value SQLi should classify as A",
                "B/C anchor cases preserve identifier whitelist and complex-builder boundaries",
            ],
            "notes": list(profile.get("notes", []))
            + [
                "Targeted v7 augmentation appends balanced hard cases without deleting the export folder.",
                "Model 1 remains frozen/read-only; this augmentation does not modify Model 1.",
            ],
        }
    )
    (export_dir / "dataset_profile.json").write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--export-dir", default="colab_export_fix_v2")
    ap.add_argument("--samples-per-class-language-extra", type=int, default=80)
    ap.add_argument("--seed", type=int, default=20260517)
    args = ap.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)

    export_dir = Path(args.export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)
    training_path = export_dir / "training_data.npz"
    arrays = _load_npz(training_path)

    vocab_path = export_dir / "vocabulary.json"
    if vocab_path.exists():
        vocab = json.loads(vocab_path.read_text(encoding="utf-8"))
    else:
        vocab = build_fixed_vocabulary()

    profile_path = export_dir / "dataset_profile.json"
    if profile_path.exists():
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    else:
        profile = {}

    records = []
    for language in LANG:
        for fix in FIX_LABELS:
            gen = GENERATORS[fix]
            for i in range(args.samples_per_class_language_extra):
                attack_type, code = gen(language, i)
                # Add harmless noise to prevent exact-template memorization.
                if i % 9 == 0:
                    code = code + ("\n# targeted v7 hardcase\n" if language == "python" else "\n// targeted v7 hardcase\n")
                records.append(_make_record(code, language, fix, attack_type, vocab))

    if not records:
        raise RuntimeError("No targeted records were generated")

    append = {
        "X": np.stack([r["X"] for r in records]).astype(np.int32),
        "y_fix": np.array([r["y_fix"] for r in records], dtype=np.int64),
        "language_id": np.array([r["language_id"] for r in records], dtype=np.int64),
        "attack_type_id": np.array([r["attack_type_id"] for r in records], dtype=np.int64),
        "evidence": np.stack([r["evidence"] for r in records]).astype(np.float32),
        "raw_code": np.array([r["raw_code"] for r in records], dtype=str),
        "normalized_text": np.array([r["normalized_text"] for r in records], dtype=str),
    }

    merged = {}
    for key, arr in arrays.items():
        if key in append:
            merged[key] = np.concatenate([arr, append[key]], axis=0)
        else:
            merged[key] = arr
    for key, arr in append.items():
        if key not in merged:
            merged[key] = arr

    np.savez_compressed(training_path, **merged)
    vocab_path.write_text(json.dumps(vocab, indent=2, ensure_ascii=False), encoding="utf-8")
    _write_profile(export_dir, profile, merged, added=len(records), samples_per_class_language_extra=args.samples_per_class_language_extra)

    print(json.dumps(json.loads((export_dir / "dataset_profile.json").read_text(encoding="utf-8")), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
