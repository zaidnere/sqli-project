# MODEL2_TARGETED_REMAINING_FAILURES_V9_AUGMENT_MARKER
"""Append targeted Model 2 hard cases for the final remaining full-pipeline failures.

Purpose:
- Do not modify Model 1.
- Do not modify suites.
- Do not add rule overrides.
- Strengthen Model 2 classification for the last observed failures:
  * D -> A: second-order stored/config/query fragments executed later.
  * B -> A: dynamic ORDER BY identifier where a safe allowlist exists but the raw variable is still used.
- Preserve A/C boundaries with anchor samples.

This script updates only files inside the existing export directory:
  training_data.npz
  vocabulary.json
  dataset_profile.json
It does not delete the folder.
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


def _pick(items: List[str], i: int) -> str:
    return items[i % len(items)]


def _a_case(language: str, i: int) -> Tuple[str, str]:
    """A anchors: direct raw value injection should remain parameterized-query."""
    if language == "python":
        patterns = [
            ("IN_BAND", '''def get_user(conn, req):
    value = req.args.get("email")
    run = conn.execute
    sql = "SELECT id,email FROM users WHERE email='" + value + "'"
    return run(sql).fetchall()
'''),
            ("IN_BAND", '''def alias_execute(cursor, token):
    exec_fn = cursor.execute
    sql = "SELECT id FROM reset_tokens WHERE token = '" + token + "'"
    return exec_fn(sql).fetchone()
'''),
            ("BLIND", '''def exists_user(conn, uid):
    q = "SELECT COUNT(*) FROM users WHERE id = " + str(uid)
    return conn.execute(q).fetchone()[0] > 0
'''),
        ]
    elif language == "javascript":
        patterns = [
            ("IN_BAND", '''async function byEmail(db, email) {
  const run = db.query.bind(db);
  const sql = "SELECT id,email FROM users WHERE email='" + email + "'";
  return run(sql);
}
'''),
            ("BLIND", '''async function existsUser(db, id) {
  const sql = "SELECT COUNT(*) AS c FROM users WHERE id=" + id;
  const [rows] = await db.query(sql);
  return rows[0].c > 0;
}
'''),
        ]
    elif language == "java":
        patterns = [
            ("IN_BAND", '''ResultSet byEmail(Connection conn, String email) throws Exception {
    Statement s = conn.createStatement();
    String sql = "SELECT id,email FROM users WHERE email='" + email + "'";
    return s.executeQuery(sql);
}
'''),
            ("BLIND", '''boolean exists(Connection conn, String id) throws Exception {
    String sql = "SELECT COUNT(*) FROM users WHERE id=" + id;
    return conn.createStatement().executeQuery(sql).next();
}
'''),
        ]
    elif language == "php":
        patterns = [
            ("IN_BAND", '''<?php
function byEmail($conn, $email) {
    $sql = "SELECT id,email FROM users WHERE email='" . $email . "'";
    return mysqli_query($conn, $sql);
}
?>
'''),
            ("BLIND", '''<?php
function existsUser($conn, $id) {
    $sql = "SELECT COUNT(*) AS c FROM users WHERE id=" . $id;
    return mysqli_query($conn, $sql);
}
?>
'''),
        ]
    else:
        raise KeyError(language)
    return patterns[i % len(patterns)]


def _b_case(language: str, i: int) -> Tuple[str, str]:
    """B anchors: dynamic identifiers/order-by must be whitelist validation, even with decoy sanitization."""
    if language == "php":
        patterns = [
            ("IN_BAND", '''<?php
function listUsers($conn, $sortBy) {
    $allowed = ["id" => "id", "email" => "email", "created_at" => "created_at"];
    $safeCol = $allowed[$sortBy] ?? "created_at";
    $sql = "SELECT id, email FROM users ORDER BY " . $sortBy;
    return mysqli_query($conn, $sql);
}
?>
'''),
            ("IN_BAND", '''<?php
function listCustomers($thisConn, $orderBy) {
    $map = array("name" => "name", "created" => "created_at");
    $safeOrder = $map[$orderBy] ?? "created_at";
    $sql = "SELECT id, name FROM customers ORDER BY " . $orderBy;
    return $thisConn->query($sql);
}
?>
'''),
            ("IN_BAND", '''<?php
function readTable($conn, $tableName) {
    $allowedTables = ["users" => "users", "orders" => "orders"];
    $safeTable = $allowedTables[$tableName] ?? "users";
    $sql = "SELECT * FROM " . $tableName;
    return mysqli_query($conn, $sql);
}
?>
'''),
        ]
    elif language == "python":
        patterns = [
            ("IN_BAND", '''def list_users(cur, sort_by):
    allowed = {"id": "id", "email": "email", "created_at": "created_at"}
    safe_col = allowed.get(sort_by, "created_at")
    sql = "SELECT id,email FROM users ORDER BY " + sort_by
    return cur.execute(sql).fetchall()
'''),
            ("IN_BAND", '''def read_table(cur, table_name):
    allowed = {"users": "users", "orders": "orders"}
    safe_table = allowed.get(table_name, "users")
    sql = "SELECT * FROM " + table_name
    return cur.execute(sql).fetchall()
'''),
        ]
    elif language == "javascript":
        patterns = [
            ("IN_BAND", '''async function listUsers(db, sortBy) {
  const allowed = { id: "id", email: "email", created_at: "created_at" };
  const safeCol = allowed[sortBy] || "created_at";
  const sql = "SELECT id,email FROM users ORDER BY " + sortBy;
  return db.query(sql);
}
'''),
            ("IN_BAND", '''async function readTable(db, tableName) {
  const allowed = { users: "users", orders: "orders" };
  const safeTable = allowed[tableName] || "users";
  const sql = "SELECT * FROM " + tableName;
  return db.query(sql);
}
'''),
        ]
    elif language == "java":
        patterns = [
            ("IN_BAND", '''ResultSet listUsers(Connection conn, String sortBy) throws Exception {
    Map<String,String> allowed = Map.of("id", "id", "email", "email", "created_at", "created_at");
    String safeCol = allowed.getOrDefault(sortBy, "created_at");
    String sql = "SELECT id,email FROM users ORDER BY " + sortBy;
    return conn.createStatement().executeQuery(sql);
}
'''),
        ]
    else:
        raise KeyError(language)
    return patterns[i % len(patterns)]


def _c_case(language: str, i: int) -> Tuple[str, str]:
    """C anchors: genuinely complex builders should stay ORM/query-builder migration."""
    if language == "python":
        patterns = [
            ("IN_BAND", '''def search(cur, filters):
    where_parts = []
    for field, value in filters.items():
        where_parts.append(field + " = '" + value + "'")
    sql = "SELECT * FROM users WHERE " + " AND ".join(where_parts)
    return cur.execute(sql).fetchall()
'''),
        ]
    elif language == "javascript":
        patterns = [
            ("IN_BAND", '''async function search(db, filters) {
  const parts = [];
  for (const [field, value] of Object.entries(filters)) parts.push(field + "='" + value + "'");
  const sql = "SELECT * FROM users WHERE " + parts.join(" AND ");
  return db.query(sql);
}
'''),
        ]
    elif language == "java":
        patterns = [
            ("IN_BAND", '''List<User> search(JdbcTemplate jdbc, Map<String,String> filters) {
    List<String> parts = new ArrayList<>();
    for (String field : filters.keySet()) parts.add(field + "='" + filters.get(field) + "'");
    String sql = "SELECT * FROM users WHERE " + String.join(" AND ", parts);
    return jdbc.query(sql);
}
'''),
        ]
    elif language == "php":
        patterns = [
            ("IN_BAND", '''<?php
function search($conn, $filters) {
    $parts = [];
    foreach ($filters as $field => $value) { $parts[] = $field . "='" . $value . "'"; }
    $sql = "SELECT * FROM users WHERE " . implode(" AND ", $parts);
    return mysqli_query($conn, $sql);
}
?>
'''),
        ]
    else:
        raise KeyError(language)
    return patterns[i % len(patterns)]


def _d_case(language: str, i: int) -> Tuple[str, str]:
    """D hard cases: stored/config/cache SQL syntax loaded earlier and executed later."""
    if language == "python":
        patterns = [
            ("SECOND_ORDER", '''class DashboardWidgetData:
    def __init__(self, conn):
        self.conn = conn
    def load_widget(self, ctx, widget_id):
        row = self.conn.execute("SELECT id, where_fragment, default_limit FROM dashboard_widgets WHERE tenant_id = ? AND id = ?", [ctx.tenant_id, int(widget_id)]).fetchone()
        return dict(row) if row else {}
    def rows(self, ctx, widget_id):
        widget = self.load_widget(ctx, widget_id)
        where_fragment = widget.get("where_fragment") or "1=1"
        limit = int(widget.get("default_limit") or 100)
        sql = "SELECT id, label, value FROM widget_rows WHERE tenant_id = ? AND " + where_fragment + f" ORDER BY created_at DESC LIMIT {limit}"
        return [dict(row) for row in self.conn.execute(sql, [ctx.tenant_id]).fetchall()]
'''),
            ("SECOND_ORDER", '''def nightly_job(conn):
    cfg = conn.execute("SELECT value FROM app_config WHERE name='archival_predicate'").fetchone()[0]
    sql = "SELECT id FROM audit_log WHERE " + cfg
    return conn.execute(sql).fetchall()
'''),
            ("SECOND_ORDER", '''def apply_saved_filter(conn, user_id):
    row = conn.execute("SELECT saved_filter FROM users WHERE id = ?", (user_id,)).fetchone()
    saved_filter = row["saved_filter"]
    query = "SELECT * FROM invoices WHERE " + saved_filter
    return conn.execute(query).fetchall()
'''),
            ("SECOND_ORDER", '''def run_report(conn, report_id):
    row = conn.execute("SELECT query_sql FROM reports WHERE id = ?", (report_id,)).fetchone()
    report_sql = row["query_sql"]
    return conn.execute(report_sql).fetchall()
'''),
        ]
    elif language == "javascript":
        patterns = [
            ("SECOND_ORDER", '''class TenantQueryExecutor {
  constructor(db, logger) { this.db = db; this.logger = logger; }
  async loadDefinition(ctx, key) { return this.db.get("SELECT query_sql FROM tenant_queries WHERE tenant_id = ? AND query_key = ?", [ctx.tenantId, key]); }
  async execute(ctx, key) {
    const def = await this.loadDefinition(ctx, key);
    if (!def) return [];
    const sql = def.query_sql;
    return this.db.all(sql);
  }
}
'''),
            ("SECOND_ORDER", '''async function executeStoredQuery(db, id) {
  const row = await db.get("SELECT sql_text FROM reports WHERE id = ?", [id]);
  const savedSql = row.sql_text;
  return db.query(savedSql);
}
'''),
            ("SECOND_ORDER", '''async function savedFilterBuilder(db, key) {
  const savedFilter = await cache.get(key);
  const sql = "SELECT * FROM orders WHERE " + savedFilter;
  return db.all(sql);
}
'''),
            ("SECOND_ORDER", '''async function configFragment(db, config) {
  const fragment = config.get("where_clause");
  const query = "SELECT id FROM audit_log WHERE " + fragment;
  return db.query(query);
}
'''),
        ]
    elif language == "java":
        patterns = [
            ("SECOND_ORDER", '''ResultSet runStored(Connection conn, String id) throws Exception {
    PreparedStatement ps = conn.prepareStatement("SELECT query_sql FROM reports WHERE id = ?");
    ps.setString(1, id);
    ResultSet row = ps.executeQuery();
    String querySql = row.getString("query_sql");
    return conn.createStatement().executeQuery(querySql);
}
'''),
            ("SECOND_ORDER", '''ResultSet configFragment(Connection conn, Config config) throws Exception {
    String fragment = config.get("where_clause");
    String sql = "SELECT id FROM audit_log WHERE " + fragment;
    return conn.createStatement().executeQuery(sql);
}
'''),
        ]
    elif language == "php":
        patterns = [
            ("SECOND_ORDER", '''<?php
function runStored($pdo, $id) {
    $stmt = $pdo->prepare("SELECT query_sql FROM reports WHERE id = ?");
    $stmt->execute([$id]);
    $querySql = $stmt->fetchColumn();
    return $pdo->query($querySql)->fetchAll();
}
?>
'''),
            ("SECOND_ORDER", '''<?php
function configFragment($conn, $config) {
    $fragment = $config->get("where_clause");
    $sql = "SELECT id FROM audit_log WHERE " . $fragment;
    return mysqli_query($conn, $sql);
}
?>
'''),
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
    notes = list(profile.get("notes", []))
    notes.append("Targeted remaining-failures v9 augmentation appends balanced hard cases for final D/B classification misses.")
    notes.append("Model 1 remains frozen/read-only; this augmentation does not modify Model 1.")
    profile.update(
        {
            "augmentationVersion": "model2_targeted_remaining_failures_v9",
            "n_samples": int(len(y)),
            "added_samples": int(added),
            "samples_per_class_language_extra": int(samples_per_class_language_extra),
            "fix_counts": {inv_fix[i]: int(np.sum(y == i)) for i in sorted(inv_fix)},
            "language_counts": {inv_lang[i]: int(np.sum(lang == i)) for i in sorted(inv_lang)},
            "attack_type_counts": {inv_atk[i]: int(np.sum(atk == i)) for i in sorted(inv_atk)},
            "evidence_features": EVIDENCE_FEATURES,
            "evidence_feature_count": len(EVIDENCE_FEATURES),
            "targeted_failure_families_v9": [
                "D: saved widget where_fragment / stored query_sql / config archival_predicate executed later",
                "B: dynamic ORDER BY/table identifier where allowlist is computed but raw variable is still used",
                "A/C anchors preserve direct-value and complex-builder boundaries",
            ],
            "notes": notes,
        }
    )
    (export_dir / "dataset_profile.json").write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--export-dir", default="colab_export_fix_v2")
    ap.add_argument("--samples-per-class-language-extra", type=int, default=60)
    ap.add_argument("--seed", type=int, default=20260519)
    args = ap.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)

    export_dir = Path(args.export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)
    training_path = export_dir / "training_data.npz"
    arrays = _load_npz(training_path)

    vocab_path = export_dir / "vocabulary.json"
    vocab = json.loads(vocab_path.read_text(encoding="utf-8")) if vocab_path.exists() else build_fixed_vocabulary()
    profile_path = export_dir / "dataset_profile.json"
    profile = json.loads(profile_path.read_text(encoding="utf-8")) if profile_path.exists() else {}

    records = []
    for language in LANG:
        for fix in FIX_LABELS:
            gen = GENERATORS[fix]
            for i in range(args.samples_per_class_language_extra):
                attack_type, code = gen(language, i)
                if i % 7 == 0:
                    code += ("\n# targeted remaining failures v9\n" if language == "python" else "\n// targeted remaining failures v9\n")
                records.append(_make_record(code, language, fix, attack_type, vocab))

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
        merged[key] = np.concatenate([arr, append[key]], axis=0) if key in append else arr
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
