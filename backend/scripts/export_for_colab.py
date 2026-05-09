r"""
Export Model-1 V17 focused generalization training data for Google Colab.
This file replaces backend/scripts/export_for_colab.py with the SAME name.

Why V17 exists
-------------
V9 made the model much more ML-first and balanced, but the adversarial real-world suite exposed two important generalization gaps:
  1. time-based SQLi was detected as vulnerable but typed as IN_BAND instead of BLIND;
  2. PHP callable-array aliases to PDO/mysqli query were missed as SQL execution sinks.

V17 is a focused follow-up to V16. It keeps V17 stable and adds only two narrow generalization families: SAFE Sequelize replacements/bindings and JavaScript saved/cache/config segment SECOND_ORDER flow: keep V9's SAFE-flow knowledge while adding generated variants that teach the model time-delay BLIND behavior and callable DB alias sinks without copying benchmark files:
  SAFE flow examples:
    user input -> allowlist/map/numeric cast/bindings -> SQL syntax/params -> safe execute
  VULNERABLE flow examples:
    user input -> raw variable/raw identifier/raw string concat -> SQL sink
  SECOND_ORDER flow examples:
    DB-loaded/config/stored fragment -> SQL syntax -> sink

Anti-leakage rule
-----------------
Audit CSVs are used only to increase the number of generated pattern families.
This exporter does NOT copy source code from benchmark ZIP suites.
It creates new generated variants with different names, structures and layouts.

Recommended Windows CMD command from backend/:
    set PYTHONPATH=.
    python scripts\export_for_colab.py ^
      --out colab_export ^
      --sequence-length 256 ^
      --generated-per-class 4 ^
      --hardcase-per-family 16 ^
      --safe-calibration-per-family 8 ^
      --generated-seeds 20260810 20260811 20260812 ^
      --audit-csv outputs\model_audit_targeted_after_v9_final.csv ^
      --audit-csv outputs\model_audit_mega_after_v9_final.csv ^
      --audit-csv outputs\model_audit_realistic_after_v9_final.csv ^
      --audit-csv outputs\model_audit_enterprise_after_v9_final.csv ^
      --audit-csv outputs\model_audit_hard_after_v9_final.csv ^
      --audit-csv outputs\model_audit_framework_after_v9_final2.csv ^
      --audit-csv outputs\model_audit_adversarial_after_v11_final.csv

Upload to Colab:
    colab_export/vocabulary.json
    colab_export/training_data.npz
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import string
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import numpy as np

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.vectorization.vocabulary import build_fixed_vocabulary, save_vocabulary
from scripts.export_for_colab_base import (
    ATTACK_TO_ID,
    ID_TO_ATTACK,
    EXT_TO_LANG,
    DatasetBuilder as _BaseDatasetBuilder,
    add_original_export_samples,
    generated_training_samples,
    add_noise_to_code,
    normalize_to_ids,
    profile_dataset as _profile_dataset_base,
)

LANG_EXT = {"python": "py", "javascript": "js", "java": "java", "php": "php"}


def ident(r: random.Random, prefix: str = "v") -> str:
    return prefix + "_" + "".join(r.choice(string.ascii_lowercase) for _ in range(8))


class WeightedDatasetBuilder(_BaseDatasetBuilder):
    """Base DatasetBuilder + per-sample loss weights for V9 training."""

    def __init__(self, vocab: dict, sequence_length: int):
        super().__init__(vocab, sequence_length)
        self.sample_weight_binary: List[float] = []
        self.sample_weight_type: List[float] = []
        self.sample_family: List[str] = []

    def add(
        self,
        code: str,
        label: str,
        attack_type: str,
        language: str,
        path: str,
        source_id: str,
        suite_name: str,
        binary_weight: float = 1.0,
        type_weight: float = 1.0,
        family: str = "base",
    ) -> bool:
        before = len(self.X)
        ok = super().add(code, label, attack_type, language, path, source_id, suite_name)
        if ok and len(self.X) == before + 1:
            self.sample_weight_binary.append(float(binary_weight))
            self.sample_weight_type.append(float(type_weight))
            self.sample_family.append(str(family))
        return ok

    def arrays(self):
        arrays = super().arrays()
        n = len(arrays["y"])
        while len(self.sample_weight_binary) < n:
            self.sample_weight_binary.append(1.0)
            self.sample_weight_type.append(1.0)
            self.sample_family.append("base")
        arrays["sample_weight_binary"] = np.array(self.sample_weight_binary[:n], dtype=np.float32)
        arrays["sample_weight_type"] = np.array(self.sample_weight_type[:n], dtype=np.float32)
        arrays["sample_family"] = np.array(self.sample_family[:n])
        return arrays


def _family_from_file(path: str) -> str:
    p = path.lower()
    if "sequelize" in p and "replacement" in p:
        return "safe:sequelize_replacements"
    if "jdbctemplate" in p:
        return "safe:jdbctemplate_params"
    if "jpa" in p or "native_query" in p:
        return "safe:jpa_setparameter"
    if "laravel" in p or "db_select_bindings" in p:
        return "safe:laravel_bindings"
    if "prepared" in p or "pdo_prepare" in p or "prepare_execute" in p:
        return "safe:prepared_params"
    if "placeholder" in p:
        return "safe:placeholder_list"
    if "whitelist" in p or "allowlist" in p or "set_contains" in p or "array_map" in p or "dict_map" in p:
        return "safe:allowlist_identifier"
    if "numeric" in p or "limit_offset" in p or "limit" in p:
        return "safe:numeric_bounds"
    if "query_builder" in p or "querybuilder" in p or "params" in p:
        return "safe:query_builder"
    if "time_based" in p or "sleep" in p or "delay" in p or "benchmark" in p:
        return "vuln:blind_time_delay"
    if "query_alias" in p or "callable" in p:
        return "vuln:php_callable_db_alias"
    if "raw_order" in p:
        return "vuln:raw_order"
    if "blind" in p or "count" in p or "permission" in p or "token" in p:
        return "vuln:blind"
    if "second" in p or "stored" in p or "cached" in p or "config" in p or "fragment" in p:
        return "vuln:second_order"
    return "generic"


def audit_focus_from_csv(paths: List[str]) -> Dict[str, int]:
    """Return generation focus counts from ML mismatch rows, never source text."""
    counts: Counter[str] = Counter()
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            p = BACKEND_DIR / raw
        if not p.exists():
            print(f"[audit] missing CSV, skipped: {raw}")
            continue
        with p.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                file_name = row.get("file") or row.get("path") or ""
                exp_v = (row.get("expected_verdict") or row.get("expected_label") or row.get("Expected") or "SAFE").strip().upper()
                exp_t = (row.get("expected_attack_type") or row.get("expected_type") or row.get("Expected Type") or "NONE").strip().upper()
                # Audit CSVs contain ml_predicted_*; API/direct test-result CSVs contain actual_* only.
                # For V17 focusing, actual_* is enough to learn which adversarial family failed,
                # while still never copying benchmark source code.
                ml_v = (row.get("ml_predicted_verdict") or row.get("actual_verdict") or row.get("Actual") or "").strip().upper()
                ml_t = (row.get("ml_predicted_attack_type") or row.get("actual_type") or row.get("Actual Type") or "").strip().upper()
                lang = file_name.split("/")[0].strip().lower() or "unknown"
                fam = _family_from_file(file_name)

                # The V17 target: balance SAFE specificity with vulnerable recall and attack-type accuracy.
                if exp_v == "SAFE" and ml_v != "SAFE":
                    # V17 treats both VULNERABLE and SUSPICIOUS predictions on SAFE samples as hard-SAFE focus rows.
                    # This captures named-JDBC/JPA and comments-only false positives without copying benchmark code.
                    counts["NONE"] += 1
                    counts[f"{lang}:NONE"] += 1
                    counts[fam] += 2
                elif exp_v == "VULNERABLE" and (ml_v != "VULNERABLE" or ml_t != exp_t):
                    # V17 gives stronger focus to vulnerable misses and type errors.
                    counts[exp_t] += 3
                    counts[f"{lang}:{exp_t}"] += 3
                    counts[f"type:{exp_t}"] += 2
                    counts[fam] += 3
                    if ml_v != "VULNERABLE":
                        counts["hard_vuln_recall"] += 3
                        counts[f"{lang}:hard_vuln_recall"] += 3

    # Convert raw counts to a bounded extra budget.
    return {k: min(24, max(1, int((v + 1) // 2))) for k, v in counts.items()}


# ─────────────────────────────────────────────────────────────────────────────
# V17 focused calibration families
# ─────────────────────────────────────────────────────────────────────────────

def py_safe_allowlist(r):
    helper = ident(r, "pick")
    return f'''
def {helper}(value, allowed, default):
    return value if value in allowed else default

def list_{ident(r, 'fn')}(request, conn):
    allowed_cols = {{"name", "email", "created_at"}}
    allowed_dir = {{"ASC", "DESC"}}
    safe_col = {helper}(request.GET.get("sort", "created_at"), allowed_cols, "created_at")
    safe_dir = {helper}(request.GET.get("dir", "ASC"), allowed_dir, "ASC")
    sql = f"SELECT id,email FROM users WHERE tenant_id = ? ORDER BY {{safe_col}} {{safe_dir}}"
    return conn.execute(sql, (request.user.tenant_id,)).fetchall()
'''


def py_safe_dict_map_table(r):
    return f'''
def load_{ident(r, 'fn')}(request, conn):
    tables = {{"users": "users_archive", "orders": "orders_archive"}}
    table_name = tables.get(request.GET.get("entity"), "users_archive")
    sql = "SELECT id, created_at FROM " + table_name + " WHERE tenant_id = ?"
    return conn.execute(sql, (request.user.tenant_id,)).fetchall()
'''


def py_safe_placeholder_list(r):
    return f'''
def bulk_{ident(r, 'fn')}(request, conn):
    ids = [int(x) for x in request.GET.getlist("id")]
    placeholders = ",".join("?" for _ in ids)
    sql = "SELECT * FROM users WHERE id IN (" + placeholders + ")"
    return conn.execute(sql, ids).fetchall()
'''


def py_safe_numeric_bounds(r):
    return f'''
def page_{ident(r, 'fn')}(request, conn):
    size = min(max(int(request.GET.get("limit", 25)), 1), 100)
    offset = max(int(request.GET.get("offset", 0)), 0)
    sql = f"SELECT * FROM orders WHERE tenant_id = ? LIMIT {{size}} OFFSET {{offset}}"
    return conn.execute(sql, (request.user.tenant_id,)).fetchall()
'''


def py_safe_sqlalchemy_params(r):
    return f'''
def repo_{ident(r, 'fn')}(request, session):
    sql = text("SELECT id,email FROM users WHERE tenant_id=:tenant AND status=:status")
    return session.execute(sql, {{"tenant": request.user.tenant_id, "status": request.GET.get("status")}}).fetchall()
'''


def js_safe_sequelize_replacements(r):
    return f'''
async function list_{ident(r, 'fn')}(req, sequelize, QueryTypes) {{
  const sql = "SELECT id,email FROM users WHERE tenant_id = :tenant AND status = :status";
  return sequelize.query(sql, {{
    replacements: {{ tenant: req.user.tenantId, status: req.query.status || "ACTIVE" }},
    type: QueryTypes.SELECT
  }});
}}
'''


def js_safe_knex_params(r):
    return f'''
async function repo_{ident(r, 'fn')}(req, knex) {{
  return knex("users")
    .where("tenant_id", req.user.tenantId)
    .andWhere("status", req.query.status || "ACTIVE")
    .select("id", "email");
}}
'''


def js_safe_allowlist_order(r):
    return f'''
async function list_{ident(r, 'fn')}(req, db) {{
  const allowed = new Set(["created_at", "email", "name"]);
  const dirAllowed = new Set(["ASC", "DESC"]);
  const sort = allowed.has(req.query.sort) ? req.query.sort : "created_at";
  const dir = dirAllowed.has(req.query.dir) ? req.query.dir : "ASC";
  const sql = `SELECT id,email FROM users WHERE tenant_id = ? ORDER BY ${{sort}} ${{dir}}`;
  return db.all(sql, [req.user.tenantId]);
}}
'''


def js_safe_placeholder_list(r):
    return f'''
async function bulk_{ident(r, 'fn')}(req, db) {{
  const ids = (req.query.ids || []).map(Number).filter(Number.isInteger);
  const placeholders = ids.map(() => "?").join(",");
  const sql = "SELECT * FROM users WHERE id IN (" + placeholders + ")";
  return db.all(sql, ids);
}}
'''


def java_safe_jdbctemplate(r):
    cls = ident(r, "Repo").replace("_", "")
    return f'''
class {cls} {{
  java.util.List<User> list(HttpServletRequest req, JdbcTemplate jdbc) {{
    String sql = "SELECT id,email FROM users WHERE tenant_id = ? AND status = ?";
    return jdbc.query(sql, new Object[] {{ req.getUserPrincipal().getName(), req.getParameter("status") }}, mapper);
  }}
}}
'''


def java_safe_jpa_setparameter(r):
    cls = ident(r, "Repo").replace("_", "")
    return f'''
class {cls} {{
  java.util.List<?> list(HttpServletRequest req, EntityManager em) {{
    Query q = em.createNativeQuery("SELECT id,email FROM users WHERE tenant_id = :tenant AND status = :status");
    q.setParameter("tenant", req.getUserPrincipal().getName());
    q.setParameter("status", req.getParameter("status"));
    return q.getResultList();
  }}
}}
'''


def java_safe_prepared_order(r):
    cls = ident(r, "Svc").replace("_", "")
    return f'''
class {cls} {{
  ResultSet list(HttpServletRequest req, Connection c) throws Exception {{
    java.util.Set<String> allowed = java.util.Set.of("created_at", "email", "name");
    String sort = allowed.contains(req.getParameter("sort")) ? req.getParameter("sort") : "created_at";
    String sql = "SELECT id,email FROM users WHERE tenant_id = ? ORDER BY " + sort;
    PreparedStatement ps = c.prepareStatement(sql);
    ps.setString(1, req.getUserPrincipal().getName());
    return ps.executeQuery();
  }}
}}
'''


def php_safe_laravel_bindings(r):
    return f'''<?php
function list_{ident(r, 'fn')}($request) {{
    $sql = "SELECT id,email FROM users WHERE tenant_id = ? AND status = ?";
    return DB::select($sql, [$request->user()->tenant_id, $request->input("status", "ACTIVE")]);
}}
?>'''


def php_safe_pdo_prepare(r):
    return f'''<?php
function list_{ident(r, 'fn')}($pdo, $q) {{
    $sql = "SELECT id,email FROM users WHERE tenant_id = ? AND status = ?";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$q["tenant"], $q["status"] ?? "ACTIVE"]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}}
?>'''


def php_safe_array_allowlist(r):
    return f'''<?php
function list_{ident(r, 'fn')}($pdo, $q) {{
    $columns = ["name" => "name", "email" => "email", "created" => "created_at"];
    $sort = $columns[$q["sort"] ?? "created"] ?? "created_at";
    $sql = "SELECT id,email FROM users WHERE tenant_id = ? ORDER BY " . $sort;
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$q["tenant"]]);
    return $stmt->fetchAll();
}}
?>'''


def php_safe_placeholder_list(r):
    return f'''<?php
function bulk_{ident(r, 'fn')}($pdo, $ids) {{
    $ids = array_map('intval', $ids);
    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    $sql = "SELECT * FROM users WHERE id IN (" . $placeholders . ")";
    $stmt = $pdo->prepare($sql);
    $stmt->execute($ids);
    return $stmt->fetchAll();
}}
?>'''


# Vulnerable counterexamples with similar surface syntax. These prevent V9 from
# learning the simplistic rule "prepared/allowlist nearby means safe".
def py_vuln_raw_order(r):
    return f'''
def list_{ident(r, 'fn')}(request, conn):
    safe = {{"name": "name", "created": "created_at"}}.get(request.GET.get("sort"), "created_at")
    raw = request.GET.get("sort", "")
    sql = "SELECT id,email FROM users ORDER BY " + raw
    return conn.execute(sql).fetchall()
'''


def js_vuln_sequelize_raw(r):
    return f'''
async function list_{ident(r, 'fn')}(req, sequelize) {{
  const status = req.query.status || "ACTIVE";
  const sql = `SELECT id,email FROM users WHERE status='${{status}}'`;
  return sequelize.query(sql);
}}
'''


def java_vuln_jdbc_raw(r):
    cls = ident(r, "Bad").replace("_", "")
    return f'''
class {cls} {{
  ResultSet list(HttpServletRequest req, Statement st) throws Exception {{
    String status = req.getParameter("status");
    String sql = "SELECT id,email FROM users WHERE status='" + status + "'";
    return st.executeQuery(sql);
  }}
}}
'''


def php_vuln_pdo_raw_order(r):
    return f'''<?php
function list_{ident(r, 'fn')}($pdo, $q) {{
    $stmt = $pdo->prepare("SELECT id FROM tenants WHERE id=?");
    $stmt->execute([$q["tenant"]]);
    $raw = $q["sort"] ?? "";
    $sql = "SELECT id,email FROM users ORDER BY " . $raw;
    return $pdo->query($sql)->fetchAll();
}}
?>'''


def generic_blind(lang: str, r: random.Random) -> str:
    if lang == "python":
        return f'''\ndef can_{ident(r, 'fn')}(request, conn):\n    token = request.GET.get("token", "")\n    sql = "SELECT id FROM sessions WHERE token='" + token + "'"\n    row = conn.execute(sql).fetchone()\n    return row is not None\n'''
    if lang == "javascript":
        return f'''\nasync function can_{ident(r, 'fn')}(req, db) {{\n  const token = req.query.token || "";\n  const sql = `SELECT id FROM sessions WHERE token='${{token}}'`;\n  const row = await db.get(sql);\n  return !!row;\n}}\n'''
    if lang == "java":
        cls = ident(r, "Auth").replace("_", "")
        return f'''\nclass {cls} {{\n  boolean can(HttpServletRequest req, Statement st) throws Exception {{\n    String token = req.getParameter("token");\n    ResultSet rs = st.executeQuery("SELECT id FROM sessions WHERE token='" + token + "'");\n    return rs.next();\n  }}\n}}\n'''
    return f'''<?php\nfunction can_{ident(r, 'fn')}($mysqli, $q) {{\n    $token = $q["token"] ?? "";\n    $sql = "SELECT id FROM sessions WHERE token='" . $token . "'";\n    $rs = $mysqli->query($sql);\n    return $rs && $rs->num_rows > 0;\n}}\n?>'''


def generic_second(lang: str, r: random.Random) -> str:
    if lang == "python":
        return f'''\ndef run_{ident(r, 'fn')}(request, conn):\n    row = conn.execute("SELECT where_clause FROM reports WHERE id=?", (request.GET.get("id"),)).fetchone()\n    where = row[0]\n    sql = "SELECT * FROM audit_log WHERE " + where\n    return conn.execute(sql).fetchall()\n'''
    if lang == "javascript":
        return f'''\nasync function run_{ident(r, 'fn')}(req, db) {{\n  const row = await db.get("SELECT where_clause FROM reports WHERE id=?", [req.params.id]);\n  const sql = "SELECT * FROM audit_log WHERE " + row.where_clause;\n  return db.all(sql);\n}}\n'''
    if lang == "java":
        cls = ident(r, "Audit").replace("_", "")
        return f'''\nclass {cls} {{\n  ResultSet run(Connection c, Statement st, String id) throws Exception {{\n    PreparedStatement ps = c.prepareStatement("SELECT where_clause FROM reports WHERE id=?");\n    ps.setString(1, id);\n    ResultSet rs = ps.executeQuery(); rs.next();\n    String where = rs.getString("where_clause");\n    return st.executeQuery("SELECT * FROM audit_log WHERE " + where);\n  }}\n}}\n'''
    return f'''<?php\nfunction run_{ident(r, 'fn')}($pdo, $id) {{\n    $stmt = $pdo->prepare("SELECT where_clause FROM reports WHERE id=?");\n    $stmt->execute([$id]);\n    $row = $stmt->fetch(PDO::FETCH_ASSOC);\n    $sql = "SELECT * FROM audit_log WHERE " . $row["where_clause"];\n    return $pdo->query($sql)->fetchAll();\n}}\n?>'''




# Extra V9 vulnerable-flow families.
# These are intentionally close to SAFE-looking code, but the unsafe value is the
# one that actually reaches SQL syntax/sink. This teaches FLOW rather than
# memorising file names.
def py_vuln_alias_execute(r):
    return f'''
def run_{ident(r, 'fn')}(request, conn):
    email = request.GET.get("email", "")
    sql = "SELECT id,email FROM users WHERE email='" + email + "'"
    execute_sql = conn.execute
    return execute_sql(sql).fetchall()
'''


def py_vuln_multi_query_one_unsafe(r):
    return f'''
def report_{ident(r, 'fn')}(request, conn):
    safe_sql = "SELECT id FROM tenants WHERE id = ?"
    conn.execute(safe_sql, (request.user.tenant_id,)).fetchone()
    raw_status = request.GET.get("status", "")
    unsafe_sql = "SELECT id,email FROM users WHERE status='" + raw_status + "'"
    return conn.execute(unsafe_sql).fetchall()
'''


def py_vuln_raw_table(r):
    return f'''
def table_{ident(r, 'fn')}(request, conn):
    allowed = {{"users": "users", "orders": "orders"}}
    decoy_table = allowed.get(request.GET.get("entity"), "users")
    raw_table = request.GET.get("entity", "")
    sql = "SELECT id FROM " + raw_table + " WHERE tenant_id = ?"
    return conn.execute(sql, (request.user.tenant_id,)).fetchall()
'''


def py_vuln_raw_limit(r):
    return f'''
def page_{ident(r, 'fn')}(request, conn):
    safe_limit = min(max(int(request.GET.get("limit", 25)), 1), 100)
    raw_offset = request.GET.get("offset", "")
    sql = "SELECT id FROM orders LIMIT " + str(safe_limit) + " OFFSET " + raw_offset
    return conn.execute(sql).fetchall()
'''


def py_vuln_joined_ids(r):
    return f'''
def bulk_{ident(r, 'fn')}(request, conn):
    ids = request.GET.getlist("id")
    raw_ids = ",".join(ids)
    sql = "SELECT * FROM users WHERE id IN (" + raw_ids + ")"
    return conn.execute(sql).fetchall()
'''


def js_vuln_exec_alias(r):
    return f'''
async function run_{ident(r, 'fn')}(req, db) {{
  const email = req.query.email || "";
  const sql = `SELECT id,email FROM users WHERE email='${{email}}'`;
  const run = db.all.bind(db);
  return run(sql);
}}
'''


def js_vuln_multi_query_one_unsafe(r):
    return f'''
async function report_{ident(r, 'fn')}(req, db) {{
  await db.get("SELECT id FROM tenants WHERE id=?", [req.user.tenantId]);
  const status = req.query.status || "";
  const unsafeSql = `SELECT id,email FROM users WHERE status='${{status}}'`;
  return db.all(unsafeSql);
}}
'''


def js_vuln_raw_order_despite_set(r):
    return f'''
async function list_{ident(r, 'fn')}(req, db) {{
  const allowed = new Set(["created_at", "email", "name"]);
  const safeSort = allowed.has(req.query.sort) ? req.query.sort : "created_at";
  const rawSort = req.query.sort || "";
  const sql = `SELECT id,email FROM users ORDER BY ${{rawSort}}`;
  return db.all(sql);
}}
'''


def js_vuln_joined_ids(r):
    return f'''
async function bulk_{ident(r, 'fn')}(req, db) {{
  const ids = String(req.query.ids || "").split(",");
  const rawIds = ids.join(",");
  const sql = "SELECT * FROM users WHERE id IN (" + rawIds + ")";
  return db.all(sql);
}}
'''


def java_vuln_raw_order_decoy_prepared(r):
    cls = ident(r, "Bad").replace("_", "")
    return f'''
class {cls} {{
  ResultSet list(HttpServletRequest req, Connection c, Statement st) throws Exception {{
    PreparedStatement safe = c.prepareStatement("SELECT id FROM tenants WHERE id=?");
    safe.setString(1, req.getUserPrincipal().getName());
    java.util.Set<String> allowed = java.util.Set.of("created_at", "email", "name");
    String safeSort = allowed.contains(req.getParameter("sort")) ? req.getParameter("sort") : "created_at";
    String rawSort = req.getParameter("sort");
    String sql = "SELECT id,email FROM users ORDER BY " + rawSort;
    return st.executeQuery(sql);
  }}
}}
'''


def java_vuln_multi_query_one_unsafe(r):
    cls = ident(r, "Svc").replace("_", "")
    return f'''
class {cls} {{
  ResultSet report(HttpServletRequest req, Connection c, Statement st) throws Exception {{
    PreparedStatement ps = c.prepareStatement("SELECT id FROM tenants WHERE id=?");
    ps.setString(1, req.getUserPrincipal().getName());
    ps.executeQuery();
    String status = req.getParameter("status");
    String sql = "SELECT id,email FROM users WHERE status='" + status + "'";
    return st.executeQuery(sql);
  }}
}}
'''


def php_vuln_mysqli_concat(r):
    return f'''<?php
function search_{ident(r, 'fn')}($mysqli, $q) {{
    $email = $q["email"] ?? "";
    $sql = "SELECT id,email FROM users WHERE email='" . $email . "'";
    return $mysqli->query($sql);
}}
?>'''


def php_vuln_raw_ids_implode(r):
    return f'''<?php
function bulk_{ident(r, 'fn')}($pdo, $q) {{
    $ids = $q["ids"] ?? [];
    $raw = implode(',', $ids);
    $sql = "SELECT * FROM users WHERE id IN (" . $raw . ")";
    return $pdo->query($sql)->fetchAll();
}}
?>'''


def php_vuln_pdo_raw_order_decoy(r):
    return f'''<?php
function list_{ident(r, 'fn')}($pdo, $q) {{
    $safe = $pdo->prepare("SELECT id FROM tenants WHERE id=?");
    $safe->execute([$q["tenant"]]);
    $allowed = ["name" => "name", "created" => "created_at"];
    $safeSort = $allowed[$q["sort"] ?? "created"] ?? "created_at";
    $rawSort = $q["sort"] ?? "";
    $sql = "SELECT id,email FROM users ORDER BY " . $rawSort;
    return $pdo->query($sql)->fetchAll();
}}
?>'''


def php_vuln_query_after_prepare(r):
    return f'''<?php
function load_{ident(r, 'fn')}($pdo, $q) {{
    $stmt = $pdo->prepare("SELECT id FROM tenants WHERE id=?");
    $stmt->execute([$q["tenant"]]);
    $status = $q["status"] ?? "";
    $sql = "SELECT id,email FROM users WHERE status='" . $status . "'";
    return $pdo->query($sql)->fetchAll();
}}
?>'''


def py_second_stored_filter_typed(r):
    return f'''
def run_{ident(r, 'fn')}(request, conn):
    saved = conn.execute("SELECT filter_sql FROM saved_filters WHERE id=?", (request.GET.get("id"),)).fetchone()
    fragment = saved[0]
    sql = "SELECT * FROM reports WHERE " + fragment
    return conn.execute(sql).fetchall()
'''


def js_second_cached_fragment_typed(r):
    return f'''
async function run_{ident(r, 'fn')}(req, db, cache) {{
  const cached = await cache.get("segment:" + req.params.id);
  const whereClause = cached.whereClause;
  const sql = "SELECT * FROM users WHERE " + whereClause;
  return db.all(sql);
}}
'''


def java_second_config_where_typed(r):
    cls = ident(r, "Audit").replace("_", "")
    return f'''
class {cls} {{
  ResultSet run(Connection c, Statement st, String key) throws Exception {{
    PreparedStatement ps = c.prepareStatement("SELECT config_value FROM app_config WHERE config_key=?");
    ps.setString(1, key);
    ResultSet rs = ps.executeQuery(); rs.next();
    String where = rs.getString("config_value");
    String sql = "SELECT * FROM audit_log WHERE " + where;
    return st.executeQuery(sql);
  }}
}}
'''


def php_second_stored_sql_typed(r):
    return f'''<?php
function run_{ident(r, 'fn')}($pdo, $id) {{
    $stmt = $pdo->prepare("SELECT report_filter FROM saved_reports WHERE id=?");
    $stmt->execute([$id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $where = $row["report_filter"];
    $sql = "SELECT * FROM audit_log WHERE " . $where;
    return $pdo->query($sql)->fetchAll();
}}
?>'''



# ─────────────────────────────────────────────────────────────────────────────
# V17 adversarial families: time-based BLIND SQLi and PHP callable DB aliases.
# These are generated variants, not copied benchmark files. They teach the model
# that a delay expression in executed raw SQL is BLIND, not IN_BAND, and that a
# callable alias to query/exec remains a SQL sink.
# ─────────────────────────────────────────────────────────────────────────────

def py_blind_time_sleep(r):
    delay_fn = r.choice(["SLEEP", "pg_sleep"])
    return f'''
def audit_{ident(r, 'fn')}(request, conn):
    user_id = request.GET.get("uid", "")
    sql = "SELECT id FROM users WHERE id='" + user_id + "' AND CASE WHEN 1=1 THEN {delay_fn}(5) ELSE 0 END"
    conn.execute(sql).fetchone()
    return {{"ok": True}}
'''


def py_blind_time_if_sleep(r):
    return f'''
def probe_{ident(r, 'fn')}(request, conn):
    name = request.GET.get("name", "")
    sql = "SELECT * FROM accounts WHERE name='" + name + "' OR IF(LENGTH(database())>0,SLEEP(4),0)"
    row = conn.execute(sql).fetchone()
    return row is not None
'''


def js_blind_time_sleep(r):
    fn = r.choice(["SLEEP", "pg_sleep", "BENCHMARK"])
    expr = "BENCHMARK(2500000,MD5('x'))" if fn == "BENCHMARK" else f"{fn}(5)"
    return f'''
async function audit_{ident(r, 'fn')}(req, db) {{
  const userId = req.query.uid || "";
  const sql = `SELECT id FROM users WHERE id='${{userId}}' AND CASE WHEN 1=1 THEN {expr} ELSE 0 END`;
  await db.get(sql);
  return true;
}}
'''


def js_blind_time_if_sleep(r):
    return f'''
async function probe_{ident(r, 'fn')}(req, db) {{
  const email = req.query.email || "";
  const sql = "SELECT id FROM users WHERE email='" + email + "' OR IF(1=1,SLEEP(3),0)";
  const row = await db.get(sql);
  return !!row;
}}
'''


def java_blind_time_waitfor(r):
    cls = ident(r, "TimeProbe").replace("_", "")
    return f'''
class {cls} {{
  boolean audit(HttpServletRequest req, Statement st) throws Exception {{
    String uid = req.getParameter("uid");
    String sql = "SELECT id FROM users WHERE id='" + uid + "'; WAITFOR DELAY '00:00:05'";
    st.executeQuery(sql);
    return true;
  }}
}}
'''


def java_blind_time_sleep(r):
    cls = ident(r, "DelayProbe").replace("_", "")
    return f'''
class {cls} {{
  boolean probe(HttpServletRequest req, Statement st) throws Exception {{
    String name = req.getParameter("name");
    String sql = "SELECT id FROM accounts WHERE name='" + name + "' OR CASE WHEN 1=1 THEN SLEEP(4) ELSE 0 END";
    ResultSet rs = st.executeQuery(sql);
    return rs.next();
  }}
}}
'''


def php_blind_time_sleep(r):
    return f'''<?php
function audit_{ident(r, 'fn')}($mysqli, $q) {{
    $uid = $q["uid"] ?? "";
    $sql = "SELECT id FROM users WHERE id='" . $uid . "' OR IF(1=1,SLEEP(5),0)";
    $mysqli->query($sql);
    return true;
}}
?>'''


def php_blind_time_benchmark(r):
    return f'''<?php
function probe_{ident(r, 'fn')}($pdo, $q) {{
    $email = $q["email"] ?? "";
    $sql = "SELECT id FROM users WHERE email='" . $email . "' OR BENCHMARK(2000000,MD5('x'))";
    $row = $pdo->query($sql)->fetch(PDO::FETCH_ASSOC);
    return $row !== false;
}}
?>'''


def php_vuln_callable_query_alias(r):
    return f'''<?php
function load_{ident(r, 'fn')}($pdo, $q) {{
    $status = $q["status"] ?? "";
    $sql = "SELECT id,email FROM users WHERE status='" . $status . "'";
    $runner = [$pdo, "query"];
    $stmt = $runner($sql);
    return $stmt->fetchAll();
}}
?>'''


def php_vuln_callable_this_pdo_query_alias(r):
    cls = ident(r, "Repo").replace("_", "")
    return f'''<?php
class {cls} {{
    private $pdo;
    public function find($q) {{
        $raw = $q["sort"] ?? "";
        $sql = "SELECT id,email FROM users ORDER BY " . $raw;
        $runner = [$this->pdo, "query"];
        return $runner($sql)->fetchAll();
    }}
}}
?>'''


def php_vuln_callable_mysqli_query_alias(r):
    return f'''<?php
function search_{ident(r, 'fn')}($mysqli, $q) {{
    $name = $q["name"] ?? "";
    $sql = "SELECT id FROM customers WHERE name='" . $name . "'";
    $run = [$mysqli, "query"];
    return $run($sql);
}}
?>'''


def php_safe_callable_non_db_alias(r):
    return f'''<?php
function render_{ident(r, 'fn')}($q) {{
    $value = $q["name"] ?? "";
    $runner = ["Html", "escape"];
    $safe = $runner($value);
    return "<span>" . $safe . "</span>";
}}
?>'''


def php_safe_callable_prepare_execute(r):
    return f'''<?php
function safe_{ident(r, 'fn')}($pdo, $q) {{
    $email = $q["email"] ?? "";
    $runner = [$pdo, "prepare"];
    $stmt = $runner("SELECT id,email FROM users WHERE email = ?");
    $stmt->execute([$email]);
    return $stmt->fetchAll();
}}
?>'''



# Extra V17 time-delay BLIND variants. These use different syntax forms so the
# model learns the semantic FLOW: raw input reaches SQL syntax whose outcome is
# timing/boolean delay, therefore BLIND even when no rows are displayed.
def py_blind_time_or_sleep_raw(r):
    return f'''
def delay_{ident(r, 'fn')}(request, conn):
    email = request.GET.get("email", "")
    sql = "SELECT id FROM users WHERE email='" + email + "' OR SLEEP(3)"
    conn.execute(sql).fetchone()
    return {{"queued": True}}
'''


def py_blind_time_select_pg_sleep(r):
    return f'''
def probe_{ident(r, 'fn')}(request, conn):
    raw = request.GET.get("flag", "")
    sql = "SELECT id FROM flags WHERE value='" + raw + "' AND (SELECT pg_sleep(2)) IS NULL"
    conn.execute(sql)
    return True
'''


def js_blind_time_benchmark_concat(r):
    return f'''
async function delay_{ident(r, 'fn')}(req, db) {{
  const raw = req.query.name || "";
  const sql = "SELECT id FROM users WHERE name='" + raw + "' OR BENCHMARK(1500000,MD5('x'))";
  await db.get(sql);
  return {{ ok: true }};
}}
'''


def js_blind_time_waitfor_template(r):
    return f'''
async function audit_{ident(r, 'fn')}(req, db) {{
  const raw = req.query.uid || "";
  const sql = `SELECT id FROM users WHERE id='${{raw}}'; WAITFOR DELAY '00:00:04'`;
  await db.exec(sql);
  return true;
}}
'''


def java_blind_time_dbms_sleep(r):
    cls = ident(r, "OracleProbe").replace("_", "")
    return f'''
class {cls} {{
  boolean run(HttpServletRequest req, Statement st) throws Exception {{
    String raw = req.getParameter("account");
    String sql = "SELECT id FROM accounts WHERE name='" + raw + "' OR DBMS_LOCK.SLEEP(3)=0";
    st.execute(sql);
    return true;
  }}
}}
'''


def java_blind_time_if_sleep(r):
    cls = ident(r, "IfDelay").replace("_", "")
    return f'''
class {cls} {{
  boolean run(HttpServletRequest req, Statement st) throws Exception {{
    String raw = req.getParameter("email");
    String sql = "SELECT id FROM users WHERE email='" + raw + "' OR IF(1=1,SLEEP(5),0)";
    st.executeQuery(sql);
    return true;
  }}
}}
'''


def php_blind_time_pg_sleep(r):
    return f'''<?php
function delay_{ident(r, 'fn')}($pdo, $q) {{
    $raw = $q["uid"] ?? "";
    $sql = "SELECT id FROM users WHERE id='" . $raw . "' OR pg_sleep(4) IS NULL";
    $pdo->query($sql);
    return true;
}}
?>'''


def php_blind_time_case_sleep(r):
    return f'''<?php
function audit_{ident(r, 'fn')}($mysqli, $q) {{
    $raw = $q["email"] ?? "";
    $sql = "SELECT id FROM users WHERE email='" . $raw . "' OR CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END";
    $mysqli->query($sql);
    return true;
}}
?>'''


# Extra V17 callable alias variants and hard counterexamples.
def php_vuln_callable_method_var_query_alias(r):
    return f'''<?php
function find_{ident(r, 'fn')}($pdo, $q) {{
    $term = $q["term"] ?? "";
    $sql = "SELECT id FROM customers WHERE name='" . $term . "'";
    $method = "query";
    $runner = [$pdo, $method];
    return $runner($sql)->fetchAll();
}}
?>'''


def php_vuln_callable_db_property_query_alias(r):
    cls = ident(r, "Storage").replace("_", "")
    return f'''<?php
class {cls} {{
    public $db;
    public function list($q) {{
        $raw = $q["filter"] ?? "";
        $sql = "SELECT * FROM audit_log WHERE " . $raw;
        $run = [$this->db, "query"];
        return $run($sql);
    }}
}}
?>'''


def php_safe_callable_query_literal(r):
    return f'''<?php
function safe_{ident(r, 'fn')}($pdo) {{
    $sql = "SELECT id,email FROM users WHERE active = 1";
    $runner = [$pdo, "query"];
    return $runner($sql)->fetchAll();
}}
?>'''


def php_safe_callable_prepared_alias_with_raw_decoy(r):
    return f'''<?php
function safe_{ident(r, 'fn')}($pdo, $q) {{
    $raw = $q["email"] ?? "";
    $sql = "SELECT id,email FROM users WHERE email = ?";
    $runner = [$pdo, "prepare"];
    $stmt = $runner($sql);
    $stmt->execute([$raw]);
    return $stmt->fetchAll();
}}
?>'''



# V17 hard-SAFE no-sink/comment/string-only families.
# These teach the model that SQL-looking payloads, SLEEP/WAITFOR tokens,
# SELECT/UNION strings and DB method names are not vulnerabilities unless the
# SQL-like value reaches a real DB execution sink.
def py_safe_comments_only_hard(r):
    payload = r.choice(["SLEEP(5)", "UNION SELECT password FROM users", "WAITFOR DELAY '00:00:05'", "pg_sleep(3)"])
    fname = ident(r, 'fn')
    return f"""
# Historical attack example for documentation only: {payload}
# Do not execute this string; it is here so reviewers know what we block.
def docs_{fname}(request):
    example = "SELECT * FROM users WHERE name='admin' OR {payload}"
    note = "training/documentation string only, no database sink"
    return {{"example": example, "note": note}}
"""


def js_safe_comments_only_hard(r):
    payload = r.choice(["SLEEP(5)", "BENCHMARK(1000000,MD5('x'))", "WAITFOR DELAY '00:00:05'", "UNION SELECT password FROM users"])
    fname = ident(r, 'fn')
    return f"""
// Security note only: {payload}
export function describe_{fname}(req) {{
  const sample = `SELECT * FROM users WHERE id='${{req.query.id}}' OR {payload}`;
  const logOnly = "This is a documentation string and is never passed to db.query/db.get/db.all";
  return {{ sample, logOnly }};
}}
"""


def java_safe_comments_only_hard(r):
    payload = r.choice(["SLEEP(5)", "DBMS_LOCK.SLEEP(3)", "WAITFOR DELAY '00:00:05'", "UNION SELECT password FROM users"])
    cls = ident(r, "Docs").replace("_", "")
    return f"""
class {cls} {{
  // Documentation-only SQLi example: {payload}
  String describe(HttpServletRequest req) {{
    String example = "SELECT * FROM users WHERE email='" + req.getParameter("email") + "' OR {payload}";
    String notExecuted = "No Statement, no PreparedStatement execution, no DB sink";
    return example + notExecuted;
  }}
}}
"""


def php_safe_comments_only_hard(r):
    payload = r.choice(["SLEEP(5)", "BENCHMARK(1000000,MD5('x'))", "WAITFOR DELAY '00:00:05'", "UNION SELECT password FROM users"])
    fname = ident(r, 'fn')
    return f"""<?php
// Documentation-only attack sample: {payload}
function describe_{fname}($request) {{
    $example = "SELECT * FROM users WHERE id='" . ($request["id"] ?? "") . "' OR {payload}";
    $note = "No PDO::query, no mysqli_query, no execute sink; string only";
    return [$example, $note];
}}
?>"""


def py_safe_time_keyword_not_sql(r):
    fname = ident(r, 'fn')
    return f"""
def wait_{fname}(request):
    delay = int(request.GET.get("delay", 1))
    # Python sleep is application timing, not SQL SLEEP inside a database query.
    time.sleep(min(max(delay, 0), 2))
    return {{"ok": True}}
"""


def js_safe_time_keyword_not_sql(r):
    fname = ident(r, 'fn')
    return f"""
export async function delay_{fname}(req) {{
  const ms = Math.min(Number(req.query.ms || 10), 1000);
  await new Promise(resolve => setTimeout(resolve, ms));
  return {{ ok: true }};
}}
"""


def java_safe_time_keyword_not_sql(r):
    cls = ident(r, "Timer").replace("_", "")
    return f"""
class {cls} {{
  boolean wait(HttpServletRequest req) throws Exception {{
    int ms = Math.min(Integer.parseInt(req.getParameter("ms")), 1000);
    Thread.sleep(ms);
    return true;
  }}
}}
"""


def php_safe_time_keyword_not_sql(r):
    fname = ident(r, 'fn')
    return f"""<?php
function wait_{fname}($request) {{
    $n = min((int)($request["n"] ?? 1), 2);
    sleep($n); // PHP sleep, not SQL SLEEP in a query string
    return true;
}}
?>"""


# -----------------------------
# V17 focused generalization families
# -----------------------------
# Generated families only: no benchmark source is copied. They target V17 gaps:
# Python no-sink SQL-looking strings/comments, Java safe named params, and PHP
# time-delay BLIND flows.

def py_safe_docstring_payload_no_sink(r):
    payload = r.choice(["SLEEP(5)", "pg_sleep(3)", "WAITFOR DELAY '00:00:05'", "BENCHMARK(1000000,MD5('x'))", "UNION SELECT password FROM users"])
    fname = ident(r, 'fn')
    return f'''
def describe_{fname}(request):
    # Documentation-only SQLi payload example: {payload}
    sample = "SELECT * FROM accounts WHERE id='" + str(request.GET.get("id", "")) + "' OR {payload}"
    rendered = {{"sample": sample, "purpose": "docs only", "sink": "none"}}
    return rendered
'''


def py_safe_payload_constant_log_only(r):
    payload = r.choice(["SLEEP(4)", "pg_sleep(2)", "IF(1=1,SLEEP(5),0)", "CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END"])
    fname = ident(r, 'fn')
    return f'''
def log_{fname}(request, logger):
    attack_example = "SELECT id FROM users WHERE name='x' OR {payload}"
    user_supplied_note = request.GET.get("note", "")
    logger.info("example=%s note=%s", attack_example, user_supplied_note)
    return {{"ok": True, "example": attack_example}}
'''


def java_safe_named_jdbc_params_more(r):
    cls = ident(r, "NamedRepo").replace("_", "")
    return f'''
import org.springframework.jdbc.core.namedparam.*;
import java.util.*;
class {cls} {{
  List<?> search(HttpServletRequest req, NamedParameterJdbcTemplate jdbc) {{
    String sql = "SELECT id,email FROM users WHERE tenant_id = :tenant AND status = :status AND email LIKE :email";
    MapSqlParameterSource params = new MapSqlParameterSource();
    params.addValue("tenant", req.getUserPrincipal().getName());
    params.addValue("status", req.getParameter("status"));
    params.addValue("email", "%" + req.getParameter("email") + "%");
    String decoy = "SELECT * FROM users WHERE email='" + req.getParameter("email") + "'";
    return jdbc.query(sql, params, mapper);
  }}
}}
'''


def java_safe_jpa_named_params_more(r):
    cls = ident(r, "JpaRepo").replace("_", "")
    return f'''
import javax.persistence.*;
class {cls} {{
  java.util.List<?> list(HttpServletRequest req, EntityManager em) {{
    Query query = em.createNativeQuery("SELECT id,email FROM users WHERE tenant_id = :tenant AND email = :email");
    query.setParameter("tenant", req.getUserPrincipal().getName());
    query.setParameter("email", req.getParameter("email"));
    String unsafeLooking = "SELECT * FROM users WHERE email='" + req.getParameter("email") + "'";
    return query.getResultList();
  }}
}}
'''


def php_blind_time_raw_mysqli_variants(r):
    fname = ident(r, 'fn')
    expr = r.choice(["IF(1=1,SLEEP(5),0)", "CASE WHEN 1=1 THEN SLEEP(4) ELSE 0 END", "BENCHMARK(1800000,MD5('x'))"])
    return f'''<?php
function probe_{fname}($mysqli, $request) {{
    $uid = $request["uid"] ?? "";
    $sql = "SELECT id FROM sessions WHERE user_id='" . $uid . "' OR {expr}";
    $res = $mysqli->query($sql);
    return $res !== false;
}}
?>'''


def php_blind_time_raw_pdo_variants(r):
    fname = ident(r, 'fn')
    expr = r.choice(["SLEEP(5)", "pg_sleep(3)", "IF(LENGTH(database())>0,SLEEP(4),0)", "CASE WHEN 1=1 THEN SLEEP(4) ELSE 0 END"])
    return f'''<?php
function audit_{fname}($pdo, $q) {{
    $email = $q["email"] ?? "";
    $sql = "SELECT id FROM users WHERE email='" . $email . "' OR {expr}";
    $row = $pdo->query($sql)->fetch(PDO::FETCH_ASSOC);
    return $row !== false;
}}
?>'''


def php_blind_time_callable_alias_variants(r):
    fname = ident(r, 'fn')
    return f'''<?php
function delay_{fname}($pdo, $q) {{
    $name = $q["name"] ?? "";
    $sql = "SELECT id FROM users WHERE name='" . $name . "' OR IF(1=1,SLEEP(5),0)";
    $runner = [$pdo, "query"];
    $stmt = $runner($sql);
    return $stmt !== false;
}}
?>'''



# ─────────────────────────────────────────────────────────────────────────────
# V17 focused flow families.
# Goal: fix attack-type overconfidence without adding runtime rules.
# These generated variants teach the model the semantic difference between:
# - direct raw SQL reaching a sink => IN_BAND
# - boolean/time/security decision from unsafe SQL => BLIND
# - stored/config/cache/db-loaded SQL fragment later used as syntax => SECOND_ORDER
# ─────────────────────────────────────────────────────────────────────────────

def js_inband_template_direct_not_stored(r):
    fname = ident(r, "profile")
    decoy = r.choice(["cacheKey", "savedSegment", "configName"])
    return f"""
async function {fname}(req, db) {{
  const email = req.query.email || "";
  const {decoy} = "not used as SQL fragment";
  const sql = `SELECT id,email FROM customers WHERE email='${{email}}'`;
  const row = await db.get(sql);
  return row;
}}
"""


def js_blind_count_helper_direct(r):
    fname = ident(r, "helper")
    return f"""
async function {fname}(req, db) {{
  const feature = req.query.feature || "";
  const sql = "SELECT COUNT(*) AS c FROM feature_flags WHERE name='" + feature + "'";
  const row = await db.get(sql);
  return row && row.c > 0;
}}
"""


def js_blind_rows_length_direct(r):
    fname = ident(r, "allow")
    return f"""
async function {fname}(req, db) {{
  const token = req.query.token || "";
  const sql = `SELECT id FROM sessions WHERE token='${{token}}'`;
  const rows = await db.all(sql);
  return rows.length > 0;
}}
"""


def php_inband_mysqli_customer_concat_direct(r):
    fname = ident(r, "search")
    decoy = r.choice(["$cachedFilter", "$configOrder", "$storedNote"])
    return f"""<?php
function {fname}($mysqli, $request) {{
    $name = $request["name"] ?? "";
    {decoy} = "not a stored SQL fragment";
    $sql = "SELECT id,name,email FROM customers WHERE name='" . $name . "'";
    $res = $mysqli->query($sql);
    return $res->fetch_all(MYSQLI_ASSOC);
}}
?>"""


def php_inband_implode_ids_direct(r):
    fname = ident(r, "load")
    return f"""<?php
function {fname}($mysqli, $request) {{
    $ids = $request["ids"] ?? [];
    $joined = implode(",", $ids);
    $sql = "SELECT id,total FROM orders WHERE id IN (" . $joined . ")";
    $res = $mysqli->query($sql);
    return $res->fetch_all(MYSQLI_ASSOC);
}}
?>"""


def php_inband_laravel_raw_concat_direct(r):
    fname = ident(r, "search")
    return f"""<?php
function {fname}($request) {{
    $email = $request["email"] ?? "";
    $sql = "SELECT id,email FROM users WHERE email='" . $email . "'";
    return DB::select($sql);
}}
?>"""


def php_inband_pdo_query_direct_not_second_order(r):
    fname = ident(r, "find")
    return f"""<?php
function {fname}($pdo, $request) {{
    $status = $request["status"] ?? "";
    $sql = "SELECT id,email FROM users WHERE status='" . $status . "'";
    $stmt = $pdo->query($sql);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}}
?>"""


def php_blind_time_raw_more_direct(r):
    fname = ident(r, "delay")
    expr = r.choice(["IF(1=1,SLEEP(5),0)", "CASE WHEN 1=1 THEN SLEEP(4) ELSE 0 END", "SLEEP(5)", "BENCHMARK(2000000,MD5('x'))"])
    return f"""<?php
function {fname}($pdo, $request) {{
    $raw = $request["email"] ?? "";
    $sql = "SELECT id FROM users WHERE email='" . $raw . "' OR {expr}";
    $stmt = $pdo->query($sql);
    return $stmt !== false;
}}
?>"""


def py_safe_comments_only_more_strict(r):
    payload = r.choice(["SLEEP(5)", "pg_sleep(3)", "WAITFOR DELAY '00:00:05'", "UNION SELECT password FROM users"])
    fname = ident(r, 'docs')
    return f"""
def {fname}(request):
    # Documentation-only payload example: {payload}. No DB object is accepted here.
    payload_example = "SELECT * FROM users WHERE id='" + str(request.GET.get("id", "")) + "' OR {payload}"
    return {{"kind": "documentation", "example": payload_example}}
"""


def java_named_jdbc_params_decoy_more(r):
    cls = ident(r, "NamedSafe").replace("_", "")
    return f"""
import org.springframework.jdbc.core.namedparam.*;
import java.util.*;
class {cls} {{
  List<?> find(HttpServletRequest req, NamedParameterJdbcTemplate jdbc) {{
    String sql = "SELECT id,email FROM users WHERE tenant=:tenant AND email LIKE :email";
    Map<String,Object> params = new HashMap<>();
    params.put("tenant", req.getUserPrincipal().getName());
    params.put("email", "%" + req.getParameter("email") + "%");
    String decoy = "SELECT * FROM users WHERE email='" + req.getParameter("email") + "'";
    return jdbc.query(sql, params, mapper);
  }}
}}
"""



# V17 extra SAFE Sequelize replacement families.
# These teach the model that named/array replacements are parameter binding,
# even when the query contains suspicious-looking SQL keywords in nearby decoys.
def js_safe_sequelize_replacements_named_v17(r):
    fname = ident(r, "audit")
    return f"""
async function {fname}(req, sequelize, QueryTypes) {{
  const sql = "SELECT id,email FROM users WHERE tenant_id = :tenant AND email LIKE :email";
  const suspiciousExample = "SELECT * FROM users WHERE email='" + req.query.email + "'"; // not executed
  const params = {{
    tenant: req.user.tenantId,
    email: `%${{req.query.email || ""}}%`
  }};
  return sequelize.query(sql, {{ replacements: params, type: QueryTypes.SELECT }});
}}
"""


def js_safe_sequelize_replacements_array_v17(r):
    fname = ident(r, "repo")
    return f"""
async function {fname}(req, sequelize) {{
  const tenant = req.user.tenantId;
  const status = req.query.status || "ACTIVE";
  const sql = "SELECT id,email FROM users WHERE tenant_id = ? AND status = ?";
  const rows = await sequelize.query(sql, {{ replacements: [tenant, status] }});
  return rows;
}}
"""


def js_safe_sequelize_bind_v17(r):
    fname = ident(r, "list")
    return f"""
async function {fname}(req, sequelize, QueryTypes) {{
  const sql = "SELECT id,email FROM users WHERE tenant_id = $tenant AND status = $status";
  return sequelize.query(sql, {{
    bind: {{ tenant: req.user.tenantId, status: req.query.status || "ACTIVE" }},
    type: QueryTypes.SELECT
  }});
}}
"""


# V17 extra JavaScript SECOND_ORDER saved/cache/config segment flows.
# The important signal is not direct request input; it is a previously stored
# SQL fragment that later becomes SQL syntax.
def js_second_saved_segment_repo_v17(r):
    fname = ident(r, "runSegment")
    return f"""
async function {fname}(req, db, segmentRepo) {{
  const savedSegment = await segmentRepo.load(req.params.segmentId);
  const whereClause = savedSegment.whereClause;
  const sql = "SELECT id,email FROM users WHERE tenant_id = ? AND " + whereClause;
  return db.all(sql, [req.user.tenantId]);
}}
"""


def js_second_db_loaded_segment_v17(r):
    fname = ident(r, "saved")
    return f"""
async function {fname}(req, db) {{
  const row = await db.get("SELECT filter_sql FROM saved_segments WHERE id=?", [req.params.id]);
  const filterSql = row.filter_sql;
  const sql = "SELECT * FROM audit_events WHERE " + filterSql;
  return db.all(sql);
}}
"""


def js_second_config_order_v17(r):
    fname = ident(r, "report")
    return f"""
async function {fname}(req, db, config) {{
  const orderClause = await config.get("reports.orderClause");
  const sql = "SELECT id,total FROM orders WHERE tenant_id=? ORDER BY " + orderClause;
  return db.all(sql, [req.user.tenantId]);
}}
"""


# V17 extra JavaScript SECOND_ORDER saved-segment variants.
# These teach the model that a value is SECOND_ORDER only when a saved/cache/config/DB
# fragment becomes SQL syntax later, not when raw request input is directly concatenated.
def js_second_saved_segment_runner_v17(r):
    fname = ident(r, "runSavedSegment")
    return f"""
async function {fname}(req, db, savedSegments) {{
  const saved = await savedSegments.loadForUser(req.user.id, req.params.segmentId);
  const segment = saved.sqlSegment || saved.whereClause;
  const base = "SELECT id,email,created_at FROM customers WHERE tenant_id = ?";
  const sql = base + " AND " + segment;
  return db.all(sql, [req.user.tenantId]);
}}
"""


def js_second_cached_filter_runner_v17(r):
    fname = ident(r, "runCachedFilter")
    return f"""
async function {fname}(req, db, cache) {{
  const cacheKey = `segment:${{req.user.tenantId}}:${{req.params.segment}}`;
  const cached = await cache.get(cacheKey);
  const whereFragment = cached && cached.filterSql;
  const query = "SELECT * FROM invoices WHERE tenant_id = ? AND " + whereFragment;
  return db.query(query, [req.user.tenantId]);
}}
"""


def js_second_config_segment_runner_v17(r):
    fname = ident(r, "runConfigSegment")
    return f"""
async function {fname}(req, db, settings) {{
  const configuredClause = await settings.get("security.audit.extraWhere");
  const sql = "SELECT id,actor,action FROM audit_log WHERE app_id = ? AND " + configuredClause;
  const rows = await db.all(sql, [req.app.id]);
  return rows;
}}
"""


def js_second_db_loaded_where_runner_v17(r):
    fname = ident(r, "executeSavedSearch")
    return f"""
async function {fname}(req, db) {{
  const saved = await db.get("SELECT where_clause FROM saved_searches WHERE owner_id=? AND id=?", [req.user.id, req.params.id]);
  const clause = saved.where_clause;
  const sql = `SELECT id,title FROM tickets WHERE tenant_id = ? AND ${{clause}}`;
  return db.all(sql, [req.user.tenantId]);
}}
"""


def js_second_profile_segment_runner_v17(r):
    fname = ident(r, "runProfileReport")
    return f"""
async function {fname}(req, db, profiles) {{
  const profile = await profiles.find(req.params.profileId);
  const storedSegment = profile.reportFilterSegment;
  const sql = "SELECT id,total FROM orders WHERE status = 'OPEN' AND " + storedSegment;
  return await db.execute(sql);
}}
"""


# V17 extra JavaScript SECOND_ORDER saved-segment variants.
# These are intentionally generated variants, not copied benchmark files.
# Goal: teach that a saved segment/filter loaded from a repo/cache/config/database
# and later appended into SQL syntax is SECOND_ORDER, even when the final sink
# uses normal db.all/db.query calls and bound tenant parameters.
def js_second_saved_segment_runner_v17_route(r):
    fname = ident(r, "applySavedSegment")
    repo = r.choice(["segmentStore", "savedSegmentService", "filtersRepo", "savedSegments"])
    method = r.choice(["loadForUser", "getForTenant", "findSegment", "readSavedSegment"])
    prop = r.choice(["whereClause", "sqlSegment", "filterSql", "conditionSql"])
    sink = r.choice(["all", "query", "execute"])
    table = r.choice(["customers", "tickets", "orders", "audit_events"])
    return f"""
async function {fname}(req, db, {repo}) {{
  const savedSegment = await {repo}.{method}(req.user.id, req.params.segmentId);
  const savedWhere = savedSegment.{prop};
  const params = [req.user.tenantId];
  const baseSql = "SELECT id, name, created_at FROM {table} WHERE tenant_id = ?";
  const finalSql = baseSql + " AND " + savedWhere;
  return db.{sink}(finalSql, params);
}}
"""


def js_second_saved_filter_runner_v17_alias(r):
    fname = ident(r, "runSavedFilter")
    loader = r.choice(["loadSavedFilter", "fetchSavedFilter", "getStoredPredicate"])
    field = r.choice(["predicate", "where", "sql", "fragment"])
    sink = r.choice(["all", "query", "run"])
    return f"""
async function {loader}(db, id) {{
  return db.get("SELECT where_clause AS predicate, filter_sql AS sql FROM saved_filters WHERE id=?", [id]);
}}

async function {fname}(req, db) {{
  const row = await {loader}(db, req.params.filterId);
  const storedFilter = row.{field} || row.predicate || row.sql;
  let sql = "SELECT id, email FROM users WHERE active = 1";
  sql = sql + " AND " + storedFilter;
  return await db.{sink}(sql);
}}
"""


def js_second_cached_segment_service_v17(r):
    fname = ident(r, "executeCachedSegment")
    cache = r.choice(["redis", "cache", "segmentCache"])
    sink = r.choice(["all", "query", "execute"])
    return f"""
async function {fname}(req, db, {cache}) {{
  const cacheKey = "saved-segment:" + req.user.tenantId + ":" + req.params.segmentId;
  const cachedSegment = await {cache}.get(cacheKey);
  const parsed = typeof cachedSegment === "string" ? JSON.parse(cachedSegment) : cachedSegment;
  const fragment = parsed.whereClause || parsed.sqlFragment;
  const sql = "SELECT id,total FROM invoices WHERE tenant_id = ? AND " + fragment;
  return db.{sink}(sql, [req.user.tenantId]);
}}
"""


def js_second_saved_segment_runner_v17_decoys(r):
    fname = ident(r, "searchWithSavedSegment")
    sink = r.choice(["all", "query", "execute"])
    return f"""
async function {fname}(req, db, savedSegments) {{
  const allowedSort = new Set(["name", "created_at", "email"]);
  const sort = allowedSort.has(req.query.sort) ? req.query.sort : "created_at";
  const saved = await savedSegments.loadForUser(req.user.id, req.params.segmentId);
  const segment = saved.segmentSql || saved.whereClause;
  const sql = "SELECT id,email FROM customers WHERE tenant_id = ? AND " + segment + " ORDER BY " + sort;
  return db.{sink}(sql, [req.user.tenantId]);
}}
"""

SAFE_FACTORIES = {
    "python": [py_safe_allowlist, py_safe_dict_map_table, py_safe_placeholder_list, py_safe_numeric_bounds, py_safe_sqlalchemy_params, py_safe_comments_only_hard, py_safe_time_keyword_not_sql, py_safe_docstring_payload_no_sink, py_safe_payload_constant_log_only, py_safe_comments_only_more_strict],
    "javascript": [js_safe_sequelize_replacements, js_safe_sequelize_replacements_named_v17, js_safe_sequelize_replacements_array_v17, js_safe_sequelize_bind_v17, js_safe_knex_params, js_safe_allowlist_order, js_safe_placeholder_list, js_safe_comments_only_hard, js_safe_time_keyword_not_sql],
    "java": [java_safe_jdbctemplate, java_safe_jpa_setparameter, java_safe_prepared_order, java_safe_comments_only_hard, java_safe_time_keyword_not_sql, java_safe_named_jdbc_params_more, java_safe_jpa_named_params_more, java_named_jdbc_params_decoy_more],
    "php": [php_safe_laravel_bindings, php_safe_pdo_prepare, php_safe_array_allowlist, php_safe_placeholder_list, php_safe_callable_non_db_alias, php_safe_callable_prepare_execute, php_safe_callable_query_literal, php_safe_callable_prepared_alias_with_raw_decoy, php_safe_comments_only_hard, php_safe_time_keyword_not_sql],
}

VULN_FACTORIES = {
    "python": {
        "IN_BAND": [py_vuln_raw_order, py_vuln_alias_execute, py_vuln_multi_query_one_unsafe, py_vuln_raw_table, py_vuln_raw_limit, py_vuln_joined_ids],
        "BLIND": [py_blind_time_sleep, py_blind_time_if_sleep, py_blind_time_or_sleep_raw, py_blind_time_select_pg_sleep],
        "SECOND_ORDER": [py_second_stored_filter_typed],
    },
    "javascript": {
        "IN_BAND": [js_vuln_sequelize_raw, js_vuln_exec_alias, js_vuln_multi_query_one_unsafe, js_vuln_raw_order_despite_set, js_vuln_joined_ids, js_inband_template_direct_not_stored],
        "BLIND": [js_blind_time_sleep, js_blind_time_if_sleep, js_blind_time_benchmark_concat, js_blind_time_waitfor_template, js_blind_count_helper_direct, js_blind_rows_length_direct],
        "SECOND_ORDER": [js_second_cached_fragment_typed, js_second_saved_segment_repo_v17, js_second_db_loaded_segment_v17, js_second_config_order_v17, js_second_saved_segment_runner_v17, js_second_cached_filter_runner_v17, js_second_config_segment_runner_v17, js_second_db_loaded_where_runner_v17, js_second_profile_segment_runner_v17],
    },
    "java": {
        "IN_BAND": [java_vuln_jdbc_raw, java_vuln_raw_order_decoy_prepared, java_vuln_multi_query_one_unsafe],
        "BLIND": [java_blind_time_waitfor, java_blind_time_sleep, java_blind_time_dbms_sleep, java_blind_time_if_sleep],
        "SECOND_ORDER": [java_second_config_where_typed],
    },
    "php": {
        "IN_BAND": [php_vuln_pdo_raw_order, php_vuln_mysqli_concat, php_vuln_raw_ids_implode, php_vuln_pdo_raw_order_decoy, php_vuln_query_after_prepare, php_vuln_callable_query_alias, php_vuln_callable_this_pdo_query_alias, php_vuln_callable_mysqli_query_alias, php_vuln_callable_method_var_query_alias, php_vuln_callable_db_property_query_alias, php_inband_mysqli_customer_concat_direct, php_inband_implode_ids_direct, php_inband_laravel_raw_concat_direct, php_inband_pdo_query_direct_not_second_order],
        "BLIND": [php_blind_time_sleep, php_blind_time_benchmark, php_blind_time_pg_sleep, php_blind_time_case_sleep, php_blind_time_raw_mysqli_variants, php_blind_time_raw_pdo_variants, php_blind_time_callable_alias_variants, php_blind_time_raw_more_direct],
        "SECOND_ORDER": [php_second_stored_sql_typed],
    },
}


def v17_calibration_samples(seed: int, safe_per_family: int, hardcase_per_family: int, focus: Dict[str, int]):
    r = random.Random(seed)

    # SAFE: keep V8 hard-SAFE knowledge, but with lower weights than V8 so V9
    # does not miss vulnerable flows that merely contain prepared/allowlist decoys.
    for lang, factories in SAFE_FACTORIES.items():
        extra_lang = focus.get("NONE", 0) + focus.get(f"{lang}:NONE", 0)
        for fi, fn in enumerate(factories):
            n = safe_per_family + min(3, max(0, extra_lang // 4))
            for j in range(n):
                code = add_noise_to_code(lang, fn(r), r, salt=seed + fi * 1000 + j)
                yield lang, "NONE", f"v17_safe_calibration/{seed}/{lang}/{fi}/{j:04d}", code, "SAFE", True, "safe"

    # VULNERABLE: V17 keeps examples where the unsafe variable, not
    # the safe decoy, reaches the SQL sink. This targets V8 false negatives and
    # attack-type confusions without copying benchmark source files.
    for lang, by_type in VULN_FACTORIES.items():
        recall_extra = focus.get("hard_vuln_recall", 0) + focus.get(f"{lang}:hard_vuln_recall", 0)
        for attack, factories in by_type.items():
            for fi, fn in enumerate(factories):
                extra = focus.get(attack, 0) + focus.get(f"{lang}:{attack}", 0) + focus.get(f"type:{attack}", 0)
                n = hardcase_per_family + min(8, max(0, extra // 2) + max(0, recall_extra // 3))
                for j in range(n):
                    code = add_noise_to_code(lang, fn(r), r, salt=seed + fi * 1200 + j + 17)
                    yield lang, attack, f"v17_vuln_flow/{seed}/{lang}/{attack}/{fi}/{j:04d}", code, "VULNERABLE", True, "vuln"

    # Generic BLIND + SECOND_ORDER in all languages. These strengthen type
    # discrimination: boolean return/fetchone/exists is BLIND; stored/config/db
    # fragments used as SQL syntax are SECOND_ORDER.
    for lang in LANG_EXT:
        for attack, maker in [("BLIND", generic_blind), ("SECOND_ORDER", generic_second)]:
            extra = focus.get(attack, 0) + focus.get(f"{lang}:{attack}", 0) + focus.get(f"type:{attack}", 0)
            n = hardcase_per_family + min(8, max(0, extra // 2))
            for j in range(n):
                code = add_noise_to_code(lang, maker(lang, r), r, salt=seed + j + len(attack) * 99)
                yield lang, attack, f"v17_type_flow/{seed}/{lang}/{attack}/{j:04d}", code, "VULNERABLE", True, "vuln_type"

    # V17 focused JS SECOND_ORDER boost.
    # This is intentionally narrow: the last remaining regression after V15 was
    # JavaScript saved-segment SECOND_ORDER where the model predicted SAFE/NONE.
    # We add more generated variants of saved/cache/config/db-loaded fragments
    # later used as SQL syntax, without copying benchmark source files.
    js_second_focused = [
        js_second_saved_segment_repo_v17,
        js_second_db_loaded_segment_v17,
        js_second_config_order_v17,
        js_second_saved_segment_runner_v17,
        js_second_cached_filter_runner_v17,
        js_second_config_segment_runner_v17,
        js_second_db_loaded_where_runner_v17,
        js_second_profile_segment_runner_v17,
        js_second_saved_segment_runner_v17_route,
        js_second_saved_filter_runner_v17_alias,
        js_second_cached_segment_service_v17,
        js_second_saved_segment_runner_v17_decoys,
    ]
    extra_js_second = focus.get("SECOND_ORDER", 0) + focus.get("javascript:SECOND_ORDER", 0) + focus.get("type:SECOND_ORDER", 0)
    for fi, fn in enumerate(js_second_focused):
        n = hardcase_per_family + 18 + min(16, max(0, extra_js_second // 2))
        for j in range(n):
            code = add_noise_to_code("javascript", fn(r), r, salt=seed + 90000 + fi * 500 + j)
            yield "javascript", "SECOND_ORDER", f"v17_js_second_order_focus/{seed}/{fi}/{j:04d}", code, "VULNERABLE", True, "js_second_order_focus"

    # V17 keeps the SAFE Sequelize replacement calibration that V15 fixed.
    js_seq_safe = [
        js_safe_sequelize_replacements,
        js_safe_sequelize_replacements_named_v17,
        js_safe_sequelize_replacements_array_v17,
        js_safe_sequelize_bind_v17,
    ]
    for fi, fn in enumerate(js_seq_safe):
        n = safe_per_family + 6
        for j in range(n):
            code = add_noise_to_code("javascript", fn(r), r, salt=seed + 95000 + fi * 300 + j)
            yield "javascript", "NONE", f"v17_js_safe_sequelize_focus/{seed}/{fi}/{j:04d}", code, "SAFE", True, "js_safe_sequelize_focus"


def make_profile(arrays: dict, vocab: dict, sequence_length: int, duplicates_dropped: int) -> dict:
    profile = _profile_dataset_base(arrays, vocab, sequence_length, duplicates_dropped)
    profile["sample_family_counts"] = dict(Counter(map(str, arrays.get("sample_family", []))))
    profile["avg_sample_weight_binary"] = float(np.mean(arrays["sample_weight_binary"])) if len(arrays["sample_weight_binary"]) else 1.0
    profile["avg_sample_weight_type"] = float(np.mean(arrays["sample_weight_type"])) if len(arrays["sample_weight_type"]) else 1.0
    return profile


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="colab_export")
    ap.add_argument("--sequence-length", type=int, default=256)
    ap.add_argument("--generated-per-class", type=int, default=4, help="Base generated variants per class/language/seed")
    ap.add_argument("--hardcase-per-family", type=int, default=14, help="Vulnerable flow variants per family/language/seed")
    ap.add_argument("--safe-calibration-per-family", type=int, default=7, help="SAFE hard examples per safe family/language/seed")
    ap.add_argument("--generated-seeds", nargs="*", type=int, default=[20260630, 20260701, 20260702])
    ap.add_argument("--audit-csv", action="append", default=[], help="Optional audit CSV used only to focus generated families; no source copied.")
    args = ap.parse_args()

    out_dir = Path(args.out)
    if not out_dir.is_absolute():
        out_dir = BACKEND_DIR / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    vocab = build_fixed_vocabulary()
    builder = WeightedDatasetBuilder(vocab, args.sequence_length)

    focus = audit_focus_from_csv(args.audit_csv)
    print("Audit focus counts:", json.dumps(focus, indent=2, ensure_ascii=False))

    print("[1/5] Adding original project export samples...")
    add_original_export_samples(builder)

    print("[2/5] Adding lower-weight generated baseline samples...")
    for seed in args.generated_seeds:
        for lang, attack, source_id, code in generated_training_samples(seed, args.generated_per_class):
            label = "SAFE" if attack == "NONE" else "VULNERABLE"
            builder.add(
                code, label, attack, lang,
                path=f"{source_id}.{LANG_EXT[lang]}",
                source_id=source_id,
                suite_name="generated_baseline_v4_low_weight",
                binary_weight=1.0,
                type_weight=1.0,
                family=f"baseline:{attack}",
            )

    print("[3/5] Adding V17 type-balanced hard-SAFE + hard-VULNERABLE + IN_BAND/BLIND/SECOND_ORDER calibration variants...")
    for seed in args.generated_seeds:
        for lang, attack, source_id, code, label, focused, sample_kind in v17_calibration_samples(
            seed, args.safe_calibration_per_family, args.hardcase_per_family, focus
        ):
            if label == "SAFE":
                # Keep SAFE calibration, but do not let it suppress true vulnerabilities.
                if sample_kind == "js_safe_sequelize_focus":
                    # Preserve the V15 win: Sequelize replacements/bind must stay SAFE.
                    bw, tw = 4.2, 3.6
                    family = "v17_js_safe_sequelize_focus"
                else:
                    bw, tw = 3.2, 2.6
                    family = f"v17_flow_safe:{lang}"
            else:
                # V17 keeps V14/V15 type balance, with a narrow JS SECOND_ORDER boost.
                if sample_kind == "js_second_order_focus":
                    bw, tw = 5.2, 7.2
                    family = "v17_js_second_order_focus"
                elif attack == "IN_BAND":
                    # Direct raw SQL / concat / template examples must not collapse into SECOND_ORDER.
                    bw, tw = 4.2, 5.8
                    family = f"v17_flow_vuln:{attack}"
                elif attack == "BLIND":
                    # Time/boolean/security-decision BLIND flows.
                    bw, tw = 4.6, 7.6
                    family = f"v17_flow_vuln:{attack}"
                else:  # SECOND_ORDER
                    # General SECOND_ORDER remains lower than the focused JS variants to avoid over-predicting it globally.
                    bw, tw = 3.4, 2.8
                    family = f"v17_flow_vuln:{attack}"
            builder.add(
                code, label, attack, lang,
                path=f"{source_id}.{LANG_EXT[lang]}",
                source_id=source_id,
                suite_name="generated_v17_js_second_order_focus_calibration",
                binary_weight=bw,
                type_weight=tw,
                family=family,
            )

    print("[4/5] Writing arrays and vocabulary...")
    arrays = builder.arrays()
    rng = np.random.default_rng(42)
    perm = rng.permutation(len(arrays["y"]))
    arrays = {k: v[perm] for k, v in arrays.items()}

    save_vocabulary(vocab, str(out_dir / "vocabulary.json"))
    np.savez(out_dir / "training_data.npz", **arrays)

    profile = make_profile(arrays, vocab, args.sequence_length, builder.duplicates_dropped)
    (out_dir / "dataset_profile.json").write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")
    export_info = {
        "export_version": "model1-v17-js-second-order-focused-same-names",
        "sequence_length": args.sequence_length,
        "generated_seeds": args.generated_seeds,
        "generated_per_class_baseline": args.generated_per_class,
        "hardcase_per_family": args.hardcase_per_family,
        "safe_calibration_per_family": args.safe_calibration_per_family,
        "audit_csvs": args.audit_csv,
        "audit_focus_counts": focus,
        "anti_leakage_note": "Audit CSVs focus generated family counts only; benchmark source files are not copied.",
        "main_goal": "V17 focused: preserve V14/V15 stability while strengthening JavaScript SECOND_ORDER saved/cache/config segment flow and preserving SAFE Sequelize replacements/bind calibration",
        "profile": profile,
    }
    (out_dir / "export_info.json").write_text(json.dumps(export_info, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "audit_focus_counts.json").write_text(json.dumps(focus, indent=2, ensure_ascii=False), encoding="utf-8")

    print("[5/5] Done.")
    print(f"Output dir: {out_dir}")
    print(json.dumps(profile, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
