r"""
Export Model-1 V9 flow-balanced training data for Google Colab.
This file replaces backend/scripts/export_for_colab.py with the SAME name.

Why V9 exists
-------------
V8 successfully taught the model many SAFE flows, but the V8 audit still showed
missed vulnerable flows and attack-type confusions in realistic files.

V9 focuses on balanced FLOW learning: keep the hard-SAFE knowledge from V8 while
adding stronger vulnerable-flow counterexamples so the model does not rely on
fusion for raw ORDER BY, raw identifiers, multi-query files, alias executes,
BLIND boolean sinks and SECOND_ORDER stored/config fragments:
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
      --hardcase-per-family 10 ^
      --safe-calibration-per-family 5 ^
      --generated-seeds 20260531 20260601 20260602 ^
      --audit-csv outputs\model_audit_mega_after_v8.csv ^
      --audit-csv outputs\model_audit_realistic_after_v8.csv ^
      --audit-csv outputs\model_audit_framework_after_v8.csv ^
      --audit-csv outputs\model_audit_enterprise_after_v8.csv ^
      --audit-csv outputs\model_audit_hard_after_v8.csv ^
      --audit-csv outputs\model_audit_targeted_after_v8.csv

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
                file_name = row.get("file") or ""
                exp_v = (row.get("expected_verdict") or "SAFE").strip().upper()
                exp_t = (row.get("expected_attack_type") or "NONE").strip().upper()
                ml_v = (row.get("ml_predicted_verdict") or "").strip().upper()
                ml_t = (row.get("ml_predicted_attack_type") or "").strip().upper()
                lang = file_name.split("/")[0].strip().lower() or "unknown"
                fam = _family_from_file(file_name)

                # The V9 target: balance SAFE specificity with vulnerable recall and attack-type accuracy.
                if exp_v == "SAFE" and ml_v == "VULNERABLE":
                    # Keep V8's hard-SAFE learning, but do not let SAFE drown out vulnerability recall.
                    counts["NONE"] += 1
                    counts[f"{lang}:NONE"] += 1
                    counts[fam] += 2
                elif exp_v == "VULNERABLE" and (ml_v != "VULNERABLE" or ml_t != exp_t):
                    # V9 gives stronger focus to vulnerable misses and type errors.
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
# V9 flow-balanced calibration families
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

SAFE_FACTORIES = {
    "python": [py_safe_allowlist, py_safe_dict_map_table, py_safe_placeholder_list, py_safe_numeric_bounds, py_safe_sqlalchemy_params],
    "javascript": [js_safe_sequelize_replacements, js_safe_knex_params, js_safe_allowlist_order, js_safe_placeholder_list],
    "java": [java_safe_jdbctemplate, java_safe_jpa_setparameter, java_safe_prepared_order],
    "php": [php_safe_laravel_bindings, php_safe_pdo_prepare, php_safe_array_allowlist, php_safe_placeholder_list],
}

VULN_FACTORIES = {
    "python": {
        "IN_BAND": [py_vuln_raw_order, py_vuln_alias_execute, py_vuln_multi_query_one_unsafe, py_vuln_raw_table, py_vuln_raw_limit, py_vuln_joined_ids],
        "BLIND": [],
        "SECOND_ORDER": [py_second_stored_filter_typed],
    },
    "javascript": {
        "IN_BAND": [js_vuln_sequelize_raw, js_vuln_exec_alias, js_vuln_multi_query_one_unsafe, js_vuln_raw_order_despite_set, js_vuln_joined_ids],
        "BLIND": [],
        "SECOND_ORDER": [js_second_cached_fragment_typed],
    },
    "java": {
        "IN_BAND": [java_vuln_jdbc_raw, java_vuln_raw_order_decoy_prepared, java_vuln_multi_query_one_unsafe],
        "BLIND": [],
        "SECOND_ORDER": [java_second_config_where_typed],
    },
    "php": {
        "IN_BAND": [php_vuln_pdo_raw_order, php_vuln_mysqli_concat, php_vuln_raw_ids_implode, php_vuln_pdo_raw_order_decoy, php_vuln_query_after_prepare],
        "BLIND": [],
        "SECOND_ORDER": [php_second_stored_sql_typed],
    },
}


def v9_calibration_samples(seed: int, safe_per_family: int, hardcase_per_family: int, focus: Dict[str, int]):
    r = random.Random(seed)

    # SAFE: keep V8 hard-SAFE knowledge, but with lower weights than V8 so V9
    # does not miss vulnerable flows that merely contain prepared/allowlist decoys.
    for lang, factories in SAFE_FACTORIES.items():
        extra_lang = focus.get("NONE", 0) + focus.get(f"{lang}:NONE", 0)
        for fi, fn in enumerate(factories):
            n = safe_per_family + min(3, max(0, extra_lang // 4))
            for j in range(n):
                code = add_noise_to_code(lang, fn(r), r, salt=seed + fi * 1000 + j)
                yield lang, "NONE", f"v9_safe_calibration/{seed}/{lang}/{fi}/{j:04d}", code, "SAFE", True, "safe"

    # VULNERABLE: V9 strongly expands examples where the unsafe variable, not
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
                    yield lang, attack, f"v9_vuln_flow/{seed}/{lang}/{attack}/{fi}/{j:04d}", code, "VULNERABLE", True, "vuln"

    # Generic BLIND + SECOND_ORDER in all languages. These strengthen type
    # discrimination: boolean return/fetchone/exists is BLIND; stored/config/db
    # fragments used as SQL syntax are SECOND_ORDER.
    for lang in LANG_EXT:
        for attack, maker in [("BLIND", generic_blind), ("SECOND_ORDER", generic_second)]:
            extra = focus.get(attack, 0) + focus.get(f"{lang}:{attack}", 0) + focus.get(f"type:{attack}", 0)
            n = hardcase_per_family + min(8, max(0, extra // 2))
            for j in range(n):
                code = add_noise_to_code(lang, maker(lang, r), r, salt=seed + j + len(attack) * 99)
                yield lang, attack, f"v9_type_flow/{seed}/{lang}/{attack}/{j:04d}", code, "VULNERABLE", True, "vuln_type"


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
    ap.add_argument("--hardcase-per-family", type=int, default=10, help="Vulnerable flow variants per family/language/seed")
    ap.add_argument("--safe-calibration-per-family", type=int, default=5, help="SAFE hard examples per safe family/language/seed")
    ap.add_argument("--generated-seeds", nargs="*", type=int, default=[20260531, 20260601, 20260602])
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

    print("[3/5] Adding V9 hard-SAFE + hard-VULNERABLE flow calibration variants...")
    for seed in args.generated_seeds:
        for lang, attack, source_id, code, label, focused, sample_kind in v9_calibration_samples(
            seed, args.safe_calibration_per_family, args.hardcase_per_family, focus
        ):
            if label == "SAFE":
                # Keep SAFE calibration, but lower than V8 to avoid suppressing true vulnerabilities.
                bw, tw = 3.2, 2.6
                family = f"v9_flow_safe:{lang}"
            else:
                # V9 restores vulnerable recall and improves attack-type discrimination.
                if attack == "IN_BAND":
                    bw, tw = 3.7, 3.2
                elif attack == "BLIND":
                    bw, tw = 3.4, 3.7
                else:  # SECOND_ORDER
                    bw, tw = 3.5, 3.9
                family = f"v9_flow_vuln:{attack}"
            builder.add(
                code, label, attack, lang,
                path=f"{source_id}.{LANG_EXT[lang]}",
                source_id=source_id,
                suite_name="generated_v9_flow_balanced_calibration",
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
        "export_version": "model1-v9-flow-balanced-same-names",
        "sequence_length": args.sequence_length,
        "generated_seeds": args.generated_seeds,
        "generated_per_class_baseline": args.generated_per_class,
        "hardcase_per_family": args.hardcase_per_family,
        "safe_calibration_per_family": args.safe_calibration_per_family,
        "audit_csvs": args.audit_csv,
        "audit_focus_counts": focus,
        "anti_leakage_note": "Audit CSVs focus generated family counts only; benchmark source files are not copied.",
        "main_goal": "teach raw CNN+BiLSTM model balanced data-flow: SAFE bound/allowlisted flow vs raw SQLi flow, BLIND boolean flow and SECOND_ORDER stored-fragment flow",
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
