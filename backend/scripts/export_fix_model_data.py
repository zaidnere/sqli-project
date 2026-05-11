# EXPORT_FIX_MODEL_DATA_MODEL2_ATTACK_ALL_V6_NO_RMTREE_MARKER
"""
Export calibrated training data for Model 2 Fix Recommendation.

Attack-all calibration v6 is Model-2-only:
- It does not modify Model 1 or its weights/vocabulary.
- It keeps the proposal architecture: frozen Model 1 embedding + semantic side features + dense softmax.
- It targets the real full-pipeline failure families without adding rule overrides:
  A vs C calibration, stronger PHP scalar-value cases, value-list/limit/offset cases,
  and stronger second-order stored/cache/config fragment cases.
"""
from __future__ import annotations

import argparse
import json
import random
import shutil
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

TABLES = ["users", "accounts", "customers", "orders", "reports", "audit_log", "profiles"]
ID_COLUMNS = ["id", "user_id", "account_id", "customer_id", "order_id", "profile_id", "actor_id"]
VALUE_VARS = ["uid", "user_id", "id", "email", "name", "accountId", "customerId", "resource", "actor", "token"]
SORT_VARS = ["sort_column", "sortColumn", "orderBy", "sort", "column", "field", "orderClause"]
TABLE_VARS = ["table", "tableName", "entity", "resource", "targetTable"]
FILTER_VARS = ["filters", "params", "criteria", "whereMap", "searchFields", "conditions"]
SAVED_VARS = ["saved_sql", "stored_filter", "report_sql", "cached_where", "savedFilter", "sql_text", "cachedFragment", "orderClause"]


def _pick(items: List[str], i: int) -> str:
    return items[i % len(items)]


def _template_A(language: str, i: int) -> Tuple[str, str]:
    """A: parameterized-query repair for scalar values, lists, limits/offsets, aliases."""
    table = _pick(TABLES, i)
    col = _pick(ID_COLUMNS, i)
    var = _pick(VALUE_VARS, i)
    if language == "python":
        patterns = [
            ("IN_BAND", f'''def get_user(cursor, {var}):\n    query = "SELECT * FROM {table} WHERE {col} = " + {var}\n    return cursor.execute(query).fetchall()\n'''),
            ("IN_BAND", f'''def find_user(cursor, name):\n    query = f"SELECT * FROM {table} WHERE name = '{{name}}'"\n    return cursor.execute(query).fetchall()\n'''),
            ("BLIND", f'''def exists_user(cursor, {var}):\n    query = "SELECT COUNT(*) AS c FROM {table} WHERE {col} = " + {var}\n    row = cursor.execute(query).fetchone()\n    return row["c"] > 0\n'''),
            ("BLIND", f'''def time_check(cursor, name):\n    sql = f"SELECT * FROM {table} WHERE name = '{{name}}' AND pg_sleep(1) IS NULL"\n    return cursor.execute(sql).fetchone()\n'''),
            ("IN_BAND", f'''def raw_alias(cursor, resource):\n    raw_query = "SELECT * FROM permissions WHERE actor_id=" + resource\n    sql = raw_query\n    return cursor.execute(sql).fetchone()\n'''),
            ("IN_BAND", f'''def multi_query(cursor, id):\n    safe = "SELECT 1"\n    query = "SELECT * FROM {table} WHERE {col} = " + id\n    return cursor.execute(query).fetchall()\n'''),
            ("IN_BAND", f'''def joined_ids(cursor, ids):\n    joined = ",".join(ids)\n    sql = "SELECT * FROM {table} WHERE id IN (" + joined + ")"\n    return cursor.execute(sql).fetchall()\n'''),
            ("IN_BAND", f'''def page(cursor, limit, offset):\n    query = "SELECT * FROM {table} LIMIT " + limit + " OFFSET " + offset\n    return cursor.execute(query).fetchall()\n'''),
            ("IN_BAND", f'''def alias_execute(conn, resource):\n    runner = conn.execute\n    q = "SELECT * FROM permissions WHERE actor_id=" + resource\n    return runner(q).fetchone()\n'''),
        ]
    elif language == "javascript":
        patterns = [
            ("IN_BAND", f'''async function getUser(db, id) {{\n  const query = "SELECT * FROM {table} WHERE {col} = " + id;\n  return db.all(query);\n}}\n'''),
            ("IN_BAND", f'''async function findUser(db, email) {{\n  const query = `SELECT * FROM {table} WHERE email = '${{email}}'`;\n  return db.all(query);\n}}\n'''),
            ("BLIND", f'''async function userExists(db, id) {{\n  const query = "SELECT COUNT(*) AS c FROM {table} WHERE {col} = " + id;\n  const row = await db.get(query);\n  return row.c > 0;\n}}\n'''),
            ("BLIND", f'''async function blindSleep(db, name) {{\n  const sql = `SELECT * FROM {table} WHERE name = '${{name}}' AND SLEEP(1)=0`;\n  return db.get(sql);\n}}\n'''),
            ("IN_BAND", f'''async function aliasRaw(db, resource) {{\n  const raw = "SELECT * FROM permissions WHERE actor_id=" + resource;\n  const q = raw;\n  return db.get(q);\n}}\n'''),
            ("IN_BAND", f'''async function joinedIds(db, ids) {{\n  const joined = ids.join(",");\n  const sql = "SELECT * FROM {table} WHERE id IN (" + joined + ")";\n  return db.all(sql);\n}}\n'''),
            ("IN_BAND", f'''async function paging(db, limit, offset) {{\n  const sql = "SELECT * FROM {table} LIMIT " + limit + " OFFSET " + offset;\n  return db.all(sql);\n}}\n'''),
            ("IN_BAND", f'''async function requestWhere(db, req) {{\n  const whereValue = req.query.name;\n  const query = "SELECT * FROM {table} WHERE name = '" + whereValue + "'";\n  return db.all(query);\n}}\n'''),
        ]
    elif language == "java":
        patterns = [
            ("IN_BAND", f'''ResultSet getUser(Connection conn, String id) throws Exception {{\n    String sql = "SELECT * FROM {table} WHERE {col} = " + id;\n    return conn.createStatement().executeQuery(sql);\n}}\n'''),
            ("IN_BAND", f'''List<User> findUser(JdbcTemplate jdbc, String email) {{\n    String sql = "SELECT * FROM {table} WHERE email = '" + email + "'";\n    return jdbc.query(sql);\n}}\n'''),
            ("IN_BAND", f'''List<User> springConcat(JdbcTemplate jdbc, String id) {{\n    String query = "SELECT * FROM {table} WHERE id = " + id;\n    return jdbc.query(query);\n}}\n'''),
            ("BLIND", f'''boolean exists(Connection conn, String id) throws Exception {{\n    String sql = "SELECT COUNT(*) FROM {table} WHERE {col} = " + id;\n    ResultSet rs = conn.createStatement().executeQuery(sql);\n    return rs.next();\n}}\n'''),
            ("IN_BAND", f'''ResultSet alias(Connection conn, String resource) throws Exception {{\n    String raw = "SELECT * FROM permissions WHERE actor_id=" + resource;\n    String sql = raw;\n    return conn.createStatement().executeQuery(sql);\n}}\n'''),
            ("IN_BAND", f'''ResultSet joinedIds(Connection conn, List<String> ids) throws Exception {{\n    String joined = String.join(",", ids);\n    String sql = "SELECT * FROM {table} WHERE id IN (" + joined + ")";\n    return conn.createStatement().executeQuery(sql);\n}}\n'''),
            ("IN_BAND", f'''ResultSet page(Connection conn, String limit, String offset) throws Exception {{\n    String sql = "SELECT * FROM {table} LIMIT " + limit + " OFFSET " + offset;\n    return conn.createStatement().executeQuery(sql);\n}}\n'''),
        ]
    elif language == "php":
        patterns = [
            ("IN_BAND", f'''<?php\nfunction getUser($pdo, $id) {{\n    $sql = "SELECT * FROM {table} WHERE {col} = " . $id;\n    return $pdo->query($sql)->fetch();\n}}\n?>\n'''),
            ("IN_BAND", f'''<?php\nfunction queryAlias($pdo, $id) {{\n    $raw = "SELECT * FROM {table} WHERE {col} = " . $id;\n    $sql = $raw;\n    return $pdo->query($sql)->fetchAll();\n}}\n?>\n'''),
            ("IN_BAND", f'''<?php\nfunction findUser($pdo, $email) {{\n    $sql = "SELECT * FROM {table} WHERE email = '" . $email . "'";\n    return $pdo->query($sql)->fetch();\n}}\n?>\n'''),
            ("BLIND", f'''<?php\nfunction existsUser($pdo, $id) {{\n    $sql = "SELECT COUNT(*) AS c FROM {table} WHERE {col} = " . $id;\n    return $pdo->query($sql)->fetchColumn() > 0;\n}}\n?>\n'''),
            ("BLIND", f'''<?php\nfunction blindCase($pdo, $name) {{\n    $sql = "SELECT * FROM {table} WHERE name='" . $name . "' AND SLEEP(1)=0";\n    return $pdo->query($sql)->fetchAll();\n}}\n?>\n'''),
            ("IN_BAND", f'''<?php\nfunction rawIds($pdo, $ids) {{\n    $joined = implode(",", $ids);\n    $sql = "SELECT * FROM {table} WHERE id IN (" . $joined . ")";\n    return $pdo->query($sql)->fetchAll();\n}}\n?>\n'''),
            ("IN_BAND", f'''<?php\nfunction page($pdo, $limit, $offset) {{\n    $sql = "SELECT * FROM {table} LIMIT " . $limit . " OFFSET " . $offset;\n    return $pdo->query($sql)->fetchAll();\n}}\n?>\n'''),
            ("IN_BAND", f'''<?php\nfunction mysqliCase($conn, $name) {{\n    $sql = "SELECT * FROM {table} WHERE name = '" . $name . "'";\n    return mysqli_query($conn, $sql);\n}}\n?>\n'''),
        ]
    else:
        raise KeyError(language)
    return patterns[i % len(patterns)]


def _template_B(language: str, i: int) -> Tuple[str, str]:
    """B: whitelist validation for dynamic identifiers."""
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
            ("IN_BAND", '''ResultSet listUsers(Connection conn, String sortColumn) throws Exception {\n    String sql = "SELECT * FROM users ORDER BY " + sortColumn;\n    return conn.createStatement().executeQuery(sql);\n}\n'''),
            ("IN_BAND", '''ResultSet readTable(Connection conn, String tableName) throws Exception {\n    String sql = "SELECT * FROM " + tableName;\n    return conn.createStatement().executeQuery(sql);\n}\n'''),
        ]
    elif language == "php":
        patterns = [
            ("IN_BAND", '''<?php\nfunction listUsers($pdo, $sort) {\n    $sql = "SELECT * FROM users ORDER BY " . $sort;\n    return $pdo->query($sql)->fetchAll();\n}\n?>\n'''),
            ("IN_BAND", '''<?php\nfunction readTable($pdo, $table) {\n    $sql = "SELECT * FROM " . $table;\n    return $pdo->query($sql)->fetchAll();\n}\n?>\n'''),
        ]
    else:
        raise KeyError(language)
    return patterns[i % len(patterns)]


def _template_C(language: str, i: int) -> Tuple[str, str]:
    """C: complex raw SQL construction that should migrate to structured query builders."""
    filters = _pick(FILTER_VARS, i)
    if language == "python":
        patterns = [
            ("IN_BAND", f'''def search(cursor, {filters}):\n    sql = "SELECT * FROM users WHERE 1=1"\n    for field, value in {filters}.items():\n        sql += " AND " + field + " = '" + value + "'"\n    return cursor.execute(sql).fetchall()\n'''),
            ("IN_BAND", f'''def report(cursor, {filters}):\n    where_parts = []\n    for key, val in {filters}.items():\n        where_parts.append(key + " LIKE '%" + val + "%'")\n    query = "SELECT * FROM users WHERE " + " AND ".join(where_parts)\n    return cursor.execute(query).fetchall()\n'''),
            ("IN_BAND", '''def helper_builder(cursor, filters):\n    query = build_user_search_sql(filters)\n    return cursor.execute(query).fetchall()\n'''),
            ("IN_BAND", '''def compose_report(cursor, criteria):\n    sql = composeReportQuery(criteria)\n    return cursor.execute(sql).fetchall()\n'''),
        ]
    elif language == "javascript":
        patterns = [
            ("IN_BAND", '''async function search(db, filters) {\n  let sql = "SELECT * FROM users WHERE 1=1";\n  for (const k of Object.keys(filters)) {\n    sql += " AND " + k + " = '" + filters[k] + "'";\n  }\n  return db.all(sql);\n}\n'''),
            ("IN_BAND", '''async function report(db, criteria) {\n  const parts = [];\n  for (const key in criteria) { parts.push(key + " LIKE '%" + criteria[key] + "%'"); }\n  const sql = "SELECT * FROM users WHERE " + parts.join(" AND ");\n  return db.all(sql);\n}\n'''),
            ("IN_BAND", '''async function helper(db, criteria) {\n  const sql = buildUserSearchQuery(criteria);\n  return db.all(sql);\n}\n'''),
            ("IN_BAND", '''async function clauseComposer(db, whereMap) {\n  const sql = composeWhereSql(whereMap);\n  return db.all(sql);\n}\n'''),
        ]
    elif language == "java":
        patterns = [
            ("IN_BAND", '''List<User> search(JdbcTemplate jdbc, Map<String,String> filters) {\n    String sql = "SELECT * FROM users WHERE 1=1";\n    for (String k : filters.keySet()) {\n        sql += " AND " + k + " = '" + filters.get(k) + "'";\n    }\n    return jdbc.query(sql);\n}\n'''),
            ("IN_BAND", '''ResultSet report(Connection conn, Map<String,String> criteria) throws Exception {\n    String where = "";\n    for (String key : criteria.keySet()) { where += " AND " + key + " LIKE '%" + criteria.get(key) + "%'"; }\n    String sql = "SELECT * FROM users WHERE 1=1" + where;\n    return conn.createStatement().executeQuery(sql);\n}\n'''),
            ("IN_BAND", '''ResultSet helper(Connection conn, Map<String,String> filters) throws Exception {\n    String sql = composeReportQuery(filters);\n    return conn.createStatement().executeQuery(sql);\n}\n'''),
            ("IN_BAND", '''ResultSet helperWhere(Connection conn, Map<String,String> whereMap) throws Exception {\n    String sql = buildDynamicWhereSql(whereMap);\n    return conn.createStatement().executeQuery(sql);\n}\n'''),
        ]
    elif language == "php":
        patterns = [
            ("IN_BAND", '''<?php\nfunction search($pdo, $filters) {\n    $sql = "SELECT * FROM users WHERE 1=1";\n    foreach ($filters as $k => $v) {\n        $sql .= " AND " . $k . " = '" . $v . "'";\n    }\n    return $pdo->query($sql)->fetchAll();\n}\n?>\n'''),
            ("IN_BAND", '''<?php\nfunction report($pdo, $criteria) {\n    $parts = [];\n    foreach ($criteria as $k => $v) { $parts[] = $k . " LIKE '%" . $v . "%'"; }\n    $sql = "SELECT * FROM users WHERE " . implode(" AND ", $parts);\n    return $pdo->query($sql)->fetchAll();\n}\n?>\n'''),
            ("IN_BAND", '''<?php\nfunction helper($pdo, $criteria) {\n    $sql = build_report_query($criteria);\n    return $pdo->query($sql)->fetchAll();\n}\n?>\n'''),
            ("IN_BAND", '''<?php\nfunction whereMap($pdo, $whereMap) {\n    $sql = compose_where_sql($whereMap);\n    return $pdo->query($sql)->fetchAll();\n}\n?>\n'''),
        ]
    else:
        raise KeyError(language)
    return patterns[i % len(patterns)]


def _template_D(language: str, i: int) -> Tuple[str, str]:
    """D: second-order cases: SQL fragments loaded from DB/config/cache/storage."""
    saved = _pick(SAVED_VARS, i)
    if language == "python":
        patterns = [
            ("SECOND_ORDER", f'''def run_saved(cursor, report_id):\n    row = cursor.execute("SELECT sql_text FROM reports WHERE id = ?", (report_id,)).fetchone()\n    {saved} = row["sql_text"]\n    return cursor.execute({saved}).fetchall()\n'''),
            ("SECOND_ORDER", '''def apply_saved_filter(cursor, user_id):\n    row = cursor.execute("SELECT saved_filter FROM users WHERE id = ?", (user_id,)).fetchone()\n    stored_filter = row["saved_filter"]\n    query = "SELECT * FROM users WHERE " + stored_filter\n    return cursor.execute(query).fetchall()\n'''),
            ("SECOND_ORDER", '''def cached_order(cursor, config):\n    order_clause = config.get("order_clause")\n    sql = "SELECT * FROM users ORDER BY " + order_clause\n    return cursor.execute(sql).fetchall()\n'''),
        ]
    elif language == "javascript":
        patterns = [
            ("SECOND_ORDER", '''async function runSaved(db, id) {\n  const row = await db.get("SELECT sql_text FROM reports WHERE id = ?", [id]);\n  const savedSql = row.sql_text;\n  return db.all(savedSql);\n}\n'''),
            ("SECOND_ORDER", '''async function applyCachedFilter(db, cacheKey) {\n  const savedFilter = await cache.get(cacheKey);\n  const sql = "SELECT * FROM users WHERE " + savedFilter;\n  return db.all(sql);\n}\n'''),
            ("SECOND_ORDER", '''async function cachedOrder(db, cacheKey) {\n  const orderClause = await cache.get(cacheKey);\n  const sql = "SELECT * FROM users ORDER BY " + orderClause;\n  return db.all(sql);\n}\n'''),
        ]
    elif language == "java":
        patterns = [
            ("SECOND_ORDER", '''ResultSet runSaved(Connection conn, String id) throws Exception {\n    PreparedStatement ps = conn.prepareStatement("SELECT sql_text FROM reports WHERE id = ?");\n    ps.setString(1, id);\n    ResultSet rs = ps.executeQuery();\n    String savedFilter = rs.getString("sql_text");\n    String sql = "SELECT * FROM users WHERE " + savedFilter;\n    return conn.createStatement().executeQuery(sql);\n}\n'''),
            ("SECOND_ORDER", '''ResultSet runConfigured(Connection conn, Config config) throws Exception {\n    String cachedWhere = config.get("where_clause");\n    String sql = "SELECT * FROM users WHERE " + cachedWhere;\n    return conn.createStatement().executeQuery(sql);\n}\n'''),
            ("SECOND_ORDER", '''ResultSet dbLoadedOrder(Connection conn, String id) throws Exception {\n    String orderClause = loadSavedOrder(conn, id);\n    String sql = "SELECT * FROM users ORDER BY " + orderClause;\n    return conn.createStatement().executeQuery(sql);\n}\n'''),
        ]
    elif language == "php":
        patterns = [
            ("SECOND_ORDER", '''<?php\nfunction runSaved($pdo, $id) {\n    $stmt = $pdo->prepare("SELECT sql_text FROM reports WHERE id = ?");\n    $stmt->execute([$id]);\n    $sql = $stmt->fetchColumn();\n    return $pdo->query($sql)->fetchAll();\n}\n?>\n'''),
            ("SECOND_ORDER", '''<?php\nfunction applyStoredFilter($pdo, $id) {\n    $stmt = $pdo->prepare("SELECT saved_filter FROM users WHERE id = ?");\n    $stmt->execute([$id]);\n    $storedFilter = $stmt->fetchColumn();\n    $sql = "SELECT * FROM users WHERE " . $storedFilter;\n    return $pdo->query($sql)->fetchAll();\n}\n?>\n'''),
            ("SECOND_ORDER", '''<?php\nfunction configOrder($pdo, $config) {\n    $orderClause = $config->get("order_clause");\n    $sql = "SELECT * FROM users ORDER BY " . $orderClause;\n    return $pdo->query($sql)->fetchAll();\n}\n?>\n'''),
        ]
    else:
        raise KeyError(language)
    return patterns[i % len(patterns)]


TEMPLATE_BY_FIX = {"A": _template_A, "B": _template_B, "C": _template_C, "D": _template_D}



def _official_failure_hardcase(language: str, fix: str, i: int) -> Tuple[str, str] | None:
    """Targeted families from the official Model1→Model2 strict full-pipeline review.

    These are training examples for Model 2 only. They are not runtime rules and they do
    not modify Model 1. The goal is to teach the classifier the remaining A/B/C/D
    distinctions seen in broad suites.
    """
    if i % 2 != 0:
        return None

    cases: dict[tuple[str, str], list[Tuple[str, str]]] = {
        ("python", "A"): [
            ("IN_BAND", """def search_by_email(self, request):
    email = norm(request.get("email"))
    sql = "SELECT id,email FROM customers WHERE email = '" + email + "'"
    return self.conn.execute(sql).fetchall()
"""),
            ("IN_BAND", """def lookup_fn_random(request, conn):
    email_abcdxyz = request.GET.get("email", "")
    sql_opaque = "SELECT * FROM users WHERE email = '" + email_abcdxyz + "'"
    return conn.execute(sql_opaque).fetchall()
"""),
            ("IN_BAND", """def find_user(conn, email):
    safe_demo = "SELECT id FROM users WHERE email = ?"
    sql = f"SELECT id, email FROM users WHERE email = '{email}'"
    return conn.execute(sql).fetchall()
"""),
            ("BLIND", """def valid_reset_token(conn, token):
    query = f"SELECT id FROM reset_tokens WHERE token = '{token}' AND used = 0"
    return bool(conn.execute(query).fetchone())
"""),
            ("IN_BAND", """def search_products(conn, keyword):
    cleaned = keyword.replace("'", "")
    sql = "SELECT id, name FROM products WHERE name LIKE '%" + cleaned + "%'"
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
"""),
            ("IN_BAND", """def search(self, request):
    cached_email = norm(request.get("email"))
    sql = "SELECT id,email FROM customers WHERE email='" + cached_email + "'"
    return self.conn.execute(sql).fetchall()
"""),
            ("BLIND", """def enabled(self, request):
    feature = norm(request.get("feature"))
    sql = "SELECT COUNT(*) FROM feature_flags WHERE feature_key='" + feature + "'"
    return self.count(sql) > 0
"""),
        ],
        ("javascript", "A"): [
            ("IN_BAND", """class DirectTemplate {
  async search(req) {
    const storedSegment = norm(req.query.q);
    const sql = `SELECT id,email FROM users WHERE email LIKE '%${storedSegment}%'`;
    return this.db.all(sql);
  }
}
"""),
            ("IN_BAND", """class RequestConfigWhereClauseRaw {
  async run(req) {
    const configWhereClause = norm(req.query.configWhereClause);
    const sql = "SELECT id,email FROM users WHERE tenant_id=? AND " + configWhereClause;
    return this.db.all(sql, [req.tenantId]);
  }
}
"""),
            ("IN_BAND", """class DirectSavedSegmentNameRaw {
  async search(req) {
    const savedSegment = norm(req.query.savedSegment);
    const sql = "SELECT id,email FROM users WHERE tenant_id=? AND " + savedSegment;
    return this.db.all(sql, [req.tenantId]);
  }
}
"""),
            ("IN_BAND", """class UnsafeHelperCalledButRequestUsed {
  async list(req) {
    const safe = safeSortColumn(req.query.sort);
    const sql = `SELECT id,email FROM users WHERE tenant_id=? ORDER BY ${req.query.sort}`;
    return this.db.all(sql, [req.tenantId]);
  }
}
"""),
        ],
        ("php", "A"): [
            ("BLIND", """<?php
function login($pdo, $u, $p) {
    $sql = "SELECT id FROM users WHERE username='$u' AND password='$p'";
    return (bool)$pdo->query($sql)->fetch();
}
?>
"""),
            ("BLIND", """<?php
function isFeatureEnabled($pdo, $userId, $flag) {
    $sql = "SELECT 1 FROM flags WHERE user_id=$userId AND name='$flag'";
    return $pdo->query($sql)->fetch() !== false;
}
?>
"""),
            ("BLIND", """<?php
function canEdit($pdo, $account, $project) {
    $sql = "SELECT 1 FROM perms WHERE account='$account' AND project='$project'";
    return (bool)$pdo->query($sql)->fetchColumn();
}
?>
"""),
        ],
        ("javascript", "C"): [
            ("IN_BAND", """class Repo {
  async run(sequelize, req) {
    const email = norm(req.query.email);
    const replacements = { email };
    const sql = `SELECT id,email FROM users WHERE email='${email}'`;
    return sequelize.query(sql, { replacements });
  }
}
"""),
            ("IN_BAND", """class UnsafeSequelizeTemplate {
  async run(sequelize, req) {
    const email = norm(req.query.email);
    const sql = `SELECT id,email FROM users WHERE email='${email}'`;
    return sequelize.query(sql);
  }
}
"""),
        ],
        ("java", "C"): [
            ("IN_BAND", """List<User> nativeFind(EntityManager em, String email) {
    String sql = "SELECT id,email FROM users WHERE email='" + email + "'";
    return em.createNativeQuery(sql).getResultList();
}
"""),
            ("IN_BAND", """List<User> nativeSearch(EntityManager em, Map<String,String> filters) {
    String sql = "SELECT * FROM users WHERE 1=1";
    for (String k : filters.keySet()) { sql += " AND " + k + "='" + filters.get(k) + "'"; }
    return em.createNativeQuery(sql).getResultList();
}
"""),
        ],
        ("python", "C"): [
            ("IN_BAND", """def build_query(name):
    return f"SELECT id, name FROM customers WHERE name = '{name}'"

def run_query(conn, statement):
    cur = conn.cursor()
    cur.execute(statement)
    return cur.fetchall()

def find_customer(conn, customer_name):
    q1 = build_query(customer_name)
    q2 = q1
    return run_query(conn, q2)
"""),
        ],
        ("python", "D"): [
            ("SECOND_ORDER", """def saved_widget_filter(cursor, widget_id):
    row = cursor.execute("SELECT saved_filter FROM widgets WHERE id = ?", (widget_id,)).fetchone()
    stored_filter = row["saved_filter"]
    sql = "SELECT * FROM widgets WHERE " + stored_filter
    return cursor.execute(sql).fetchall()
"""),
        ],
        ("javascript", "D"): [
            ("SECOND_ORDER", """async function runStoredQuery(db, id) {
  const row = await db.get("SELECT sql_text FROM reports WHERE id = ?", [id]);
  const storedSql = row.sql_text;
  return db.all(storedSql);
}
"""),
        ],
    }
    options = cases.get((language, fix))
    if not options:
        return None
    return options[(i // 2) % len(options)]


def make_sample(language: str, fix: str, i: int) -> Tuple[str, str]:
    special = _official_failure_hardcase(language, fix, i)
    if special is not None:
        attack_type, code = special
    else:
        attack_type, code = TEMPLATE_BY_FIX[fix](language, i)
    if i % 5 == 0:
        code = code.replace("users", _pick(TABLES, i + 1))
    if i % 7 == 0:
        code = "\n" + code
    if i % 11 == 0:
        comment = "# calibration-v5 hardcase variation\n" if language == "python" else "// calibration-v5 hardcase variation\n"
        code = code + "\n" + comment
    if i % 13 == 0 and fix == "A":
        # Add harmless helper/alias decoys to prevent over-learning C from helper-like names.
        decoy = "\n# helper decoy does not build SQL\n" if language == "python" else "\n// helper decoy does not build SQL\n"
        code = code + decoy
    return attack_type, code


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="colab_export_fix_v2")
    ap.add_argument("--samples-per-class-language", type=int, default=420)
    ap.add_argument("--seed", type=int, default=20260515)
    args = ap.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)

    vocab = build_fixed_vocabulary()
    out = Path(args.out)
    # Do not delete the export folder. Keep the workflow in one folder and overwrite only the files we generate.
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
        "exporterVersion": "model2_attack_all_v6",
        "n_samples": len(X),
        "fix_counts": {k: int(sum(v == idx for v in y_fix)) for k, idx in FIX_LABELS.items()},
        "language_counts": {k: int(sum(v == idx for v in language_id)) for k, idx in LANG.items()},
        "attack_type_counts": {k: int(sum(v == idx for v in attack_type_id)) for k, idx in ATTACK.items()},
        "evidence_features": EVIDENCE_FEATURES,
        "evidence_feature_count": len(EVIDENCE_FEATURES),
        "output_files": ["training_data.npz", "vocabulary.json", "dataset_profile.json"],
        "notes": [
            "Balanced by language and fix class.",
            "Attack-all calibration v6 targets A-vs-C overprediction, PHP scalar value SQLi, list/limit/offset value contexts, and stronger D stored-fragment contexts.",
            "Model 1 remains frozen/read-only; this export does not modify Model 1.",
        ],
    }
    (out / "dataset_profile.json").write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(profile, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
