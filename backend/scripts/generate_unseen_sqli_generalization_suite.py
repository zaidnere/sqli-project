r"""
Generate a new, randomized, unseen SQLi generalization suite.

The generator intentionally creates fresh variable/function names, comments,
whitespace, and harmless decoys so the detector cannot rely on exact filenames
or memorized code strings.

Run from backend/:
    venv\Scripts\python.exe scripts\generate_unseen_sqli_generalization_suite.py --out test_suites\unseen_generalization_suite.zip --per-class 8 --seed 20260506
"""
from __future__ import annotations

import argparse
import csv
import random
import string
import zipfile
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Callable, Dict, List, Tuple

LANG_EXT = {"python": ".py", "javascript": ".js", "java": ".java", "php": ".php"}
ATTACKS = ["SAFE", "IN_BAND", "BLIND", "SECOND_ORDER"]

WORDS = [
    "tenant", "invoice", "profile", "audit", "widget", "report", "session", "token",
    "customer", "account", "billing", "feature", "policy", "access", "order", "catalog",
]
SQL_TABLES = ["users", "orders", "invoices", "audit_log", "reports", "sessions", "profiles"]
COLS = ["id", "created_at", "email", "status", "name", "tenant_id", "updated_at"]


def ident(r: random.Random, prefix: str = "v") -> str:
    return prefix + "_" + "".join(r.choice(string.ascii_lowercase) for _ in range(7))


def comment(r: random.Random, lang: str) -> str:
    text = r.choice([
        "decoy: SELECT * FROM users WHERE id = raw_input",
        "הערה בעברית: לא להריץ SQL מתוך מחרוזת גולמית",
        "safe path uses parameters, unsafe path should be detected",
        "noise comment with SQL_CONCAT looking words but no sink",
    ])
    if lang in {"python"}:
        return f"# {text}"
    if lang in {"javascript", "java"}:
        return f"// {text}"
    return f"// {text}"


def py_safe(r: random.Random) -> str:
    order = ident(r, "order")
    limit = ident(r, "limit")
    q = ident(r, "q")
    table = r.choice(SQL_TABLES)
    col = r.choice(COLS)
    return f'''
{comment(r, 'python')}
def search_{ident(r, 'fn')}(request, conn):
    allowed = {{"created": "created_at", "email": "email", "name": "name"}}
    {order} = allowed.get(request.GET.get("sort"), "created_at")
    {limit} = min(max(int(request.GET.get("limit", 25)), 1), 100)
    {q} = "SELECT id, email FROM {table} WHERE tenant_id = ? ORDER BY " + {order} + " LIMIT ?"
    decoy = "SELECT * FROM {table} WHERE email = " + request.GET.get("email", "")
    return conn.execute({q}, (request.user.tenant_id, {limit})).fetchall()
'''


def py_inband(r: random.Random) -> str:
    email = ident(r, "email")
    sql = ident(r, "sql")
    return f'''
{comment(r, 'python')}
def lookup_{ident(r, 'fn')}(request, conn):
    {email} = request.GET.get("email", "")
    {sql} = "SELECT * FROM users WHERE email = '" + {email} + "'"
    return conn.execute({sql}).fetchall()
'''


def py_blind(r: random.Random) -> str:
    token = ident(r, "token")
    sql = ident(r, "sql")
    return f'''
def active_{ident(r, 'fn')}(request, conn):
    {token} = request.GET.get("token", "")
    {sql} = "SELECT id FROM sessions WHERE token = '" + {token} + "'"
    row = conn.execute({sql}).fetchone()
    return row is not None
'''


def py_second(r: random.Random) -> str:
    func = ident(r, "load")
    frag = ident(r, "frag")
    sql = ident(r, "sql")
    return f'''
def {func}(conn, tenant):
    row = conn.execute("SELECT where_clause FROM saved_filters WHERE tenant_id = ?", (tenant,)).fetchone()
    return row[0]

def run_{ident(r, 'fn')}(request, conn):
    {frag} = {func}(conn, request.user.tenant_id)
    {sql} = "SELECT * FROM audit_log WHERE " + {frag}
    return conn.execute({sql}).fetchall()
'''


def js_safe(r: random.Random) -> str:
    sort = ident(r, "sort")
    params = ident(r, "params")
    return f'''
{comment(r, 'javascript')}
async function list_{ident(r, 'fn')}(req, db) {{
  const allowed = new Set(["created_at", "email", "name"]);
  const {sort} = allowed.has(req.query.sort) ? req.query.sort : "created_at";
  const limit = Math.min(Math.max(Number(req.query.limit || 25), 1), 100);
  const sql = "SELECT id, email FROM users WHERE tenant_id = ? ORDER BY " + {sort} + " LIMIT ?";
  const decoy = `SELECT * FROM users WHERE email = '${{req.query.email}}'`;
  const {params} = [req.user.tenantId, limit];
  return db.all(sql, {params});
}}
'''


def js_inband(r: random.Random) -> str:
    return f'''
async function find_{ident(r, 'fn')}(req, db) {{
  const email = req.query.email || "";
  const sql = `SELECT * FROM users WHERE email = '${{email}}'`;
  return db.all(sql);
}}
'''


def js_blind(r: random.Random) -> str:
    return f'''
async function can_{ident(r, 'fn')}(req, db) {{
  const role = req.query.role || "";
  const sql = `SELECT id FROM permissions WHERE role = '${{role}}'`;
  const rows = await db.all(sql);
  return rows.length > 0;
}}
'''


def js_second(r: random.Random) -> str:
    return f'''
async function load_{ident(r, 'seg')}(db, id) {{
  const row = await db.get("SELECT query_sql FROM saved_segments WHERE id = ?", [id]);
  return row.query_sql;
}}
async function run_{ident(r, 'fn')}(req, db) {{
  const sql = await load_{ident(r, 'seg')}(db, req.params.id);
  return db.all(sql);
}}
'''


def java_safe(r: random.Random) -> str:
    cls = ident(r, "Repo").replace("_", "")
    return f'''
import java.sql.*; import java.util.*;
class {cls} {{
  List<String> list(HttpServletRequest req, Connection c) throws Exception {{
    Set<String> allowed = Set.of("created_at", "email", "name");
    String sort = allowed.contains(req.getParameter("sort")) ? req.getParameter("sort") : "created_at";
    int limit = Math.min(Math.max(Integer.parseInt(req.getParameter("limit")), 1), 100);
    String sql = "SELECT id,email FROM users WHERE tenant_id = ? ORDER BY " + sort + " LIMIT ?";
    PreparedStatement ps = c.prepareStatement(sql);
    ps.setString(1, req.getUserPrincipal().getName());
    ps.setInt(2, limit);
    ps.executeQuery();
    return List.of();
  }}
}}
'''


def java_inband(r: random.Random) -> str:
    cls = ident(r, "Svc").replace("_", "")
    return f'''
import java.sql.*;
class {cls} {{
  ResultSet find(HttpServletRequest req, Statement st) throws Exception {{
    String email = req.getParameter("email");
    String sql = "SELECT * FROM users WHERE email='" + email + "'";
    return st.executeQuery(sql);
  }}
}}
'''


def java_blind(r: random.Random) -> str:
    cls = ident(r, "Auth").replace("_", "")
    return f'''
import java.sql.*;
class {cls} {{
  boolean allowed(HttpServletRequest req, Statement st) throws Exception {{
    String token = req.getParameter("token");
    String sql = "SELECT id FROM sessions WHERE token='" + token + "'";
    return st.executeQuery(sql).next();
  }}
}}
'''


def java_second(r: random.Random) -> str:
    cls = ident(r, "Audit").replace("_", "")
    return f'''
import java.sql.*;
class {cls} {{
  String load(Connection c, String id) throws Exception {{
    PreparedStatement ps = c.prepareStatement("SELECT where_clause FROM reports WHERE id=?");
    ps.setString(1, id);
    ResultSet rs = ps.executeQuery(); rs.next(); return rs.getString("where_clause");
  }}
  ResultSet run(Connection c, Statement st, String id) throws Exception {{
    String where = load(c, id);
    String sql = "SELECT * FROM audit_log WHERE " + where;
    return st.executeQuery(sql);
  }}
}}
'''


def php_safe(r: random.Random) -> str:
    return f'''<?php
{comment(r, 'php')}
function list_{ident(r, 'fn')}($pdo, $q) {{
    $allowed = ["created" => "created_at", "email" => "email", "name" => "name"];
    $sort = $allowed[$q["sort"] ?? "created"] ?? "created_at";
    $limit = min(max((int)($q["limit"] ?? 25), 1), 100);
    $sql = "SELECT id,email FROM users WHERE tenant_id = ? ORDER BY $sort LIMIT $limit";
    $decoy = "SELECT * FROM users WHERE email = " . ($q["email"] ?? "");
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$q["tenant"]]);
    return $stmt->fetchAll();
}}
?>'''


def php_inband(r: random.Random) -> str:
    return f'''<?php
function search_{ident(r, 'fn')}($mysqli) {{
    $email = $_GET["email"] ?? "";
    $sql = "SELECT * FROM users WHERE email='" . $email . "'";
    return mysqli_query($mysqli, $sql);
}}
?>'''


def php_blind(r: random.Random) -> str:
    return f'''<?php
function login_{ident(r, 'fn')}($mysqli) {{
    $name = $_POST["name"] ?? "";
    $sql = "SELECT id FROM users WHERE name='" . $name . "'";
    $res = mysqli_query($mysqli, $sql);
    return mysqli_num_rows($res) > 0;
}}
?>'''


def php_second(r: random.Random) -> str:
    return f'''<?php
function load_{ident(r, 'f')}($pdo, $id) {{
    $stmt = $pdo->prepare("SELECT where_clause FROM saved_filters WHERE id=?");
    $stmt->execute([$id]);
    $row = $stmt->fetch();
    return $row["where_clause"];
}}
function run_{ident(r, 'fn')}($pdo, $id) {{
    $where = load_{ident(r, 'f')}($pdo, $id);
    $sql = "SELECT * FROM audit_log WHERE " . $where;
    return $pdo->query($sql)->fetchAll();
}}
?>'''

TEMPLATES = {
    "python": {"SAFE": py_safe, "IN_BAND": py_inband, "BLIND": py_blind, "SECOND_ORDER": py_second},
    "javascript": {"SAFE": js_safe, "IN_BAND": js_inband, "BLIND": js_blind, "SECOND_ORDER": js_second},
    "java": {"SAFE": java_safe, "IN_BAND": java_inband, "BLIND": java_blind, "SECOND_ORDER": java_second},
    "php": {"SAFE": php_safe, "IN_BAND": php_inband, "BLIND": php_blind, "SECOND_ORDER": php_second},
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--per-class", type=int, default=8)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    r = random.Random(args.seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    manifest_rows = []

    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        idx = 1
        for lang, attacks in TEMPLATES.items():
            for attack, fn in attacks.items():
                for _ in range(args.per_class):
                    code = fn(r)
                    ext = LANG_EXT[lang]
                    expected_label = "SAFE" if attack == "SAFE" else "VULNERABLE"
                    expected_attack = "NONE" if attack == "SAFE" else attack
                    fname = f"{lang}/{idx:03d}_{attack}_unseen_{ident(r, 'case')}{ext}"
                    zf.writestr(fname, code)
                    manifest_rows.append({
                        "file": fname,
                        "language": lang,
                        "expected_label": expected_label,
                        "expected_attack_type": expected_attack,
                    })
                    idx += 1
        sio = StringIO()
        writer = csv.DictWriter(sio, fieldnames=["file", "language", "expected_label", "expected_attack_type"])
        writer.writeheader()
        writer.writerows(manifest_rows)
        zf.writestr("manifest.csv", sio.getvalue())

    print(f"Generated {len(manifest_rows)} files: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
