"""
Export preprocessing artifacts for Google Colab training.

Generates the synthetic dataset and vocabulary for the CNN+BiLSTM model.

KEY DIFFERENCE from earlier versions
------------------------------------
The previous augmentation prefixed every base sample with a comment
(e.g. "# handle user request\n<code>"). Because clean_code() strips all
comments before tokenization, every prefix variant collapsed to the SAME
normalized sequence — so 1 200 "samples" were really only ~105 unique
sequences seen many times. The model could not learn from that.

This version uses LANGUAGE-AWARE STRUCTURAL TRANSFORMS that survive
preprocessing because they add real keyword/punctuation tokens:

    identity           — the base snippet as-is
    wrap_function      — wrap in def handle(request): / function(req,res){}
    try_except         — wrap in try/except (or try/catch)
    validate_pre       — add an `if not x: return None` check
    extra_var          — introduce an intermediate variable
    extra_query_after  — append a second harmless query
    log_post           — append a logger call
    return_result      — add `result = ...; return result`

After augmentation we VERIFY that n_unique == n_samples; if not, we drop
the duplicates so the dataset reflects honest counts.

Run from the backend/ directory:
    python scripts/export_for_colab.py

Outputs (inside backend/colab_export/):
    vocabulary.json       – fixed token→id mapping
    training_data.npz     – X (int32, shape N × MODEL_SEQ_LEN) + y (float32 labels)
    export_info.json      – dataset statistics and architecture spec

After training in Colab, place sqli_model.npz in:
    backend/app/model/weights/sqli_model.npz
"""

import os
import sys
import json
import numpy as np

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND_DIR)

from app.vectorization.vocabulary import build_fixed_vocabulary, save_vocabulary
from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.preprocessing.normalizer import normalize_tokens
from scripts.dataset_mutations import generate_mutated_vuln, generate_mutated_safe

OUTPUT_DIR = os.path.join(BACKEND_DIR, "colab_export")

# Reduced from 256 → 128. The dataset's median non-pad length is 23 tokens,
# max ~80 even after augmentation. 256 was wildly oversized — 80%+ pad
# tokens dilute the BiLSTM signal and make every training step ~2x slower.
# The chunker splits long files at function boundaries in production, so
# 128 is more than enough for any single chunk.
MODEL_SEQ_LEN = 128


# ─────────────────────────────────────────────────────────────────────────────
# Base samples — each is a (language, sub_category, code) triple
# ─────────────────────────────────────────────────────────────────────────────
# language    : "python" | "javascript" | "php" | "java"
# sub_category: just for documentation/coverage; not used at training time
# code        : raw source snippet (no leading/trailing newlines)
# ─────────────────────────────────────────────────────────────────────────────

VULNERABLE_BASE: list[tuple[str, str, str]] = [
    # ── Python: f-string injection ────────────────────────────────────────────
    ("python", "fstring", 'uid = request.args.get("id")\nquery = f"SELECT * FROM users WHERE id={uid}"\nconn.execute(query)'),
    ("python", "fstring", 'name = request.form["name"]\nsql = f"SELECT * FROM employees WHERE name=\'{name}\'"\ncursor.execute(sql)'),
    ("python", "fstring", 'search = request.GET["q"]\nresult = db.execute(f"SELECT * FROM products WHERE name LIKE \'%{search}%\'")'),
    ("python", "fstring", 'role = params["role"]\nq = f"SELECT * FROM permissions WHERE role=\'{role}\'"\ndb.query(q)'),
    ("python", "fstring", 'dept = request.args["department"]\nresult = conn.execute(f"SELECT * FROM staff WHERE dept=\'{dept}\'")'),
    ("python", "fstring", 'pid = request.GET.get("pid")\nquery = f"SELECT * FROM posts WHERE id={pid}"\ndb.execute(query)'),
    ("python", "fstring", 'tag = request.args.get("tag")\ncursor.execute(f"SELECT * FROM articles WHERE tag=\'{tag}\'")'),
    ("python", "fstring", 'email = request.form.get("email")\ndb.execute(f"SELECT id FROM users WHERE email=\'{email}\'")'),
    ("python", "fstring", 'token = request.headers.get("token")\ncursor.execute(f"SELECT * FROM sessions WHERE token=\'{token}\'")'),
    ("python", "fstring", 'year = request.GET["year"]\nconn.execute(f"SELECT * FROM events WHERE year={year}")'),
    ("python", "fstring", 'cat = request.args["category"]\ndb.execute(f"SELECT * FROM items WHERE category=\'{cat}\'")'),
    ("python", "fstring", 'status = request.form["status"]\ncursor.execute(f"UPDATE orders SET status=\'{status}\' WHERE id={oid}")'),
    ("python", "fstring", 'region = request.args.get("region")\nresult = db.execute(f"SELECT * FROM sales WHERE region=\'{region}\'")'),
    ("python", "fstring", 'user = request.form.get("username")\npwd = request.form.get("password")\ndb.execute(f"SELECT * FROM users WHERE username=\'{user}\' AND password=\'{pwd}\'")'),
    ("python", "fstring", 'ip = request.headers.get("X-Forwarded-For","0.0.0.0")\ncursor.execute(f"INSERT INTO logs (ip) VALUES (\'{ip}\')")'),
    ("python", "fstring_dyncol",   'sortcol = request.GET["sort"]\ncursor.execute(f"SELECT * FROM products ORDER BY {sortcol}")'),
    ("python", "fstring_dyntable", 'table = request.GET["table"]\ndb.execute(f"SELECT * FROM {table}")'),
    ("python", "fstring", 'sid = request.GET.get("session")\ncursor.execute(f"DELETE FROM sessions WHERE id=\'{sid}\'")'),

    # ── Python: direct string concatenation ───────────────────────────────────
    ("python", "concat", 'user_id = request.GET["uid"]\nquery = "SELECT * FROM users WHERE id = " + user_id\ndb.execute(query)'),
    ("python", "concat", 'name = form["username"]\nsql = "SELECT * FROM accounts WHERE username=\'" + name + "\'"\ncursor.execute(sql)'),
    ("python", "concat", 'email = params.get("email")\nq = "SELECT id FROM users WHERE email=\'" + email + "\'"\nconn.execute(q)'),
    ("python", "concat", 'order_id = request.args.get("order")\nquery = "SELECT * FROM orders WHERE id=" + order_id\nresult = db.query(query)'),
    ("python", "concat", 'product = request.form["product"]\nsql = "SELECT * FROM products WHERE name=\'" + product + "\'"\ncursor.execute(sql)'),
    ("python", "concat", 'uid = request.GET.get("uid", "")\nquery = "SELECT name FROM users WHERE id=" + uid\nconn.execute(query)'),
    ("python", "concat", 'uname = input_data["user"]\nsql = "DELETE FROM sessions WHERE username=\'" + uname + "\'"\ndb.execute(sql)'),
    ("python", "concat", 'cat = request.args["category"]\nquery = "SELECT * FROM items WHERE category=\'" + cat + "\'"\ncur.execute(query)'),
    ("python", "concat", 'pass_val = request.form.get("password")\nsql = "SELECT id FROM users WHERE password=\'" + pass_val + "\'"\ncursor.execute(sql)'),
    ("python", "concat_dyntable", 'table_name = request.GET["table"]\nquery = "SELECT * FROM " + table_name\ndb.execute(query)'),
    ("python", "concat_dyncol",   'col = request.args["sort"]\nquery = "SELECT * FROM products ORDER BY " + col\ncursor.execute(query)'),
    ("python", "concat", 'search = request.form.get("q", "")\nsql = "SELECT * FROM articles WHERE title LIKE \'%" + search + "%\'"\ndb.execute(sql)'),
    ("python", "concat", 'year = request.GET["year"]\nresult = db.execute("SELECT * FROM events WHERE year=" + year)'),
    ("python", "concat", 'region = request.args["region"]\ncursor.execute("SELECT * FROM sales WHERE region=\'" + region + "\'")'),
    ("python", "concat", 'dept = request.form["department"]\ndb.execute("SELECT * FROM employees WHERE dept=\'" + dept + "\'")'),
    ("python", "concat", 'tag = request.GET.get("tag", "")\ncursor.execute("SELECT * FROM posts WHERE tag=\'" + tag + "\'")'),
    ("python", "concat", 'status = request.args.get("status")\ndb.execute("SELECT * FROM orders WHERE status=\'" + status + "\'")'),
    ("python", "concat", 'ip = request.headers.get("X-Forwarded-For")\ncursor.execute("INSERT INTO logs (ip) VALUES (\'" + ip + "\')")'),

    # ── Python: % format & .format() injection ────────────────────────────────
    ("python", "format_pct", 'user = request.POST.get("user")\nsql = "SELECT * FROM logins WHERE user=\'%s\'" % user\ndb.execute(sql)'),
    ("python", "format_pct", 'uid = request.GET["id"]\nquery = "SELECT * FROM accounts WHERE id=%s" % uid\ncursor.execute(query)'),
    ("python", "format_dot", 'val = request.form["value"]\nsql = "SELECT * FROM data WHERE value=\'{}\'".format(val)\ndb.execute(sql)'),
    ("python", "format_dot", 'token = request.GET["token"]\nquery = "SELECT user_id FROM tokens WHERE token=\'{}\'".format(token)\nconn.execute(query)'),
    ("python", "format_dot", 'tid = request.args.get("tid")\ncursor.execute("DELETE FROM tasks WHERE id={}".format(tid))'),

    # ── Python: blind / time-based ────────────────────────────────────────────
    # Proposal (page 4-5) names BLIND as a primary motivation for using deep
    # learning over Regex. Two sub-types: BOOLEAN (response varies based on
    # condition truth) and TIME (response delay reveals condition truth).

    # Python BLIND BOOLEAN — Flask args, suffix injection
    ("python", "blind_boolean", 'uid = request.GET["id"]\npayload = request.GET.get("p", "")\nq = "SELECT id FROM users WHERE id=" + uid + " AND " + payload\ndb.execute(q)'),
    ("python", "blind_boolean", 'aid = request.args.get("aid","1")\ncond = request.args.get("c","1=1")\ndb.execute(f"SELECT * FROM accounts WHERE id={aid} AND {cond}")'),
    ("python", "blind_boolean", 'pid = request.GET["pid"]\nguess = request.GET.get("g")\nq = f"SELECT 1 FROM products WHERE id={pid} AND SUBSTRING(name,1,1)=\'{guess}\'"\ncur.execute(q)'),
    ("python", "blind_boolean", 'tid = request.form["tid"]\nch = request.form["ch"]\ncursor.execute("SELECT 1 FROM tokens WHERE id=" + tid + " AND ASCII(SUBSTR(token,1,1))=" + ch)'),
    ("python", "blind_boolean", 'oid = request.GET["oid"]\nbit = request.GET["bit"]\ndb.execute(f"SELECT * FROM orders WHERE id={oid} AND (SELECT COUNT(*) FROM users) > {bit}")'),
    ("python", "blind_boolean", 'uid = request.GET.get("uid")\nletter = request.GET.get("letter","a")\ndb.execute("SELECT id FROM users WHERE id=" + uid + " AND password LIKE \'" + letter + "%\'")'),
    ("python", "blind_boolean", 'rid = request.args["rid"]\ncondition = request.args.get("cond","1=1")\nq = f"SELECT 1 FROM reports WHERE id={rid} AND ({condition})"\ncur.execute(q)'),
    ("python", "blind_boolean", 'eid = request.GET["eid"]\nidx = request.GET["idx"]\nch = request.GET["ch"]\ncur.execute(f"SELECT 1 FROM employees WHERE id={eid} AND SUBSTRING(ssn,{idx},1)=\'{ch}\'")'),

    # Python BLIND TIME-based — SLEEP / pg_sleep / WAITFOR
    ("python", "blind_time",    'uid = request.GET.get("id")\ncond = request.GET.get("cond","")\nsql = f"SELECT id FROM users WHERE id={uid} AND IF({cond}, SLEEP(5), 0)"\ncursor.execute(sql)'),
    ("python", "blind_time",    'pid = request.args["pid"]\nguess = request.args.get("g","a")\ndb.execute(f"SELECT * FROM products WHERE id={pid} AND IF(SUBSTRING(name,1,1)=\'{guess}\', SLEEP(3), 0)")'),
    ("python", "blind_time",    'aid = request.GET["aid"]\nsec = request.GET.get("s","2")\ndb.execute("SELECT 1 FROM accounts WHERE id=" + aid + " AND SLEEP(" + sec + ")")'),
    ("python", "blind_time_pg", 'uid = request.GET["uid"]\nlen_g = request.GET.get("n","8")\ncur.execute(f"SELECT 1 FROM users WHERE id={uid} AND LENGTH(password)={len_g} AND pg_sleep(2) IS NULL")'),
    ("python", "blind_time_mssql", 'tid = request.form["tid"]\ncond = request.form.get("c","1=1")\ndb.execute(f"SELECT 1 FROM tokens WHERE id={tid}; IF ({cond}) WAITFOR DELAY \'0:0:5\'")'),
    ("python", "blind_time",    'rid = request.args["rid"]\nidx = request.args["i"]\nch = request.args["c"]\ndb.execute(f"SELECT 1 FROM reports WHERE id={rid} AND IF(SUBSTR(title,{idx},1)=\'{ch}\', BENCHMARK(5000000, MD5(1)), 0)")'),
    ("python", "blind_time",    'sid = request.GET["sid"]\nbit = request.GET.get("bit","1")\nq = "SELECT 1 FROM sessions WHERE id=" + sid + " AND IF(" + bit + ", SLEEP(4), 0)"\ncursor.execute(q)'),

    # Python BLIND — wrapped in higher-level helpers (proposal: data flow over time)
    ("python", "blind_boolean", 'def check_priv(req):\n    uid = req.GET["uid"]\n    suffix = req.GET.get("s","")\n    cur.execute(f"SELECT 1 FROM admins WHERE user_id={uid} AND {suffix}")'),
    ("python", "blind_time",    'def slow_probe(req):\n    pid = req.GET["pid"]\n    cond = req.GET.get("cond","1=1")\n    db.execute(f"SELECT 1 FROM payments WHERE id={pid} AND IF({cond}, SLEEP(2), 0)")'),

    # JavaScript BLIND
    ("javascript", "blind_boolean", 'const uid = req.query.uid;\nconst payload = req.query.p || "1=1";\ndb.query(`SELECT 1 FROM users WHERE id=${uid} AND ${payload}`);'),
    ("javascript", "blind_boolean", 'const oid = req.query.oid;\nconst guess = req.body.g;\ndb.query("SELECT 1 FROM orders WHERE id=" + oid + " AND SUBSTRING(token,1,1)=\'" + guess + "\'");'),
    ("javascript", "blind_time",    'const aid = req.params.aid;\nconst cond = req.query.cond || "1=1";\ndb.query(`SELECT 1 FROM accounts WHERE id=${aid} AND IF(${cond}, SLEEP(3), 0)`);'),
    ("javascript", "blind_time",    'const tid = req.body.tid;\nconst sec = req.body.s || "2";\ndb.query("SELECT 1 FROM tokens WHERE id=" + tid + " AND SLEEP(" + sec + ")");'),

    # PHP BLIND
    ("php", "blind_boolean", '$uid = $_GET["id"];\n$cond = $_GET["c"] ?? "1=1";\n$q = "SELECT 1 FROM users WHERE id=" . $uid . " AND " . $cond;\nmysqli_query($conn, $q);'),
    ("php", "blind_boolean", '$pid = $_GET["pid"];\n$g = $_GET["g"] ?? "a";\nmysql_query("SELECT 1 FROM products WHERE id=" . $pid . " AND SUBSTRING(name,1,1)=\'" . $g . "\'");'),
    ("php", "blind_time",    '$uid = $_GET["uid"];\n$cond = $_GET["cond"] ?? "1=1";\n$query = "SELECT 1 FROM users WHERE id=" . $uid . " AND IF(" . $cond . ", SLEEP(5), 0)";\n$conn->query($query);'),
    ("php", "blind_time",    '$rid = $_POST["rid"];\n$sec = $_POST["s"] ?? "3";\nmysqli_query($conn, "SELECT 1 FROM reports WHERE id=" . $rid . " AND SLEEP(" . $sec . ")");'),

    # Java BLIND
    ("java", "blind_boolean", 'String uid = request.getParameter("uid");\nString cond = request.getParameter("c");\nString sql = "SELECT 1 FROM users WHERE id=" + uid + " AND " + cond;\nstmt.executeQuery(sql);'),
    ("java", "blind_boolean", 'String pid = request.getParameter("pid");\nString guess = request.getParameter("g");\nString sql = "SELECT 1 FROM products WHERE id=" + pid + " AND SUBSTRING(name,1,1)=\'" + guess + "\'";\nstmt.executeQuery(sql);'),
    ("java", "blind_time",    'String aid = request.getParameter("aid");\nString cond = request.getParameter("cond");\nString sql = "SELECT 1 FROM accounts WHERE id=" + aid + " AND IF(" + cond + ", SLEEP(5), 0)";\nstmt.executeQuery(sql);'),
    ("java", "blind_time",    'String tid = request.getParameter("tid");\nString sec = request.getParameter("s");\nString sql = "SELECT 1 FROM tokens WHERE id=" + tid + " AND SLEEP(" + sec + ")";\nstmt.executeQuery(sql);'),

    # ── Python: union-based (added to widen coverage) ─────────────────────────
    ("python", "union", 'uid = request.GET["id"]\nq = "SELECT name FROM users WHERE id=" + uid + " UNION SELECT password FROM secrets"\ndb.execute(q)'),
    ("python", "union", 'col = request.args.get("c")\nq = f"SELECT {col} FROM users UNION SELECT password FROM admin"\ncursor.execute(q)'),

    # ── Python: second-order (vulnerable storage of user input) ───────────────
    # Proposal page 5 names SECOND_ORDER as the hardest class — input is stored
    # safely-looking, then a *later* function reads it back into a SQL string.
    # Examples below cover BOTH halves of the chain (storage and read-back),
    # because real second-order detection requires understanding the full flow.

    # Python — INSERT/UPDATE side (storage of user input that will be unsafe later)
    ("python", "second_order", 'username = request.form["username"]\ndb.execute("INSERT INTO users (username) VALUES (\'" + username + "\')")'),
    ("python", "second_order", 'bio = request.form.get("bio", "")\nuid = get_current_user_id()\ndb.execute("UPDATE profiles SET bio=\'" + bio + "\' WHERE user_id=" + str(uid))'),
    ("python", "second_order", 'comment = request.form["comment"]\ndb.execute(f"INSERT INTO comments (text) VALUES (\'{comment}\')")'),
    ("python", "second_order", 'nickname = request.form["nick"]\ncursor.execute(f"INSERT INTO members (nickname) VALUES (\'{nickname}\')")'),
    ("python", "second_order", 'tag = request.json["tag"]\ndb.execute("INSERT INTO post_tags (tag) VALUES (\'" + tag + "\')")'),
    ("python", "second_order", 'desc = request.form.get("description","")\ncursor.execute(f"UPDATE products SET description=\'{desc}\' WHERE id=1")'),
    ("python", "second_order", 'note = request.json["note"]\ndb.execute(f"INSERT INTO audit (note) VALUES (\'{note}\')")'),
    ("python", "second_order", 'role = request.form["role"]\ncursor.execute("UPDATE users SET role=\'" + role + "\' WHERE id=current_user_id()")'),

    # Python — READ-BACK side (reads stored value into a new SQL string)
    ("python", "second_order_read", 'def render_profile(uid):\n    cur.execute("SELECT username FROM users WHERE id=?", (uid,))\n    name = cur.fetchone()[0]\n    cur.execute(f"SELECT * FROM activity WHERE actor=\'{name}\'")'),
    ("python", "second_order_read", 'def show_tag_posts(tag_id):\n    cur.execute("SELECT tag FROM post_tags WHERE id=?", (tag_id,))\n    tag = cur.fetchone()[0]\n    db.execute("SELECT * FROM posts WHERE tags LIKE \'%" + tag + "%\'")'),
    ("python", "second_order_read", 'def lookup_owner(pid):\n    row = cur.execute("SELECT owner FROM products WHERE id=?", (pid,)).fetchone()\n    cur.execute(f"SELECT * FROM employees WHERE name=\'{row[0]}\'")'),
    ("python", "second_order_read", 'def reload_pref(uid):\n    cur.execute("SELECT pref_key FROM prefs WHERE uid=?", (uid,))\n    k = cur.fetchone()[0]\n    db.execute("SELECT value FROM defaults WHERE key=\'" + k + "\'")'),
    ("python", "second_order_read", 'def get_role_perms(uid):\n    cur.execute("SELECT role FROM users WHERE id=?", (uid,))\n    r = cur.fetchone()[0]\n    cur.execute(f"SELECT * FROM permissions WHERE role=\'{r}\'")'),
    ("python", "second_order_read", 'def echo_audit(eid):\n    cur.execute("SELECT note FROM audit WHERE id=?", (eid,))\n    note = cur.fetchone()[0]\n    db.execute(f"INSERT INTO audit_copy (note) VALUES (\'{note}\')")'),

    # JavaScript SECOND_ORDER
    ("javascript", "second_order",      'const username = req.body.username;\ndb.query("INSERT INTO users (username) VALUES (\'" + username + "\')");'),
    ("javascript", "second_order",      'const bio = req.body.bio;\nconst uid = req.session.userId;\ndb.query(`UPDATE profiles SET bio=\'${bio}\' WHERE user_id=${uid}`);'),
    ("javascript", "second_order_read", 'async function showProfile(uid) {\n    const r = await db.query("SELECT username FROM users WHERE id=?", [uid]);\n    const name = r[0].username;\n    return db.query(`SELECT * FROM activity WHERE actor=\'${name}\'`);\n}'),
    ("javascript", "second_order_read", 'async function fetchTagPosts(tagId) {\n    const r = await db.query("SELECT tag FROM tags WHERE id=?", [tagId]);\n    const tag = r[0].tag;\n    return db.query("SELECT * FROM posts WHERE tag=\'" + tag + "\'");\n}'),

    # PHP SECOND_ORDER
    ("php", "second_order",      '$user = $_POST["user"];\nmysqli_query($conn, "INSERT INTO users (username) VALUES (\'" . $user . "\')");'),
    ("php", "second_order",      '$bio = $_POST["bio"] ?? "";\n$uid = $_SESSION["uid"];\n$conn->query("UPDATE profiles SET bio=\'" . $bio . "\' WHERE user_id=" . $uid);'),
    ("php", "second_order_read", 'function show_profile($pdo, $uid) {\n    $stmt = $pdo->prepare("SELECT username FROM users WHERE id=?");\n    $stmt->execute([$uid]);\n    $name = $stmt->fetchColumn();\n    $pdo->query("SELECT * FROM activity WHERE actor=\'" . $name . "\'");\n}'),
    ("php", "second_order_read", 'function load_role($mysqli, $uid) {\n    $stmt = $mysqli->prepare("SELECT role FROM users WHERE id=?");\n    $stmt->bind_param("i", $uid);\n    $stmt->execute();\n    $r = $stmt->get_result()->fetch_assoc();\n    mysqli_query($mysqli, "SELECT * FROM perms WHERE role=\'" . $r["role"] . "\'");\n}'),

    # Java SECOND_ORDER
    ("java", "second_order",      'String username = request.getParameter("username");\nString sql = "INSERT INTO users (username) VALUES (\'" + username + "\')";\nstmt.executeUpdate(sql);'),
    ("java", "second_order",      'String bio = request.getParameter("bio");\nint uid = (Integer) session.getAttribute("uid");\nString sql = "UPDATE profiles SET bio=\'" + bio + "\' WHERE user_id=" + uid;\nstmt.executeUpdate(sql);'),
    ("java", "second_order_read", 'public void showProfile(int uid) throws SQLException {\n    PreparedStatement ps = conn.prepareStatement("SELECT username FROM users WHERE id=?");\n    ps.setInt(1, uid);\n    ResultSet rs = ps.executeQuery();\n    rs.next();\n    String name = rs.getString(1);\n    stmt.executeQuery("SELECT * FROM activity WHERE actor=\'" + name + "\'");\n}'),
    ("java", "second_order_read", 'public void getRolePerms(int uid) throws SQLException {\n    PreparedStatement ps = conn.prepareStatement("SELECT role FROM users WHERE id=?");\n    ps.setInt(1, uid);\n    ResultSet rs = ps.executeQuery();\n    rs.next();\n    String role = rs.getString(1);\n    stmt.executeQuery("SELECT * FROM perms WHERE role=\'" + role + "\'");\n}'),

    # ── JavaScript: template literals + concat ────────────────────────────────
    ("javascript", "concat",          'const uid = req.query.uid;\nconst query = "SELECT * FROM users WHERE id=" + uid;\nconn.query(query);'),
    ("javascript", "template",        'const name = req.body.name;\nconst sql = `SELECT * FROM users WHERE name=\'${name}\'`;\ndb.query(sql);'),
    ("javascript", "concat",          'const email = req.params.email;\npool.query("SELECT * FROM accounts WHERE email=\'" + email + "\'");'),
    ("javascript", "concat",          'const id = req.query.id;\nconst q = "SELECT * FROM orders WHERE user_id=" + id;\nconnection.query(q, callback);'),
    ("javascript", "concat",          'const search = req.body.search;\ndb.query("SELECT * FROM products WHERE name LIKE \'%" + search + "%\'");'),
    ("javascript", "concat",          'const token = req.headers.authorization;\ndb.query("SELECT * FROM sessions WHERE token=\'" + token + "\'");'),
    ("javascript", "concat",          'const cat = req.query.category;\nconst query = "SELECT * FROM items WHERE category=\'" + cat + "\'";\ndb.execute(query);'),
    ("javascript", "concat",          'const pwd = req.body.password;\nconst q = "SELECT id FROM users WHERE password=\'" + pwd + "\'";\ndb.query(q);'),
    ("javascript", "template",        'const role = req.query.role;\ndb.query(`SELECT * FROM permissions WHERE role=\'${role}\'`);'),
    ("javascript", "concat",          'const username = req.body.username;\nconst password = req.body.password;\ndb.query("SELECT * FROM users WHERE username=\'" + username + "\' AND password=\'" + password + "\'");'),
    ("javascript", "concat",          'const tag = req.body.tag;\npool.execute("SELECT * FROM posts WHERE tag=\'" + tag + "\'");'),
    ("javascript", "concat",          'const status = req.query.status;\ndb.query("SELECT * FROM orders WHERE status=\'" + status + "\'");'),
    ("javascript", "template_dyncol", 'const col = req.query.sort;\ndb.query(`SELECT * FROM users ORDER BY ${col}`);'),

    # ── PHP: dot concat ───────────────────────────────────────────────────────
    ("php", "concat",        '$uid = $_GET["id"];\n$query = "SELECT * FROM users WHERE id=" . $uid;\nmysql_query($query);'),
    ("php", "concat",        '$name = $_POST["username"];\n$sql = "SELECT * FROM accounts WHERE name=\'" . $name . "\'";\nmysqli_query($conn, $sql);'),
    ("php", "concat",        '$email = $_REQUEST["email"];\n$q = "SELECT id FROM users WHERE email=\'" . $email . "\'";\nmysql_query($q);'),
    ("php", "concat",        '$pass = $_POST["password"];\n$query = "SELECT * FROM users WHERE password=\'" . $pass . "\'";\n$result = $conn->query($query);'),
    ("php", "concat",        '$cat = $_GET["category"];\n$query = "SELECT * FROM products WHERE cat=\'" . $cat . "\'";\n$result = mysqli_query($con, $query);'),
    ("php", "concat",        '$search = $_GET["q"];\n$sql = "SELECT * FROM articles WHERE title LIKE \'%" . $search . "%\'";\n$result = mysql_query($sql);'),
    ("php", "concat_dyncol", '$sort = $_GET["sort"];\n$query = "SELECT * FROM users ORDER BY " . $sort;\n$result = $conn->query($query);'),
    ("php", "sprintf",       '$id = $_GET["id"];\n$query = sprintf("SELECT * FROM users WHERE id=%s", $id);\nmysql_query($query);'),

    # ── Java: + concat into executeQuery ──────────────────────────────────────
    ("java", "concat",        'String userId = request.getParameter("id");\nString sql = "SELECT * FROM users WHERE id=" + userId;\nstatement.executeQuery(sql);'),
    ("java", "concat",        'String name = request.getParameter("username");\nString query = "SELECT * FROM accounts WHERE name=\'" + name + "\'";\nrs = stmt.executeQuery(query);'),
    ("java", "concat",        'String email = request.getParameter("email");\nString q = "SELECT id FROM users WHERE email=\'" + email + "\'";\nResultSet rs = stmt.executeQuery(q);'),
    ("java", "concat",        'String search = request.getParameter("q");\nString sql = "SELECT * FROM products WHERE name LIKE \'%" + search + "%\'";\nstmt.executeQuery(sql);'),
    ("java", "concat",        'String pass = request.getParameter("password");\nString sql = "SELECT * FROM users WHERE password=\'" + pass + "\'";\nResultSet rs = statement.executeQuery(sql);'),
    ("java", "stringbuilder", 'String category = request.getParameter("category");\nStringBuilder sb = new StringBuilder("SELECT * FROM items WHERE ");\nsb.append("category=\'").append(category).append("\'");\nResultSet rs = stmt.executeQuery(sb.toString());'),
    ("java", "concat_dyncol", 'String sortCol = request.getParameter("sort");\nString query = "SELECT * FROM users ORDER BY " + sortCol;\nResultSet rs = conn.createStatement().executeQuery(query);'),
]


SAFE_BASE: list[tuple[str, str, str]] = [
    # ── Python: parameterized — produces SAFE_EXEC signal ────────────────────
    ("python", "param_qmark", 'user_id = request.GET["uid"]\ncursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'),
    ("python", "param_pct",   'name = form["username"]\ncursor.execute("SELECT * FROM accounts WHERE username = %s", (name,))'),
    ("python", "param_pct",   'email = params.get("email")\ncursor.execute("SELECT id FROM users WHERE email = %s", [email])'),
    ("python", "param_qmark", 'order_id = request.args.get("order")\ncursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))'),
    ("python", "param_qmark", 'product = request.form["product"]\ncursor.execute("SELECT * FROM products WHERE name = ?", (product,))'),
    ("python", "param_pct",   'uid = request.GET.get("uid", "")\ncursor.execute("SELECT name FROM users WHERE id = %s", (uid,))'),
    ("python", "param_pct",   'pass_val = request.form.get("password")\ncursor.execute("SELECT id FROM users WHERE password_hash = %s", (hash_pw(pass_val),))'),
    ("python", "param_pct",   'search = request.form.get("q", "")\ncursor.execute("SELECT * FROM articles WHERE title LIKE %s", (f"%{search}%",))'),
    ("python", "param_qmark", 'year = request.GET["year"]\ncursor.execute("SELECT * FROM events WHERE year = ?", (year,))'),
    ("python", "param_pct",   'region = request.args["region"]\ncursor.execute("SELECT * FROM sales WHERE region = %s", (region,))'),
    ("python", "param_qmark", 'dept = request.form["department"]\ncursor.execute("SELECT * FROM employees WHERE dept = ?", (dept,))'),
    ("python", "param_pct",   'cat = request.args["category"]\ncursor.execute("SELECT * FROM items WHERE category = %s", (cat,))'),
    ("python", "param_qmark", 'tag = request.GET.get("tag")\ncursor.execute("SELECT * FROM posts WHERE tag = ?", (tag,))'),
    ("python", "param_pct",   'status = request.args.get("status")\ncursor.execute("SELECT * FROM orders WHERE status = %s", (status,))'),
    ("python", "param_qmark", 'email = request.form["email"]\ncursor.execute("SELECT id FROM users WHERE email = ?", (email,))'),
    ("python", "param_pct",   'token = request.headers.get("token")\ncursor.execute("SELECT * FROM sessions WHERE token = %s", (token,))'),
    ("python", "param_qmark", 'pid = request.GET.get("pid")\ncursor.execute("SELECT * FROM posts WHERE id = ?", (pid,))'),
    ("python", "param_pct",   'role = request.args.get("role")\ncursor.execute("SELECT * FROM permissions WHERE role = %s", (role,))'),
    ("python", "param_qmark", 'ip = request.remote_addr\ncursor.execute("INSERT INTO logs (ip) VALUES (?)", (ip,))'),

    # ── Python: SQLAlchemy text() with bound params ──────────────────────────
    ("python", "sqlalchemy", 'from sqlalchemy import text\nuid = request.args.get("id")\nstmt = text("SELECT * FROM users WHERE id = :uid")\nresult = conn.execute(stmt, {"uid": uid})'),
    ("python", "sqlalchemy", 'from sqlalchemy import text\nname = form["username"]\nstmt = text("SELECT * FROM accounts WHERE username = :name")\nresult = conn.execute(stmt, {"name": name})'),
    ("python", "sqlalchemy", 'from sqlalchemy import text\nemail = request.form["email"]\nstmt = text("SELECT id FROM users WHERE email = :email")\nresult = conn.execute(stmt, {"email": email})'),
    ("python", "sqlalchemy", 'from sqlalchemy import text\nsearch = request.args.get("q", "")\nstmt = text("SELECT * FROM products WHERE name LIKE :s")\nresult = conn.execute(stmt, {"s": f"%{search}%"})'),

    # ── Python: stored procedures ────────────────────────────────────────────
    ("python", "callproc", 'uid = request.GET["id"]\ncursor.callproc("GetUser", [uid])'),
    ("python", "callproc", 'name = request.form["username"]\ncursor.callproc("GetUserByName", (name,))'),

    # ── Python: validation + parameterized ───────────────────────────────────
    ("python", "validate_param",    'uid = request.GET.get("id", "")\nif not uid.isdigit():\n    abort(400)\ncursor.execute("SELECT * FROM users WHERE id = ?", (int(uid),))'),
    ("python", "validate_param",    'name = request.form.get("name", "").strip()\nif len(name) > 100 or not name.replace(" ", "").isalnum():\n    abort(400)\ncursor.execute("SELECT * FROM users WHERE name = ?", (name,))'),
    ("python", "whitelist_dyncol",  'allowed = {"name", "email", "age"}\ncol = request.GET["sort"]\nif col not in allowed:\n    abort(400)\ncursor.execute(f"SELECT * FROM users ORDER BY {col}")'),
    ("python", "whitelist_dyntable",'allowed_tables = {"users", "products", "orders"}\ntable = request.GET.get("table")\nif table not in allowed_tables:\n    abort(400)\ncursor.execute("SELECT * FROM " + table)'),

    # ── Python: ORM (no raw SQL at all) ──────────────────────────────────────
    ("python", "orm", 'user_id = request.GET.get("uid")\nuser = User.objects.get(id=user_id)'),
    ("python", "orm", 'name = form["username"]\nresults = User.query.filter_by(username=name).all()'),
    ("python", "orm", 'email = request.args["email"]\nuser = db.session.query(User).filter(User.email == email).first()'),
    ("python", "orm", 'category = request.GET["cat"]\nproducts = Product.objects.filter(category=category)'),
    ("python", "orm", 'dept = request.form["department"]\nstaff = Employee.objects.filter(department=dept)'),
    ("python", "orm", 'search = request.args.get("q", "")\nresults = Product.query.filter(Product.name.ilike(f"%{search}%")).all()'),
    ("python", "orm", 'tag = request.GET.get("tag")\nresults = Post.objects.filter(tags__name=tag)'),
    ("python", "orm", 'role = request.form["role"]\nperms = Permission.objects.filter(role=role)'),
    ("python", "orm", 'uid = request.args.get("user_id")\norders = Order.objects.filter(user_id=uid)'),

    # ── Python: pure logic, no DB at all ─────────────────────────────────────
    ("python", "no_db", 'items = [1, 2, 3, 4, 5]\nresult = [x * 2 for x in items if x > 2]\nreturn result'),
    ("python", "no_db", 'name = request.form.get("name", "").upper()\nreturn name[:50]'),
    ("python", "no_db", 'values = [int(x) for x in request.GET.getlist("ids") if x.isdigit()]\nreturn sum(values)'),
    ("python", "no_db", 'data = request.json\nif not isinstance(data, dict):\n    raise ValueError("Bad input")\nreturn data.get("key", "")'),
    ("python", "no_db", 'page = int(request.args.get("page", 1))\nlimit = min(int(request.args.get("limit", 10)), 100)\noffset = (page - 1) * limit\nreturn {"page": page, "limit": limit, "offset": offset}'),
    ("python", "no_db", 'token = secrets.token_hex(32)\nexpiry = datetime.utcnow() + timedelta(hours=1)\nreturn {"token": token, "expiry": expiry.isoformat()}'),

    # ── JavaScript: parameterized ────────────────────────────────────────────
    ("javascript", "param", 'const uid = req.query.uid;\nconn.query("SELECT * FROM users WHERE id = ?", [uid]);'),
    ("javascript", "param", 'const name = req.body.name;\ndb.query("SELECT * FROM users WHERE name = ?", [name], callback);'),
    ("javascript", "param", 'const email = req.params.email;\npool.execute("SELECT * FROM accounts WHERE email = ?", [email]);'),
    ("javascript", "param", 'const id = req.query.id;\nconnection.execute("SELECT * FROM orders WHERE user_id = ?", [id]);'),
    ("javascript", "param", 'const search = req.body.search;\ndb.query("SELECT * FROM products WHERE name LIKE ?", [`%${search}%`]);'),
    ("javascript", "param", 'const token = req.headers.authorization;\ndb.query("SELECT * FROM sessions WHERE token = ?", [token]);'),
    ("javascript", "param", 'const cat = req.query.category;\ndb.execute("SELECT * FROM items WHERE category = ?", [cat]);'),
    ("javascript", "param", 'const tag = req.body.tag;\npool.execute("SELECT * FROM posts WHERE tag = ?", [tag]);'),
    ("javascript", "param", 'const status = req.query.status;\ndb.query("SELECT * FROM orders WHERE status = ?", [status]);'),

    # ── JavaScript: ORM ──────────────────────────────────────────────────────
    ("javascript", "orm", 'const uid = req.query.uid;\nconst user = await User.findByPk(uid);'),
    ("javascript", "orm", 'const name = req.body.name;\nconst users = await User.findAll({ where: { name } });'),
    ("javascript", "orm", 'const email = req.body.email;\nconst user = await User.findOne({ where: { email } });'),
    ("javascript", "orm", 'const cat = req.query.category;\nconst items = await Item.findAll({ where: { category: cat } });'),
    ("javascript", "orm", 'const dept = req.body.department;\nconst staff = await Employee.findAll({ where: { department: dept } });'),

    # ── PHP: prepared statements ─────────────────────────────────────────────
    ("php", "param", '$uid = $_GET["id"];\n$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");\n$stmt->execute([$uid]);'),
    ("php", "param", '$name = $_POST["username"];\n$stmt = $pdo->prepare("SELECT * FROM accounts WHERE name = ?");\n$stmt->execute([$name]);'),
    ("php", "param", '$email = $_REQUEST["email"];\n$stmt = $mysqli->prepare("SELECT id FROM users WHERE email = ?");\n$stmt->bind_param("s", $email);\n$stmt->execute();'),
    ("php", "param", '$pass = $_POST["password"];\n$stmt = $pdo->prepare("SELECT * FROM users WHERE password_hash = ?");\n$stmt->execute([password_hash($pass, PASSWORD_DEFAULT)]);'),
    ("php", "param", '$cat = $_GET["category"];\n$stmt = $pdo->prepare("SELECT * FROM products WHERE cat = ?");\n$stmt->execute([$cat]);'),
    ("php", "param", '$tag = $_GET["tag"];\n$stmt = $pdo->prepare("SELECT * FROM posts WHERE tag = ?");\n$stmt->execute([$tag]);'),

    # ── Java: PreparedStatement ──────────────────────────────────────────────
    ("java", "param", 'String userId = request.getParameter("id");\nPreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nstmt.setString(1, userId);\nResultSet rs = stmt.executeQuery();'),
    ("java", "param", 'String name = request.getParameter("username");\nPreparedStatement ps = conn.prepareStatement("SELECT * FROM accounts WHERE name = ?");\nps.setString(1, name);\nps.executeQuery();'),
    ("java", "param", 'String email = request.getParameter("email");\nPreparedStatement ps = conn.prepareStatement("SELECT id FROM users WHERE email = ?");\nps.setString(1, email);\nResultSet rs = ps.executeQuery();'),
    ("java", "param", 'String search = request.getParameter("q");\nPreparedStatement stmt = conn.prepareStatement("SELECT * FROM products WHERE name LIKE ?");\nstmt.setString(1, "%" + search + "%");\nResultSet rs = stmt.executeQuery();'),
    ("java", "param", 'String dept = request.getParameter("dept");\nPreparedStatement ps = conn.prepareStatement("SELECT * FROM staff WHERE dept = ?");\nps.setString(1, dept);\nResultSet rs = ps.executeQuery();'),
    ("java", "param", 'String tag = request.getParameter("tag");\nPreparedStatement stmt = conn.prepareStatement("SELECT * FROM posts WHERE tag = ?");\nstmt.setString(1, tag);\nResultSet rs = stmt.executeQuery();'),

    # ── Whitelist-guarded dynamic SQL (looks vulnerable, is safe) ────────────
    # These are critical: f-string / concat into a SQL string IS used, but the
    # interpolated value is constrained to a fixed set first. The model must
    # learn to read the validation context, not just react to FSTRING_SQL.

    # Python: set whitelist for ORDER BY column
    ("python", "whitelist_set_orderby",
     'ALLOWED = {"name", "price", "created_at"}\ncol = request.GET["sort"]\nif col not in ALLOWED:\n    raise ValueError("invalid sort")\ncursor.execute(f"SELECT * FROM products ORDER BY {col}")'),
    ("python", "whitelist_set_orderby",
     'SAFE_COLS = {"id", "email", "username"}\nsort_by = request.args.get("sort", "id")\nif sort_by not in SAFE_COLS:\n    abort(400)\ncursor.execute(f"SELECT * FROM users ORDER BY {sort_by} ASC")'),
    ("python", "whitelist_frozenset",
     'COLUMNS = frozenset({"name","price","stock"})\nc = request.args["c"]\nif c not in COLUMNS:\n    raise ValueError\nq = f"SELECT id, {c} FROM products"\ncursor.execute(q)'),

    # Python: tuple/list whitelist for sort direction
    ("python", "whitelist_tuple_dir",
     'direction = request.GET.get("dir", "ASC")\nif direction not in ("ASC", "DESC"):\n    raise ValueError\ncursor.execute(f"SELECT * FROM users ORDER BY id {direction}")'),
    ("python", "whitelist_list_dir",
     'order = request.args.get("order")\nallowed = ["asc", "desc"]\nif order not in allowed:\n    abort(400)\ncursor.execute(f"SELECT * FROM events ORDER BY date {order}")'),

    # Python: dict mapping (user key -> safe SQL fragment)
    ("python", "whitelist_dict_map",
     'SORT_MAP = {"name": "u.name", "date": "u.created_at", "id": "u.id"}\nkey = request.args.get("sort")\nfragment = SORT_MAP.get(key, "u.id")\ncursor.execute(f"SELECT * FROM users u ORDER BY {fragment}")'),
    ("python", "whitelist_dict_table",
     'TABLE_MAP = {"u": "users", "p": "products", "o": "orders"}\nkey = request.GET["t"]\ntable = TABLE_MAP.get(key)\nif not table:\n    return []\ncursor.execute(f"SELECT id FROM {table}")'),

    # Python: hardcoded constant interpolated into f-string (no user input there)
    ("python", "constant_in_fstring",
     'TABLE = "audit_log"\nuid = request.GET.get("uid")\ncursor.execute(f"SELECT * FROM {TABLE} WHERE user_id = ?", (uid,))'),
    ("python", "constant_in_fstring",
     'SCHEMA = "public"\ncursor.execute(f"SELECT count(*) FROM {SCHEMA}.users")'),

    # Python: regex validation before f-string
    ("python", "regex_validate_then_fstring",
     'import re\ncol = request.args.get("col", "")\nif not re.fullmatch(r"[a-z_]{1,32}", col):\n    abort(400)\ncursor.execute(f"SELECT {col} FROM users")'),

    # Python: enum-based whitelist
    ("python", "enum_whitelist",
     'from enum import Enum\nclass Direction(Enum):\n    ASC = "ASC"\n    DESC = "DESC"\ndir_str = Direction(request.args["d"]).value\ncursor.execute(f"SELECT * FROM rows ORDER BY id {dir_str}")'),

    # Python: if/elif chain selecting fully hardcoded queries
    ("python", "hardcoded_branch",
     'mode = request.args.get("mode")\nif mode == "active":\n    cursor.execute("SELECT * FROM users WHERE active = 1")\nelif mode == "all":\n    cursor.execute("SELECT * FROM users")\nelse:\n    abort(400)'),

    # JavaScript: array whitelist + template literal
    ("javascript", "whitelist_array_orderby",
     'const ALLOWED = ["name", "price", "created_at"];\nconst sort = req.query.sort;\nif (!ALLOWED.includes(sort)) {\n  return res.status(400).end();\n}\ndb.query(`SELECT * FROM products ORDER BY ${sort}`);'),
    ("javascript", "whitelist_set_has",
     'const COLS = new Set(["id","email","username"]);\nconst c = req.query.c;\nif (!COLS.has(c)) {\n  throw new Error("bad column");\n}\ndb.query(`SELECT ${c} FROM users`);'),
    ("javascript", "whitelist_object_map",
     'const SORT_MAP = { name: "u.name", date: "u.created_at" };\nconst key = req.query.sort;\nconst frag = SORT_MAP[key];\nif (!frag) {\n  return res.status(400).end();\n}\ndb.query(`SELECT * FROM users u ORDER BY ${frag}`);'),
    ("javascript", "constant_in_template",
     'const TABLE = "audit_log";\nconst uid = req.query.uid;\ndb.query(`SELECT * FROM ${TABLE} WHERE user_id = ?`, [uid]);'),
    ("javascript", "regex_validate_template",
     'const col = req.query.col || "";\nif (!/^[a-z_]{1,32}$/.test(col)) {\n  return res.status(400).end();\n}\ndb.query(`SELECT ${col} FROM users`);'),

    # PHP: array whitelist + dot concat
    ("php", "whitelist_array_orderby",
     '$allowed = ["name", "price", "created_at"];\n$sort = $_GET["sort"] ?? "name";\nif (!in_array($sort, $allowed, true)) {\n    http_response_code(400);\n    exit;\n}\n$query = "SELECT * FROM products ORDER BY " . $sort;\nmysqli_query($conn, $query);'),
    ("php", "whitelist_array_table",
     '$tables = ["users", "products", "orders"];\n$t = $_GET["t"] ?? "";\nif (!in_array($t, $tables, true)) {\n    die("bad table");\n}\n$query = "SELECT id FROM " . $t;\n$conn->query($query);'),
    ("php", "whitelist_assoc_map",
     '$sort_map = ["name" => "u.name", "date" => "u.created_at"];\n$key = $_GET["sort"] ?? "name";\nif (!isset($sort_map[$key])) {\n    http_response_code(400);\n    exit;\n}\n$frag = $sort_map[$key];\n$query = "SELECT * FROM users u ORDER BY " . $frag;\nmysqli_query($conn, $query);'),
    ("php", "regex_validate_concat",
     '$col = $_GET["col"] ?? "";\nif (!preg_match("/^[a-z_]{1,32}$/", $col)) {\n    http_response_code(400);\n    exit;\n}\n$query = "SELECT " . $col . " FROM users";\nmysqli_query($conn, $query);'),
    ("php", "constant_in_string",
     '$TABLE = "audit_log";\n$uid = $_GET["uid"] ?? "";\n$stmt = $pdo->prepare("SELECT * FROM " . $TABLE . " WHERE user_id = ?");\n$stmt->execute([$uid]);'),

    # Java: Set whitelist + concat into PreparedStatement (safe because column is fixed-set)
    ("java", "whitelist_set_orderby",
     'Set<String> ALLOWED = Set.of("name", "price", "created_at");\nString sort = request.getParameter("sort");\nif (!ALLOWED.contains(sort)) {\n    response.sendError(400);\n    return;\n}\nString sql = "SELECT * FROM products ORDER BY " + sort;\nResultSet rs = stmt.executeQuery(sql);'),
    ("java", "whitelist_switch_hardcoded",
     'String mode = request.getParameter("mode");\nString sql;\nswitch (mode) {\n    case "active": sql = "SELECT * FROM users WHERE active = 1"; break;\n    case "all":    sql = "SELECT * FROM users"; break;\n    default: response.sendError(400); return;\n}\nResultSet rs = stmt.executeQuery(sql);'),
    ("java", "whitelist_map_lookup",
     'Map<String, String> SORT_MAP = Map.of("name", "u.name", "date", "u.created_at");\nString key = request.getParameter("sort");\nString frag = SORT_MAP.get(key);\nif (frag == null) {\n    response.sendError(400);\n    return;\n}\nString sql = "SELECT * FROM users u ORDER BY " + frag;\nResultSet rs = stmt.executeQuery(sql);'),
    # ── Dynamic IN-clause with placeholders (common safe idiom) ──────────────
    # The query uses an f-string only to inject `?,?,?` placeholders whose
    # count matches the user input list. The actual values flow through
    # parameterised execute. Looks suspicious (FSTRING_SQL fires) but is safe.
    # The model previously misclassified this around 0.5 — adding it here.
    ("python", "in_clause_placeholders",
     'def get_users_by_ids(ids):\n    placeholders = ",".join("?" for _ in ids)\n    sql = f"SELECT * FROM users WHERE id IN ({placeholders})"\n    cursor.execute(sql, tuple(ids))'),
    ("python", "in_clause_placeholders",
     'def get_regions(tenant_id, regions):\n    placeholders = ",".join("?" for _ in regions)\n    sql = f"SELECT * FROM reports WHERE tenant_id = ? AND region IN ({placeholders})"\n    params = [tenant_id] + list(regions)\n    cursor.execute(sql, tuple(params))'),
    ("python", "in_clause_placeholders",
     'def find_by_status(statuses):\n    if not statuses:\n        return []\n    qmarks = ",".join(["?"] * len(statuses))\n    cursor.execute(f"SELECT * FROM orders WHERE status IN ({qmarks})", tuple(statuses))'),
    ("python", "in_clause_placeholders",
     'def fetch_records(tenant_id, ids):\n    placeholders = ", ".join("?" * len(ids))\n    cursor.execute(f"DELETE FROM records WHERE tenant_id = ? AND id IN ({placeholders})", (tenant_id, *ids))'),
    ("python", "in_clause_placeholders",
     'def lookup_by_keys(keys):\n    qs = ",".join("?" for k in keys)\n    sql = f"SELECT k, v FROM kv WHERE k IN ({qs})"\n    cursor.execute(sql, keys)'),

    ("java", "constant_in_concat",
     'final String TABLE = "audit_log";\nString uid = request.getParameter("uid");\nPreparedStatement ps = conn.prepareStatement("SELECT * FROM " + TABLE + " WHERE user_id = ?");\nps.setString(1, uid);\nps.executeQuery();'),

    # ── Static DDL — schema/index/view setup (NO user input) ─────────────────
    # These are safe by construction: the executed SQL is a hardcoded literal,
    # there is no source of dynamic input. The model previously over-reacted
    # to multi-line SQL strings inside cursor.execute(), giving 0.7+ scores
    # on schema setup code. Training on these patterns calibrates that down.

    # Python: CREATE TABLE
    ("python", "ddl_create_table",
     'def create_schema(db_path):\n    conn = sqlite3.connect(db_path)\n    cur = conn.cursor()\n    cur.execute("""CREATE TABLE IF NOT EXISTS users (\n        id INTEGER PRIMARY KEY AUTOINCREMENT,\n        email TEXT NOT NULL UNIQUE,\n        created_at TEXT NOT NULL\n    )""")\n    conn.commit()'),
    ("python", "ddl_create_multi",
     'def init_db(conn):\n    cur = conn.cursor()\n    cur.execute("""CREATE TABLE IF NOT EXISTS posts (\n        id INTEGER PRIMARY KEY,\n        title TEXT NOT NULL,\n        body TEXT NOT NULL\n    )""")\n    cur.execute("""CREATE TABLE IF NOT EXISTS tags (\n        id INTEGER PRIMARY KEY,\n        name TEXT UNIQUE\n    )""")\n    conn.commit()'),
    ("python", "ddl_create_index",
     'def add_indexes(conn):\n    cur = conn.cursor()\n    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)")\n    cur.execute("CREATE INDEX IF NOT EXISTS idx_posts_created ON posts (created_at DESC)")\n    conn.commit()'),
    ("python", "ddl_create_view",
     'def setup_views(conn):\n    cur = conn.cursor()\n    cur.execute("""CREATE VIEW IF NOT EXISTS active_users AS\n        SELECT id, email FROM users WHERE is_active = 1\n    """)\n    conn.commit()'),
    ("python", "ddl_pragma",
     'def configure_db(conn):\n    cur = conn.cursor()\n    cur.execute("PRAGMA foreign_keys = ON")\n    cur.execute("PRAGMA journal_mode = WAL")\n    cur.execute("PRAGMA synchronous = NORMAL")'),
    ("python", "ddl_alter_table",
     'def migrate_v2(conn):\n    cur = conn.cursor()\n    cur.execute("ALTER TABLE users ADD COLUMN last_login TEXT")\n    cur.execute("ALTER TABLE users ADD COLUMN locale TEXT DEFAULT \'en\'")\n    conn.commit()'),
    ("python", "ddl_drop",
     'def teardown(conn):\n    cur = conn.cursor()\n    cur.execute("DROP TABLE IF EXISTS temp_imports")\n    cur.execute("DROP INDEX IF EXISTS idx_temp")\n    conn.commit()'),
    ("python", "ddl_with_session",
     'def create_schema(db_path):\n    with DatabaseSession(db_path) as conn:\n        cur = conn.cursor()\n        cur.execute("""CREATE TABLE IF NOT EXISTS app_users (\n            id INTEGER PRIMARY KEY,\n            email TEXT NOT NULL UNIQUE\n        )""")\n        conn.commit()'),
    ("python", "ddl_seed_executemany",
     'def seed(conn):\n    cur = conn.cursor()\n    rows = [(1, "Alice"), (2, "Bob"), (3, "Charlie")]\n    cur.executemany("INSERT INTO users (id, name) VALUES (?, ?)", rows)\n    conn.commit()'),
    ("python", "ddl_static_select",
     'def get_table_count(conn):\n    cur = conn.cursor()\n    cur.execute("SELECT COUNT(*) FROM users")\n    return cur.fetchone()[0]'),

    # JavaScript: schema setup
    ("javascript", "ddl_create_table",
     'async function createSchema(db) {\n    await db.query(`CREATE TABLE IF NOT EXISTS users (\n        id SERIAL PRIMARY KEY,\n        email VARCHAR(255) UNIQUE NOT NULL\n    )`);\n}'),
    ("javascript", "ddl_create_index",
     'async function addIndexes(db) {\n    await db.query("CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)");\n    await db.query("CREATE INDEX IF NOT EXISTS idx_posts_created ON posts (created_at DESC)");\n}'),

    # PHP: schema setup
    ("php", "ddl_create_table",
     'function createSchema($pdo) {\n    $pdo->exec("CREATE TABLE IF NOT EXISTS users (\n        id INT AUTO_INCREMENT PRIMARY KEY,\n        email VARCHAR(255) UNIQUE NOT NULL\n    )");\n}'),
    ("php", "ddl_alter",
     'function migrate($pdo) {\n    $pdo->exec("ALTER TABLE users ADD COLUMN last_login DATETIME NULL");\n    $pdo->exec("ALTER TABLE users ADD COLUMN locale VARCHAR(8) DEFAULT \'en\'");\n}'),

    # Java: schema setup
    ("java", "ddl_create_table",
     'public void createSchema(Connection conn) throws SQLException {\n    Statement stmt = conn.createStatement();\n    stmt.execute("CREATE TABLE IF NOT EXISTS users (id BIGINT PRIMARY KEY, email VARCHAR(255) UNIQUE)");\n    stmt.close();\n}'),
    ("java", "ddl_create_index",
     'public void addIndexes(Connection conn) throws SQLException {\n    Statement stmt = conn.createStatement();\n    stmt.execute("CREATE INDEX idx_users_email ON users (email)");\n    stmt.close();\n}'),

    # ── Whitelist-validated dynamic identifiers (Gap-A v2 Fix B) ─────────────
    # Strict-allowlist ORDER BY / column / table identifier construction.
    # All emit FSTRING_SQL (or string concat) but ALSO emit WHITELIST_VAR,
    # which lets the type head learn this is NONE and the rule layer treat
    # it as safe.

    ("python", "whitelist_order_by",
     'ALLOWED_SORT_COLUMNS = {"id", "name", "created_at"}\ndef list_users(sort_by):\n    safe_col = sort_by if sort_by in ALLOWED_SORT_COLUMNS else "created_at"\n    sql = f"SELECT id, name FROM users ORDER BY {safe_col}"\n    cursor.execute(sql)'),
    ("python", "whitelist_order_by",
     'ALLOWED_SORT_ORDERS = {"ASC", "DESC"}\ndef sort_dir(d):\n    safe_d = d.upper() if d.upper() in ALLOWED_SORT_ORDERS else "DESC"\n    sql = f"SELECT * FROM products ORDER BY price {safe_d}"\n    cursor.execute(sql)'),
    ("python", "whitelist_order_by",
     'ALLOWED_SORT_COLUMNS = {"id", "customer_name", "amount", "created_at"}\nALLOWED_SORT_ORDERS = {"ASC", "DESC"}\ndef list_invoices(tenant_id, sort_by, sort_order):\n    safe_col = sort_by if sort_by in ALLOWED_SORT_COLUMNS else "created_at"\n    safe_dir = sort_order.upper() if sort_order.upper() in ALLOWED_SORT_ORDERS else "DESC"\n    sql = f"SELECT id, customer_name FROM invoices WHERE tenant_id = ? ORDER BY {safe_col} {safe_dir}"\n    cursor.execute(sql, (tenant_id,))'),
    ("python", "whitelist_table",
     'ALLOWED_TABLES = {"users", "orders", "products"}\ndef get_count(table):\n    safe_table = table if table in ALLOWED_TABLES else "users"\n    sql = f"SELECT COUNT(*) FROM {safe_table}"\n    cursor.execute(sql)'),
    ("python", "whitelist_column",
     'VALID_COLUMNS = {"email", "username", "id"}\ndef find_by(col, val):\n    safe_col = col if col in VALID_COLUMNS else "id"\n    cursor.execute(f"SELECT * FROM users WHERE {safe_col} = ?", (val,))'),
    ("python", "whitelist_concat",
     'ALLOWED_FIELDS = {"name", "email"}\ndef sort_field(field):\n    safe_f = field if field in ALLOWED_FIELDS else "name"\n    sql = "SELECT * FROM users ORDER BY " + safe_f\n    cursor.execute(sql)'),
    ("python", "whitelist_dict_lookup",
     'SAFE_COLUMN_MAP = {"name": "customer_name", "date": "created_at"}\ndef lookup(col):\n    safe_col = SAFE_COLUMN_MAP[col] if col in SAFE_COLUMN_MAP else "customer_name"\n    sql = f"SELECT id FROM customers ORDER BY {safe_col}"\n    cursor.execute(sql)'),
    ("python", "whitelist_with_param",
     'ALLOWED_SORT_COLUMNS = {"id", "name"}\ndef search(name, sort_by):\n    safe_col = sort_by if sort_by in ALLOWED_SORT_COLUMNS else "id"\n    sql = f"SELECT * FROM users WHERE name LIKE ? ORDER BY {safe_col}"\n    cursor.execute(sql, (f"%{name}%",))'),

    ("javascript", "whitelist_order_by",
     'const ALLOWED_SORT_COLUMNS = new Set(["id", "name", "created_at"]);\nfunction listUsers(sortBy) {\n    const safeCol = ALLOWED_SORT_COLUMNS.has(sortBy) ? sortBy : "created_at";\n    const sql = `SELECT id, name FROM users ORDER BY ${safeCol}`;\n    db.query(sql);\n}'),
    ("javascript", "whitelist_order_by",
     'const VALID_ORDERS = new Set(["ASC", "DESC"]);\nasync function listProducts(order) {\n    const safeOrder = VALID_ORDERS.has(order.toUpperCase()) ? order.toUpperCase() : "DESC";\n    await db.query(`SELECT * FROM products ORDER BY price ${safeOrder}`);\n}'),

    ("php", "whitelist_order_by",
     '$ALLOWED_SORT_COLUMNS = ["id", "name", "created_at"];\nfunction listUsers($pdo, $sortBy) {\n    global $ALLOWED_SORT_COLUMNS;\n    $safeCol = in_array($sortBy, $ALLOWED_SORT_COLUMNS) ? $sortBy : "created_at";\n    $sql = "SELECT id, name FROM users ORDER BY $safeCol";\n    $pdo->query($sql);\n}'),

    ("java", "whitelist_order_by",
     'private static final Set<String> ALLOWED_SORT_COLUMNS = Set.of("id", "name", "created_at");\npublic ResultSet listUsers(String sortBy) throws SQLException {\n    String safeCol = ALLOWED_SORT_COLUMNS.contains(sortBy) ? sortBy : "created_at";\n    String sql = "SELECT id, name FROM users ORDER BY " + safeCol;\n    return stmt.executeQuery(sql);\n}'),

    # ── BLIND with boolean-coerced fetch result (Gap-A v2 Fix B) ─────────────
    # User input → SQL → fetch → reduce to bool. Distinguishes BLIND from
    # SECOND_ORDER (which has DB_LOADED_VAR but NOT BOOLEAN_SINK).

    ("python", "blind_count_gt",
     'def can_view(user_email, invoice_id):\n    sql = "SELECT COUNT(*) FROM acl WHERE email = \'" + user_email + "\' AND id = " + invoice_id\n    cursor.execute(sql)\n    result = cursor.fetchone()[0] > 0\n    return result'),
    ("python", "blind_count_gt",
     'def is_admin(user_id):\n    sql = "SELECT COUNT(*) FROM admins WHERE user_id = " + user_id\n    cursor.execute(sql)\n    return cursor.fetchone()[0] > 0'),
    ("python", "blind_is_not_none",
     'def authenticate(username, password):\n    sql = "SELECT 1 FROM users WHERE u = \'" + username + "\' AND p = \'" + password + "\'"\n    cursor.execute(sql)\n    return cursor.fetchone() is not None'),
    ("python", "blind_is_not_none",
     'def has_session(token):\n    sql = "SELECT 1 FROM sessions WHERE token = \'" + token + "\'"\n    cursor.execute(sql)\n    row = cursor.fetchone()\n    return row is not None'),
    ("python", "blind_count_eq",
     'def is_owner(user_id, post_id):\n    sql = "SELECT COUNT(*) FROM posts WHERE id = " + post_id + " AND owner = " + user_id\n    cursor.execute(sql)\n    return cursor.fetchone()[0] == 1'),
    ("python", "blind_bool_wrap",
     'def has_permission(uid, perm):\n    sql = f"SELECT 1 FROM perms WHERE uid = {uid} AND name = \'{perm}\'"\n    cursor.execute(sql)\n    return bool(cursor.fetchone())'),
    ("python", "blind_temp_var",
     'def can_edit(user_id, doc_id):\n    sql = f"SELECT COUNT(*) FROM doc_acl WHERE user = {user_id} AND doc = {doc_id} AND edit = 1"\n    cursor.execute(sql)\n    n = cursor.fetchone()[0]\n    return n > 0'),
    ("python", "blind_complex_acl",
     'def can_view_invoice(user_email, invoice_id):\n    sql = ("SELECT COUNT(*) FROM invoice_acl a JOIN users u ON u.id = a.user_id "\n           "WHERE u.email = \'" + user_email + "\' AND a.invoice_id = " + invoice_id + " AND a.can_view = 1")\n    cursor.execute(sql)\n    return cursor.fetchone()[0] > 0'),
    ("python", "blind_concat_login",
     'def login(username, pw_hash):\n    sql = "SELECT 1 FROM users WHERE u = \'" + username + "\' AND h = \'" + pw_hash + "\'"\n    cursor.execute(sql)\n    row = cursor.fetchone()\n    return row is not None'),
    ("python", "blind_fstring_count",
     'def has_role(user_id, role):\n    sql = f"SELECT COUNT(*) FROM user_roles WHERE u = {user_id} AND r = \'{role}\'"\n    cursor.execute(sql)\n    return cursor.fetchone()[0] > 0'),
    ("python", "blind_orm_like_concat",
     'def is_member(uid, gid):\n    sql = "SELECT 1 FROM members WHERE uid = " + str(uid) + " AND gid = " + str(gid)\n    cursor.execute(sql)\n    return cursor.fetchone() is not None'),
    ("python", "blind_negative_check",
     'def is_blocked(email):\n    sql = "SELECT 1 FROM blocklist WHERE email = \'" + email + "\'"\n    cursor.execute(sql)\n    return cursor.fetchone() is None'),

    ("javascript", "blind_count_gt",
     'async function isAdmin(userId) {\n    const sql = "SELECT COUNT(*) FROM admins WHERE user_id = " + userId;\n    const rows = await db.query(sql);\n    return rows[0].count > 0;\n}'),
    ("javascript", "blind_is_not_none",
     'async function authenticate(username, password) {\n    const sql = `SELECT 1 FROM users WHERE u = \'${username}\' AND p = \'${password}\'`;\n    const row = await db.queryOne(sql);\n    return row !== null;\n}'),

    ("php", "blind_count_gt",
     'function isAdmin($mysqli, $userId) {\n    $sql = "SELECT COUNT(*) FROM admins WHERE user_id = " . $userId;\n    $r = mysqli_query($mysqli, $sql);\n    $row = mysqli_fetch_row($r);\n    return $row[0] > 0;\n}'),

    ("java", "blind_count_gt",
     'public boolean isAdmin(String userId) throws SQLException {\n    String sql = "SELECT COUNT(*) FROM admins WHERE user_id = " + userId;\n    ResultSet rs = stmt.executeQuery(sql);\n    rs.next();\n    return rs.getInt(1) > 0;\n}'),

    # ── SECOND_ORDER with DB-loaded fragment reuse (Gap-A v2 Fix B) ──────────
    # The dangerous variable comes from a fetch call, then is concatenated
    # into a NEW SQL query. Critical: NO BOOLEAN_SINK (distinguishes from BLIND).

    ("python", "second_order_cached_fragment",
     'def render(report_id, tenant_id):\n    cursor.execute("SELECT cached_where FROM cache WHERE id = ? AND t = ?", (report_id, tenant_id))\n    cached_where = cursor.fetchone()[0]\n    sql = "SELECT id, name FROM invoices WHERE t = " + str(tenant_id) + " AND " + cached_where\n    cursor.execute(sql)'),
    ("python", "second_order_stored_bio",
     'def update_status(user_id):\n    cursor.execute("SELECT bio FROM profiles WHERE user_id = ?", (user_id,))\n    user_bio = cursor.fetchone()[0]\n    log = "INSERT INTO audit (msg) VALUES (\'updated: " + user_bio + "\')"\n    cursor.executescript(log)'),
    ("python", "second_order_username_reuse",
     'def render_profile(user_id):\n    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))\n    name = cursor.fetchone()[0]\n    cursor.execute("SELECT * FROM activity WHERE actor = \'" + name + "\'")'),
    ("python", "second_order_cached_filter",
     'def list_records(filter_id):\n    cursor.execute("SELECT filter_sql FROM saved_filters WHERE id = ?", (filter_id,))\n    raw = cursor.fetchone()[0]\n    sql = "SELECT * FROM records WHERE " + raw\n    cursor.execute(sql)'),
    ("python", "second_order_tag_reuse",
     'def show_tag_posts(tag_id):\n    cursor.execute("SELECT tag FROM tags WHERE id = ?", (tag_id,))\n    tag = cursor.fetchone()[0]\n    cursor.execute(f"SELECT * FROM posts WHERE tags LIKE \'%{tag}%\'")'),
    ("python", "second_order_role_reuse",
     'def get_perms(user_id):\n    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))\n    role = cursor.fetchone()[0]\n    cursor.execute("SELECT permission FROM role_perms WHERE role = \'" + role + "\'")'),
    ("python", "second_order_email_reuse",
     'def notify(uid):\n    cursor.execute("SELECT email FROM users WHERE id = ?", (uid,))\n    email = cursor.fetchone()[0]\n    cursor.execute(f"SELECT * FROM notifications WHERE recipient = \'{email}\'")'),
    ("python", "second_order_template_lookup",
     'def render_email(template_id):\n    cursor.execute("SELECT body FROM templates WHERE id = ?", (template_id,))\n    body = cursor.fetchone()[0]\n    cursor.execute("INSERT INTO outbox (content) VALUES (\'" + body + "\')")'),
    ("python", "second_order_setting_reuse",
     'def apply_setting(uid):\n    cursor.execute("SELECT pref FROM user_settings WHERE uid = ?", (uid,))\n    pref = cursor.fetchone()[0]\n    cursor.execute(f"UPDATE config SET value = \'{pref}\' WHERE uid = {uid}")'),
    ("python", "second_order_via_fetchall",
     'def reapply_filters(uid):\n    rows = cursor.execute("SELECT raw_filter FROM filters WHERE uid = ?", (uid,)).fetchall()\n    for row in rows:\n        sql = "SELECT * FROM data WHERE " + row[0]\n        cursor.execute(sql)'),

    ("javascript", "second_order_cached_fragment",
     'async function render(reportId, tenantId) {\n    const r = await db.query("SELECT cached_where FROM cache WHERE id = ? AND t = ?", [reportId, tenantId]);\n    const cachedWhere = r[0].cached_where;\n    const sql = "SELECT id FROM invoices WHERE t = " + tenantId + " AND " + cachedWhere;\n    await db.query(sql);\n}'),
    ("javascript", "second_order_username_reuse",
     'async function showProfile(userId) {\n    const r = await db.query("SELECT username FROM users WHERE id = ?", [userId]);\n    const name = r[0].username;\n    return db.query(`SELECT * FROM activity WHERE actor = \'${name}\'`);\n}'),

    ("php", "second_order_cached_fragment",
     'function render($pdo, $reportId, $tenantId) {\n    $stmt = $pdo->prepare("SELECT cached_where FROM cache WHERE id = ?");\n    $stmt->execute([$reportId]);\n    $cw = $stmt->fetchColumn();\n    $sql = "SELECT id FROM invoices WHERE t = " . $tenantId . " AND " . $cw;\n    $pdo->query($sql);\n}'),

    ("java", "second_order_cached_fragment",
     'public void render(int reportId) throws SQLException {\n    PreparedStatement ps = conn.prepareStatement("SELECT cached_where FROM cache WHERE id = ?");\n    ps.setInt(1, reportId);\n    ResultSet rs = ps.executeQuery();\n    rs.next();\n    String cw = rs.getString(1);\n    String sql = "SELECT id FROM invoices WHERE " + cw;\n    stmt.executeQuery(sql);\n}'),
]



# ─────────────────────────────────────────────────────────────────────────────
# Structural augmentation — language-aware transforms
# ─────────────────────────────────────────────────────────────────────────────
# Each transform takes a code snippet and returns a new snippet whose
# normalized token sequence is genuinely different from the original.
# The transforms are SAFETY-NEUTRAL: they never turn vulnerable code safe
# or vice versa — they only add structural context (function wrappers,
# error handling, validation that does not relate to the SQL injection
# itself, intermediate variables, follow-up logging).
# ─────────────────────────────────────────────────────────────────────────────

def _indent(code: str, prefix: str = "    ") -> str:
    return "\n".join(prefix + line for line in code.split("\n"))


# ── Python transforms ────────────────────────────────────────────────────────

def _py_identity(c):       return c
def _py_wrap_function(c):  return f"def handle(request):\n{_indent(c)}"
def _py_try_except(c):     return f"try:\n{_indent(c)}\nexcept Exception as err:\n    pass"
def _py_validate_pre(c):   return f"if request is None:\n    return None\n{c}"
def _py_extra_var(c):      return f"_ctx = get_context()\n{c}"
def _py_log_post(c):       return f"{c}\nlogger.info(\"done\")"
def _py_return_result(c):  return f"{c}\nreturn result"
def _py_extra_select(c):   return f"_meta = db.execute(\"SELECT 1\")\n{c}"


# ── JavaScript transforms ────────────────────────────────────────────────────

def _js_identity(c):       return c
def _js_wrap_function(c):  return f"function handle(req, res) {{\n{_indent(c)}\n}}"
def _js_try_catch(c):      return f"try {{\n{_indent(c)}\n}} catch (err) {{\n  console.error(err);\n}}"
def _js_validate_pre(c):   return f"if (!req) {{\n  return;\n}}\n{c}"
def _js_extra_var(c):      return f"const _ctx = getContext();\n{c}"
def _js_log_post(c):       return f"{c}\nconsole.log(\"done\");"
def _js_arrow_wrap(c):     return f"const handle = async (req, res) => {{\n{_indent(c)}\n}};"
def _js_extra_select(c):   return f"const _meta = await db.query(\"SELECT 1\");\n{c}"


# ── PHP transforms ───────────────────────────────────────────────────────────

def _php_identity(c):      return c
def _php_wrap_function(c): return f"function handle($request) {{\n{_indent(c)}\n}}"
def _php_try_catch(c):     return f"try {{\n{_indent(c)}\n}} catch (Exception $err) {{\n  error_log($err);\n}}"
def _php_validate_pre(c):  return f"if (!isset($_GET) && !isset($_POST)) {{\n  return;\n}}\n{c}"
def _php_extra_var(c):     return f"$ctx = get_context();\n{c}"
def _php_log_post(c):      return f"{c}\nerror_log(\"done\");"
def _php_isset_check(c):   return f"if (!isset($_GET[\"x\"])) {{\n  $_GET[\"x\"] = \"\";\n}}\n{c}"
def _php_extra_select(c):  return f"$meta = mysql_query(\"SELECT 1\");\n{c}"


# ── Java transforms ──────────────────────────────────────────────────────────

def _java_identity(c):     return c
def _java_wrap_method(c):  return f"public void handle(HttpServletRequest request) throws Exception {{\n{_indent(c)}\n}}"
def _java_try_catch(c):    return f"try {{\n{_indent(c)}\n}} catch (Exception err) {{\n  err.printStackTrace();\n}}"
def _java_validate_pre(c): return f"if (request == null) {{\n  return;\n}}\n{c}"
def _java_extra_var(c):    return f"Object ctx = getContext();\n{c}"
def _java_log_post(c):     return f"{c}\nlogger.info(\"done\");"
def _java_extra_select(c): return f"Statement meta = conn.createStatement();\nmeta.executeQuery(\"SELECT 1\");\n{c}"
def _java_string_var(c):   return f"String prefix = \"v1\";\n{c}"


TRANSFORMS_BY_LANGUAGE: dict[str, list] = {
    "python":     [_py_identity, _py_wrap_function, _py_try_except, _py_validate_pre,
                   _py_extra_var, _py_log_post, _py_return_result, _py_extra_select],
    "javascript": [_js_identity, _js_wrap_function, _js_try_catch, _js_validate_pre,
                   _js_extra_var, _js_log_post, _js_arrow_wrap, _js_extra_select],
    "php":        [_php_identity, _php_wrap_function, _php_try_catch, _php_validate_pre,
                   _php_extra_var, _php_log_post, _php_isset_check, _php_extra_select],
    "java":       [_java_identity, _java_wrap_method, _java_try_catch, _java_validate_pre,
                   _java_extra_var, _java_log_post, _java_extra_select, _java_string_var],
}


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline helpers
# ─────────────────────────────────────────────────────────────────────────────

def preprocess_to_ids(code: str, vocab: dict) -> np.ndarray:
    cleaned = clean_code(code)
    tokens  = tokenize_code(cleaned)
    norm    = normalize_tokens(tokens)
    unk_id  = vocab["UNK"]
    pad_id  = vocab["PAD"]
    ids = [vocab.get(t, unk_id) for t in norm]
    if len(ids) >= MODEL_SEQ_LEN:
        return np.array(ids[:MODEL_SEQ_LEN], dtype=np.int32)
    return np.array(ids + [pad_id] * (MODEL_SEQ_LEN - len(ids)), dtype=np.int32)


def normalized_signature(code: str) -> tuple[str, ...]:
    """Return the normalized token sequence — used to detect duplicates."""
    return tuple(normalize_tokens(tokenize_code(clean_code(code))))


# ─────────────────────────────────────────────────────────────────────────────
# Dataset builder
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Attack-type taxonomy (Gap A from proposal alignment review)
# ─────────────────────────────────────────────────────────────────────────────
# The proposal (page 8, page 31) requires Model 1 to classify both:
#   1. binary vuln/safe   → emitted as `y` (existing)
#   2. attack type        → emitted as `y_type` (NEW)
#
# Class taxonomy (4 classes, matches proposal page 4):
#   0 NONE         — safe code (no attack)
#   1 IN_BAND      — direct injection that returns data; UNION is a sub-case
#   2 BLIND        — boolean / time-based (no direct data return)
#   3 SECOND_ORDER — store-then-execute pattern
#
# Mapping is purely metadata — derived from the existing `category` field on
# each base sample. No new training data is added in this step.
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_TYPE_NONE         = 0
ATTACK_TYPE_IN_BAND      = 1
ATTACK_TYPE_BLIND        = 2
ATTACK_TYPE_SECOND_ORDER = 3

ATTACK_TYPE_NAMES = {
    ATTACK_TYPE_NONE:         "NONE",
    ATTACK_TYPE_IN_BAND:      "IN_BAND",
    ATTACK_TYPE_BLIND:        "BLIND",
    ATTACK_TYPE_SECOND_ORDER: "SECOND_ORDER",
}


def category_to_attack_type(category: str, label: float) -> int:
    """
    Map a (sub-)category string to an attack-type ID.

    Safe samples → NONE regardless of category.
    Vulnerable samples → IN_BAND / BLIND / SECOND_ORDER by category prefix.

    The default for unrecognised vulnerable categories is IN_BAND, which is
    the broadest and most-populated class. We log unknowns at export time so
    we can review before training.
    """
    if label == 0.0:
        return ATTACK_TYPE_NONE

    cat = category.lower()

    # Strip "mut/<source>/<construction>/<sink>" → use the construction part
    # for mutation-generated samples, since that's where the attack type lives.
    if cat.startswith("mut/"):
        parts = cat.split("/")
        # parts[1] = source name, parts[2] = construction, parts[3] = sink
        cat = parts[2] if len(parts) >= 3 else parts[-1]

    # Order matters — check more specific patterns first
    if "second_order" in cat or cat == "second_order":
        return ATTACK_TYPE_SECOND_ORDER
    if cat.startswith("blind"):
        return ATTACK_TYPE_BLIND
    # IN_BAND is the proposal's umbrella for: classic concat/fstring/format,
    # and union-based (proposal page 4: "In-band SQLi (Union-based)")
    if any(cat.startswith(p) for p in (
        "fstring", "concat", "format", "union", "sprintf",
        "stringbuilder", "sb_", "template",
        "dot_", "dquote_", "insert_", "update_", "delete_",
        "pct_", "ddl_inject",
    )):
        return ATTACK_TYPE_IN_BAND
    # Default for any other vulnerable category — the broadest class
    return ATTACK_TYPE_IN_BAND


def build_dataset(vocab: dict) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict]:
    """
    Apply every language-appropriate transform to every base sample.
    Drop duplicates so the final count is honest.
    Returns (X, y, y_type, statistics_dict).
    """
    rng = np.random.default_rng(42)

    seen: set[tuple] = set()
    X_list: list[np.ndarray] = []
    y_list: list[float] = []
    y_type_list: list[int] = []   # NEW — attack-type label per sample

    raw_vuln = 0
    raw_safe = 0
    dup_vuln = 0
    dup_safe = 0
    unknown_categories: set[str] = set()

    def _add_samples(base_samples, label):
        nonlocal raw_vuln, raw_safe, dup_vuln, dup_safe
        for language, category, code in base_samples:
            transforms = TRANSFORMS_BY_LANGUAGE.get(language, [_py_identity])
            for transform in transforms:
                augmented = transform(code)
                if label == 1.0:
                    raw_vuln += 1
                else:
                    raw_safe += 1
                sig = normalized_signature(augmented)
                if sig in seen:
                    if label == 1.0:
                        dup_vuln += 1
                    else:
                        dup_safe += 1
                    continue
                seen.add(sig)
                X_list.append(preprocess_to_ids(augmented, vocab))
                y_list.append(label)
                y_type_list.append(category_to_attack_type(category, label))

    _add_samples(VULNERABLE_BASE, 1.0)
    _add_samples(SAFE_BASE,       0.0)

    # ── Append systematically mutated samples ─────────────────────────────
    # Mutations are generated by combining fragments along 5 axes (source,
    # sink, query type, construction style for vuln / validation style for safe,
    # language). See scripts/dataset_mutations.py for the full taxonomy.
    # We dedup against the hand-crafted BASE samples and against each other
    # so the final dataset remains 100% unique sequences.
    vuln_muts = generate_mutated_vuln()
    safe_muts = generate_mutated_safe()
    raw_vuln_before = raw_vuln
    raw_safe_before = raw_safe
    _add_samples(vuln_muts, 1.0)
    _add_samples(safe_muts, 0.0)
    mutation_added_vuln = (raw_vuln - raw_vuln_before)
    mutation_added_safe = (raw_safe - raw_safe_before)

    X = np.array(X_list, dtype=np.int32)
    y = np.array(y_list, dtype=np.float32)
    y_type = np.array(y_type_list, dtype=np.int32)

    # Shuffle with fixed seed so train/val splits are reproducible
    perm = rng.permutation(len(y))
    X, y, y_type = X[perm], y[perm], y_type[perm]

    # Per-class breakdown of the attack-type labels
    type_counts = {
        ATTACK_TYPE_NAMES[k]: int((y_type == k).sum())
        for k in sorted(ATTACK_TYPE_NAMES)
    }

    stats = {
        "raw_vuln_after_transform":  raw_vuln,
        "raw_safe_after_transform":  raw_safe,
        "dropped_dup_vuln":          dup_vuln,
        "dropped_dup_safe":          dup_safe,
        "kept_vuln":                 int(y.sum()),
        "kept_safe":                 int((1 - y).sum()),
        "mutation_base_vuln":        len(vuln_muts),
        "mutation_base_safe":        len(safe_muts),
        "mutation_raw_vuln":         mutation_added_vuln,
        "mutation_raw_safe":         mutation_added_safe,
        "attack_type_counts":        type_counts,
    }
    return X, y, y_type, stats


# ─────────────────────────────────────────────────────────────────────────────
# Coverage report
# ─────────────────────────────────────────────────────────────────────────────

def signal_coverage(samples_with_label, signal: str) -> str:
    """Fraction of base samples whose any-transform output contains `signal`."""
    n_total = len(samples_with_label)
    n_hit = 0
    for lang, _cat, code in samples_with_label:
        for transform in TRANSFORMS_BY_LANGUAGE.get(lang, [_py_identity]):
            if signal in normalize_tokens(tokenize_code(clean_code(transform(code)))):
                n_hit += 1
                break
    return f"{n_hit}/{n_total}"


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 1. Vocabulary
    vocab = build_fixed_vocabulary()
    vocab_path = os.path.join(OUTPUT_DIR, "vocabulary.json")
    save_vocabulary(vocab, vocab_path)
    print(f"[1/3] Vocabulary exported  ({len(vocab)} tokens) -> {vocab_path}")

    # 2. Dataset
    X, y, y_type, stats = build_dataset(vocab)
    n_unique = len(set(map(tuple, X.tolist())))

    data_path = os.path.join(OUTPUT_DIR, "training_data.npz")
    np.savez(data_path, X=X, y=y, y_type=y_type)
    print(
        f"[2/3] Dataset exported     "
        f"({len(X)} samples: {int(y.sum())} vuln, {int((1 - y).sum())} safe, "
        f"{n_unique} unique) -> {data_path}"
    )

    # 3. Diagnostic info
    info = {
        "vocab_size": len(vocab),
        "model_seq_len": MODEL_SEQ_LEN,
        "n_samples": len(X),
        "n_unique_after_dedup": n_unique,
        "n_vulnerable": int(y.sum()),
        "n_safe": int((1 - y).sum()),
        "base_vulnerable": len(VULNERABLE_BASE),
        "base_safe": len(SAFE_BASE),
        "attack_type_counts": stats["attack_type_counts"],
        "attack_type_class_ids": {
            "NONE": 0, "IN_BAND": 1, "BLIND": 2, "SECOND_ORDER": 3,
        },
        "augmentation": {
            "type": "language-aware structural transforms",
            "transforms_per_language": {
                lang: len(ts) for lang, ts in TRANSFORMS_BY_LANGUAGE.items()
            },
            "deduplication": {
                "raw_vuln_after_transform": stats["raw_vuln_after_transform"],
                "raw_safe_after_transform": stats["raw_safe_after_transform"],
                "dropped_dup_vuln":         stats["dropped_dup_vuln"],
                "dropped_dup_safe":         stats["dropped_dup_safe"],
            },
        },
        "signal_coverage": {
            "FSTRING_SQL_in_vuln_base": signal_coverage(VULNERABLE_BASE, "FSTRING_SQL"),
            "UNSAFE_EXEC_in_vuln_base": signal_coverage(VULNERABLE_BASE, "UNSAFE_EXEC"),
            "SQL_CONCAT_in_vuln_base":  signal_coverage(VULNERABLE_BASE, "SQL_CONCAT"),
            "SAFE_EXEC_in_safe_base":   signal_coverage(SAFE_BASE,       "SAFE_EXEC"),
        },
        "architecture": {
            "embed_dim":          64,
            "conv_filters":       64,
            "kernel_size":        3,
            "lstm_hidden":        32,
            "dense_hidden":       64,
            "dense_in":           128,
            # Dual-head: vuln head (sigmoid) + attack-type head (softmax over 4 classes)
            "vuln_head_activation":   "sigmoid",
            "type_head_activation":   "softmax",
            "type_head_classes":      4,
        },
        # Weight keys produced by training and consumed by the backend.
        # Includes the new attack-type head (dense2_type_W / dense2_type_b).
        "weights_keys": [
            "emb_W", "conv_W", "conv_b",
            "bilstm_fwd_W", "bilstm_fwd_b",
            "bilstm_bwd_W", "bilstm_bwd_b",
            "dense1_W",      "dense1_b",
            "dense2_W",      "dense2_b",            # vuln head (1×64)
            "dense2_type_W", "dense2_type_b",       # NEW: attack-type head (4×64)
        ],
    }
    info_path = os.path.join(OUTPUT_DIR, "export_info.json")
    with open(info_path, "w") as f:
        json.dump(info, f, indent=2)
    print(f"[3/3] Export info written               -> {info_path}")

    # Console summary
    print()
    print("Augmentation effectiveness:")
    print(f"  Raw VULN samples after transform: {stats['raw_vuln_after_transform']:>4}  "
          f"(dropped {stats['dropped_dup_vuln']} dupes -> kept {stats['kept_vuln']})")
    print(f"  Raw SAFE samples after transform: {stats['raw_safe_after_transform']:>4}  "
          f"(dropped {stats['dropped_dup_safe']} dupes -> kept {stats['kept_safe']})")
    print(f"  Final n_samples == n_unique:      {len(X) == n_unique}")
    print()
    print(f"Mutation contribution:")
    print(f"  Mutation BASE vuln samples generated: {stats['mutation_base_vuln']:>4}")
    print(f"  Mutation BASE safe samples generated: {stats['mutation_base_safe']:>4}")
    print(f"  Mutation RAW (after transforms) vuln: {stats['mutation_raw_vuln']:>4}")
    print(f"  Mutation RAW (after transforms) safe: {stats['mutation_raw_safe']:>4}")
    print()
    print("Signal coverage (across base samples after augmentation):")
    for k, v in info["signal_coverage"].items():
        print(f"  {k:30s} {v}")
    print()
    print("Attack-type label distribution (Gap A, dual-head training):")
    total = sum(stats["attack_type_counts"].values())
    for name, count in stats["attack_type_counts"].items():
        pct = (100.0 * count / total) if total else 0.0
        print(f"  {name:14s} {count:>5d}  ({pct:5.1f}%)")
    print()
    print("=" * 60)
    print("Colab export complete.")
    print(f"  Upload: {vocab_path}")
    print(f"          {data_path}")
    print(f"  Run:    model1_detection.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
