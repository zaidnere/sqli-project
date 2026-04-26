"""
Export preprocessing artifacts for Google Colab training.

Generates the synthetic dataset and vocabulary for the CNN+BiLSTM model.
For Juliet CWE-89 integration (optional), use import_juliet.py instead.

Run from the backend/ directory:
    python scripts/export_for_colab.py

Outputs (inside backend/colab_export/):
    vocabulary.json       – fixed token→id mapping (173 tokens)
    training_data.npz     – X (int32, shape N×256) + y (float32 labels)
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

OUTPUT_DIR = os.path.join(BACKEND_DIR, "colab_export")
MODEL_SEQ_LEN = 256


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


# ─────────────────────────────────────────────────────────────────────────────
# VULNERABLE samples  (label = 1)
# Covers: Python f-string, concat, format, PHP, Java, JavaScript patterns
# ─────────────────────────────────────────────────────────────────────────────
VULNERABLE_SAMPLES = [
    # Python: f-string injection
    'uid = request.args.get("id")\nquery = f"SELECT * FROM users WHERE id={uid}"\nconn.execute(query)',
    'name = request.form["name"]\nsql = f"SELECT * FROM employees WHERE name=\'{name}\'"\ncursor.execute(sql)',
    'search = request.GET["q"]\nresult = db.execute(f"SELECT * FROM products WHERE name LIKE \'%{search}%\'")',
    'role = params["role"]\nq = f"SELECT * FROM permissions WHERE role=\'{role}\'"\ndb.query(q)',
    'dept = request.args["department"]\nresult = conn.execute(f"SELECT * FROM staff WHERE dept=\'{dept}\'")',
    'pid = request.GET.get("pid")\nquery = f"SELECT * FROM posts WHERE id={pid}"\ndb.execute(query)',
    'tag = request.args.get("tag")\ncursor.execute(f"SELECT * FROM articles WHERE tag=\'{tag}\'")',
    'email = request.form.get("email")\ndb.execute(f"SELECT id FROM users WHERE email=\'{email}\'")',
    'token = request.headers.get("token")\ncursor.execute(f"SELECT * FROM sessions WHERE token=\'{token}\'")',
    'year = request.GET["year"]\nconn.execute(f"SELECT * FROM events WHERE year={year}")',
    'cat = request.args["category"]\ndb.execute(f"SELECT * FROM items WHERE category=\'{cat}\'")',
    'status = request.form["status"]\ncursor.execute(f"UPDATE orders SET status=\'{status}\' WHERE id={oid}")',
    'region = request.args.get("region")\nresult = db.execute(f"SELECT * FROM sales WHERE region=\'{region}\'")',
    'user = request.form.get("username")\npwd = request.form.get("password")\ndb.execute(f"SELECT * FROM users WHERE username=\'{user}\' AND password=\'{pwd}\'")',
    'ip = request.headers.get("X-Forwarded-For","0.0.0.0")\ncursor.execute(f"INSERT INTO logs (ip) VALUES (\'{ip}\')")',
    'sortcol = request.GET["sort"]\ncursor.execute(f"SELECT * FROM products ORDER BY {sortcol}")',
    'table = request.GET["table"]\ndb.execute(f"SELECT * FROM {table}")',
    'sid = request.GET.get("session")\ncursor.execute(f"DELETE FROM sessions WHERE id=\'{sid}\'")',

    # Python: direct string concatenation
    'user_id = request.GET["uid"]\nquery = "SELECT * FROM users WHERE id = " + user_id\ndb.execute(query)',
    'name = form["username"]\nsql = "SELECT * FROM accounts WHERE username=\'" + name + "\'"\ncursor.execute(sql)',
    'email = params.get("email")\nq = "SELECT id FROM users WHERE email=\'" + email + "\'"\nconn.execute(q)',
    'order_id = request.args.get("order")\nquery = "SELECT * FROM orders WHERE id=" + order_id\nresult = db.query(query)',
    'product = request.form["product"]\nsql = "SELECT * FROM products WHERE name=\'" + product + "\'"\ncursor.execute(sql)',
    'uid = request.GET.get("uid", "")\nquery = "SELECT name FROM users WHERE id=" + uid\nconn.execute(query)',
    'uname = input_data["user"]\nsql = "DELETE FROM sessions WHERE username=\'" + uname + "\'"\ndb.execute(sql)',
    'cat = request.args["category"]\nquery = "SELECT * FROM items WHERE category=\'" + cat + "\'"\ncur.execute(query)',
    'pass_val = request.form.get("password")\nsql = "SELECT id FROM users WHERE password=\'" + pass_val + "\'"\ncursor.execute(sql)',
    'table_name = request.GET["table"]\nquery = "SELECT * FROM " + table_name\ndb.execute(query)',
    'col = request.args["sort"]\nquery = "SELECT * FROM products ORDER BY " + col\ncursor.execute(query)',
    'search = request.form.get("q", "")\nsql = "SELECT * FROM articles WHERE title LIKE \'%" + search + "%\'"\ndb.execute(sql)',
    'year = request.GET["year"]\nresult = db.execute("SELECT * FROM events WHERE year=" + year)',
    'region = request.args["region"]\ncursor.execute("SELECT * FROM sales WHERE region=\'" + region + "\'")',
    'dept = request.form["department"]\ndb.execute("SELECT * FROM employees WHERE dept=\'" + dept + "\'")',
    'tag = request.GET.get("tag", "")\ncursor.execute("SELECT * FROM posts WHERE tag=\'" + tag + "\'")',
    'status = request.args.get("status")\ndb.execute("SELECT * FROM orders WHERE status=\'" + status + "\'")',
    'ip = request.headers.get("X-Forwarded-For")\ncursor.execute("INSERT INTO logs (ip) VALUES (\'" + ip + "\')")',

    # Python: multi-step accumulation
    'def search_user(request):\n    username = request.GET["user"]\n    query = "SELECT * FROM users "\n    query += "WHERE username=\'" + username + "\'"\n    return db.execute(query)',
    'def login(request):\n    user = request.form.get("username")\n    pwd = request.form.get("password")\n    q = "SELECT * FROM users WHERE username=\'" + user + "\' AND password=\'" + pwd + "\'"\n    return db.execute(q)',
    'def get_record(request):\n    rid = request.args.get("id")\n    base = "SELECT * FROM records WHERE id="\n    full_query = base + rid\n    conn.execute(full_query)',

    # Python: % format & .format()
    'user = request.POST.get("user")\nsql = "SELECT * FROM logins WHERE user=\'%s\'" % user\ndb.execute(sql)',
    'uid = request.GET["id"]\nquery = "SELECT * FROM accounts WHERE id=%s" % uid\ncursor.execute(query)',
    'val = request.form["value"]\nsql = "SELECT * FROM data WHERE value=\'{}\'".format(val)\ndb.execute(sql)',
    'token = request.GET["token"]\nquery = "SELECT user_id FROM tokens WHERE token=\'{}\'".format(token)\nconn.execute(query)',
    'tid = request.args.get("tid")\ncursor.execute("DELETE FROM tasks WHERE id={}".format(tid))',

    # Python: blind / time-based
    'def check_user(request):\n    uid = request.GET["id"]\n    payload = request.GET.get("p", "")\n    q = "SELECT id FROM users WHERE id=" + uid + " AND " + payload\n    db.execute(q)',
    'uid = request.GET.get("id")\ncond = request.GET.get("cond","")\nsql = f"SELECT id FROM users WHERE id={uid} AND IF({cond}, SLEEP(5), 0)"\ncursor.execute(sql)',

    # Python: second-order
    'def register(request):\n    username = request.form["username"]\n    db.execute("INSERT INTO users (username) VALUES (\'" + username + "\')")',
    'def update_profile(request):\n    bio = request.form.get("bio", "")\n    uid = get_current_user_id()\n    db.execute("UPDATE profiles SET bio=\'" + bio + "\' WHERE user_id=" + str(uid))',

    # JavaScript
    'const uid = req.query.uid;\nconst query = "SELECT * FROM users WHERE id=" + uid;\nconn.query(query);',
    'const name = req.body.name;\nconst sql = `SELECT * FROM users WHERE name=\'${name}\'`;\ndb.query(sql);',
    'const email = req.params.email;\npool.query("SELECT * FROM accounts WHERE email=\'" + email + "\'");',
    'const id = req.query.id;\nconst q = "SELECT * FROM orders WHERE user_id=" + id;\nconnection.query(q, callback);',
    'const search = req.body.search;\ndb.query("SELECT * FROM products WHERE name LIKE \'%" + search + "%\'");',
    'const token = req.headers.authorization;\ndb.query("SELECT * FROM sessions WHERE token=\'" + token + "\'");',
    'const cat = req.query.category;\nconst query = "SELECT * FROM items WHERE category=\'" + cat + "\'";\ndb.execute(query);',
    'const pwd = req.body.password;\nconst q = "SELECT id FROM users WHERE password=\'" + pwd + "\'";\ndb.query(q);',
    'const role = req.query.role;\ndb.query(`SELECT * FROM permissions WHERE role=\'${role}\'`);',
    'const username = req.body.username;\nconst password = req.body.password;\ndb.query("SELECT * FROM users WHERE username=\'" + username + "\' AND password=\'" + password + "\'");',
    'const tag = req.body.tag;\npool.execute("SELECT * FROM posts WHERE tag=\'" + tag + "\'");',
    'const status = req.query.status;\ndb.query("SELECT * FROM orders WHERE status=\'" + status + "\'");',
    'app.get("/user", (req, res) => {\n  const id = req.query.id;\n  db.query(`SELECT * FROM users WHERE id=${id}`, (err, rows) => { res.json(rows); });\n});',

    # PHP
    '$uid = $_GET["id"];\n$query = "SELECT * FROM users WHERE id=" . $uid;\nmysql_query($query);',
    '$name = $_POST["username"];\n$sql = "SELECT * FROM accounts WHERE name=\'" . $name . "\'";\nmysqli_query($conn, $sql);',
    '$email = $_REQUEST["email"];\n$q = "SELECT id FROM users WHERE email=\'" . $email . "\'";\nmysql_query($q);',
    '$pass = $_POST["password"];\n$query = "SELECT * FROM users WHERE password=\'" . $pass . "\'";\n$result = $conn->query($query);',
    '$cat = $_GET["category"];\n$query = "SELECT * FROM products WHERE cat=\'" . $cat . "\'";\n$result = mysqli_query($con, $query);',
    '$search = $_GET["q"];\n$sql = "SELECT * FROM articles WHERE title LIKE \'%" . $search . "%\'";\n$result = mysql_query($sql);',
    '$sort = $_GET["sort"];\n$query = "SELECT * FROM users ORDER BY " . $sort;\n$result = $conn->query($query);',
    '$id = $_GET["id"];\n$query = sprintf("SELECT * FROM users WHERE id=%s", $id);\nmysql_query($query);',

    # Java
    'String userId = request.getParameter("id");\nString sql = "SELECT * FROM users WHERE id=" + userId;\nstatement.executeQuery(sql);',
    'String name = request.getParameter("username");\nString query = "SELECT * FROM accounts WHERE name=\'" + name + "\'";\nrs = stmt.executeQuery(query);',
    'String email = request.getParameter("email");\nString q = "SELECT id FROM users WHERE email=\'" + email + "\'";\nResultSet rs = stmt.executeQuery(q);',
    'String search = request.getParameter("q");\nString sql = "SELECT * FROM products WHERE name LIKE \'%" + search + "%\'";\nstmt.executeQuery(sql);',
    'String pass = request.getParameter("password");\nString sql = "SELECT * FROM users WHERE password=\'" + pass + "\'";\nResultSet rs = statement.executeQuery(sql);',
    'String category = request.getParameter("category");\nStringBuilder sb = new StringBuilder("SELECT * FROM items WHERE ");\nsb.append("category=\'").append(category).append("\'");\nResultSet rs = stmt.executeQuery(sb.toString());',
    'String sortCol = request.getParameter("sort");\nString query = "SELECT * FROM users ORDER BY " + sortCol;\nResultSet rs = conn.createStatement().executeQuery(query);',
]


# ─────────────────────────────────────────────────────────────────────────────
# SAFE samples  (label = 0)
# ─────────────────────────────────────────────────────────────────────────────
SAFE_SAMPLES = [
    # Python: parameterized — produces SAFE_EXEC signal
    'user_id = request.GET["uid"]\ncursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
    'name = form["username"]\ncursor.execute("SELECT * FROM accounts WHERE username = %s", (name,))',
    'email = params.get("email")\ncursor.execute("SELECT id FROM users WHERE email = %s", [email])',
    'order_id = request.args.get("order")\ncursor.execute("SELECT * FROM orders WHERE id = ?", (order_id,))',
    'product = request.form["product"]\ncursor.execute("SELECT * FROM products WHERE name = ?", (product,))',
    'uid = request.GET.get("uid", "")\ncursor.execute("SELECT name FROM users WHERE id = %s", (uid,))',
    'pass_val = request.form.get("password")\ncursor.execute("SELECT id FROM users WHERE password_hash = %s", (hash_pw(pass_val),))',
    'search = request.form.get("q", "")\ncursor.execute("SELECT * FROM articles WHERE title LIKE %s", (f"%{search}%",))',
    'year = request.GET["year"]\ncursor.execute("SELECT * FROM events WHERE year = ?", (year,))',
    'region = request.args["region"]\ncursor.execute("SELECT * FROM sales WHERE region = %s", (region,))',
    'dept = request.form["department"]\ncursor.execute("SELECT * FROM employees WHERE dept = ?", (dept,))',
    'cat = request.args["category"]\ncursor.execute("SELECT * FROM items WHERE category = %s", (cat,))',
    'tag = request.GET.get("tag")\ncursor.execute("SELECT * FROM posts WHERE tag = ?", (tag,))',
    'status = request.args.get("status")\ncursor.execute("SELECT * FROM orders WHERE status = %s", (status,))',
    'email = request.form["email"]\ncursor.execute("SELECT id FROM users WHERE email = ?", (email,))',
    'token = request.headers.get("token")\ncursor.execute("SELECT * FROM sessions WHERE token = %s", (token,))',
    'pid = request.GET.get("pid")\ncursor.execute("SELECT * FROM posts WHERE id = ?", (pid,))',
    'role = request.args.get("role")\ncursor.execute("SELECT * FROM permissions WHERE role = %s", (role,))',
    'ip = request.remote_addr\ncursor.execute("INSERT INTO logs (ip) VALUES (?)", (ip,))',

    # Python: multi-line safe
    'def get_user(request):\n    uid = request.GET.get("id")\n    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))\n    return cursor.fetchone()',
    'def login(request):\n    user = request.form.get("username")\n    pwd = request.form.get("password")\n    cursor.execute("SELECT * FROM users WHERE username = %s AND password_hash = %s", (user, hash_password(pwd)))\n    return cursor.fetchone()',
    'def get_orders(request):\n    uid = request.GET.get("user_id")\n    if not uid or not uid.isdigit():\n        return []\n    cursor.execute("SELECT * FROM orders WHERE user_id = ?", (int(uid),))\n    return cursor.fetchall()',
    'def update_bio(request):\n    uid = get_current_user_id(request)\n    bio = request.form.get("bio", "")[:500]\n    cursor.execute("UPDATE profiles SET bio = %s WHERE user_id = %s", (bio, uid))\n    db.commit()',

    # Python: SQLAlchemy text()
    'from sqlalchemy import text\nuid = request.args.get("id")\nstmt = text("SELECT * FROM users WHERE id = :uid")\nresult = conn.execute(stmt, {"uid": uid})',
    'from sqlalchemy import text\nname = form["username"]\nstmt = text("SELECT * FROM accounts WHERE username = :name")\nresult = conn.execute(stmt, {"name": name})',
    'from sqlalchemy import text\nemail = request.form["email"]\nstmt = text("SELECT id FROM users WHERE email = :email")\nresult = conn.execute(stmt, {"email": email})',
    'from sqlalchemy import text\nsearch = request.args.get("q", "")\nstmt = text("SELECT * FROM products WHERE name LIKE :s")\nresult = conn.execute(stmt, {"s": f"%{search}%"})',

    # Python: stored procedures
    'uid = request.GET["id"]\ncursor.callproc("GetUser", [uid])',
    'name = request.form["username"]\ncursor.callproc("GetUserByName", (name,))',

    # Python: validation + parameterized
    'uid = request.GET.get("id", "")\nif not uid.isdigit():\n    abort(400)\ncursor.execute("SELECT * FROM users WHERE id = ?", (int(uid),))',
    'name = request.form.get("name", "").strip()\nif len(name) > 100 or not name.replace(" ", "").isalnum():\n    abort(400)\ncursor.execute("SELECT * FROM users WHERE name = ?", (name,))',
    'allowed = {"name", "email", "age"}\ncol = request.GET["sort"]\nif col not in allowed:\n    abort(400)\ncursor.execute(f"SELECT * FROM users ORDER BY {col}")',
    'allowed_tables = {"users", "products", "orders"}\ntable = request.GET.get("table")\nif table not in allowed_tables:\n    abort(400)\ncursor.execute("SELECT * FROM " + table)',

    # Python: ORM
    'user_id = request.GET.get("uid")\nuser = User.objects.get(id=user_id)',
    'name = form["username"]\nresults = User.query.filter_by(username=name).all()',
    'email = request.args["email"]\nuser = db.session.query(User).filter(User.email == email).first()',
    'category = request.GET["cat"]\nproducts = Product.objects.filter(category=category)',
    'dept = request.form["department"]\nstaff = Employee.objects.filter(department=dept)',
    'search = request.args.get("q", "")\nresults = Product.query.filter(Product.name.ilike(f"%{search}%")).all()',
    'tag = request.GET.get("tag")\nresults = Post.objects.filter(tags__name=tag)',
    'role = request.form["role"]\nperms = Permission.objects.filter(role=role)',
    'uid = request.args.get("user_id")\norders = Order.objects.filter(user_id=uid)',

    # Python: pure logic
    'items = [1, 2, 3, 4, 5]\nresult = [x * 2 for x in items if x > 2]\nreturn result',
    'name = request.form.get("name", "").upper()\nreturn name[:50]',
    'values = [int(x) for x in request.GET.getlist("ids") if x.isdigit()]\nreturn sum(values)',
    'data = request.json\nif not isinstance(data, dict):\n    raise ValueError("Bad input")\nreturn data.get("key", "")',
    'page = int(request.args.get("page", 1))\nlimit = min(int(request.args.get("limit", 10)), 100)\noffset = (page - 1) * limit\nreturn {"page": page, "limit": limit, "offset": offset}',
    'token = secrets.token_hex(32)\nexpiry = datetime.utcnow() + timedelta(hours=1)\nreturn {"token": token, "expiry": expiry.isoformat()}',

    # JavaScript: parameterized
    'const uid = req.query.uid;\nconn.query("SELECT * FROM users WHERE id = ?", [uid]);',
    'const name = req.body.name;\ndb.query("SELECT * FROM users WHERE name = ?", [name], callback);',
    'const email = req.params.email;\npool.execute("SELECT * FROM accounts WHERE email = ?", [email]);',
    'const id = req.query.id;\nconnection.execute("SELECT * FROM orders WHERE user_id = ?", [id]);',
    'const search = req.body.search;\ndb.query("SELECT * FROM products WHERE name LIKE ?", [`%${search}%`]);',
    'const token = req.headers.authorization;\ndb.query("SELECT * FROM sessions WHERE token = ?", [token]);',
    'const cat = req.query.category;\ndb.execute("SELECT * FROM items WHERE category = ?", [cat]);',
    'const tag = req.body.tag;\npool.execute("SELECT * FROM posts WHERE tag = ?", [tag]);',
    'const status = req.query.status;\ndb.query("SELECT * FROM orders WHERE status = ?", [status]);',

    # JavaScript: ORM
    'const uid = req.query.uid;\nconst user = await User.findByPk(uid);',
    'const name = req.body.name;\nconst users = await User.findAll({ where: { name } });',
    'const email = req.body.email;\nconst user = await User.findOne({ where: { email } });',
    'const cat = req.query.category;\nconst items = await Item.findAll({ where: { category: cat } });',
    'const dept = req.body.department;\nconst staff = await Employee.findAll({ where: { department: dept } });',

    # PHP: prepared statements
    '$uid = $_GET["id"];\n$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");\n$stmt->execute([$uid]);',
    '$name = $_POST["username"];\n$stmt = $pdo->prepare("SELECT * FROM accounts WHERE name = ?");\n$stmt->execute([$name]);',
    '$email = $_REQUEST["email"];\n$stmt = $mysqli->prepare("SELECT id FROM users WHERE email = ?");\n$stmt->bind_param("s", $email);\n$stmt->execute();',
    '$pass = $_POST["password"];\n$stmt = $pdo->prepare("SELECT * FROM users WHERE password_hash = ?");\n$stmt->execute([password_hash($pass, PASSWORD_DEFAULT)]);',
    '$cat = $_GET["category"];\n$stmt = $pdo->prepare("SELECT * FROM products WHERE cat = ?");\n$stmt->execute([$cat]);',
    '$tag = $_GET["tag"];\n$stmt = $pdo->prepare("SELECT * FROM posts WHERE tag = ?");\n$stmt->execute([$tag]);',

    # Java: PreparedStatement
    'String userId = request.getParameter("id");\nPreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nstmt.setString(1, userId);\nResultSet rs = stmt.executeQuery();',
    'String name = request.getParameter("username");\nPreparedStatement ps = conn.prepareStatement("SELECT * FROM accounts WHERE name = ?");\nps.setString(1, name);\nps.executeQuery();',
    'String email = request.getParameter("email");\nPreparedStatement ps = conn.prepareStatement("SELECT id FROM users WHERE email = ?");\nps.setString(1, email);\nResultSet rs = ps.executeQuery();',
    'String search = request.getParameter("q");\nPreparedStatement stmt = conn.prepareStatement("SELECT * FROM products WHERE name LIKE ?");\nstmt.setString(1, "%" + search + "%");\nResultSet rs = stmt.executeQuery();',
    'String dept = request.getParameter("dept");\nPreparedStatement ps = conn.prepareStatement("SELECT * FROM staff WHERE dept = ?");\nps.setString(1, dept);\nResultSet rs = ps.executeQuery();',
    'String tag = request.getParameter("tag");\nPreparedStatement stmt = conn.prepareStatement("SELECT * FROM posts WHERE tag = ?");\nstmt.setString(1, tag);\nResultSet rs = stmt.executeQuery();',
]


# ─────────────────────────────────────────────────────────────────────────────
# Augmentation
# ─────────────────────────────────────────────────────────────────────────────

VULN_PREFIXES = [
    "", "# handle user request\n", "# database query\n", "# process input\n",
    "# retrieve record\n", "# fetch data\n", "# user lookup\n", "# admin function\n",
]

SAFE_PREFIXES = [
    "", "# safe database access\n", "# parameterized query\n", "# secure lookup\n",
    "# validated input\n", "# ORM access\n", "# prepared statement\n", "# input validation\n",
]


def build_dataset(vocab: dict) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(42)
    X, y = [], []

    for code in VULNERABLE_SAMPLES:
        for prefix in VULN_PREFIXES:
            X.append(preprocess_to_ids(prefix + code, vocab))
            y.append(1.0)

    for code in SAFE_SAMPLES:
        for prefix in SAFE_PREFIXES:
            X.append(preprocess_to_ids(prefix + code, vocab))
            y.append(0.0)

    X_arr = np.array(X, dtype=np.int32)
    y_arr = np.array(y, dtype=np.float32)
    idx = rng.permutation(len(y_arr))
    return X_arr[idx], y_arr[idx]


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    vocab = build_fixed_vocabulary()
    vocab_path = os.path.join(OUTPUT_DIR, "vocabulary.json")
    save_vocabulary(vocab, vocab_path)
    print(f"[1/3] Vocabulary exported  ({len(vocab)} tokens) → {vocab_path}")

    X, y = build_dataset(vocab)
    n_vuln  = int(y.sum())
    n_safe  = int((1 - y).sum())
    n_unique = len(set(map(tuple, X.tolist())))

    data_path = os.path.join(OUTPUT_DIR, "training_data.npz")
    np.savez(data_path, X=X, y=y)
    print(f"[2/3] Dataset exported     ({len(X)} samples: {n_vuln} vuln, {n_safe} safe, {n_unique} unique) → {data_path}")

    # Signal coverage
    def sig_count(samples, signal):
        return sum(1 for c in samples
                   if signal in normalize_tokens(tokenize_code(clean_code(c))))

    fstring = sig_count(VULNERABLE_SAMPLES, "FSTRING_SQL")
    unsafe  = sig_count(VULNERABLE_SAMPLES, "UNSAFE_EXEC")
    concat  = sig_count(VULNERABLE_SAMPLES, "SQL_CONCAT")
    safe_ex = sig_count(SAFE_SAMPLES,       "SAFE_EXEC")

    info = {
        "vocab_size": len(vocab),
        "model_seq_len": MODEL_SEQ_LEN,
        "n_samples": len(X),
        "n_vulnerable": n_vuln,
        "n_safe": n_safe,
        "n_unique": n_unique,
        "base_vulnerable": len(VULNERABLE_SAMPLES),
        "base_safe": len(SAFE_SAMPLES),
        "augmentation_prefixes": len(VULN_PREFIXES),
        "signal_coverage": {
            "FSTRING_SQL_in_vuln": f"{fstring}/{len(VULNERABLE_SAMPLES)}",
            "UNSAFE_EXEC_in_vuln": f"{unsafe}/{len(VULNERABLE_SAMPLES)}",
            "SQL_CONCAT_in_vuln":  f"{concat}/{len(VULNERABLE_SAMPLES)}",
            "SAFE_EXEC_in_safe":   f"{safe_ex}/{len(SAFE_SAMPLES)}",
        },
        "architecture": {
            "embed_dim": 64,
            "conv_filters": 64,
            "kernel_size": 3,
            "lstm_hidden": 32,
            "dense_hidden": 64,
            "dense_in": 128,
            "output_activation": "sigmoid",
        },
        "weights_keys": [
            "emb_W", "conv_W", "conv_b",
            "bilstm_fwd_W", "bilstm_fwd_b",
            "bilstm_bwd_W", "bilstm_bwd_b",
            "dense1_W", "dense1_b",
            "dense2_W", "dense2_b",
        ],
        "juliet_note": "For Juliet CWE-89 integration, use: python scripts/import_juliet.py",
    }
    info_path = os.path.join(OUTPUT_DIR, "export_info.json")
    with open(info_path, "w") as f:
        json.dump(info, f, indent=2)
    print(f"[3/3] Export info written               → {info_path}")

    print()
    print("Signal coverage (base samples):")
    for k, v in info["signal_coverage"].items():
        print(f"  {k:30s} {v}")
    print()
    print("=" * 60)
    print("Colab export complete.")
    print(f"  Upload: {vocab_path}")
    print(f"          {data_path}")
    print(f"  Run:    sqli_colab_training.ipynb")
    print()
    print("For Juliet CWE-89 dataset (optional):")
    print("  python scripts/import_juliet.py --juliet-dir /path/to/CWE89/")
    print("=" * 60)


if __name__ == "__main__":
    main()
