"""
dataset_mutations.py
====================

Combinatorial dataset augmentation across multiple axes:

    Web framework (input source)  ×  DB library (sink)  ×  Query type
        ×  Construction style (vuln) | Validation style (safe)

This module generates a deterministic set of base samples by combining
axis values. The Cartesian product of all axes would produce thousands
of near-duplicates, so each language has a curated cap. Generation is
seeded — same code, same samples.

The samples produced here are added to VULNERABLE_BASE / SAFE_BASE in
export_for_colab.py. The structural transforms in that file then
multiply each base sample by 8 to produce the final training set.

Why this approach (vs LLM generation)?
- Reproducible:  examiner can re-run, same samples come out.
- Zero per-sample review cost: trust the templates, trust the output.
- No label noise: each template's safety class is fixed by construction.
- No external dependencies, no API costs.

Trade-off:
- Less idiomatic variety than hand-written real-world code.
- For the patterns the templates cover, that's fine. For surgical
  extension to specific real-world idioms (e.g. "Django ORM
  extra(where=...) misuse"), use targeted GPT prompts — see
  scripts/GPT_PROMPTS.md.
"""

from __future__ import annotations
import random

Sample = tuple[str, str, str]  # (language, category, code)


# ─────────────────────────────────────────────────────────────────────────────
# Shared slot pools
# ─────────────────────────────────────────────────────────────────────────────

PY_VARS = ["uid", "eid", "name", "email", "token", "code", "pid", "sku", "kind"]
PY_KEYS = ["id", "user_id", "employee", "sid", "idx", "key", "ref"]
TABLES  = ["users", "orders", "products", "employees", "sessions",
           "logs", "comments", "members", "audit", "events"]
COLUMNS = ["id", "name", "email", "username", "token", "sku",
           "category", "status", "ref", "code"]


# ─────────────────────────────────────────────────────────────────────────────
# Python axes
# ─────────────────────────────────────────────────────────────────────────────

PY_SOURCES = [
    # name,             template (uses {v} for variable, {k} for HTTP key)
    ("flask_args_get",  '{v} = request.args.get("{k}")'),
    ("flask_args_idx",  '{v} = request.args["{k}"]'),
    ("flask_form_idx",  '{v} = request.form["{k}"]'),
    ("flask_form_get",  '{v} = request.form.get("{k}", "")'),
    ("flask_json",      '{v} = request.json["{k}"]'),
    ("flask_cookie",    '{v} = request.cookies.get("{k}", "")'),
    ("flask_header",    '{v} = request.headers.get("{k}", "")'),
    ("django_get",      '{v} = request.GET["{k}"]'),
    ("django_get_get",  '{v} = request.GET.get("{k}", "")'),
    ("django_post",     '{v} = request.POST.get("{k}")'),
    ("tornado",         '{v} = self.get_argument("{k}")'),
    ("plain_dict",      '{v} = params["{k}"]'),
    ("env",             '{v} = os.environ["{k}"]'),
]

PY_SINKS = [
    ("cursor_exec",     "cursor.execute({q})"),
    ("cur_exec",        "cur.execute({q})"),
    ("conn_exec",       "conn.execute({q})"),
    ("connection_exec", "connection.execute({q})"),
    ("db_query",        "db.query({q})"),
    ("db_execute",      "db.execute({q})"),
    ("session_exec",    "session.execute({q})"),
    ("engine_exec",     "engine.execute({q})"),
]

# (name, template — uses {t}=table, {c}=column, {v}=variable)
PY_VULN_QUERIES = [
    ("fstring_eq_str",   'f"SELECT * FROM {t} WHERE {c}=\'{{{v}}}\'"'),
    ("fstring_eq_int",   'f"SELECT * FROM {t} WHERE id={{{v}}}"'),
    ("fstring_like",     'f"SELECT * FROM {t} WHERE {c} LIKE \'%{{{v}}}%\'"'),
    ("fstring_in",       'f"SELECT * FROM {t} WHERE {c} IN ({{{v}}})"'),
    ("fstring_orderby",  'f"SELECT * FROM {t} ORDER BY {{{v}}}"'),
    ("fstring_limit",    'f"SELECT * FROM {t} LIMIT {{{v}}}"'),
    ("concat_eq_str",    '"SELECT * FROM {t} WHERE {c}=\'" + {v} + "\'"'),
    ("concat_eq_int",    '"SELECT * FROM {t} WHERE id=" + {v}'),
    ("concat_like",      '"SELECT * FROM {t} WHERE {c} LIKE \'%" + {v} + "%\'"'),
    ("concat_orderby",   '"SELECT * FROM {t} ORDER BY " + {v}'),
    ("pct_format_str",   '"SELECT * FROM {t} WHERE {c}=\'%s\'" % {v}'),
    ("pct_format_int",   '"SELECT * FROM {t} WHERE id=%s" % {v}'),
    ("dot_format",       '"SELECT * FROM {t} WHERE {c}=\'{{}}\'".format({v})'),
    ("insert_fstring",   'f"INSERT INTO {t} ({c}) VALUES (\'{{{v}}}\')"'),
    ("insert_concat",    '"INSERT INTO {t} ({c}) VALUES (\'" + {v} + "\')"'),
    ("update_fstring",   'f"UPDATE {t} SET {c}=\'{{{v}}}\' WHERE id=1"'),
    ("update_concat",    '"UPDATE {t} SET {c}=\'" + {v} + "\' WHERE id=1"'),
    ("delete_fstring",   'f"DELETE FROM {t} WHERE {c}=\'{{{v}}}\'"'),
    ("delete_concat",    '"DELETE FROM {t} WHERE id=" + {v}'),
]

# Safe-construction templates.
# {v} appears as a parameter binding, NEVER inlined into the SQL.
PY_SAFE_QUERIES = [
    ("param_qmark_str",  ('"SELECT * FROM {t} WHERE {c} = ?"', "({v},)")),
    ("param_qmark_int",  ('"SELECT * FROM {t} WHERE id = ?"',  "({v},)")),
    ("param_pct_str",    ('"SELECT * FROM {t} WHERE {c} = %s"', "({v},)")),
    ("param_pct_int",    ('"SELECT * FROM {t} WHERE id = %s"',  "({v},)")),
    ("param_named",      ('"SELECT * FROM {t} WHERE {c} = :name"', '{{"name": {v}}}')),
    ("param_qmark_like", ('"SELECT * FROM {t} WHERE {c} LIKE ?"', '("%" + {v} + "%",)')),
    ("insert_param",     ('"INSERT INTO {t} ({c}) VALUES (?)"', "({v},)")),
    ("update_param",     ('"UPDATE {t} SET {c} = ? WHERE id = ?"', "({v}, 1)")),
    ("delete_param",     ('"DELETE FROM {t} WHERE id = ?"', "({v},)")),
]

# Validation patterns to inject before unsafe-LOOKING but guarded code.
# Each returns a (validation_block, follows_with_fstring_or_concat) pair.
PY_VALIDATIONS = [
    ("isdigit",        '    if not str({v}).isdigit():\n        return None\n'),
    ("len_check",      '    if not {v} or len({v}) > 64:\n        return None\n'),
    ("regex",          '    import re\n    if not re.fullmatch(r"[a-zA-Z0-9_]+", {v} or ""):\n        return None\n'),
    ("type_cast",      '    {v} = int({v})\n'),
    ("whitelist_set",  '    ALLOWED = {{"asc", "desc"}}\n    if {v} not in ALLOWED:\n        return None\n'),
    ("whitelist_dict", '    MAP = {{"a": "{c}", "b": "id"}}\n    {v} = MAP.get({v})\n    if not {v}:\n        return None\n'),
]


def _python_vuln(rng: random.Random, max_count: int = 100) -> list[Sample]:
    """Generate Python vulnerable samples from source × sink × construction."""
    combos = [
        (src, sink, ctor)
        for src in PY_SOURCES
        for sink in PY_SINKS
        for ctor in PY_VULN_QUERIES
    ]
    rng.shuffle(combos)

    out, seen_shapes = [], set()
    for (src_n, src_t), (snk_n, snk_t), (ctr_n, ctr_t) in combos:
        if len(out) >= max_count:
            break
        # Shape key — avoid generating semantically identical samples
        shape = (src_n, snk_n, ctr_n)
        if shape in seen_shapes:
            continue
        seen_shapes.add(shape)

        v, k = rng.choice(PY_VARS), rng.choice(PY_KEYS)
        t, c = rng.choice(TABLES),  rng.choice(COLUMNS)

        src_line = src_t.format(v=v, k=k)
        query    = ctr_t.format(t=t, c=c, v=v)
        sink     = snk_t.format(q="sql")
        code = f"{src_line}\nsql = {query}\n{sink}"
        out.append(("python", f"mut/{src_n}/{ctr_n}/{snk_n}", code))
    return out


def _python_safe(rng: random.Random, max_count: int = 100) -> list[Sample]:
    """Generate Python safe samples — parameterised and validated patterns."""
    out, seen_shapes = [], set()

    # Pure parameterised samples (no f-string / concat)
    combos_param = [
        (src, sink, q) for src in PY_SOURCES for sink in PY_SINKS for q in PY_SAFE_QUERIES
    ]
    rng.shuffle(combos_param)
    for (src_n, src_t), (snk_n, snk_t), (q_n, (q_sql, q_params)) in combos_param:
        if len(out) >= max_count // 2:
            break
        shape = (src_n, snk_n, q_n)
        if shape in seen_shapes:
            continue
        seen_shapes.add(shape)

        v, k = rng.choice(PY_VARS), rng.choice(PY_KEYS)
        t, c = rng.choice(TABLES),  rng.choice(COLUMNS)

        src_line = src_t.format(v=v, k=k)
        sql_line = q_sql.format(t=t, c=c)
        params   = q_params.format(v=v)
        # cursor.execute(sql, params) form
        sink_arg = snk_t.format(q=f"{sql_line}, {params}")
        code = f"{src_line}\n{sink_arg}"
        out.append(("python", f"mut/{src_n}/{q_n}/{snk_n}", code))

    # Validation-then-dynamic-SQL samples (looks vulnerable, is safe)
    # These are crucial — they teach the model to read validation context.
    combos_validate = [
        (src, val, sink) for src in PY_SOURCES for val in PY_VALIDATIONS for sink in PY_SINKS
    ]
    rng.shuffle(combos_validate)
    for (src_n, src_t), (val_n, val_t), (snk_n, snk_t) in combos_validate:
        if len(out) >= max_count:
            break
        shape = (src_n, val_n, snk_n)
        if shape in seen_shapes:
            continue
        seen_shapes.add(shape)

        v, k = rng.choice(PY_VARS), rng.choice(PY_KEYS)
        t, c = rng.choice(TABLES),  rng.choice(COLUMNS)

        src_line = "    " + src_t.format(v=v, k=k)
        val_block = val_t.format(v=v, c=c)
        # After validation passes, the dynamic value is used in either a
        # parameterised query (if cast to int) OR in a SQL fragment that
        # has been confirmed safe by the validation. We use parameterised
        # form to keep the safety guarantee airtight.
        if val_n == "type_cast":
            # int cast → used as integer in parameterised query
            sink_call = snk_t.format(q=f'"SELECT * FROM {t} WHERE id = ?", ({v},)')
        elif val_n == "whitelist_dict":
            # Whitelist dict has already mapped {v} to a SAFE column name.
            # Now inline it (this IS the user's pattern).
            sink_call = snk_t.format(q=f'f"SELECT * FROM {t} ORDER BY {{{v}}}"')
        elif val_n == "whitelist_set":
            sink_call = snk_t.format(q=f'f"SELECT * FROM {t} ORDER BY id {{{v}}}"')
        else:
            # Validation passed (regex/length/isdigit) → safe to use in param query
            sink_call = snk_t.format(q=f'"SELECT * FROM {t} WHERE {c} = ?", ({v},)')
        sink_line = "    " + sink_call

        code = f"def handle_request(request):\n{src_line}\n{val_block}{sink_line}"
        out.append(("python", f"mut/{src_n}/safe-{val_n}/{snk_n}", code))

    return out


# ─────────────────────────────────────────────────────────────────────────────
# JavaScript axes
# ─────────────────────────────────────────────────────────────────────────────

JS_SOURCES = [
    ("query",   'const {v} = req.query.{k};'),
    ("body",    'const {v} = req.body.{k};'),
    ("params",  'const {v} = req.params.{k};'),
    ("headers", 'const {v} = req.headers["{k}"];'),
    ("cookies", 'const {v} = req.cookies.{k};'),
]

JS_SINKS = [
    ("conn_query",   "conn.query({q});"),
    ("db_query",     "db.query({q});"),
    ("pool_query",   "pool.query({q});"),
    ("pool_exec",    "pool.execute({q});"),
    ("connection",   "connection.query({q});"),
    ("db_execute",   "db.execute({q});"),
]

JS_VULN_QUERIES = [
    ("template_eq_str",  '`SELECT * FROM {t} WHERE {c}=\'${{{v}}}\'`'),
    ("template_eq_int",  '`SELECT * FROM {t} WHERE id=${{{v}}}`'),
    ("template_like",    '`SELECT * FROM {t} WHERE {c} LIKE \'%${{{v}}}%\'`'),
    ("template_orderby", '`SELECT * FROM {t} ORDER BY ${{{v}}}`'),
    ("concat_eq_str",    '"SELECT * FROM {t} WHERE {c}=\'" + {v} + "\'"'),
    ("concat_eq_int",    '"SELECT * FROM {t} WHERE id=" + {v}'),
    ("concat_like",      '"SELECT * FROM {t} WHERE {c} LIKE \'%" + {v} + "%\'"'),
    ("insert_template",  '`INSERT INTO {t} ({c}) VALUES (\'${{{v}}}\')`'),
    ("update_concat",    '"UPDATE {t} SET {c}=\'" + {v} + "\' WHERE id=1"'),
]

JS_SAFE_QUERIES = [
    ("param_q",       ('"SELECT * FROM {t} WHERE {c} = ?"',  "[{v}]")),
    ("param_q_int",   ('"SELECT * FROM {t} WHERE id = ?"',   "[{v}]")),
    ("param_q_like",  ('"SELECT * FROM {t} WHERE {c} LIKE ?"','[`%${{{v}}}%`]')),
    ("insert_param",  ('"INSERT INTO {t} ({c}) VALUES (?)"', "[{v}]")),
    ("update_param",  ('"UPDATE {t} SET {c} = ? WHERE id = 1"',"[{v}]")),
]


def _js_vuln(rng: random.Random, max_count: int = 30) -> list[Sample]:
    combos = [(s, snk, c) for s in JS_SOURCES for snk in JS_SINKS for c in JS_VULN_QUERIES]
    rng.shuffle(combos)
    out, seen = [], set()
    for (src_n, src_t), (snk_n, snk_t), (ctr_n, ctr_t) in combos:
        if len(out) >= max_count: break
        shape = (src_n, snk_n, ctr_n)
        if shape in seen: continue
        seen.add(shape)
        v, k = rng.choice(["uid","eid","name","tok","code"]), rng.choice(["id","key","ref"])
        t, c = rng.choice(TABLES), rng.choice(COLUMNS)
        src = src_t.format(v=v, k=k)
        q   = ctr_t.format(t=t, c=c, v=v)
        snk = snk_t.format(q=f"sql")
        out.append(("javascript", f"mut/{src_n}/{ctr_n}/{snk_n}",
                    f"{src}\nconst sql = {q};\n{snk}"))
    return out


def _js_safe(rng: random.Random, max_count: int = 30) -> list[Sample]:
    combos = [(s, snk, c) for s in JS_SOURCES for snk in JS_SINKS for c in JS_SAFE_QUERIES]
    rng.shuffle(combos)
    out, seen = [], set()
    for (src_n, src_t), (snk_n, snk_t), (q_n, (q_sql, q_params)) in combos:
        if len(out) >= max_count: break
        shape = (src_n, snk_n, q_n)
        if shape in seen: continue
        seen.add(shape)
        v, k = rng.choice(["uid","eid","name","tok","code"]), rng.choice(["id","key","ref"])
        t, c = rng.choice(TABLES), rng.choice(COLUMNS)
        src = src_t.format(v=v, k=k)
        sql = q_sql.format(t=t, c=c)
        prm = q_params.format(v=v)
        snk = snk_t.format(q=f"{sql}, {prm}")
        out.append(("javascript", f"mut/{src_n}/{q_n}/{snk_n}", f"{src}\n{snk}"))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# PHP axes
# ─────────────────────────────────────────────────────────────────────────────

PHP_SOURCES = [
    ("get",     '${v} = $_GET["{k}"];'),
    ("post",    '${v} = $_POST["{k}"];'),
    ("request", '${v} = $_REQUEST["{k}"];'),
    ("cookie",  '${v} = $_COOKIE["{k}"] ?? "";'),
    ("server",  '${v} = $_SERVER["HTTP_{ku}"] ?? "";'),
]

PHP_SINKS = [
    ("mysqli_query", 'mysqli_query($conn, ${q});'),
    ("conn_query",   '$conn->query(${q});'),
    ("mysql_query",  'mysql_query(${q});'),
    ("pdo_exec",     '$pdo->exec(${q});'),
]

PHP_VULN_QUERIES = [
    ("dot_eq_str",  '"SELECT * FROM {t} WHERE {c}=\'" . ${v} . "\'"'),
    ("dot_eq_int",  '"SELECT * FROM {t} WHERE id=" . ${v}'),
    ("dot_like",    '"SELECT * FROM {t} WHERE {c} LIKE \'%" . ${v} . "%\'"'),
    ("dot_orderby", '"SELECT * FROM {t} ORDER BY " . ${v}'),
    ("dquote_var",  '"SELECT * FROM {t} WHERE {c}=\'${{{v}}}\'"'),
    ("sprintf",     'sprintf("SELECT * FROM {t} WHERE id=%s", ${v})'),
    ("insert_dot",  '"INSERT INTO {t} ({c}) VALUES (\'" . ${v} . "\')"'),
    ("update_dot",  '"UPDATE {t} SET {c}=\'" . ${v} . "\' WHERE id=1"'),
]

PHP_SAFE_QUERIES = [
    ("pdo_prepare", '$stmt = $pdo->prepare("SELECT * FROM {t} WHERE {c} = ?");\n$stmt->execute([${v}]);'),
    ("pdo_named",   '$stmt = $pdo->prepare("SELECT * FROM {t} WHERE {c} = :name");\n$stmt->execute(["name" => ${v}]);'),
    ("mysqli_bind", '$stmt = $mysqli->prepare("SELECT * FROM {t} WHERE {c} = ?");\n$stmt->bind_param("s", ${v});\n$stmt->execute();'),
    ("insert_prep", '$stmt = $pdo->prepare("INSERT INTO {t} ({c}) VALUES (?)");\n$stmt->execute([${v}]);'),
    ("update_prep", '$stmt = $pdo->prepare("UPDATE {t} SET {c} = ? WHERE id = ?");\n$stmt->execute([${v}, 1]);'),
]


def _php_vuln(rng: random.Random, max_count: int = 25) -> list[Sample]:
    combos = [(s, snk, c) for s in PHP_SOURCES for snk in PHP_SINKS for c in PHP_VULN_QUERIES]
    rng.shuffle(combos)
    out, seen = [], set()
    for (src_n, src_t), (snk_n, snk_t), (ctr_n, ctr_t) in combos:
        if len(out) >= max_count: break
        shape = (src_n, snk_n, ctr_n)
        if shape in seen: continue
        seen.add(shape)
        v, k = rng.choice(["uid","eid","name","tok","code"]), rng.choice(["id","key","ref"])
        t, c = rng.choice(TABLES), rng.choice(COLUMNS)
        src = src_t.format(v=v, k=k, ku=k.upper())
        q   = ctr_t.format(t=t, c=c, v=v)
        snk = snk_t.format(q="query")
        out.append(("php", f"mut/{src_n}/{ctr_n}/{snk_n}",
                    f"{src}\n$query = {q};\n{snk}"))
    return out


def _php_safe(rng: random.Random, max_count: int = 25) -> list[Sample]:
    combos = [(s, q) for s in PHP_SOURCES for q in PHP_SAFE_QUERIES]
    rng.shuffle(combos)
    out, seen = [], set()
    for (src_n, src_t), (q_n, q_t) in combos:
        if len(out) >= max_count: break
        shape = (src_n, q_n)
        if shape in seen: continue
        seen.add(shape)
        v, k = rng.choice(["uid","eid","name","tok","code"]), rng.choice(["id","key","ref"])
        t, c = rng.choice(TABLES), rng.choice(COLUMNS)
        src = src_t.format(v=v, k=k, ku=k.upper())
        body = q_t.format(t=t, c=c, v=v)
        out.append(("php", f"mut/{src_n}/{q_n}", f"{src}\n{body}"))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Java axes
# ─────────────────────────────────────────────────────────────────────────────

JAVA_SOURCES = [
    ("get_param", 'String {v} = request.getParameter("{k}");'),
    ("get_attr",  'String {v} = (String) request.getAttribute("{k}");'),
    ("get_header",'String {v} = request.getHeader("{k}");'),
    ("path_param",'String {v} = pathParts[1];  // from URL'),
]

JAVA_VULN_QUERIES = [
    ("concat_eq_str", '"SELECT * FROM {t} WHERE {c}=\'" + {v} + "\'"'),
    ("concat_eq_int", '"SELECT * FROM {t} WHERE id=" + {v}'),
    ("concat_like",   '"SELECT * FROM {t} WHERE {c} LIKE \'%" + {v} + "%\'"'),
    ("concat_orderby",'"SELECT * FROM {t} ORDER BY " + {v}'),
    ("sb_append",     'new StringBuilder("SELECT * FROM {t} WHERE id=").append({v}).toString()'),
    ("string_format", 'String.format("SELECT * FROM {t} WHERE {c}=\'%s\'", {v})'),
]

JAVA_SAFE_QUERIES = [
    ("pstmt_qmark",   'PreparedStatement ps = conn.prepareStatement("SELECT * FROM {t} WHERE {c} = ?");\nps.setString(1, {v});\nResultSet rs = ps.executeQuery();'),
    ("pstmt_int",     'PreparedStatement ps = conn.prepareStatement("SELECT * FROM {t} WHERE id = ?");\nps.setInt(1, Integer.parseInt({v}));\nResultSet rs = ps.executeQuery();'),
    ("pstmt_like",    'PreparedStatement ps = conn.prepareStatement("SELECT * FROM {t} WHERE {c} LIKE ?");\nps.setString(1, "%" + {v} + "%");\nResultSet rs = ps.executeQuery();'),
    ("pstmt_insert",  'PreparedStatement ps = conn.prepareStatement("INSERT INTO {t} ({c}) VALUES (?)");\nps.setString(1, {v});\nps.executeUpdate();'),
    ("pstmt_update",  'PreparedStatement ps = conn.prepareStatement("UPDATE {t} SET {c} = ? WHERE id = ?");\nps.setString(1, {v});\nps.setInt(2, 1);\nps.executeUpdate();'),
]


def _java_vuln(rng: random.Random, max_count: int = 20) -> list[Sample]:
    combos = [(s, c) for s in JAVA_SOURCES for c in JAVA_VULN_QUERIES]
    rng.shuffle(combos)
    out, seen = [], set()
    for (src_n, src_t), (ctr_n, ctr_t) in combos:
        if len(out) >= max_count: break
        shape = (src_n, ctr_n)
        if shape in seen: continue
        seen.add(shape)
        v, k = rng.choice(["uid","eid","name","tok","code"]), rng.choice(["id","key","ref"])
        t, c = rng.choice(TABLES), rng.choice(COLUMNS)
        src = src_t.format(v=v, k=k)
        q   = ctr_t.format(t=t, c=c, v=v)
        body = f"String sql = {q};\nResultSet rs = stmt.executeQuery(sql);"
        out.append(("java", f"mut/{src_n}/{ctr_n}", f"{src}\n{body}"))
    return out


def _java_safe(rng: random.Random, max_count: int = 20) -> list[Sample]:
    combos = [(s, q) for s in JAVA_SOURCES for q in JAVA_SAFE_QUERIES]
    rng.shuffle(combos)
    out, seen = [], set()
    for (src_n, src_t), (q_n, q_t) in combos:
        if len(out) >= max_count: break
        shape = (src_n, q_n)
        if shape in seen: continue
        seen.add(shape)
        v, k = rng.choice(["uid","eid","name","tok","code"]), rng.choice(["id","key","ref"])
        t, c = rng.choice(TABLES), rng.choice(COLUMNS)
        src = src_t.format(v=v, k=k)
        body = q_t.format(t=t, c=c, v=v)
        out.append(("java", f"mut/{src_n}/{q_n}", f"{src}\n{body}"))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def generate_mutated_vuln(seed: int = 42) -> list[Sample]:
    """Return the full list of mutation-generated vulnerable base samples."""
    rng = random.Random(seed)
    return (
        _python_vuln(rng, max_count=100)
        + _js_vuln(rng,    max_count=30)
        + _php_vuln(rng,   max_count=25)
        + _java_vuln(rng,  max_count=20)
    )


def generate_mutated_safe(seed: int = 43) -> list[Sample]:
    """Return the full list of mutation-generated safe base samples."""
    rng = random.Random(seed)
    return (
        _python_safe(rng, max_count=100)
        + _js_safe(rng,   max_count=30)
        + _php_safe(rng,  max_count=25)
        + _java_safe(rng, max_count=20)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Standalone smoke test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    vuln = generate_mutated_vuln()
    safe = generate_mutated_safe()
    print(f"Mutated vuln samples: {len(vuln)}")
    print(f"Mutated safe samples: {len(safe)}")
    print()
    print("First 3 vuln samples:")
    for lang, cat, code in vuln[:3]:
        print(f"  [{lang}] {cat}")
        print("    " + code.replace("\n", "\n    "))
        print()
    print("First 3 safe samples:")
    for lang, cat, code in safe[:3]:
        print(f"  [{lang}] {cat}")
        print("    " + code.replace("\n", "\n    "))
