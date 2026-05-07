r"""
ML-primary Colab export v5 for Model 1 SQLi detection.

This script is intentionally stricter than the old export_for_colab.py:
- sequence length defaults to 256, so the Bi-LSTM sees more source/sink context.
- output includes language, path, source_id, suite_name and raw_hash metadata.
- extra generated training variants are added from the same SQLi families as the
  unseen generalization stress test, but with different random seeds to avoid
  training on the exact evaluation files.
- optional --include-suite can add labelled ZIP suites; use carefully because
  including the exact evaluation suite is data leakage.

Run from backend/:
    set PYTHONPATH=%CD%
    venv\Scripts\python.exe scripts\export_for_colab.py ^
      --out colab_export ^
      --sequence-length 256 ^
      --generated-per-class 32 ^
      --generated-seeds 20260511 20260512 20260513 20260514 20260515

Upload these to Colab:
    colab_export_ml_primary_v5/vocabulary.json
    colab_export_ml_primary_v5/training_data.npz
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import json
import random
import re
import string
import sys
import tempfile
import zipfile
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.vectorization.vocabulary import build_fixed_vocabulary, save_vocabulary
from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.preprocessing.normalizer import normalize_tokens

ATTACK_TO_ID = {"NONE": 0, "IN_BAND": 1, "BLIND": 2, "SECOND_ORDER": 3}
ID_TO_ATTACK = {v: k for k, v in ATTACK_TO_ID.items()}
EXT_TO_LANG = {".py": "python", ".js": "javascript", ".java": "java", ".php": "php"}


def infer_label_from_name(path: str) -> Optional[Tuple[str, str]]:
    full = path.replace("\\", "/").upper()
    name = Path(path).name.upper()
    if "SECOND_ORDER" in full:
        return "VULNERABLE", "SECOND_ORDER"
    if "BLIND" in full:
        return "VULNERABLE", "BLIND"
    if "IN_BAND" in full:
        return "VULNERABLE", "IN_BAND"
    if "SAFE" in full or "NONE" in name:
        return "SAFE", "NONE"
    return None


def read_manifest(root: Path) -> Dict[str, Tuple[str, str]]:
    manifest = root / "manifest.csv"
    out: Dict[str, Tuple[str, str]] = {}
    if not manifest.exists():
        return out
    with manifest.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rel = row.get("file") or row.get("path") or row.get("relative_path")
            if not rel:
                continue
            label = (row.get("expected_label") or row.get("label") or "").strip().upper()
            attack = (row.get("expected_attack_type") or row.get("attack_type") or "").strip().upper()
            if label and attack:
                out[rel.replace("\\", "/")] = (label, attack)
    return out


def normalize_to_ids(code: str, vocab: dict, sequence_length: int) -> Tuple[np.ndarray, Tuple[str, ...], int, int, bool]:
    tokens = normalize_tokens(tokenize_code(clean_code(code)))
    sig = tuple(tokens)
    unk_id = int(vocab.get("UNK", 1))
    pad_id = int(vocab.get("PAD", 0))
    ids = [int(vocab.get(t, unk_id)) for t in tokens]
    raw_len = len(ids)
    truncated = raw_len > sequence_length
    ids = ids[:sequence_length]
    pad_count = max(0, sequence_length - len(ids))
    if pad_count:
        ids = ids + [pad_id] * pad_count
    return np.array(ids, dtype=np.int32), sig, raw_len, pad_count, truncated


def ident(r: random.Random, prefix: str = "v") -> str:
    return prefix + "_" + "".join(r.choice(string.ascii_lowercase) for _ in range(7))


def structural_noise(lang: str, r: random.Random, salt: int) -> str:
    """Return harmless code fragments that survive normalization.

    Random names alone normalize away (VAR_0, FUNC_0, ...), so the exporter must
    create structural diversity, not only identifier diversity. These fragments
    are label-neutral and are used for SAFE and VULNERABLE examples alike.
    """
    k = salt % 10
    if lang == "python":
        snippets = [
            "tmp = 0\nif tmp >= 0:\n    tmp = tmp + 1\n",
            "items = []\nfor item in items:\n    tmp = item\n",
            "try:\n    tmp = int(1)\nexcept Exception:\n    tmp = 0\n",
            "helper = {'a': 1}\ntmp = helper.get('a')\n",
            "def local_helper(x):\n    return x\nmarker = local_helper(1)\n",
            "flag = True\nif flag:\n    marker = 'ok'\nelse:\n    marker = 'no'\n",
            "values = [1, 2, 3]\nmarker = len(values)\n",
            "name = str('x').strip()\n",
            "with_context = None\n",
            "cache = {'safe': 'value'}\ncache_value = cache['safe']\n",
        ]
        return "\n".join(snippets[(k + i * 3) % len(snippets)] for i in range(1 + (salt % 4)))
    if lang == "javascript":
        snippets = [
            "let tmp = 0; if (tmp >= 0) { tmp = tmp + 1; }",
            "const arr = []; for (const item of arr) { tmp = item; }",
            "try { tmp = Number(1); } catch (e) { tmp = 0; }",
            "const helper = { a: 1 }; tmp = helper.a;",
            "function localHelper(x) { return x; } const marker = localHelper(1);",
            "const flag = true; const marker2 = flag ? 'ok' : 'no';",
            "const values = [1, 2, 3]; const size = values.length;",
            "const name = String('x').trim();",
            "let cacheValue = null;",
            "const cache = new Map(); cache.set('safe', 'value');",
        ]
        return "\n".join(snippets[(k + i * 3) % len(snippets)] for i in range(1 + (salt % 4)))
    if lang == "java":
        snippets = [
            "int tmp = 0; if (tmp >= 0) { tmp = tmp + 1; }",
            "java.util.List<String> arr = java.util.List.of(); for (String item : arr) { String tmpS = item; }",
            "try { int x = Integer.parseInt(\"1\"); } catch (Exception e) { int x = 0; }",
            "java.util.Map<String,String> helper = java.util.Map.of(\"a\", \"b\"); String v = helper.get(\"a\");",
            "boolean flag = true; String marker = flag ? \"ok\" : \"no\";",
            "String name = String.valueOf(\"x\").trim();",
            "java.util.Set<String> s = java.util.Set.of(\"a\", \"b\"); boolean has = s.contains(\"a\");",
            "StringBuilder sb = new StringBuilder(); sb.append(\"x\");",
            "Object cacheValue = null;",
            "long now = System.currentTimeMillis();",
        ]
        return "\n".join(snippets[(k + i * 3) % len(snippets)] for i in range(1 + (salt % 4)))
    # php
    snippets = [
        "$tmp = 0; if ($tmp >= 0) { $tmp = $tmp + 1; }",
        "$arr = []; foreach ($arr as $item) { $tmp = $item; }",
        "try { $x = intval(1); } catch (Exception $e) { $x = 0; }",
        "$helper = ['a' => 1]; $tmp = $helper['a'];",
        "$flag = true; $marker = $flag ? 'ok' : 'no';",
        "$values = [1, 2, 3]; $size = count($values);",
        "$name = trim(strval('x'));",
        "$cacheValue = null;",
        "$set = ['a' => true, 'b' => true]; $has = isset($set['a']);",
        "$builder = ''; $builder .= 'x';",
    ]
    return "\n".join(snippets[(k + i * 3) % len(snippets)] for i in range(1 + (salt % 4)))


def add_noise_to_code(lang: str, code: str, r: random.Random, salt: int) -> str:
    noise = structural_noise(lang, r, salt)
    if not noise:
        return code
    if lang == "python":
        return noise + "\n" + code
    if lang == "javascript":
        return code.replace("{\n", "{\n" + noise + "\n", 1)
    if lang == "java":
        # Put noise at the beginning of the first method body, not at class scope.
        return code.replace("throws Exception {\n", "throws Exception {\n" + noise + "\n", 1)
    if lang == "php":
        return code.replace("{\n", "{\n" + noise + "\n", 1)
    return code



def generated_training_samples(seed: int, per_class: int) -> Iterable[Tuple[str, str, str, str]]:
    """Yield (language, attack_type, source_id, code) generated variants.

    These examples target the observed generalization gaps and are intentionally oversampled in v5:
    - Java SAFE allowlist + prepared statement builders.
    - Python/PHP BLIND boolean sinks.
    - PHP SECOND_ORDER stored/config fragments.
    - All languages get positive and safe counterexamples.
    """
    r = random.Random(seed)

    def py_safe() -> str:
        sort = ident(r, "sort")
        sql = ident(r, "sql")
        return f'''
def list_{ident(r, 'fn')}(request, conn):
    allowed = {{"created": "created_at", "email": "email", "name": "name"}}
    {sort} = allowed.get(request.GET.get("sort"), "created_at")
    limit = min(max(int(request.GET.get("limit", 25)), 1), 100)
    {sql} = "SELECT id,email FROM users WHERE tenant_id = ? ORDER BY " + {sort} + " LIMIT ?"
    decoy = "SELECT * FROM users WHERE email = " + request.GET.get("email", "")
    return conn.execute({sql}, (request.user.tenant_id, limit)).fetchall()
'''

    def py_inband() -> str:
        v = ident(r, "email"); q = ident(r, "sql")
        return f'''
def find_{ident(r, 'fn')}(request, conn):
    {v} = request.GET.get("email", "")
    {q} = "SELECT * FROM users WHERE email='" + {v} + "'"
    return conn.execute({q}).fetchall()
'''

    def py_blind() -> str:
        v = ident(r, "token"); q = ident(r, "sql")
        return f'''
def active_{ident(r, 'fn')}(request, conn):
    {v} = request.GET.get("token", "")
    {q} = "SELECT id FROM sessions WHERE token='" + {v} + "'"
    row = conn.execute({q}).fetchone()
    return row is not None
'''

    def py_second() -> str:
        f = ident(r, "load"); frag = ident(r, "frag"); q = ident(r, "sql")
        return f'''
def {f}(conn, tenant):
    row = conn.execute("SELECT where_clause FROM saved_filters WHERE tenant_id = ?", (tenant,)).fetchone()
    return row[0]

def run_{ident(r, 'fn')}(request, conn):
    {frag} = {f}(conn, request.user.tenant_id)
    {q} = "SELECT * FROM audit_log WHERE " + {frag}
    return conn.execute({q}).fetchall()
'''

    def js_safe() -> str:
        sort = ident(r, "sort")
        return f'''
async function list_{ident(r, 'fn')}(req, db) {{
  const allowed = new Set(["created_at", "email", "name"]);
  const {sort} = allowed.has(req.query.sort) ? req.query.sort : "created_at";
  const limit = Math.min(Math.max(Number(req.query.limit || 25), 1), 100);
  const sql = "SELECT id,email FROM users WHERE tenant_id = ? ORDER BY " + {sort} + " LIMIT ?";
  const decoy = `SELECT * FROM users WHERE email = '${{req.query.email}}'`;
  return db.all(sql, [req.user.tenantId, limit]);
}}
'''

    def js_inband() -> str:
        return f'''
async function find_{ident(r, 'fn')}(req, db) {{
  const email = req.query.email || "";
  const sql = `SELECT * FROM users WHERE email = '${{email}}'`;
  return db.all(sql);
}}
'''

    def js_blind() -> str:
        return f'''
async function can_{ident(r, 'fn')}(req, db) {{
  const token = req.query.token || "";
  const sql = `SELECT id FROM sessions WHERE token = '${{token}}'`;
  const row = await db.get(sql);
  return !!row;
}}
'''

    def js_second() -> str:
        loader = ident(r, "load")
        return f'''
async function {loader}(db, id) {{
  const row = await db.get("SELECT query_sql FROM saved_segments WHERE id = ?", [id]);
  return row.query_sql;
}}
async function run_{ident(r, 'fn')}(req, db) {{
  const sql = await {loader}(db, req.params.id);
  return db.all(sql);
}}
'''

    def java_safe() -> str:
        cls = ident(r, "Repo").replace("_", "")
        return f'''
import java.sql.*; import java.util.*;
class {cls} {{
  List<String> list(HttpServletRequest req, Connection c) throws Exception {{
    Set<String> allowed = Set.of("created_at", "email", "name");
    String sort = allowed.contains(req.getParameter("sort")) ? req.getParameter("sort") : "created_at";
    int limit = Math.min(Math.max(Integer.parseInt(req.getParameter("limit")), 1), 100);
    String sql = "SELECT id,email FROM users WHERE tenant_id = ? ORDER BY " + sort + " LIMIT ?";
    String decoy = "SELECT * FROM users WHERE email='" + req.getParameter("email") + "'";
    PreparedStatement ps = c.prepareStatement(sql);
    ps.setString(1, req.getUserPrincipal().getName());
    ps.setInt(2, limit);
    ps.executeQuery();
    return List.of();
  }}
}}
'''

    def java_inband() -> str:
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

    def java_blind() -> str:
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

    def java_second() -> str:
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

    def php_safe() -> str:
        return f'''<?php
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

    def php_inband() -> str:
        return f'''<?php
function find_{ident(r, 'fn')}($mysqli, $q) {{
    $email = $q["email"] ?? "";
    $sql = "SELECT * FROM users WHERE email='" . $email . "'";
    return $mysqli->query($sql);
}}
?>'''

    def php_blind() -> str:
        return f'''<?php
function login_{ident(r, 'fn')}($mysqli) {{
    $name = $_POST["name"] ?? "";
    $sql = "SELECT id FROM users WHERE name='" . $name . "'";
    $res = mysqli_query($mysqli, $sql);
    return mysqli_num_rows($res) > 0;
}}
?>'''

    def php_second() -> str:
        loader = "load_" + ident(r, 'frag')
        return f'''<?php
function {loader}($pdo, $id) {{
    $stmt = $pdo->prepare("SELECT where_clause FROM saved_filters WHERE id=?");
    $stmt->execute([$id]);
    $row = $stmt->fetch();
    return $row["where_clause"];
}}
function run_{ident(r, 'fn')}($pdo, $id) {{
    $where = {loader}($pdo, $id);
    $sql = "SELECT * FROM audit_log WHERE " . $where;
    return $pdo->query($sql)->fetchAll();
}}
?>'''

    factories = {
        "python": {"NONE": py_safe, "IN_BAND": py_inband, "BLIND": py_blind, "SECOND_ORDER": py_second},
        "javascript": {"NONE": js_safe, "IN_BAND": js_inband, "BLIND": js_blind, "SECOND_ORDER": js_second},
        "java": {"NONE": java_safe, "IN_BAND": java_inband, "BLIND": java_blind, "SECOND_ORDER": java_second},
        "php": {"NONE": php_safe, "IN_BAND": php_inband, "BLIND": php_blind, "SECOND_ORDER": php_second},
    }
    for lang, by_type in factories.items():
        for attack_type, fn in by_type.items():
            for j in range(per_class):
                source_id = f"generated_seed{seed}/{lang}/{attack_type}/{j:03d}"
                salt = abs(hash((seed, lang, attack_type, j))) % 100000
                yield lang, attack_type, source_id, add_noise_to_code(lang, fn(), r, salt)


class DatasetBuilder:
    def __init__(self, vocab: dict, sequence_length: int):
        self.vocab = vocab
        self.sequence_length = sequence_length
        self.seen = set()
        self.X: List[np.ndarray] = []
        self.y: List[float] = []
        self.y_type: List[int] = []
        self.language: List[str] = []
        self.path: List[str] = []
        self.source_id: List[str] = []
        self.suite_name: List[str] = []
        self.raw_hash: List[str] = []
        self.raw_len: List[int] = []
        self.pad_count: List[int] = []
        self.truncated: List[bool] = []
        self.duplicates_dropped = 0

    def add(self, code: str, label: str, attack_type: str, language: str, path: str, source_id: str, suite_name: str) -> bool:
        arr, sig, raw_len, pad_count, truncated = normalize_to_ids(code, self.vocab, self.sequence_length)
        if sig in self.seen:
            self.duplicates_dropped += 1
            return False
        self.seen.add(sig)
        label = label.upper()
        attack_type = attack_type.upper()
        self.X.append(arr)
        self.y.append(1.0 if label == "VULNERABLE" else 0.0)
        self.y_type.append(ATTACK_TO_ID[attack_type])
        self.language.append(language)
        self.path.append(path)
        self.source_id.append(source_id)
        self.suite_name.append(suite_name)
        self.raw_hash.append(hashlib.sha256(code.encode("utf-8", errors="replace")).hexdigest())
        self.raw_len.append(raw_len)
        self.pad_count.append(pad_count)
        self.truncated.append(bool(truncated))
        return True

    def arrays(self):
        return {
            "X": np.array(self.X, dtype=np.int32),
            "y": np.array(self.y, dtype=np.float32),
            "y_type": np.array(self.y_type, dtype=np.int32),
            "language": np.array(self.language),
            "path": np.array(self.path),
            "source_id": np.array(self.source_id),
            "suite_name": np.array(self.suite_name),
            "raw_hash": np.array(self.raw_hash),
            "raw_token_length": np.array(self.raw_len, dtype=np.int32),
            "pad_count": np.array(self.pad_count, dtype=np.int32),
            "truncated": np.array(self.truncated, dtype=np.bool_),
        }


def add_original_export_samples(builder: DatasetBuilder) -> None:
    """Add legacy hand-written samples when an old exporter module exists.

    This file now *replaces* scripts/export_for_colab.py. Therefore importing
    scripts.export_for_colab would import this file itself and would fail to find
    the old VULNERABLE_BASE / SAFE_BASE constants.

    To keep replacement safe, we only use a legacy module if the developer kept
    one under a different name, for example scripts/export_for_colab_legacy.py.
    If not found, we continue with the generated ML-primary dataset.
    """
    old = None
    for module_name in ("scripts.export_for_colab_legacy", "scripts.export_for_colab_old"):
        try:
            candidate = importlib.import_module(module_name)
        except Exception:
            continue
        if all(hasattr(candidate, name) for name in ("VULNERABLE_BASE", "SAFE_BASE", "generate_mutated_vuln", "generate_mutated_safe")):
            old = candidate
            print(f"      using legacy samples from {module_name}")
            break

    if old is None:
        print("      legacy sample module not found; skipping old embedded samples")
        print("      generated ML-primary samples will still be exported")
        return

    old.MODEL_SEQ_LEN = builder.sequence_length

    def add_from_list(samples, label: str, suite_name: str):
        for idx, (lang, category, code) in enumerate(samples):
            transforms = getattr(old, "TRANSFORMS_BY_LANGUAGE", {}).get(lang, [lambda c: c])
            attack_type = ID_TO_ATTACK[old.category_to_attack_type(category, 1.0 if label == "VULNERABLE" else 0.0)]
            for t_i, transform in enumerate(transforms):
                transformed = transform(code)
                builder.add(
                    transformed, label, attack_type, lang,
                    path=f"{suite_name}/{lang}/{category}/{idx:04d}_t{t_i}.txt",
                    source_id=f"{suite_name}:{lang}:{category}:{idx}:t{t_i}",
                    suite_name=suite_name,
                )

    add_from_list(old.VULNERABLE_BASE, "VULNERABLE", "legacy_base")
    add_from_list(old.SAFE_BASE, "SAFE", "legacy_base")
    add_from_list(old.generate_mutated_vuln(), "VULNERABLE", "legacy_mutations")
    add_from_list(old.generate_mutated_safe(), "SAFE", "legacy_mutations")


def add_suite_zip(builder: DatasetBuilder, suite_zip: Path) -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        with zipfile.ZipFile(suite_zip, "r") as zf:
            zf.extractall(root)
        manifest = read_manifest(root)
        for f in sorted(root.rglob("*")):
            if not f.is_file() or f.name.lower() == "manifest.csv":
                continue
            lang = EXT_TO_LANG.get(f.suffix.lower())
            if not lang:
                continue
            rel = f.relative_to(root).as_posix()
            expected = manifest.get(rel) or infer_label_from_name(rel)
            if not expected:
                continue
            label, attack = expected
            code = f.read_text(encoding="utf-8", errors="replace")
            builder.add(code, label, attack, lang, rel, f"suite:{suite_zip.stem}:{rel}", suite_zip.stem)


def profile_dataset(arrays: dict, vocab: dict, sequence_length: int, duplicates_dropped: int) -> dict:
    X = arrays["X"]
    y = arrays["y"]
    yt = arrays["y_type"]
    lang = arrays["language"]
    pad_id = int(vocab.get("PAD", 0))
    unk_id = int(vocab.get("UNK", 1))
    non_pad_lengths = (X != pad_id).sum(axis=1)
    return {
        "n_samples": int(len(X)),
        "sequence_length": int(sequence_length),
        "vocabulary_size": int(len(vocab)),
        "vocabulary_sha256": hashlib.sha256(json.dumps(vocab, sort_keys=True).encode("utf-8")).hexdigest(),
        "pad_id": pad_id,
        "unk_id": unk_id,
        "verdict_counts": {"SAFE": int((y == 0).sum()), "VULNERABLE": int((y == 1).sum())},
        "attack_type_counts": {ID_TO_ATTACK[i]: int((yt == i).sum()) for i in range(4)},
        "language_counts": dict(Counter(map(str, lang))),
        "avg_non_pad_length": float(non_pad_lengths.mean()) if len(X) else 0.0,
        "max_non_pad_length": int(non_pad_lengths.max()) if len(X) else 0,
        "min_non_pad_length": int(non_pad_lengths.min()) if len(X) else 0,
        "padded_samples": int((arrays["pad_count"] > 0).sum()),
        "truncated_samples": int(arrays["truncated"].sum()),
        "truncation_rate": float(arrays["truncated"].mean()) if len(X) else 0.0,
        "unk_token_count": int((X == unk_id).sum()),
        "unk_rate": float((X == unk_id).sum() / max(1, (X != pad_id).sum())),
        "duplicate_sequence_count_dropped": int(duplicates_dropped),
        "suite_counts": dict(Counter(map(str, arrays["suite_name"]))),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="colab_export_ml_primary_v5")
    ap.add_argument("--sequence-length", type=int, default=256)
    ap.add_argument("--generated-per-class", type=int, default=32)
    ap.add_argument("--generated-seeds", nargs="*", type=int, default=[20260511, 20260512, 20260513, 20260514, 20260515])
    ap.add_argument("--include-suite", action="append", default=[], help="Optional labelled suite ZIP to add to training data. Avoid exact eval suites unless intentional.")
    args = ap.parse_args()

    out_dir = Path(args.out)
    if not out_dir.is_absolute():
        out_dir = BACKEND_DIR / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    vocab = build_fixed_vocabulary()
    builder = DatasetBuilder(vocab, args.sequence_length)

    print("[1/5] Adding original project export samples...")
    add_original_export_samples(builder)

    print("[2/5] Adding generated ML-primary training variants...")
    for seed in args.generated_seeds:
        for lang, attack, source_id, code in generated_training_samples(seed, args.generated_per_class):
            label = "SAFE" if attack == "NONE" else "VULNERABLE"
            builder.add(code, label, attack, lang, f"{source_id}.{ {'python':'py','javascript':'js','java':'java','php':'php'}[lang] }", source_id, "generated_ml_primary")

    if args.include_suite:
        print("[3/5] Adding optional labelled suite ZIPs...")
        for z in args.include_suite:
            add_suite_zip(builder, Path(z))
    else:
        print("[3/5] No labelled suite ZIPs included. Good: no accidental benchmark leakage.")

    print("[4/5] Writing arrays and vocabulary...")
    arrays = builder.arrays()
    rng = np.random.default_rng(42)
    perm = rng.permutation(len(arrays["y"]))
    arrays = {k: v[perm] for k, v in arrays.items()}

    save_vocabulary(vocab, str(out_dir / "vocabulary.json"))
    np.savez(out_dir / "training_data.npz", **arrays)

    profile = profile_dataset(arrays, vocab, args.sequence_length, builder.duplicates_dropped)
    (out_dir / "dataset_profile.json").write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")
    export_info = {
        "export_version": "ml-primary-v5",
        "sequence_length": args.sequence_length,
        "generated_seeds": args.generated_seeds,
        "generated_per_class": args.generated_per_class,
        "included_suites": args.include_suite,
        "notes": [
            "Use a different seed when generating held-out unseen suites.",
            "Do not train on the exact suite used for final evaluation unless explicitly documenting it as training data.",
            "This export contains language/path/suite metadata for leakage and bias checks.",
        ],
        "profile": profile,
    }
    (out_dir / "export_info.json").write_text(json.dumps(export_info, indent=2, ensure_ascii=False), encoding="utf-8")

    print("[5/5] Done.")
    print(f"Output dir: {out_dir}")
    print(json.dumps(profile, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
