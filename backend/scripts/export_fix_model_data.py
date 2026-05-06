"""Export balanced Model 2 training data. Does not modify Model 1."""
from __future__ import annotations
import argparse, json, random
from pathlib import Path
import numpy as np
from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.tokenizer import tokenize_code
from app.preprocessing.normalizer import normalize_tokens
from app.vectorization.vocabulary import build_fixed_vocabulary
from app.vectorization.vectorizer import vectorize_tokens
from app.model.fix_model_inference import EVIDENCE_FEATURES, build_evidence_vector
FIX_LABELS={"A":0,"B":1,"C":2,"D":3}; LANG={"python":0,"javascript":1,"java":2,"php":3}; ATTACK={"NONE":0,"IN_BAND":1,"BLIND":2,"SECOND_ORDER":3}
def samples(lang, fix, i):
    if lang=="python" and fix=="A": return f'def get_user(cursor, user_id):\n    query = "SELECT * FROM users WHERE id = " + user_id\n    return cursor.execute(query).fetchone()\n'
    if lang=="python" and fix=="B": return f'def list_users(cursor, sort_column):\n    query = "SELECT * FROM users ORDER BY " + sort_column\n    return cursor.execute(query).fetchall()\n'
    if lang=="python" and fix=="C": return 'def search(cursor, filters):\n    sql = "SELECT * FROM users WHERE 1=1"\n    for field, value in filters.items():\n        sql += " AND " + field + " = \\\'" + value + "\\\'"\n    return cursor.execute(sql).fetchall()\n'
    if lang=="python" and fix=="D": return 'def run_saved(cursor, report_id):\n    row = cursor.execute("SELECT sql_text FROM reports WHERE id = ?", (report_id,)).fetchone()\n    saved_sql = row["sql_text"]\n    return cursor.execute(saved_sql).fetchall()\n'
    if lang=="javascript" and fix=="A": return 'async function getUser(db, email) {\n  const sql = "SELECT * FROM users WHERE email = \\\'" + email + "\\\'";\n  return db.all(sql);\n}\n'
    if lang=="javascript" and fix=="B": return 'async function listUsers(db, sortColumn) {\n  const sql = "SELECT * FROM users ORDER BY " + sortColumn;\n  return db.all(sql);\n}\n'
    if lang=="javascript" and fix=="C": return 'async function search(db, filters) {\n  let sql = "SELECT * FROM users WHERE 1=1";\n  for (const k of Object.keys(filters)) { sql += " AND " + k + "=\\\'" + filters[k] + "\\\'"; }\n  return db.all(sql);\n}\n'
    if lang=="javascript" and fix=="D": return 'async function runSaved(db, id) {\n  const row = await db.get("SELECT sql_text FROM reports WHERE id = ?", [id]);\n  return db.all(row.sql_text);\n}\n'
    if lang=="java" and fix=="A": return 'List<User> getUsers(JdbcTemplate jdbc, String email) {\n    String sql = "SELECT * FROM users WHERE email = \\\'" + email + "\\\'";\n    return jdbc.query(sql);\n}\n'
    if lang=="java" and fix=="B": return 'ResultSet listUsers(Connection conn, String sortColumn) throws Exception {\n    String sql = "SELECT * FROM users ORDER BY " + sortColumn;\n    return conn.createStatement().executeQuery(sql);\n}\n'
    if lang=="java" and fix=="C": return 'List<User> search(JdbcTemplate jdbc, Map<String,String> filters) {\n    String sql = "SELECT * FROM users WHERE 1=1";\n    for (String k : filters.keySet()) { sql += " AND " + k + "=\\\'" + filters.get(k) + "\\\'"; }\n    return jdbc.query(sql);\n}\n'
    if lang=="java" and fix=="D": return 'ResultSet runSaved(Connection conn, String id) throws Exception {\n    ResultSet rs = conn.prepareStatement("SELECT sql_text FROM reports WHERE id = ?").executeQuery();\n    String sql = rs.getString("sql_text");\n    return conn.createStatement().executeQuery(sql);\n}\n'
    if lang=="php" and fix=="A": return '<?php\nfunction getUser($pdo, $email) {\n    $sql = "SELECT * FROM users WHERE email = \\\'" . $email . "\\\'";\n    return $pdo->query($sql)->fetch();\n}\n?>\n'
    if lang=="php" and fix=="B": return '<?php\nfunction listUsers($pdo, $sort) {\n    $sql = "SELECT * FROM users ORDER BY " . $sort;\n    return $pdo->query($sql)->fetchAll();\n}\n?>\n'
    if lang=="php" and fix=="C": return '<?php\nfunction search($pdo, $filters) {\n    $sql = "SELECT * FROM users WHERE 1=1";\n    foreach ($filters as $k => $v) { $sql .= " AND " . $k . "=\\\'" . $v . "\\\'"; }\n    return $pdo->query($sql)->fetchAll();\n}\n?>\n'
    if lang=="php" and fix=="D": return '<?php\nfunction runSaved($pdo, $id) {\n    $stmt = $pdo->prepare("SELECT sql_text FROM reports WHERE id = ?");\n    $stmt->execute([$id]);\n    $sql = $stmt->fetchColumn();\n    return $pdo->query($sql)->fetchAll();\n}\n?>\n'
    raise KeyError((lang,fix))
def mutate(code, i):
    # harmless variation; normalizer still captures semantics
    return ("\n" * (i % 2)) + code.replace("users", ["users","accounts","customers"][i%3]).replace("user_id", ["user_id","uid","account_id"][i%3])
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--out', default='colab_export_fix'); ap.add_argument('--samples-per-class-language', type=int, default=80); ap.add_argument('--seed', type=int, default=20260506); args=ap.parse_args()
    random.seed(args.seed); vocab=build_fixed_vocabulary(); out=Path(args.out); out.mkdir(parents=True,exist_ok=True)
    X=[]; y=[]; lang_ids=[]; atk=[]; ev=[]; raw=[]; normtxt=[]
    for language in LANG:
      for fix in FIX_LABELS:
       for i in range(args.samples_per_class_language):
        code=mutate(samples(language, fix, i), i); norm=normalize_tokens(tokenize_code(clean_code(code))); vec=vectorize_tokens(norm, vocab)
        X.append(vec['tokenIds']); y.append(FIX_LABELS[fix]); lang_ids.append(LANG[language]); atk.append(ATTACK['SECOND_ORDER' if fix=='D' else 'IN_BAND']); ev.append(build_evidence_vector(norm, code, language)); raw.append(code); normtxt.append(' '.join(norm))
    np.savez_compressed(out/'training_data.npz', X=np.array(X,dtype=np.int32), y_fix=np.array(y,dtype=np.int64), language_id=np.array(lang_ids,dtype=np.int64), attack_type_id=np.array(atk,dtype=np.int64), evidence=np.array(ev,dtype=np.float32), raw_code=np.array(raw,dtype=str), normalized_text=np.array(normtxt,dtype=str))
    (out/'vocabulary.json').write_text(json.dumps(vocab,indent=2,ensure_ascii=False),encoding='utf-8')
    profile={'n_samples':len(X),'fix_counts':{k:int(sum(v==i for v in y)) for k,i in FIX_LABELS.items()},'language_counts':{k:int(sum(v==i for v in lang_ids)) for k,i in LANG.items()},'evidence_features':EVIDENCE_FEATURES}
    (out/'dataset_profile.json').write_text(json.dumps(profile,indent=2),encoding='utf-8'); print(json.dumps(profile,indent=2))
if __name__=='__main__': main()
