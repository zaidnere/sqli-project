import sqlite3

def normalize_message(value):
    return " ".join(str(value).strip().split())

def write_profile_audit(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT bio FROM user_profiles WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return

    bio = normalize_message(row[0])
    sql = "INSERT INTO audit_log(message) VALUES ('profile bio: " + bio + "')"
    cur.executescript(sql)
    conn.commit()
