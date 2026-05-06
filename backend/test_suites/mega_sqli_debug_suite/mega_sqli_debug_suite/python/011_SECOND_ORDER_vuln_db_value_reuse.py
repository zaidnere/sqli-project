import sqlite3
def write_profile_audit(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT bio FROM user_profiles WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return
    bio = row[0]
    sql = "INSERT INTO audit_log(message) VALUES ('bio: " + bio + "')"
    cur.executescript(sql)
    conn.commit()
