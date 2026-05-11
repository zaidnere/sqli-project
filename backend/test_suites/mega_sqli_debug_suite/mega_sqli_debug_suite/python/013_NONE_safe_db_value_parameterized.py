import sqlite3
def write_profile_audit_safe(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT bio FROM user_profiles WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return
    msg = f"bio: {row[0]}"
    cur.execute("INSERT INTO audit_log(message) VALUES (?)", (msg,))
    conn.commit()
