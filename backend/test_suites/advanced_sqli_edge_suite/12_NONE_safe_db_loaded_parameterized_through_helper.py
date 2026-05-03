import sqlite3

def make_message(value):
    return f"profile bio: {value}"

def write_profile_audit_safe(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT bio FROM user_profiles WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return

    message = make_message(row[0])
    cur.execute("INSERT INTO audit_log(message) VALUES (?)", (message,))
    conn.commit()
