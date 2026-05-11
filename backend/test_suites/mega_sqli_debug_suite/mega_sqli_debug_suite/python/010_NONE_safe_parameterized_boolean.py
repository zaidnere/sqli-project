import sqlite3
def is_email_registered_safe(conn, email):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
    count = cur.fetchone()[0]
    return count > 0
