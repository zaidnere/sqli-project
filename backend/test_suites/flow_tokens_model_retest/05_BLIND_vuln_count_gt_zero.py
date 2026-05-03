import sqlite3
def is_email_registered(conn, email):
    sql = "SELECT COUNT(*) FROM users WHERE email = '" + email + "'"
    cur = conn.cursor()
    cur.execute(sql)
    count = cur.fetchone()[0]
    return count > 0
