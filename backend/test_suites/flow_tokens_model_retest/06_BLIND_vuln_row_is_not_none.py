import sqlite3
def authenticate(conn, username, password_hash):
    sql = "SELECT 1 FROM users WHERE username = '" + username + "' AND password_hash = '" + password_hash + "'"
    cur = conn.cursor()
    cur.execute(sql)
    row = cur.fetchone()
    return row is not None
