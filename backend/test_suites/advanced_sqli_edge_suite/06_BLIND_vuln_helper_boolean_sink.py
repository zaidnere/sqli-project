import sqlite3

def as_bool(row):
    return row is not None

def username_exists(conn, username):
    sql = "SELECT 1 FROM users WHERE username = '" + username + "'"
    cur = conn.cursor()
    cur.execute(sql)
    found = cur.fetchone()
    return as_bool(found)
