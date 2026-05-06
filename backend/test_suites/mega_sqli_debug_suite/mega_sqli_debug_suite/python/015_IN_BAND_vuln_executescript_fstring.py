import sqlite3
def delete_user(conn, email):
    sql = f"DELETE FROM users WHERE email = '{email}'"
    cur = conn.cursor()
    cur.executescript(sql)
    conn.commit()
