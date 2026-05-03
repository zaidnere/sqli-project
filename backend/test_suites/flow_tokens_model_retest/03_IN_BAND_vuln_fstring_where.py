import sqlite3
def get_user_by_email(conn, email):
    query = f"SELECT id, email FROM users WHERE email = '{email}'"
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()
