import sqlite3
def list_users(conn, sort_by, sort_order):
    query = f"SELECT id, username, created_at FROM users ORDER BY {sort_by} {sort_order}"
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()
