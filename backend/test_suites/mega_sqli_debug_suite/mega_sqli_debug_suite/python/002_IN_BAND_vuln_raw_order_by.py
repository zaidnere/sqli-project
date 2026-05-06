import sqlite3
def list_users(conn, sort_by, direction):
    sql = f"SELECT id, username, created_at FROM users ORDER BY {sort_by} {direction}"
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
