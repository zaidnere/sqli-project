import sqlite3
def is_valid_column(value):
    return value is not None and len(value) < 50
def list_users(conn, sort_by):
    safe_col = sort_by if is_valid_column(sort_by) else "created_at"
    query = f"SELECT id, username FROM users ORDER BY {safe_col}"
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()
