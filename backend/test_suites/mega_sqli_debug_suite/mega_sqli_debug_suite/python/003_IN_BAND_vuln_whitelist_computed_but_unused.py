import sqlite3
ALLOWED_COLUMNS = {"id", "username", "created_at"}

def list_users(conn, sort_by):
    safe_col = sort_by if sort_by in ALLOWED_COLUMNS else "created_at"
    sql = f"SELECT id, username FROM users ORDER BY {sort_by}"
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
