import sqlite3
ALLOWED_COLUMNS = {"id", "username", "created_at"}
ALLOWED_DIRECTIONS = {"ASC", "DESC"}

def list_users(conn, sort_by, sort_order):
    safe_col = sort_by if sort_by in ALLOWED_COLUMNS else "created_at"
    safe_dir = sort_order.upper() if sort_order.upper() in ALLOWED_DIRECTIONS else "DESC"
    query = f"SELECT id, username, created_at FROM users ORDER BY {safe_col} {safe_dir}"
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()
