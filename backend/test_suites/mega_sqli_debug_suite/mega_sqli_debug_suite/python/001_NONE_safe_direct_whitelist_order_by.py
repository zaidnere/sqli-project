import sqlite3
ALLOWED_COLUMNS = {"id", "username", "created_at"}
ALLOWED_DIRECTIONS = {"ASC", "DESC"}

def list_users(conn, sort_by, direction):
    safe_col = sort_by if sort_by in ALLOWED_COLUMNS else "created_at"
    safe_dir = direction.upper() if direction.upper() in ALLOWED_DIRECTIONS else "DESC"
    sql = f"SELECT id, username, created_at FROM users ORDER BY {safe_col} {safe_dir}"
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
