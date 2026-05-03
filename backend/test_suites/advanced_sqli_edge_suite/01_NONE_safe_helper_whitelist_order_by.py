import sqlite3

ALLOWED_COLUMNS = {"id", "username", "email", "created_at"}
ALLOWED_DIRECTIONS = {"ASC", "DESC"}

def pick_allowed(value, allowed, default):
    return value if value in allowed else default

def normalize_sort(sort_by, direction):
    col = pick_allowed(sort_by, ALLOWED_COLUMNS, "created_at")
    dir_ = pick_allowed(direction.upper(), ALLOWED_DIRECTIONS, "DESC")
    return col, dir_

def list_users(conn, sort_by, direction):
    safe_col, safe_dir = normalize_sort(sort_by, direction)
    sql = f"""
        SELECT id, username, email, created_at
        FROM users
        ORDER BY {safe_col} {safe_dir}
    """
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
