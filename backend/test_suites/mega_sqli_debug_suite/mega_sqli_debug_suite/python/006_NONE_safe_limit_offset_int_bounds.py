import sqlite3
def list_page(conn, page, page_size):
    safe_page = max(1, int(page))
    safe_page_size = min(100, max(1, int(page_size)))
    offset = (safe_page - 1) * safe_page_size
    sql = f"SELECT id, title FROM articles ORDER BY created_at DESC LIMIT {safe_page_size} OFFSET {offset}"
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
