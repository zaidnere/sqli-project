import sqlite3
def list_page(conn, page_size, offset):
    sql = f"SELECT id, title FROM articles ORDER BY created_at DESC LIMIT {page_size} OFFSET {offset}"
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
