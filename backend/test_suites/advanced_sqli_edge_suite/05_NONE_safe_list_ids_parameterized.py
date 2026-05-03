import sqlite3

def get_orders_safe(conn, raw_ids):
    if not raw_ids:
        return []
    placeholders = ",".join("?" for _ in raw_ids)
    sql = f"SELECT id, total, status FROM orders WHERE id IN ({placeholders})"
    cur = conn.cursor()
    cur.execute(sql, tuple(raw_ids))
    return cur.fetchall()
