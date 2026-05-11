import sqlite3
def get_orders(conn, order_ids):
    if not order_ids:
        return []
    placeholders = ",".join("?" for _ in order_ids)
    sql = f"SELECT id, total FROM orders WHERE id IN ({placeholders})"
    cur = conn.cursor()
    cur.execute(sql, tuple(order_ids))
    return cur.fetchall()
