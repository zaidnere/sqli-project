import sqlite3
def get_orders(conn, raw_ids):
    ids_csv = ",".join(raw_ids)
    sql = "SELECT id, total FROM orders WHERE id IN (" + ids_csv + ")"
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
