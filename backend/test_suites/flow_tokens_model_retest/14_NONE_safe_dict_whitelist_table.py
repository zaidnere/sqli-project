import sqlite3
TABLE_MAP = {"users": "users", "orders": "orders", "invoices": "invoices"}
def count_rows(conn, requested_table):
    safe_table = TABLE_MAP.get(requested_table, "users")
    sql = f"SELECT COUNT(*) FROM {safe_table}"
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchone()[0]
