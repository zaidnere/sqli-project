import sqlite3
TABLE_MAP = {"users": "users", "orders": "orders", "invoices": "invoices"}
def count_rows(conn, requested_table):
    table = TABLE_MAP.get(requested_table, "users")
    sql = f"SELECT COUNT(*) FROM {table}"
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchone()[0]
