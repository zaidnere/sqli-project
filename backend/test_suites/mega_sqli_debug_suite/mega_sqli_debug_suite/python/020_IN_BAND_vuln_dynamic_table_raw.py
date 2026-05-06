import sqlite3
def export_table(conn, table_name):
    sql = f"SELECT * FROM {table_name}"
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
