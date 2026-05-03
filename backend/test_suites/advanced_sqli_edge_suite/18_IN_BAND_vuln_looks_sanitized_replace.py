import sqlite3

def search_products(conn, keyword):
    cleaned = keyword.replace("'", "")
    sql = "SELECT id, name FROM products WHERE name LIKE '%" + cleaned + "%'"
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
