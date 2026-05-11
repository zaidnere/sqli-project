import sqlite3
def build_query(name):
    return f"SELECT id, name FROM customers WHERE name = '{name}'"

def run_query(conn, statement):
    cur = conn.cursor()
    cur.execute(statement)
    return cur.fetchall()

def find_customer(conn, customer_name):
    q1 = build_query(customer_name)
    q2 = q1
    return run_query(conn, q2)
