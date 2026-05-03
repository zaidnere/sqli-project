import sqlite3

def make_customer_query(name):
    base = "SELECT id, name, email FROM customers"
    clause = f" WHERE name = '{name}'"
    return base + clause

def run_query(conn, statement):
    cur = conn.cursor()
    cur.execute(statement)
    return cur.fetchall()

def find_customer(conn, customer_name):
    q1 = make_customer_query(customer_name)
    q2 = q1
    return run_query(conn, q2)
