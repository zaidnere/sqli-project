import sqlite3

ALLOWED_STATUS = {"OPEN", "CLOSED", "REVIEW"}

def list_tickets(conn, status):
    safe_status = status if status in ALLOWED_STATUS else "OPEN"
    sql = "SELECT id, title, status FROM tickets WHERE status = ?"
    cur = conn.cursor()
    cur.execute(sql, (safe_status,))
    return cur.fetchall()
