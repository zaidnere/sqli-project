import sqlite3
ALLOWED_STATUS = {"OPEN", "CLOSED", "REVIEW"}
def list_tickets(conn, status):
    safe_status = status if status in ALLOWED_STATUS else "OPEN"
    cur = conn.cursor()
    cur.execute("SELECT id, title FROM tickets WHERE status = ?", (safe_status,))
    return cur.fetchall()
