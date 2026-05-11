import sqlite3
def run_cached_report(conn, report_id):
    cur = conn.cursor()
    cur.execute("SELECT where_clause FROM saved_reports WHERE id = ?", (report_id,))
    row = cur.fetchone()
    if not row:
        return []
    where_clause = row[0]
    sql = "SELECT id, total FROM invoices WHERE " + where_clause
    cur.execute(sql)
    return cur.fetchall()
