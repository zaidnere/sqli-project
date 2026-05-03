import sqlite3
def run_cached_report(conn, tenant_id, report_id):
    cur = conn.cursor()
    cur.execute("SELECT cached_where_fragment FROM cached_reports WHERE id = ? AND tenant_id = ?", (report_id, tenant_id))
    row = cur.fetchone()
    if not row:
        return []
    cached_where_fragment = row[0]
    sql = "SELECT id, amount_total FROM invoices WHERE tenant_id = " + str(tenant_id) + " AND " + cached_where_fragment
    cur.execute(sql)
    return cur.fetchall()
