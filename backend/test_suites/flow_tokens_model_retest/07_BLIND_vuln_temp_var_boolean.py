import sqlite3
def can_view_invoice(conn, user_email, invoice_id):
    sql = (
        "SELECT COUNT(*) FROM invoice_acl a "
        "JOIN users u ON u.id = a.user_id "
        "WHERE u.email = '" + user_email + "' "
        "AND a.invoice_id = " + invoice_id
    )
    cur = conn.cursor()
    cur.execute(sql)
    result_count = cur.fetchone()[0]
    allowed = result_count > 0
    return allowed
