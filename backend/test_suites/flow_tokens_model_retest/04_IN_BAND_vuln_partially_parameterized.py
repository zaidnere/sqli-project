import sqlite3
def search_users(conn, tenant_id, status, role):
    sql = "SELECT id, username FROM users WHERE tenant_id = ?"
    params = [tenant_id]
    sql += " AND status = ?"
    params.append(status)
    sql += " AND role = '" + role + "'"
    cur = conn.cursor()
    cur.execute(sql, tuple(params))
    return cur.fetchall()
