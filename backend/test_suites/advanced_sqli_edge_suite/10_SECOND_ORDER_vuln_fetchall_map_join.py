import sqlite3

def rebuild_digest(conn, tenant_id):
    cur = conn.cursor()
    cur.execute("SELECT note_text FROM pending_notes WHERE tenant_id = ?", (tenant_id,))
    rows = cur.fetchall()

    parts = [str(row[0]).strip() for row in rows]
    digest = " || ".join(parts)

    sql = "INSERT INTO note_digest(tenant_id, digest_text) VALUES (" + str(tenant_id) + ", '" + digest + "')"
    cur.executescript(sql)
    conn.commit()
