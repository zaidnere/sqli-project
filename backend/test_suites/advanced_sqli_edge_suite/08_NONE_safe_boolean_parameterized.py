import sqlite3

def can_access_project_safe(conn, email, project_id):
    sql = """
        SELECT COUNT(*)
        FROM project_members pm
        JOIN users u ON u.id = pm.user_id
        WHERE u.email = ?
          AND pm.project_id = ?
    """
    cur = conn.cursor()
    cur.execute(sql, (email, project_id))
    count_value = cur.fetchone()[0]
    return count_value > 0
