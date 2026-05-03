import sqlite3

def is_positive(value):
    return value > 0

def can_access_project(conn, email, project_id):
    sql = (
        "SELECT COUNT(*) FROM project_members pm "
        "JOIN users u ON u.id = pm.user_id "
        "WHERE u.email = '" + email + "' "
        "AND pm.project_id = " + project_id
    )
    cur = conn.cursor()
    cur.execute(sql)
    count_value = cur.fetchone()[0]
    decision = is_positive(count_value)
    return decision
