import sqlite3
def update_profile_status(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT bio FROM user_profiles WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return
    user_bio = row[0]
    sql = "INSERT INTO status_updates(message) VALUES ('Profile updated with bio: " + user_bio + "')"
    cur.executescript(sql)
    conn.commit()
