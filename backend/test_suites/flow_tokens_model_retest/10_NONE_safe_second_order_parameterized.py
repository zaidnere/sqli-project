import sqlite3
def update_profile_status_safe(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT bio FROM user_profiles WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    if not row:
        return
    user_bio = row[0]
    message = f"Profile updated with bio: {user_bio}"
    cur.execute("INSERT INTO status_updates(message) VALUES (?)", (message,))
    conn.commit()
