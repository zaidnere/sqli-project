import sqlite3
def create_schema(conn):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
