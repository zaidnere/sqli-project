import sqlite3
def create_schema(conn):
    script = """
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE
    );
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      message TEXT NOT NULL
    );
    """
    conn.executescript(script)
    conn.commit()
