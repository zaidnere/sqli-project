import sqlite3
from dataclasses import dataclass

@dataclass
class CachedFilter:
    where_clause: str

def load_filter(conn, report_id):
    cur = conn.cursor()
    cur.execute("SELECT where_clause FROM report_filters WHERE id = ?", (report_id,))
    row = cur.fetchone()
    if not row:
        return None
    return CachedFilter(where_clause=row[0])

def run_report(conn, report_id):
    cached = load_filter(conn, report_id)
    if not cached:
        return []

    sql = "SELECT id, title, amount FROM reports WHERE " + cached.where_clause
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
