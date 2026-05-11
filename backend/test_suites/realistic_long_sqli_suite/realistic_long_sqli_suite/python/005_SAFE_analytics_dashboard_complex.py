import sqlite3
from dataclasses import dataclass
from typing import Any

ALLOWED_GROUP_COLUMNS = {
    "country": "country",
    "device_type": "device_type",
    "campaign_id": "campaign_id",
}
ALLOWED_METRICS = {
    "views": "SUM(views)",
    "clicks": "SUM(clicks)",
    "revenue": "SUM(revenue)",
}


@dataclass
class DashboardRequest:
    tenant_id: int
    group_by: str
    metric: str
    start_date: str
    end_date: str
    page: int = 1
    page_size: int = 25


def choose_group_column(value: str) -> str:
    return ALLOWED_GROUP_COLUMNS.get(value, "campaign_id")


def choose_metric(value: str) -> str:
    return ALLOWED_METRICS.get(value, "SUM(views)")


def normalize_limit(page: Any, page_size: Any) -> tuple[int, int]:
    safe_page = max(1, int(page))
    safe_size = min(100, max(1, int(page_size)))
    return safe_size, (safe_page - 1) * safe_size


class AnalyticsRepository:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def dashboard(self, request: DashboardRequest) -> list[dict[str, Any]]:
        group_col = choose_group_column(request.group_by)
        metric_expr = choose_metric(request.metric)
        limit, offset = normalize_limit(request.page, request.page_size)

        sql = f"""
            SELECT {group_col} AS bucket, {metric_expr} AS metric_value
            FROM analytics_events
            WHERE tenant_id = ?
              AND event_date >= ?
              AND event_date <= ?
            GROUP BY {group_col}
            ORDER BY metric_value DESC
            LIMIT {limit} OFFSET {offset}
        """

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(sql, (request.tenant_id, request.start_date, request.end_date))
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]
