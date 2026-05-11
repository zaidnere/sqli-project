import logging
import sqlite3
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)

ALLOWED_SORT_COLUMNS = {
    "sku": "sku",
    "name": "name",
    "quantity": "quantity",
    "updated_at": "updated_at",
}
ALLOWED_SORT_DIRECTIONS = {"ASC", "DESC"}


@dataclass
class InventoryFilter:
    tenant_id: int
    warehouse_id: Optional[int] = None
    statuses: Optional[list[str]] = None
    keyword: Optional[str] = None
    sort_by: str = "updated_at"
    sort_dir: str = "DESC"
    page: int = 1
    page_size: int = 50


def normalize_sort(sort_by: str, sort_dir: str) -> tuple[str, str]:
    safe_col = ALLOWED_SORT_COLUMNS.get(sort_by, "updated_at")
    safe_dir = sort_dir.upper() if sort_dir.upper() in ALLOWED_SORT_DIRECTIONS else "DESC"
    return safe_col, safe_dir


def normalize_page(page: Any, page_size: Any) -> tuple[int, int, int]:
    safe_page = max(1, int(page))
    safe_page_size = min(100, max(1, int(page_size)))
    offset = (safe_page - 1) * safe_page_size
    return safe_page_size, offset, safe_page


class InventoryRepository:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def list_items(self, filters: InventoryFilter) -> list[dict[str, Any]]:
        safe_col, safe_dir = normalize_sort(filters.sort_by, filters.sort_dir)
        limit, offset, _ = normalize_page(filters.page, filters.page_size)

        sql_parts = [
            "SELECT id, tenant_id, sku, name, quantity, status, updated_at",
            "FROM inventory_items",
            "WHERE tenant_id = ?",
        ]
        params: list[Any] = [filters.tenant_id]

        if filters.warehouse_id is not None:
            sql_parts.append("AND warehouse_id = ?")
            params.append(filters.warehouse_id)

        if filters.keyword:
            like_value = f"%{filters.keyword.strip().lower()}%"
            sql_parts.append("AND (LOWER(sku) LIKE ? OR LOWER(name) LIKE ?)")
            params.extend([like_value, like_value])

        if filters.statuses:
            placeholders = ",".join("?" for _ in filters.statuses)
            sql_parts.append(f"AND status IN ({placeholders})")
            params.extend(filters.statuses)

        sql_parts.append(f"ORDER BY {safe_col} {safe_dir}")
        sql_parts.append(f"LIMIT {limit} OFFSET {offset}")

        sql = " ".join(sql_parts)
        logger.info("Running inventory search for tenant=%s", filters.tenant_id)

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(sql, tuple(params))
            return [dict(row) for row in cur.fetchall()]
