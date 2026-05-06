import logging
import sqlite3
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)

@dataclass
class CustomerSearchRequest:
    tenant_id: int
    status: Optional[str] = None
    region: Optional[str] = None
    keyword: Optional[str] = None
    page: int = 1


class CustomerRepository:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def _normalize_keyword(self, value: Optional[str]) -> str:
        if not value:
            return ""
        return " ".join(str(value).lower().strip().split())[:80]

    def search_customers(self, request: CustomerSearchRequest) -> list[dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        sql = """
            SELECT id, tenant_id, customer_name, email, region, status, created_at
            FROM customers
            WHERE tenant_id = ?
        """
        params: list[Any] = [request.tenant_id]

        if request.status:
            sql += " AND status = ?"
            params.append(request.status)

        if request.region:
            sql += " AND region = ?"
            params.append(request.region)

        keyword = self._normalize_keyword(request.keyword)

        # Vulnerability: this looks like a normal query builder, but the keyword
        # is still concatenated into SQL text.
        if keyword:
            sql += (
                " AND (LOWER(customer_name) LIKE '%"
                + keyword
                + "%' OR LOWER(email) LIKE '%"
                + keyword
                + "%' OR LOWER(notes) LIKE '%"
                + keyword
                + "%')"
            )

        sql += " ORDER BY created_at DESC LIMIT 50"

        logger.info("customer search tenant=%s status=%s region=%s", request.tenant_id, request.status, request.region)
        cur.execute(sql, tuple(params))
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]
