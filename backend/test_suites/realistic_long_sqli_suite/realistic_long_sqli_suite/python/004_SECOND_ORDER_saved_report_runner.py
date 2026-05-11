import logging
import sqlite3
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class SavedReport:
    id: int
    tenant_id: int
    name: str
    where_fragment: str


class SavedReportRepository:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def load_saved_report(self, tenant_id: int, report_id: int) -> Optional[SavedReport]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, tenant_id, name, where_fragment FROM saved_reports WHERE tenant_id = ? AND id = ?",
            (tenant_id, report_id),
        )
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        return SavedReport(id=row[0], tenant_id=row[1], name=row[2], where_fragment=row[3])

    def run_report(self, tenant_id: int, report_id: int) -> list[dict[str, Any]]:
        report = self.load_saved_report(tenant_id, report_id)
        if not report:
            return []

        # Second-order vulnerability:
        # where_fragment came from the database, possibly from a previous user-controlled save action.
        sql = (
            "SELECT id, customer_name, amount_total, created_at "
            "FROM invoices "
            "WHERE tenant_id = " + str(tenant_id) + " AND " + report.where_fragment + " "
            "ORDER BY created_at DESC"
        )

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        logger.warning("running saved report id=%s tenant=%s", report_id, tenant_id)
        cur.execute(sql)
        rows = cur.fetchall()
        conn.close()
        return [dict(row) for row in rows]
