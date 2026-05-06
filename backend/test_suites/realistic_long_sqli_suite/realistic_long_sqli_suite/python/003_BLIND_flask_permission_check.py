import logging
import sqlite3

logger = logging.getLogger(__name__)


class PermissionService:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def can_view_invoice(self, user_email: str, invoice_id: str, tenant_id: int) -> bool:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        # Vulnerability: user_email and invoice_id are concatenated.
        # The caller only receives True/False, so this is a blind SQLi pattern.
        sql = (
            "SELECT COUNT(*) "
            "FROM invoice_acl a "
            "JOIN users u ON u.id = a.user_id "
            "WHERE a.tenant_id = " + str(tenant_id) + " "
            "AND u.email = '" + user_email + "' "
            "AND a.invoice_id = " + invoice_id + " "
            "AND a.can_view = 1"
        )

        logger.debug("checking invoice permission")
        cur.execute(sql)
        count = cur.fetchone()[0]
        conn.close()
        allowed = count > 0
        return allowed

    def require_invoice_access(self, user_email: str, invoice_id: str, tenant_id: int) -> None:
        if not self.can_view_invoice(user_email, invoice_id, tenant_id):
            raise PermissionError("Access denied")
