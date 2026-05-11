# TEST_INVOICE_ACCESS_FIX_GENERATOR_CONTEXTUAL_SQLITE_REWRITE_MARKER
"""Targeted regression test for Python sqlite3 raw SQL concatenation fixes.

Run from backend:
    set PYTHONPATH=.
    python scripts\test_invoice_access_fix_generator.py
"""
from __future__ import annotations

import py_compile
import re
import tempfile
from pathlib import Path

from app.fix_engine.fix_generator import generate_fix


ORIGINAL_CODE = '''import sqlite3

class InvoiceService:
    def can_view_invoice(self, user_email: str, invoice_id: str, tenant_id: int) -> bool:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        sql = (
            "SELECT COUNT(*) "
            "FROM invoice_acl a "
            "JOIN users u ON u.id = a.user_id "
            "WHERE a.tenant_id = " + str(tenant_id) + " "
            "AND u.email = '" + user_email + "' "
            "AND a.invoice_id = " + invoice_id + " "
            "AND a.can_view = 1"
        )

        cur.execute(sql)
        count = cur.fetchone()[0]
        conn.close()
        allowed = count > 0
        return allowed

    def require_invoice_access(self, user_email: str, invoice_id: str, tenant_id: int):
        if not self.can_view_invoice(user_email, invoice_id, tenant_id):
            raise PermissionError("forbidden")
'''


def _assert_contains(text: str, needle: str) -> None:
    if needle not in text:
        raise AssertionError(f"Missing expected text: {needle!r}\n--- fixed code ---\n{text}")


def main() -> int:
    result = generate_fix(
        ORIGINAL_CODE,
        "python",
        ["SQL_STRING", "SQL_CONCAT", "UNSAFE_EXEC"],
        preferred_fix_type="A",
        model_prediction={"fixType": "A"},
    )
    if result is None:
        raise AssertionError("generate_fix returned None")

    fixed = result.fixed_code
    with tempfile.TemporaryDirectory() as td:
        fixed_path = Path(td) / "fixed_invoice_access.py"
        fixed_path.write_text(fixed, encoding="utf-8")
        py_compile.compile(str(fixed_path), doraise=True)

    _assert_contains(fixed, "def can_view_invoice")
    _assert_contains(fixed, "WHERE a.tenant_id = ?")
    _assert_contains(fixed, "AND u.email = ?")
    _assert_contains(fixed, "AND a.invoice_id = ?")
    _assert_contains(fixed, "cur.execute(sql, (tenant_id, user_email, invoice_id))")
    _assert_contains(fixed, "count = cur.fetchone()[0]")
    _assert_contains(fixed, "conn.close()")
    _assert_contains(fixed, "allowed = count > 0")
    _assert_contains(fixed, "return allowed")
    _assert_contains(fixed, "def require_invoice_access")

    forbidden = [
        "cur.execute(sql)\n",
        "cur.execute(sql)\r\n",
        "(str,)",
        "sql = \" )",
        "sql = \")",
        "sql = \"\"",
    ]
    for bad in forbidden:
        if bad in fixed:
            raise AssertionError(f"Found forbidden broken output: {bad!r}\n--- fixed code ---\n{fixed}")

    if re.search(r"cur\.execute\(\s*sql\s*\)", fixed):
        raise AssertionError("Found single-argument cur.execute(sql) after fix")

    print("PASS: invoice access contextual sqlite fix compiles and preserves parameters")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
