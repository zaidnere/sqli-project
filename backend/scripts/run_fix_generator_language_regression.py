# FIX_GENERATOR_LANGUAGE_AWARE_REGRESSION_V2_MARKER
"""
Language-aware regression checks for Model 2 fix generation.

This script does NOT modify the project.
It isolates fix_generator behavior by forcing a preferred Model 2 fix type
and then validates that the generated remediation is language/API aware.

Outputs:
  outputs/fix_generator_language_regression_results.csv
  outputs/fix_generator_language_regression_summary.json
"""
from __future__ import annotations

import argparse
import ast
import csv
import json
import py_compile
import re
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from app.fix_engine.fix_generator import generate_fix
from app.preprocessing.code_cleaner import clean_code
from app.preprocessing.normalizer import normalize_tokens
from app.preprocessing.tokenizer import tokenize_code

DEFAULT_CSV = Path("outputs/fix_generator_language_regression_results.csv")
DEFAULT_JSON = Path("outputs/fix_generator_language_regression_summary.json")


@dataclass
class Case:
    id: str
    language: str
    preferred_fix_type: str
    code: str
    must_contain: list[str]
    must_not_contain: list[str]
    regex_must_match: list[str]
    regex_must_not_match: list[str]
    compile_python: bool = False


@dataclass
class Result:
    id: str
    language: str
    expected_fix_type: str
    got_fix_type: str
    passed: bool
    failed_checks: str
    fixed_preview: str
    fixed_code: str


def _normalize(code: str) -> list[str]:
    return normalize_tokens(tokenize_code(clean_code(code)))


def _fixed_code(case: Case) -> tuple[str, str]:
    pred = {"fixType": case.preferred_fix_type, "fixStrategy": case.preferred_fix_type, "confidence": 1.0}
    fix = generate_fix(
        case.code,
        case.language,
        _normalize(case.code),
        preferred_fix_type=case.preferred_fix_type,
        model_prediction=pred,
    )
    if fix is None:
        return "", ""
    return getattr(fix, "fix_type", ""), getattr(fix, "fixed_code", "") or ""


def _python_compiles(code: str) -> tuple[bool, str]:
    candidates = [code]
    if code and all((not line.strip()) or line.startswith((" ", "\t")) for line in code.splitlines()):
        candidates.append("def _generated_fix_wrapper():\n" + code)
    last = "unknown compile error"
    for candidate in candidates:
        try:
            ast.parse(candidate)
            with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
                f.write(candidate)
                path = f.name
            py_compile.compile(path, doraise=True)
            return True, ""
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
    return False, last


def _run_case(case: Case) -> Result:
    got_type, fixed = _fixed_code(case)
    failures: list[str] = []

    if got_type != case.preferred_fix_type:
        failures.append(f"fix_type expected {case.preferred_fix_type}, got {got_type or '<empty>'}")
    if not fixed.strip():
        failures.append("empty fixed_code")

    for s in case.must_contain:
        if s not in fixed:
            failures.append(f"missing literal: {s}")
    for s in case.must_not_contain:
        if s in fixed:
            failures.append(f"forbidden literal present: {s}")
    for pattern in case.regex_must_match:
        if not re.search(pattern, fixed, re.S):
            failures.append(f"missing regex: {pattern}")
    for pattern in case.regex_must_not_match:
        if re.search(pattern, fixed, re.S):
            failures.append(f"forbidden regex matched: {pattern}")

    if case.compile_python:
        ok, err = _python_compiles(fixed)
        if not ok:
            failures.append(f"python compile failed: {err}")

    return Result(
        id=case.id,
        language=case.language,
        expected_fix_type=case.preferred_fix_type,
        got_fix_type=got_type,
        passed=not failures,
        failed_checks=" | ".join(failures),
        fixed_preview=fixed[:900].replace("\r", " ").replace("\n", "\\n"),
        fixed_code=fixed,
    )


def _cases() -> list[Case]:
    return [
        Case(
            id="python_sqlite_invoice_multivalue_context_preserved",
            language="python",
            preferred_fix_type="A",
            compile_python=True,
            code='''\
import sqlite3

class InvoiceService:
    def __init__(self, db_path):
        self.db_path = db_path

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
''',
            must_contain=[
                "SELECT COUNT(*)",
                "FROM invoice_acl",
                "JOIN users",
                "WHERE a.tenant_id = ?",
                "AND u.email = ?",
                "AND a.invoice_id = ?",
                "cur.execute(sql, (tenant_id, user_email, invoice_id))",
                "count = cur.fetchone()[0]",
                "allowed = count > 0",
                "return allowed",
            ],
            must_not_contain=["sql = \")", "(str,)", "cur.execute(sql)\n"],
            regex_must_match=[r"cur\.execute\(sql,\s*\(tenant_id,\s*user_email,\s*invoice_id\)\)"],
            regex_must_not_match=[r"cur\.execute\(sql\)"],
        ),
        Case(
            id="php_mysqli_optional_filters_keep_mysqli",
            language="php",
            preferred_fix_type="A",
            code='''\
<?php
function searchCustomers($tenantId, $status, $keyword) {
    $sql = "SELECT id, tenant_id, customer_name, email, status " .
           "FROM customers WHERE tenant_id = " . $tenantId;

    if ($status !== null && trim($status) !== "") {
        $sql .= " AND status = '" . $status . "'";
    }

    if ($keyword !== null && trim($keyword) !== "") {
        $clean = "%" . strtolower(trim($keyword)) . "%";
        $sql .= " AND (LOWER(customer_name) LIKE '" . $clean . "' OR LOWER(email) LIKE '" . $clean . "')";
    }

    $result = mysqli_query($this->conn, $sql);
    return $result;
}
?>
''',
            must_contain=[
                "FROM customers WHERE tenant_id = ?",
                "$params",
                "$types",
                "$stmt = $this->conn->prepare($sql)",
                "bind_param",
                "$tenantId",
                "$status",
                "$clean",
                "LOWER(customer_name) LIKE ?",
                "LOWER(email) LIKE ?",
            ],
            must_not_contain=["$pdo", "SELECT * FROM table", "execute([$tenantId])"],
            regex_must_match=[
                r"\$types\s*=\s*[\"']i[\"']",
                r"\$types\s*\.\=",
                r"bind_param\(\$types,\s*\.\.\.\$params\)",
            ],
            regex_must_not_match=[r"\$pdo->prepare", r"mysqli_query\([^\n;]+\$sql\)"],
        ),
        Case(
            id="php_pdo_stays_pdo",
            language="php",
            preferred_fix_type="A",
            code='''\
<?php
function findUser($pdo, $email) {
    $sql = "SELECT * FROM users WHERE email = '" . $email . "'";
    $rows = $pdo->query($sql)->fetchAll();
    return $rows;
}
?>
''',
            must_contain=["$pdo->prepare", "execute", "$email", "?"],
            must_not_contain=["bind_param", "mysqli_query", "$this->conn->prepare"],
            regex_must_match=[r"\$stmt\s*=\s*\$pdo->prepare\(\$sql\)", r"\$stmt->execute\(\[\$email\]\)"],
            regex_must_not_match=[r"mysqli_"],
        ),
        Case(
            id="javascript_mysql2_uses_execute_array",
            language="javascript",
            preferred_fix_type="A",
            code='''\
async function findUser(db, email) {
  const sql = "SELECT * FROM users WHERE email = '" + email + "'";
  const rows = await db.query(sql);
  return rows;
}
''',
            must_contain=["SELECT * FROM users WHERE email = ?", "db", "email"],
            must_not_contain=["client.query(sql, [email])", "$1", " value"],
            regex_must_match=[r"await\s+db\.(?:execute|query)\(sql,\s*\[email\]\)"],
            regex_must_not_match=[r"db\.query\(sql\)"],
        ),
        Case(
            id="javascript_pg_uses_numbered_placeholders",
            language="javascript",
            preferred_fix_type="A",
            code='''\
async function findUser(client, email) {
  const sql = "SELECT * FROM users WHERE email = '" + email + "'";
  const result = await client.query(sql);
  return result.rows;
}
''',
            must_contain=["SELECT * FROM users WHERE email = $1", "client.query(sql, [email])"],
            must_not_contain=["?", "db.execute", " value"],
            regex_must_match=[r"await\s+client\.query\(sql,\s*\[email\]\)"],
            regex_must_not_match=[r"client\.query\(sql\)"],
        ),
        Case(
            id="java_jdbc_prepared_statement",
            language="java",
            preferred_fix_type="A",
            code='''\
ResultSet findUser(Connection conn, String email) throws Exception {
    String sql = "SELECT * FROM users WHERE email = '" + email + "'";
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery(sql);
    return rs;
}
''',
            must_contain=[
                "PreparedStatement stmt = conn.prepareStatement(sql)",
                "stmt.setString(1, email)",
                "ResultSet rs = stmt.executeQuery()",
                "SELECT * FROM users WHERE email = ?",
            ],
            must_not_contain=["createStatement()", "executeQuery(sql)", " value"],
            regex_must_match=[r"stmt\.setString\(1,\s*email\)", r"stmt\.executeQuery\(\)"],
            regex_must_not_match=[r"executeQuery\(sql\)"],
        ),
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=str(DEFAULT_CSV))
    ap.add_argument("--json", default=str(DEFAULT_JSON))
    args = ap.parse_args()

    results = [_run_case(c) for c in _cases()]
    passed = sum(r.passed for r in results)
    total = len(results)

    Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
    with open(args.csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))

    summary = {
        "suite": "fix_generator_language_aware_regression_v2",
        "totalCases": total,
        "passed": passed,
        "failed": total - passed,
        "accuracyPct": round((passed / total) * 100, 2) if total else 0.0,
        "csv": args.csv,
        "json": args.json,
    }
    Path(args.json).write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print("Fix Generator Language-Aware Regression V2")
    print("------------------------------------------")
    print(f"Total:   {total}")
    print(f"Passed:  {passed}")
    print(f"Failed:  {total - passed}")
    print(f"CSV:     {args.csv}")
    print(f"JSON:    {args.json}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
