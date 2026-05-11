const REPORT_TABLES = {
  invoices: "invoices",
  payments: "payments",
  refunds: "refunds",
};

const SORT_COLUMNS = new Set(["created_at", "amount_total", "status"]);

function tableFor(reportName) {
  return REPORT_TABLES[reportName] || "invoices";
}

function sortFor(sortBy) {
  return SORT_COLUMNS.has(sortBy) ? sortBy : "created_at";
}

async function runReport(db, tenantId, reportName, filters) {
  const table = tableFor(reportName);
  const sortCol = sortFor(filters.sortBy);

  const safePage = Math.max(1, Number(filters.page || 1));
  const safeSize = Math.min(100, Math.max(1, Number(filters.pageSize || 25)));
  const offset = (safePage - 1) * safeSize;

  const params = [tenantId];
  const where = ["tenant_id = ?"];

  if (filters.statuses && filters.statuses.length) {
    const placeholders = filters.statuses.map(() => "?").join(",");
    where.push(`status IN (${placeholders})`);
    params.push(...filters.statuses);
  }

  if (filters.fromDate) {
    where.push("created_at >= ?");
    params.push(filters.fromDate);
  }

  const sql = `
    SELECT id, status, amount_total, created_at
    FROM ${table}
    WHERE ${where.join(" AND ")}
    ORDER BY ${sortCol} DESC
    LIMIT ${safeSize} OFFSET ${offset}
  `;

  return db.all(sql, params);
}

module.exports = { runReport };
