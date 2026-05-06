const ALLOWED_SORT_COLUMNS = new Set(["created_at", "total", "status"]);
const ALLOWED_DIRECTIONS = new Set(["ASC", "DESC"]);

function normalizeSort(sortBy, direction) {
  const safeCol = ALLOWED_SORT_COLUMNS.has(sortBy) ? sortBy : "created_at";
  const upperDirection = String(direction || "").toUpperCase();
  const safeDir = ALLOWED_DIRECTIONS.has(upperDirection) ? upperDirection : "DESC";
  return { safeCol, safeDir };
}

function normalizePage(page, pageSize) {
  const safePage = Math.max(1, Number(page));
  const safeSize = Math.min(100, Math.max(1, Number(pageSize)));
  const offset = (safePage - 1) * safeSize;
  return { safeSize, offset };
}

async function listOrders(db, req) {
  const { safeCol, safeDir } = normalizeSort(req.query.sortBy, req.query.direction);
  const { safeSize, offset } = normalizePage(req.query.page || 1, req.query.pageSize || 50);

  const params = [req.user.tenantId];
  const where = ["tenant_id = ?"];

  if (req.query.status) {
    where.push("status = ?");
    params.push(req.query.status);
  }

  if (Array.isArray(req.query.ids) && req.query.ids.length > 0) {
    const placeholders = req.query.ids.map(() => "?").join(",");
    where.push(`id IN (${placeholders})`);
    params.push(...req.query.ids);
  }

  const sql = `
    SELECT id, customer_email, total, status, created_at
    FROM orders
    WHERE ${where.join(" AND ")}
    ORDER BY ${safeCol} ${safeDir}
    LIMIT ${safeSize} OFFSET ${offset}
  `;

  return db.all(sql, params);
}

module.exports = { listOrders };
