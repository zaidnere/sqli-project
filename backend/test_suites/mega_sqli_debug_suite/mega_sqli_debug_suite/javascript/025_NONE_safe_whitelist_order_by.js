const ALLOWED_COLUMNS = new Set(["id", "email", "created_at"]);
const ALLOWED_DIRECTIONS = new Set(["ASC", "DESC"]);

async function listUsers(db, sortBy, direction) {
  const safeCol = ALLOWED_COLUMNS.has(sortBy) ? sortBy : "created_at";
  const safeDir = ALLOWED_DIRECTIONS.has(String(direction).toUpperCase()) ? String(direction).toUpperCase() : "DESC";
  const sql = `SELECT id, email, created_at FROM users ORDER BY ${safeCol} ${safeDir}`;
  return db.all(sql);
}
module.exports = { listUsers };
