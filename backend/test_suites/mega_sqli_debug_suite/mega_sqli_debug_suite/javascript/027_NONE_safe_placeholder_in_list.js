async function getOrders(db, ids) {
  if (!ids.length) return [];
  const placeholders = ids.map(() => "?").join(",");
  const sql = `SELECT id, total FROM orders WHERE id IN (${placeholders})`;
  return db.all(sql, ids);
}
module.exports = { getOrders };
