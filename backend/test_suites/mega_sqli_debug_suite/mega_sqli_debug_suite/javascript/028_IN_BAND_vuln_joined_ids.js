async function getOrders(db, ids) {
  const csv = ids.join(",");
  const sql = "SELECT id, total FROM orders WHERE id IN (" + csv + ")";
  return db.all(sql);
}
module.exports = { getOrders };
