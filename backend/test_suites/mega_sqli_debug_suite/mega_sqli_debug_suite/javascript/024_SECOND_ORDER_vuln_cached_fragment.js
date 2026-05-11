async function runSavedReport(db, reportId) {
  const row = await db.get("SELECT where_fragment FROM saved_reports WHERE id = ?", [reportId]);
  if (!row) return [];
  const sql = "SELECT id, total FROM invoices WHERE " + row.where_fragment;
  return db.all(sql);
}
module.exports = { runSavedReport };
