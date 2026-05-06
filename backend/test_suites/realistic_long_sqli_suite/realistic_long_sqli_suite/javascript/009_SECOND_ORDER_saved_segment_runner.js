async function loadSegment(db, tenantId, segmentId) {
  return db.get(
    "SELECT id, tenant_id, name, where_clause FROM saved_segments WHERE tenant_id = ? AND id = ?",
    [tenantId, segmentId]
  );
}

async function runCampaignSegment(db, tenantId, segmentId) {
  const segment = await loadSegment(db, tenantId, segmentId);
  if (!segment) {
    return [];
  }

  const sql =
    "SELECT id, email, first_name, last_name " +
    "FROM contacts " +
    "WHERE tenant_id = " + tenantId + " AND " + segment.where_clause + " " +
    "ORDER BY created_at DESC";

  return db.all(sql);
}

module.exports = { loadSegment, runCampaignSegment };
