async function isFeatureEnabled(db, userEmail, featureKey) {
  const sql =
    "SELECT COUNT(*) AS c " +
    "FROM feature_flags f " +
    "JOIN users u ON u.id = f.user_id " +
    "WHERE u.email = '" + userEmail + "' " +
    "AND f.feature_key = '" + featureKey + "' " +
    "AND f.enabled = 1";

  const row = await db.get(sql);
  return row.c > 0;
}

async function requireFeature(req, res, next, db) {
  const ok = await isFeatureEnabled(db, req.user.email, req.params.featureKey);
  if (!ok) {
    res.status(403).json({ error: "feature disabled" });
    return;
  }
  next();
}

module.exports = { isFeatureEnabled, requireFeature };
