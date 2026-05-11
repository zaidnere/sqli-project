async function getCustomerProfile(db, req) {
  const email = req.query.email;
  const tenantId = req.user.tenantId;

  const sql = `
    SELECT id, tenant_id, email, display_name, created_at
    FROM customer_profiles
    WHERE tenant_id = ${tenantId}
      AND email = '${email}'
  `;

  const rows = await db.all(sql);
  return rows.length ? rows[0] : null;
}

async function handleCustomerProfile(req, res, db) {
  const profile = await getCustomerProfile(db, req);
  if (!profile) {
    res.status(404).json({ error: "not found" });
    return;
  }
  res.json(profile);
}

module.exports = { getCustomerProfile, handleCustomerProfile };
