async function isEmailRegistered(db, email) {
  const sql = "SELECT COUNT(*) AS c FROM users WHERE email = '" + email + "'";
  const row = await db.get(sql);
  return row.c > 0;
}
module.exports = { isEmailRegistered };
