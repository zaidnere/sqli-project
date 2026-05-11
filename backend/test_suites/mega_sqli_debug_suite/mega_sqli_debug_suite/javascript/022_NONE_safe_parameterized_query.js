async function getUserSafe(db, email) {
  const sql = "SELECT id, email FROM users WHERE email = ?";
  return db.all(sql, [email]);
}
module.exports = { getUserSafe };
