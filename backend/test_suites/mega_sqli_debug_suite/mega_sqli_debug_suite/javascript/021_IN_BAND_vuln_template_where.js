async function getUser(db, email) {
  const sql = `SELECT id, email FROM users WHERE email = '${email}'`;
  return db.all(sql);
}
module.exports = { getUser };
