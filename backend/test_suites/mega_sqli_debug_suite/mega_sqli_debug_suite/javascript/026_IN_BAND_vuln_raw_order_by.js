async function listUsers(db, sortBy, direction) {
  const sql = `SELECT id, email, created_at FROM users ORDER BY ${sortBy} ${direction}`;
  return db.all(sql);
}
module.exports = { listUsers };
