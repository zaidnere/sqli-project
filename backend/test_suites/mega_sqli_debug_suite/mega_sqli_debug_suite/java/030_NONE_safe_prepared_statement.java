import java.sql.*;

public class UserDaoSafe {
    private final Connection conn;
    public UserDaoSafe(Connection conn) { this.conn = conn; }

    public ResultSet findByEmail(String email) throws Exception {
        String sql = "SELECT id, email FROM users WHERE email = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, email);
        return ps.executeQuery();
    }
}
