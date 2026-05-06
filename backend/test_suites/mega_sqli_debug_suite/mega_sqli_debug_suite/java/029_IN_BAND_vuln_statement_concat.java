import java.sql.*;

public class UserDaoVuln {
    private final Connection conn;
    public UserDaoVuln(Connection conn) { this.conn = conn; }

    public ResultSet findByEmail(String email) throws Exception {
        Statement st = conn.createStatement();
        String sql = "SELECT id, email FROM users WHERE email = '" + email + "'";
        return st.executeQuery(sql);
    }
}
