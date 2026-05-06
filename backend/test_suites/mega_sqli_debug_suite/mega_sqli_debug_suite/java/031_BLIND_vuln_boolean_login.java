import java.sql.*;

public class LoginService {
    private final Connection conn;
    public LoginService(Connection conn) { this.conn = conn; }

    public boolean login(String username, String hash) throws Exception {
        Statement st = conn.createStatement();
        String sql = "SELECT 1 FROM users WHERE username = '" + username + "' AND password_hash = '" + hash + "'";
        ResultSet rs = st.executeQuery(sql);
        return rs.next();
    }
}
