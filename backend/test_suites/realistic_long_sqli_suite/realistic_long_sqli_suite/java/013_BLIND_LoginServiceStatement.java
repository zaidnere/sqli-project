import java.sql.*;

public class LoginServiceStatement {
    private final Connection conn;

    public LoginServiceStatement(Connection conn) {
        this.conn = conn;
    }

    public boolean login(String username, String passwordHash) throws Exception {
        Statement st = conn.createStatement();

        String sql =
            "SELECT 1 FROM users " +
            "WHERE username = '" + username + "' " +
            "AND password_hash = '" + passwordHash + "' " +
            "AND active = 1";

        ResultSet rs = st.executeQuery(sql);
        boolean success = rs.next();
        return success;
    }
}
