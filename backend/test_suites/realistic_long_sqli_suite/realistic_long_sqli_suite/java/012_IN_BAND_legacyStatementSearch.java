import java.sql.*;
import java.util.logging.Logger;

public class LegacyCustomerSearch {
    private static final Logger log = Logger.getLogger("LegacyCustomerSearch");
    private final Connection conn;

    public LegacyCustomerSearch(Connection conn) {
        this.conn = conn;
    }

    public ResultSet search(String tenantId, String keyword, String status) throws Exception {
        Statement st = conn.createStatement();

        String sql =
            "SELECT id, tenant_id, customer_name, email, status " +
            "FROM customers " +
            "WHERE tenant_id = " + tenantId;

        if (status != null && !status.isBlank()) {
            sql += " AND status = '" + status + "'";
        }

        if (keyword != null && !keyword.isBlank()) {
            String cleanKeyword = keyword.trim().toLowerCase();
            sql += " AND (LOWER(customer_name) LIKE '%" + cleanKeyword + "%' " +
                   "OR LOWER(email) LIKE '%" + cleanKeyword + "%')";
        }

        log.info("running legacy customer search");
        return st.executeQuery(sql);
    }
}
