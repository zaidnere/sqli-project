import java.sql.*;
import java.util.*;

public class InvoiceDaoSafeSort {
    private static final Set<String> ALLOWED = Set.of("id", "created_at", "amount_total");
    private final Connection conn;
    public InvoiceDaoSafeSort(Connection conn) { this.conn = conn; }

    public ResultSet list(String sortBy) throws Exception {
        String safeCol = ALLOWED.contains(sortBy) ? sortBy : "created_at";
        Statement st = conn.createStatement();
        String sql = "SELECT id, amount_total FROM invoices ORDER BY " + safeCol;
        return st.executeQuery(sql);
    }
}
