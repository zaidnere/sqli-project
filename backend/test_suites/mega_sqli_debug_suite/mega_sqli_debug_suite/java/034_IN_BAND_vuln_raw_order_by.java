import java.sql.*;

public class InvoiceDaoRawSort {
    private final Connection conn;
    public InvoiceDaoRawSort(Connection conn) { this.conn = conn; }

    public ResultSet list(String sortBy) throws Exception {
        Statement st = conn.createStatement();
        String sql = "SELECT id, amount_total FROM invoices ORDER BY " + sortBy;
        return st.executeQuery(sql);
    }
}
