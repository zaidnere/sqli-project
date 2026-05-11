import java.sql.*;
import java.util.*;

public class SpringOrderRepository {
    private static final Set<String> ALLOWED_SORT = Set.of("created_at", "total", "status");
    private static final Set<String> ALLOWED_DIRECTION = Set.of("ASC", "DESC");
    private final Connection conn;

    public SpringOrderRepository(Connection conn) {
        this.conn = conn;
    }

    private String safeSort(String sortBy) {
        return ALLOWED_SORT.contains(sortBy) ? sortBy : "created_at";
    }

    private String safeDirection(String direction) {
        if (direction == null) return "DESC";
        String upper = direction.toUpperCase(Locale.ROOT);
        return ALLOWED_DIRECTION.contains(upper) ? upper : "DESC";
    }

    public ResultSet listOrders(int tenantId, String status, String sortBy, String direction) throws Exception {
        String safeCol = safeSort(sortBy);
        String safeDir = safeDirection(direction);

        String sql =
            "SELECT id, tenant_id, customer_email, total, status, created_at " +
            "FROM orders " +
            "WHERE tenant_id = ? " +
            "AND (? IS NULL OR status = ?) " +
            "ORDER BY " + safeCol + " " + safeDir;

        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setInt(1, tenantId);
        ps.setString(2, status);
        ps.setString(3, status);
        return ps.executeQuery();
    }
}
