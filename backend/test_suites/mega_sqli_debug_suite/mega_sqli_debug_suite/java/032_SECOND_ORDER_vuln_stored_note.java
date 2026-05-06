import java.sql.*;

public class AuditService {
    private final Connection conn;
    public AuditService(Connection conn) { this.conn = conn; }

    public void archiveNote(int noteId) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT note_text FROM notes WHERE id = ?");
        ps.setInt(1, noteId);
        ResultSet rs = ps.executeQuery();
        if (!rs.next()) return;
        String note = rs.getString(1);

        Statement st = conn.createStatement();
        String sql = "INSERT INTO archived_notes(note_text) VALUES ('" + note + "')";
        st.execute(sql);
    }
}
