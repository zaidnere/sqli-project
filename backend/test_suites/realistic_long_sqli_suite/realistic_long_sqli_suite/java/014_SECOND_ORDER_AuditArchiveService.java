import java.sql.*;
import java.util.logging.Logger;

public class AuditArchiveService {
    private static final Logger log = Logger.getLogger("AuditArchiveService");
    private final Connection conn;

    public AuditArchiveService(Connection conn) {
        this.conn = conn;
    }

    public void archiveUserNote(int noteId) throws Exception {
        PreparedStatement ps = conn.prepareStatement(
            "SELECT note_text FROM user_notes WHERE id = ?"
        );
        ps.setInt(1, noteId);

        ResultSet rs = ps.executeQuery();
        if (!rs.next()) {
            return;
        }

        String noteText = rs.getString(1);

        Statement st = conn.createStatement();
        String sql =
            "INSERT INTO archived_notes(note_text, archived_at) VALUES ('" +
            noteText +
            "', CURRENT_TIMESTAMP)";

        log.info("archiving note id=" + noteId);
        st.execute(sql);
    }
}
