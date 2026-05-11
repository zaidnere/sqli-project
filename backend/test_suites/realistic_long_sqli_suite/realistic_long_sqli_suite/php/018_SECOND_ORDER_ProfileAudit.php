<?php

class ProfileAudit {
    private mysqli $conn;

    public function __construct(mysqli $conn) {
        $this->conn = $conn;
    }

    public function writeAudit(int $userId): void {
        $stmt = $this->conn->prepare("SELECT bio FROM profiles WHERE user_id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();

        $row = $stmt->get_result()->fetch_assoc();
        if (!$row) {
            return;
        }

        $bio = $row["bio"];
        $sql = "INSERT INTO audit_log(message, created_at) VALUES ('profile bio: " . $bio . "', NOW())";

        mysqli_query($this->conn, $sql);
    }
}
?>
