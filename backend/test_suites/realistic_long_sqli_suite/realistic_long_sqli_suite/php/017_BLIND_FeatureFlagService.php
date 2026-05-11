<?php

class FeatureFlagService {
    private mysqli $conn;

    public function __construct(mysqli $conn) {
        $this->conn = $conn;
    }

    public function isEnabled(string $email, string $featureKey): bool {
        $sql = "SELECT COUNT(*) AS c FROM feature_flags f " .
               "JOIN users u ON u.id = f.user_id " .
               "WHERE u.email = '" . $email . "' " .
               "AND f.feature_key = '" . $featureKey . "' " .
               "AND f.enabled = 1";

        $result = mysqli_query($this->conn, $sql);
        $row = mysqli_fetch_assoc($result);
        return $row["c"] > 0;
    }
}
?>
