<?php

class CustomerSearchService {
    private mysqli $conn;

    public function __construct(mysqli $conn) {
        $this->conn = $conn;
    }

    public function search(int $tenantId, ?string $status, ?string $keyword) {
        $sql = "SELECT id, tenant_id, customer_name, email, status " .
               "FROM customers WHERE tenant_id = " . $tenantId;

        if ($status !== null && trim($status) !== "") {
            $sql .= " AND status = '" . $status . "'";
        }

        if ($keyword !== null && trim($keyword) !== "") {
            $clean = strtolower(trim($keyword));
            $sql .= " AND (LOWER(customer_name) LIKE '%" . $clean . "%' " .
                    "OR LOWER(email) LIKE '%" . $clean . "%')";
        }

        return mysqli_query($this->conn, $sql);
    }
}
?>
