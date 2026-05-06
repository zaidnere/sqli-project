<?php

class InventoryRepository {
    private PDO $pdo;

    private array $allowedSort = [
        "sku" => "sku",
        "quantity" => "quantity",
        "updated_at" => "updated_at"
    ];

    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
    }

    private function safeSort(?string $sortBy): string {
        return $this->allowedSort[$sortBy] ?? "updated_at";
    }

    public function listItems(int $tenantId, ?string $keyword, ?string $sortBy, int $page, int $pageSize): array {
        $safeSort = $this->safeSort($sortBy);
        $safePage = max(1, (int)$page);
        $safeSize = min(100, max(1, (int)$pageSize));
        $offset = ($safePage - 1) * $safeSize;

        $params = [$tenantId];
        $where = ["tenant_id = ?"];

        if ($keyword !== null && trim($keyword) !== "") {
            $where[] = "(LOWER(sku) LIKE ? OR LOWER(name) LIKE ?)";
            $term = "%" . strtolower(trim($keyword)) . "%";
            $params[] = $term;
            $params[] = $term;
        }

        $sql = "SELECT id, sku, name, quantity, updated_at FROM inventory_items " .
               "WHERE " . implode(" AND ", $where) .
               " ORDER BY " . $safeSort .
               " DESC LIMIT " . $safeSize . " OFFSET " . $offset;

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}
?>
