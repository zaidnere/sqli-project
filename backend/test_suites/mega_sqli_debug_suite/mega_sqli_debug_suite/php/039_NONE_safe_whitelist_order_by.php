<?php
function listUsers($conn, $sortBy) {
    $allowed = ["id" => "id", "email" => "email", "created_at" => "created_at"];
    $safeCol = $allowed[$sortBy] ?? "created_at";
    $sql = "SELECT id, email FROM users ORDER BY " . $safeCol;
    return mysqli_query($conn, $sql);
}
?>
