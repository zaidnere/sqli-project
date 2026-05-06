<?php
function listUsers($conn, $sortBy) {
    $sql = "SELECT id, email FROM users ORDER BY " . $sortBy;
    return mysqli_query($conn, $sql);
}
?>
