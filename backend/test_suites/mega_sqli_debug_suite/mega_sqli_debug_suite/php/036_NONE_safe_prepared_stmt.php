<?php
function findUserSafe($conn, $email) {
    $stmt = $conn->prepare("SELECT id, email FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    return $stmt->get_result();
}
?>
