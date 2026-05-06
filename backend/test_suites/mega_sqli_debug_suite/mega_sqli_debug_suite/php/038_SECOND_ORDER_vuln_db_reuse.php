<?php
function archiveBio($conn, $userId) {
    $stmt = $conn->prepare("SELECT bio FROM profiles WHERE user_id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    if (!$row) return;

    $bio = $row["bio"];
    $sql = "INSERT INTO audit_log(message) VALUES ('bio: " . $bio . "')";
    mysqli_query($conn, $sql);
}
?>
