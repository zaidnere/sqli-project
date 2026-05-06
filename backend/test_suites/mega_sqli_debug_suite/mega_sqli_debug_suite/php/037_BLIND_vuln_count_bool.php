<?php
function isEmailRegistered($conn, $email) {
    $sql = "SELECT COUNT(*) AS c FROM users WHERE email = '" . $email . "'";
    $result = mysqli_query($conn, $sql);
    $row = mysqli_fetch_assoc($result);
    return $row["c"] > 0;
}
?>
