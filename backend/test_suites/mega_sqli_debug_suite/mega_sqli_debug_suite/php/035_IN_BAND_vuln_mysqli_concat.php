<?php
function findUser($conn, $email) {
    $sql = "SELECT id, email FROM users WHERE email = '" . $email . "'";
    return mysqli_query($conn, $sql);
}
?>
