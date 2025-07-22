<?php
// Vulnerable login page for testing
$servername = "127.0.0.1";
$username_db = "testuser";
$password_db = "testpass";
$dbname = "testbed";

if ($_POST['username'] && $_POST['password']) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // Vulnerable SQL query (SQL injection possible)
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    
    echo "<h2>Login Attempt</h2>";
    echo "<p>Query: " . htmlspecialchars($query) . "</p>";
    
    // Actually connect to database and execute query
    try {
        $conn = new mysqli($servername, $username_db, $password_db, $dbname);
        if ($conn->connect_error) {
            echo "<p style='color: orange;'>Database connection failed: " . $conn->connect_error . "</p>";
        } else {
            $result = $conn->query($query);
            if ($result && $result->num_rows > 0) {
                echo "<p style='color: green;'>Login successful! Welcome " . htmlspecialchars($username) . "</p>";
                while($row = $result->fetch_assoc()) {
                    echo "<p>User ID: " . $row["id"]. " - Username: " . $row["username"]. "</p>";
                }
            } else {
                echo "<p style='color: red;'>Login failed! Invalid credentials.</p>";
            }
        }
        $conn->close();
    } catch (Exception $e) {
        echo "<p style='color: orange;'>Database error: " . $e->getMessage() . "</p>";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Login</title>
</head>
<body>
    <h1>Vulnerable Login Page</h1>
    <form method="POST">
        <p>
            Username: <input type="text" name="username" required>
        </p>
        <p>
            Password: <input type="password" name="password" required>
        </p>
        <p>
            <input type="submit" value="Login">
        </p>
    </form>
    
    <h2>Hints for Testing:</h2>
    <ul>
        <li>Try SQL injection: admin' OR '1'='1</li>
        <li>Brute force: admin/admin</li>
        <li>XSS: &lt;script&gt;alert('XSS')&lt;/script&gt;</li>
    </ul>
</body>
</html>
