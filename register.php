<?php
// Include the database connection
include 'includes/db_connect.php';

// Check if the form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get and sanitize user inputs
    $username = htmlspecialchars(trim($_POST['username'] ?? ''));
    $email = htmlspecialchars(trim($_POST['email'] ?? ''));
    $password = trim($_POST['password'] ?? '');

    if (empty($username) || empty($email) || empty($password)) {
        echo "Please fill in all fields.";
    } else {
        // Hash the password for security
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Prepare SQL statement to prevent SQL injection
        $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");

        if (!$stmt) {
            die("Prepare failed: " . $conn->error);
        }

        // Bind parameters and execute
        $stmt->bind_param("sss", $username, $email, $hashed_password);

        if ($stmt->execute()) {
            echo "Registration successful! You can now <a href='login.php'>login</a>.";
        } else {
            echo "Error: " . $stmt->error;
        }

        // Close statement and connection
        $stmt->close();
        $conn->close();
    }
}
?>

<!-- HTML form for user registration -->
<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
</head>
<body>
    <h2>Register</h2>
    <form action="register.php" method="POST">
        <label>Username:</label><br>
        <input type="text" name="username" required><br><br>

        <label>Email:</label><br>
        <input type="email" name="email" required><br><br>

        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>

        <input type="submit" value="Register">
    </form>
</body>
</html>
