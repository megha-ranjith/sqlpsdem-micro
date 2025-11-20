<?php
require_once 'config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $email = $_POST['email'];
    
    // VULNERABLE: Using mysqli_real_escape_string
    // Attack string admin'-- gets escaped to admin\'-- and stored in DB
    $username_escaped = mysqli_real_escape_string($conn, $username);
    $password_hashed = md5($password);
    $email_escaped = mysqli_real_escape_string($conn, $email);
    
    // First stage: Store attack string (no vulnerability triggered yet)
    $sql = "INSERT INTO users (username, password, email) 
            VALUES ('$username_escaped', '$password_hashed', '$email_escaped')";
    
    if (mysqli_query($conn, $sql)) {
        echo '<!DOCTYPE html>
<html>
<head>
    <title>Registration Successful</title>
    <style>
        body { font-family: Arial; max-width: 600px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
        .success { background: #d4edda; border: 2px solid #28a745; padding: 20px; border-radius: 8px; }
        .info { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; margin: 20px 0; border-radius: 5px; }
        a { display: inline-block; margin-top: 15px; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }
        a:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="success">
        <h2>✓ Registration Successful!</h2>
        <p><strong>Username:</strong> ' . htmlspecialchars($username_escaped) . '</p>
        <p><strong>Email:</strong> ' . htmlspecialchars($email_escaped) . '</p>
    </div>';
    
        if (strpos($username, "'") !== false || strpos($username, "--") !== false) {
            echo '<div class="info">
                <strong>⚠️ Note:</strong> Your username contains special characters (<code>' . htmlspecialchars($username) . '</code>). 
                This has been stored in the database. When you change your password later, this could trigger a second-order SQL injection!
            </div>';
        }
        
        echo '<a href="login.php">Login Now</a>
</body>
</html>';
    } else {
        echo '<!DOCTYPE html>
<html>
<head>
    <title>Registration Failed</title>
    <style>
        body { font-family: Arial; max-width: 600px; margin: 50px auto; padding: 20px; }
        .error { background: #f8d7da; border: 2px solid #dc3545; padding: 20px; border-radius: 8px; color: #721c24; }
    </style>
</head>
<body>
    <div class="error">
        <h2>✗ Registration Failed</h2>
        <p>Error: ' . mysqli_error($conn) . '</p>
        <a href="register.php">Try Again</a>
    </div>
</body>
</html>';
    }
} else {
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQLPsdem Demo - Register</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 500px;
            width: 100%;
            padding: 40px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .warning {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
        }
        .warning strong {
            color: #856404;
            display: block;
            margin-bottom: 8px;
        }
        .warning code {
            background: #fff;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #d32f2f;
            font-weight: bold;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
            font-size: 14px;
        }
        input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 15px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        button:active {
            transform: translateY(0);
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 14px;
        }
        .footer a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        .footer a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ SQLPsdem Demo</h1>
        <p class="subtitle">User Registration - Stage 1 of Second-Order Attack</p>
        
        <div class="warning">
            <strong>⚠️ Test Second-Order SQL Injection:</strong>
            Register with username: <code>admin'--</code>
            <br><br>
            This malicious input will be safely stored in the database. The vulnerability will only trigger later when you try to change your password (Stage 2).
        </div>
        
        <form method="POST" action="register.php">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required 
                       placeholder="Enter username (try: admin'--)">
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required 
                       placeholder="Enter password">
            </div>
            
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required 
                       placeholder="Enter email address">
            </div>
            
            <button type="submit">Register Account</button>
        </form>
        
        <div class="footer">
            Already have an account? <a href="login.php">Login here</a>
        </div>
    </div>
</body>
</html>
<?php } ?>