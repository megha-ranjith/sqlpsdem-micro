<?php
require_once 'config.php';

// Check if user is logged in
if (!isset($_SESSION['logged_in']) || !$_SESSION['logged_in']) {
    header('Location: login.php');
    exit();
}

$attack_detected = false;
$sql_query = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $new_password = md5($_POST['new_password']);
    
    // VULNERABLE TO SECOND-ORDER SQL INJECTION!
    // Username comes from SESSION (retrieved from database - PDS)
    // If username contains attack string like admin'--, vulnerability triggers here!
    $username = $_SESSION['username'];
    
    // This query is vulnerable to second-order attack
    $sql = "UPDATE users SET password = '$new_password' WHERE username = '$username'";
    $sql_query = $sql;
    
    // Check if attack pattern exists in username
    if (strpos($username, "'") !== false || strpos($username, "--") !== false) {
        $attack_detected = true;
    }
    
    $result = mysqli_query($conn, $sql);
    $success = $result !== false;
    $affected_rows = mysqli_affected_rows($conn);
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQLPsdem Demo - Change Password</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 40px 20px;
        }
        .container {
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 700px;
            margin: 0 auto;
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
        .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196F3;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        .info-box strong {
            color: #1565c0;
        }
        .info-box code {
            background: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #d32f2f;
        }
        .warning-box {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
        }
        .warning-box strong {
            color: #856404;
            display: block;
            margin-bottom: 8px;
        }
        .attack-box {
            background: #ffebee;
            border: 3px solid #f44336;
            padding: 20px;
            margin: 25px 0;
            border-radius: 8px;
        }
        .attack-box h3 {
            color: #d32f2f;
            margin-bottom: 15px;
            font-size: 20px;
        }
        .attack-box p {
            margin: 10px 0;
            line-height: 1.6;
        }
        .sql-query {
            background: #f5f5f5;
            border: 2px solid #ff9800;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            color: #d32f2f;
            overflow-x: auto;
        }
        .success-box {
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin: 20px 0;
            border-radius: 5px;
            color: #155724;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
        }
        input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 15px;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn-group {
            display: flex;
            gap: 15px;
            margin-top: 25px;
        }
        button {
            flex: 1;
            padding: 14px;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        .btn-secondary {
            background: #6c757d;
            color: white;
        }
        .btn-secondary:hover {
            background: #5a6268;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔑 SQLPsdem Demo</h1>
        <p class="subtitle">Change Password - Stage 2 of Second-Order Attack</p>
        
        <div class="info-box">
            <strong>ℹ️ Logged in as:</strong> <code><?php echo htmlspecialchars($_SESSION['username']); ?></code>
        </div>
        
        <?php if (!isset($_POST['new_password'])): ?>
            <div class="warning-box">
                <strong>⚠️ Second-Order Attack Demonstration:</strong>
                If you registered with username <code>admin'--</code>, changing your password here will trigger a second-order SQL injection vulnerability!
                <br><br>
                <strong>Why?</strong> The username stored in the database contains malicious characters that will be used unsafely in the UPDATE query.
            </div>
        <?php endif; ?>
        
        <?php if (isset($_POST['new_password'])): ?>
            
            <div class="sql-query">
                <strong>🔍 SQL Query Executed:</strong><br>
                <?php echo htmlspecialchars($sql_query); ?>
            </div>
            
            <?php if ($attack_detected): ?>
                <div class="attack-box">
                    <h3>🚨 SECOND-ORDER SQL INJECTION DETECTED!</h3>
                    <p><strong>Attack Vector:</strong> Username contains malicious characters: <code><?php echo htmlspecialchars($_SESSION['username']); ?></code></p>
                    <p><strong>What happened:</strong></p>
                    <ul style="margin-left: 20px; line-height: 1.8;">
                        <li><strong>Stage 1 (Registration):</strong> Attack string <code>admin'--</code> was safely escaped and stored in database</li>
                        <li><strong>Stage 2 (Password Change):</strong> The stored username is retrieved and used directly in SQL query</li>
                        <li><strong>Result:</strong> The <code>'--</code> in username comments out the rest of the query!</li>
                    </ul>
                    <p style="margin-top: 15px;"><strong>Impact:</strong> This could have changed another user's password (e.g., the 'admin' user) instead of your own!</p>
                    <p style="margin-top: 15px; padding: 10px; background: #fff; border-radius: 5px;">
                        <strong>🛡️ SQLPsdem Protection:</strong> The proxy should have detected this pattern (<code>'--</code>) and blocked the query before it reached the database!
                    </p>
                </div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="success-box">
                    <strong>✓ Query Executed Successfully</strong><br>
                    Affected rows: <?php echo $affected_rows; ?>
                    <?php if (!$attack_detected): ?>
                        <br>Password changed successfully!
                    <?php endif; ?>
                </div>
            <?php else: ?>
                <div style="background: #f8d7da; border-left: 4px solid #dc3545; padding: 15px; border-radius: 5px; color: #721c24;">
                    <strong>✗ Query Failed</strong><br>
                    Error: <?php echo mysqli_error($conn); ?>
                </div>
            <?php endif; ?>
            
        <?php endif; ?>
        
        <form method="POST" action="change_password.php">
            <div class="form-group">
                <label for="new_password">New Password:</label>
                <input type="password" id="new_password" name="new_password" required 
                       placeholder="Enter new password">
            </div>
            
            <div class="btn-group">
                <button type="submit" class="btn-primary">Change Password</button>
                <a href="login.php" style="text-decoration: none;">
                    <button type="button" class="btn-secondary">Logout</button>
                </a>
            </div>
        </form>
    </div>
</body>
</html>