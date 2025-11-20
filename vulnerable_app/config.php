<?php
/**
 * SQLPsdem Demo - Database Configuration
 * 
 * This file connects to MySQL database
 * Default XAMPP settings (no password)
 */

// Database credentials
$host = 'localhost';        // MySQL host (default: localhost)
$db   = 'sqlpsdem_test';    // Database name (must match what you created in phpMyAdmin)
$user = 'root';             // MySQL username (default: root for XAMPP)
$pass = '';                 // MySQL password (default: empty for XAMPP)

// Create database connection
$conn = mysqli_connect($host, $user, $pass, $db);

// Check connection
if (!$conn) {
    die("
    <!DOCTYPE html>
    <html>
    <head>
        <title>Database Connection Error</title>
        <style>
            body { 
                font-family: Arial; 
                background: #f8d7da; 
                padding: 50px; 
                text-align: center; 
            }
            .error-box {
                background: white;
                border: 3px solid #dc3545;
                border-radius: 10px;
                padding: 40px;
                max-width: 600px;
                margin: 0 auto;
                box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            }
            h1 { color: #dc3545; margin-bottom: 20px; }
            .error-details {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
                text-align: left;
                font-family: 'Courier New', monospace;
                font-size: 14px;
            }
            .steps {
                text-align: left;
                margin-top: 30px;
                line-height: 2;
            }
            .steps li {
                margin: 10px 0;
            }
        </style>
    </head>
    <body>
        <div class='error-box'>
            <h1>❌ Database Connection Failed</h1>
            <p><strong>Could not connect to MySQL database</strong></p>
            
            <div class='error-details'>
                Error: " . mysqli_connect_error() . "
            </div>
            
            <div class='steps'>
                <strong>Troubleshooting Steps:</strong>
                <ol>
                    <li>✅ Check if MySQL is running in XAMPP Control Panel (should be green)</li>
                    <li>✅ Verify database name: <code>sqlpsdem_test</code> exists in phpMyAdmin</li>
                    <li>✅ Check credentials in <code>config.php</code>:
                        <ul>
                            <li>Host: <code>localhost</code></li>
                            <li>Database: <code>sqlpsdem_test</code></li>
                            <li>Username: <code>root</code></li>
                            <li>Password: <code>(empty)</code></li>
                        </ul>
                    </li>
                    <li>✅ Create database and table if not exists:
                        <br><small>Go to <a href='http://localhost/phpmyadmin' target='_blank'>phpMyAdmin</a> → SQL tab → Run CREATE TABLE script</small>
                    </li>
                </ol>
            </div>
        </div>
    </body>
    </html>
    ");
}

// Set character encoding to UTF-8
mysqli_set_charset($conn, 'utf8');

// Start session for login functionality
session_start();

// Success (silent - no output if connection works)
?>