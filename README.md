# SQLPsdem: Simple Proxy-Based Detection of Second-Order SQL Injection

This project is a **minimal, educational prototype** for detecting and blocking both first-order and second-order SQL injection attacks. It mirrors the core ideas of the "SQLPsdem" technique proposed in the IEEE paper:

> "SQLPsdem: A Proxy-Based Mechanism Towards Detecting, Locating and Preventing Second-Order SQL Injections"

---  

## 📦 Features

- **Vulnerable App**: Simple PHP application (register, login, change password) intentionally contains a classic second-order SQL injection flaw.
- **Proxy Detection**: Python server intercepts outgoing SQL queries and checks for multiple attack patterns using regular expressions.
- **Second-Order Awareness**: Proxy is able to detect and block SQL injection that arises only after stored data is re-used.
- **Real-Time Feedback**: Colorful command-line alerts highlight detected and blocked attacks.
- **Easy Setup**: Clear, simple folder structure and configuration for rapid demonstrations or learning.

---

## ⚙️ Technology Stack
 
- **Python 3.x** (`attack_detector.py`, `proxy_server.py`)
- **PHP 7+** (classic procedural; `register.php`, `login.php`, `change_password.php`)
- **MySQL / MariaDB** (tested via XAMPP)
- **XAMPP** or similar LAMP stack for local server

---

## 📂 Folder Structure
```
sqlpsdem/
├── attack_detector.py # Python detection rules
├── proxy_server.py # Python proxy server (demo and live mode)
├── static_analyzer.py # Python static analyzer (optional, for code scanning)
├── vulnerable_app/
│ ├── config.php
│ ├── register.php
│ ├── login.php
│ └── change_password.php
```

---

## 🚀 Quick Start

#### 1. Prerequisites

- Install [XAMPP](https://www.apachefriends.org/) and start **Apache** and **MySQL**
- Install [Python 3.x](https://www.python.org/) and run:
```bash
- pip install colorama
```
  
#### 2. Setup

- Copy the `sqlpsdem` project folder to your preferred location (e.g., `C:\xampp\htdocs\sqlpsdem`)
- Copy the files from `vulnerable_app/` to your XAMPP `htdocs` for browser access


#### 3. Database

- Open phpMyAdmin (`http://localhost/phpmyadmin`)
- Create a new database: `sqlpsdem_test`
- Create the `users` table with:
```bash
CREATE TABLE users (
id INT AUTO_INCREMENT PRIMARY KEY,
username VARCHAR(50) NOT NULL UNIQUE,
password VARCHAR(255) NOT NULL,
email VARCHAR(100),
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```


#### 4. Run Proxy (Python)

```bash
cd path/to/sqlpsdem
python proxy_server.py
```
Choose demo mode, or run proxy live (see comments in code)


#### 5. Test in Browser

- Open `http://localhost/sqlpsdem/vulnerable_app/register.php`
- Register with test credentials (try a normal user and with `admin'--`)
- Attempt login and password change
- Watch Python terminal for real-time detection/alerts

---

## 🧪 Manual Testing

- Register with username: `admin'--`  
- Login and change password → triggers second-order injection
- Proxy displays detection alert and blocks attack

---

## 🛡️ Prevention & Detection

- Proxy intercepts and checks all outgoing SQL queries
- Built-in regex patterns detect:
  - Tautology (OR 1=1, --)
  - UNION-based attacks
  - Piggybacked statements (; DROP TABLE ...)
  - Inference/Blind SQLi (SLEEP, SUBSTRING, etc)
  - Encoding (`0x...`, CHAR(), etc)
  - Stored Proc attacks

---

## 📖 Reference

- Based on:  
  > "SQLPsdem: A Proxy-Based Mechanism Towards Detecting, Locating and Preventing Second-Order SQL Injections"  
  IEEE Transactions on Software Engineering, 2024

---

## ✍️ Author

- **Megha Ranjith**
- GitHub: [@megha-ranjith](https://github.com/megha-ranjith)
- For learning/research/demo use only

---

## 🔒 Disclaimer

This demo app includes intentional vulnerabilities and should **NOT** be deployed in production environments.

---

## 📝 License

MIT License



