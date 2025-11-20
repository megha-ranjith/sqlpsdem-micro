"""
SQLPsdem Proxy Server
MySQL proxy that intercepts queries and prevents SQL injection
Based on Section III-B: Proxy-Based Dynamic Execution Module

Author: Implementation for Micro Project
Date: November 2025
"""

import socket
import threading
import re
from colorama import Fore, Style, init

# Import the attack detector
try:
    from attack_detector import AttackDetector, AttackType, InjectionOrder
except ImportError:
    print("ERROR: Please ensure attack_detector.py is in the same directory!")
    print("Download attack_detector.py and place it in the same folder as this file.")
    exit(1)

init(autoreset=True)

class MySQLProxy:
    """
    Proxy server that sits between PHP application and MySQL database
    Implements the dynamic execution module from the paper
    
    Functions:
    1. Intercepts SQL queries before they reach the database
    2. Detects SQL injection attacks using attack_detector
    3. Prevents attacks by sanitizing or blocking malicious queries
    4. Logs all activities for analysis
    """
    
    def __init__(self, listen_host='127.0.0.1', listen_port=3307, 
                 mysql_host='127.0.0.1', mysql_port=3306):
        """
        Initialize proxy server
        
        Args:
            listen_host: Host to listen on (default: localhost)
            listen_port: Port to listen on (default: 3307)
            mysql_host: MySQL server host (default: localhost)
            mysql_port: MySQL server port (default: 3306)
        """
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.mysql_host = mysql_host
        self.mysql_port = mysql_port
        self.detector = AttackDetector()
        self.stats = {
            'total_queries': 0,
            'attacks_blocked': 0,
            'safe_queries': 0
        }
    
    def start(self):
        """Start the proxy server"""
        print(f"{Fore.GREEN}╔════════════════════════════════════════════════════════════╗")
        print(f"{Fore.GREEN}║          SQLPsdem Proxy Server - Starting...               ║")
        print(f"{Fore.GREEN}╚════════════════════════════════════════════════════════════╝")
        print(f"{Fore.CYAN}[i] Listening on {self.listen_host}:{self.listen_port}")
        print(f"{Fore.CYAN}[i] Forwarding to MySQL at {self.mysql_host}:{self.mysql_port}")
        print(f"{Fore.YELLOW}[!] Press Ctrl+C to stop and view statistics\n")
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.listen_host, self.listen_port))
            server_socket.listen(5)
            
            print(f"{Fore.GREEN}[✓] Proxy is ready to intercept SQL queries!")
            print(f"{Fore.WHITE}Waiting for connections...\n")
            
            while True:
                client_socket, client_address = server_socket.accept()
                print(f"{Fore.BLUE}[+] New connection from {client_address}")
                
                # Handle client in separate thread
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket,)
                )
                thread.daemon = True
                thread.start()
        
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Shutting down proxy...")
            self.print_stats()
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to start proxy: {e}")
        finally:
            server_socket.close()
    
    def handle_client(self, client_socket):
        """
        Handle client connection and intercept queries
        
        Args:
            client_socket: Socket connection from client
        """
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                # Extract SQL query from data
                query = self.extract_query(data)
                
                if query:
                    self.stats['total_queries'] += 1
                    
                    # Detect SQL injection
                    # data_source: 1 = user input (for demo)
                    # In production, this would be extracted from Head tags
                    is_attack, attack_type, pattern, order = self.detector.detect(query, 1)
                    
                    if is_attack:
                        self.stats['attacks_blocked'] += 1
                        self.log_attack(query, attack_type, pattern, order)
                        
                        # PREVENTION: Sanitize the query
                        sanitized = self.detector.sanitize(query)
                        print(f"{Fore.GREEN}[PREVENTED] Sanitized query:")
                        print(f"{Fore.WHITE}  {sanitized[:150]}...\n")
                        
                        # Block the original query (don't forward to MySQL)
                        error_msg = f"ERROR: SQL Injection Detected and Blocked by SQLPsdem\n"
                        error_msg += f"Attack Type: {attack_type.name}\n"
                        error_msg += f"Pattern: {pattern}\n"
                        client_socket.send(error_msg.encode())
                        continue
                    
                    else:
                        self.stats['safe_queries'] += 1
                        self.log_safe(query)
                
                # In production, forward safe query to MySQL here
                # For demo, we just log and continue
                
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Connection error: {e}")
        finally:
            client_socket.close()
    
    def extract_query(self, data: bytes) -> str:
        """
        Extract SQL query from MySQL protocol data
        
        Args:
            data: Raw bytes received from client
            
        Returns:
            Extracted SQL query string or empty string
        """
        try:
            # Simple extraction - in production, would parse MySQL protocol properly
            decoded = data.decode('utf-8', errors='ignore')
            
            # Look for SQL keywords
            sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER']
            
            for keyword in sql_keywords:
                if keyword in decoded.upper():
                    # Extract query portion
                    start = decoded.upper().find(keyword)
                    query = decoded[start:].split('\x00')[0]
                    return query
            
            return ""
        except:
            return ""
    
    def log_attack(self, query: str, attack_type: AttackType, pattern: str, order: InjectionOrder):
        """
        Log detected attack with details
        
        Args:
            query: SQL query that contains attack
            attack_type: Type of attack detected
            pattern: Matched attack pattern
            order: First-order or second-order injection
        """
        print(f"{Fore.RED}{'='*80}")
        print(f"{Fore.RED}║ 🚨 ATTACK DETECTED!")
        print(f"{Fore.RED}{'='*80}")
        print(f"{Fore.YELLOW}Attack Type   : {attack_type.name} (τ{attack_type.value})")
        print(f"{Fore.YELLOW}Injection Order: {order.value.upper()}")
        print(f"{Fore.YELLOW}Matched Pattern: {pattern}")
        print(f"{Fore.WHITE}SQL Query     :")
        print(f"{Fore.WHITE}  {query[:200]}...")
        print(f"{Fore.RED}{'='*80}\n")
    
    def log_safe(self, query: str):
        """
        Log safe query
        
        Args:
            query: Safe SQL query
        """
        print(f"{Fore.GREEN}[✓ SAFE] {query[:120]}...\n")
    
    def print_stats(self):
        """Print statistics summary"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}║               SQLPsdem Statistics Report")
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.WHITE}Total Queries Intercepted : {self.stats['total_queries']}")
        print(f"{Fore.RED}Attacks Detected & Blocked : {self.stats['attacks_blocked']}")
        print(f"{Fore.GREEN}Safe Queries Processed     : {self.stats['safe_queries']}")
        
        if self.stats['total_queries'] > 0:
            block_rate = (self.stats['attacks_blocked'] / self.stats['total_queries']) * 100
            print(f"{Fore.YELLOW}Attack Block Rate          : {block_rate:.2f}%")
        
        print(f"{Fore.CYAN}{'='*70}\n")

# Demo function to test the detector without running full proxy
def demo_detection():
    """
    Standalone demo to test detection without network setup
    Useful for quick testing and demonstrations
    """
    print(f"{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}║          SQLPsdem Detection Engine - Demo Mode")
    print(f"{Fore.CYAN}{'='*70}\n")
    
    detector = AttackDetector()
    
    # Test queries
    test_cases = [
        ("SELECT * FROM users WHERE username = 'john'", 1, "Normal safe query"),
        ("SELECT * FROM users WHERE id = 1 OR 1=1--", 1, "Tautology attack (τ1)"),
        ("SELECT * FROM users UNION SELECT password FROM admin", 1, "Union attack (τ2)"),
        ("SELECT * FROM users; DROP TABLE users--", 1, "Piggyback attack (τ3)"),
        ("SELECT * FROM users WHERE id = 1 AND SLEEP(5)", 1, "Inference attack (τ4)"),
        ("SELECT * FROM users WHERE name = 0x61646D696E", 1, "Encoding attack (τ5)"),
        ("EXEC xp_cmdshell 'dir'", 1, "Stored procedure attack (τ7)"),
        ("UPDATE users SET password = 'new' WHERE username = 'admin'--'", 2, "Second-order attack"),
    ]
    
    for query, data_source, description in test_cases:
        print(f"{Fore.CYAN}Test: {description}")
        print(f"{Fore.WHITE}Query: {query}")
        
        is_attack, attack_type, pattern, order = detector.detect(query, data_source)
        
        if is_attack:
            print(f"{Fore.RED}Result: ATTACK DETECTED")
            print(f"{Fore.YELLOW}  Type: {attack_type.name} (τ{attack_type.value})")
            print(f"{Fore.YELLOW}  Order: {order.value}")
            print(f"{Fore.YELLOW}  Pattern: {pattern}")
            sanitized = detector.sanitize(query)
            print(f"{Fore.GREEN}  Sanitized: {sanitized}")
        else:
            print(f"{Fore.GREEN}Result: SAFE")
        
        print(f"{Fore.WHITE}{'-'*70}\n")

if __name__ == "__main__":
    import sys
    
    print("\nSQLPsdem Proxy Server")
    print("=" * 60)
    print("Choose mode:")
    print("1. Start proxy server (requires XAMPP MySQL)")
    print("2. Run detection demo (no network setup needed)")
    print("=" * 60)
    
    choice = input("Enter choice (1 or 2, default=2): ").strip()
    
    if choice == "1":
        print("\nStarting proxy server...\n")
        proxy = MySQLProxy()
        proxy.start()
    else:
        print("\nRunning detection demo...\n")
        demo_detection()