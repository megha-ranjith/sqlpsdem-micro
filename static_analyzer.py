"""
SQLPsdem Static Analyzer
Analyzes PHP code for SQL injection vulnerabilities
Based on Section III-A: Static Analysis Module

Author: Implementation for Micro Project
Date: November 2025
"""

import re
import hashlib
import os
from typing import List, Dict, Tuple
from pathlib import Path

class StaticAnalyzer:
    """
    Implements static analysis from Section III-A of the paper
    
    Functions:
    1. Locates SQL statements in PHP code (Section III-A1)
    2. Identifies injection points (SIPs) (Section III-A2, III-A3)
    3. Classifies data sources (Section III-A4)
    4. Reconstructs SQL with Head tags and Inner tags (Section III-A4)
    """
    
    # MySQL execution functions from Table II in the paper
    EXECUTION_FUNCTIONS = [
        'mysql_query',
        'mysql_db_query',
        'mysqli_query',
        'mysqli_multi_query',
        'mysqli_real_query',
        'mysql_unbuffered_query',
    ]
    
    # Data source classification (Section III-A4)
    DATA_SOURCE_CONSTANT = 0      # Fixed values (safe)
    DATA_SOURCE_USER = 1          # GET, POST, REQUEST (first-order)
    DATA_SOURCE_PDS = 2           # Session, Cookie, Database, Files (second-order)
    
    def __init__(self, app_name='TestApp'):
        """
        Initialize analyzer
        
        Args:
            app_name: Application name for Inner tag generation
        """
        self.app_name = app_name
        self.sql_statements = []
        self.injection_points = []
    
    def analyze_file(self, php_file: str) -> List[Dict]:
        """
        Analyze PHP file and extract SQL injection points
        
        Args:
            php_file: Path to PHP file
            
        Returns:
            List of dictionaries containing SQL statements and SIPs
        """
        print(f"[*] Analyzing {php_file}...")
        
        if not os.path.exists(php_file):
            print(f"[ERROR] File not found: {php_file}")
            return []
        
        try:
            with open(php_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"[ERROR] Failed to read file: {e}")
            return []
        
        # Step 1: Locate SQL statements (Section III-A1)
        sql_statements = self.locate_sql_statements(content)
        print(f"[+] Found {len(sql_statements)} SQL statements")
        
        # Step 2: Identify injection points (Section III-A2, III-A3)
        for sql_stmt in sql_statements:
            sips = self.extract_sips(sql_stmt)
            
            # Step 3: Reconstruct SQL with identifiers (Section III-A4)
            reconstructed = self.reconstruct_sql(sql_stmt, sips)
            
            self.sql_statements.append({
                'original': sql_stmt,
                'reconstructed': reconstructed,
                'sips': sips,
                'file': php_file
            })
        
        return self.sql_statements
    
    def analyze_directory(self, directory: str) -> List[Dict]:
        """
        Analyze all PHP files in a directory
        
        Args:
            directory: Path to directory
            
        Returns:
            List of all SQL statements found
        """
        print(f"[*] Scanning directory: {directory}")
        
        php_files = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.php'):
                    php_files.append(os.path.join(root, file))
        
        print(f"[+] Found {len(php_files)} PHP files")
        
        for php_file in php_files:
            self.analyze_file(php_file)
        
        return self.sql_statements
    
    def locate_sql_statements(self, content: str) -> List[str]:
        """
        Locate SQL statements based on execution functions (Section III-A1)
        
        Args:
            content: PHP file content
            
        Returns:
            List of SQL statement strings
        """
        sql_statements = []
        
        for func in self.EXECUTION_FUNCTIONS:
            # Pattern to match: mysqli_query($conn, "SELECT ...")
            # or: mysql_query("SELECT ...")
            patterns = [
                # Pattern 1: Double quotes
                rf'{func}\s*\([^)]*?["\']([^"\']*(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)[^"\']*)["\']',
                # Pattern 2: Single quotes
                rf"{func}\s*\([^)]*?['\"]([^'\"]*(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)[^'\"]*)['\"]",
            ]
            
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    sql_stmt = match.group(1)
                    if sql_stmt not in sql_statements:
                        sql_statements.append(sql_stmt)
        
        return sql_statements
    
    def extract_sips(self, sql_statement: str) -> List[Dict]:
        """
        Extract Suspicious Injection Points (Section III-A3)
        
        SIPs are variables that could be exploited:
        - POST, GET, REQUEST variables (first-order)
        - SESSION, COOKIE variables (second-order)
        - Database retrieved variables (second-order)
        
        Args:
            sql_statement: SQL statement to analyze
            
        Returns:
            List of SIPs with their data sources
        """
        sips = []
        
        # Pattern definitions with data source classification
        variable_patterns = [
            # First-order: Direct user input
            (r'\$_(POST|GET|REQUEST)\[["\']([^"\']+)["\']\]', self.DATA_SOURCE_USER),
            
            # Second-order: Persistent data stores
            (r'\$_(SESSION|COOKIE)\[["\']([^"\']+)["\']\]', self.DATA_SOURCE_PDS),
            
            # Simple variables (could be from anywhere - assume user input)
            (r'\$([a-zA-Z_][a-zA-Z0-9_]*)', self.DATA_SOURCE_USER),
        ]
        
        for pattern, data_source in variable_patterns:
            matches = re.finditer(pattern, sql_statement)
            for match in matches:
                variable_name = match.group(0)
                
                # Check if this variable is already in list
                if not any(sip['variable'] == variable_name for sip in sips):
                    sips.append({
                        'variable': variable_name,
                        'data_source': data_source,
                        'position': match.start()
                    })
        
        return sips
    
    def reconstruct_sql(self, sql_statement: str, sips: List[Dict]) -> str:
        """
        Reconstruct SQL with Head tags and Inner tags (Section III-A4)
        
        Head tag format (Equation 4):
        Ht = exist<T><α1><α2>...<αn><λ>
        
        Where:
        - T: SQL type (S=SELECT, U=UPDATE, I=INSERT, D=DELETE, C=CALL)
        - αi: Data source for each variable (0=constant, 1=user, 2=PDS)
        - λ: Inner tag (unique identifier)
        
        Args:
            sql_statement: Original SQL statement
            sips: List of Suspicious Injection Points
            
        Returns:
            Reconstructed SQL with tags
        """
        # Determine SQL type
        sql_type = self.determine_sql_type(sql_statement)
        
        # Calculate Inner tag λ (Equation 5)
        inner_tag = self.calculate_inner_tag()
        
        # Build data source string
        data_sources = [str(sip['data_source']) for sip in sips]
        data_source_str = ''.join(data_sources) if data_sources else '0'
        
        # Build Head tag (Equation 4)
        head_tag = f"exist<{sql_type}><{data_source_str}><{inner_tag}>"
        
        # Add tags to SQL
        reconstructed = f"/* {head_tag} */ {sql_statement}"
        
        return reconstructed
    
    def determine_sql_type(self, sql_statement: str) -> str:
        """
        Determine SQL statement type
        
        Args:
            sql_statement: SQL statement
            
        Returns:
            Single character type: S, U, I, D, C
        """
        sql_upper = sql_statement.upper().strip()
        
        if sql_upper.startswith('SELECT'):
            return 'S'
        elif sql_upper.startswith('UPDATE'):
            return 'U'
        elif sql_upper.startswith('INSERT'):
            return 'I'
        elif sql_upper.startswith('DELETE'):
            return 'D'
        elif sql_upper.startswith('CALL'):
            return 'C'
        else:
            return 'O'  # Other
    
    def calculate_inner_tag(self) -> str:
        """
        Calculate Inner tag using MD5 (Equation 5)
        
        Formula: λ = MD5(⊕) ⊕ pKey
        Where pKey is application name
        
        Returns:
            Inner tag string (16 characters)
        """
        combined = f"SQLi_{self.app_name}"
        md5_hash = hashlib.md5(combined.encode()).hexdigest()
        return md5_hash[:16]  # Use first 16 characters
    
    def generate_report(self) -> str:
        """
        Generate detailed analysis report
        
        Returns:
            Formatted report string
        """
        report = "\n" + "="*80 + "\n"
        report += "SQLPsdem Static Analysis Report\n"
        report += "="*80 + "\n\n"
        
        report += f"Application Name: {self.app_name}\n"
        report += f"Total SQL Statements Found: {len(self.sql_statements)}\n"
        
        total_sips = sum(len(s['sips']) for s in self.sql_statements)
        report += f"Total Suspicious Injection Points: {total_sips}\n\n"
        
        # Count by data source
        user_sips = sum(1 for s in self.sql_statements for sip in s['sips'] if sip['data_source'] == self.DATA_SOURCE_USER)
        pds_sips = sum(1 for s in self.sql_statements for sip in s['sips'] if sip['data_source'] == self.DATA_SOURCE_PDS)
        
        report += f"First-Order Injection Points (User Input): {user_sips}\n"
        report += f"Second-Order Injection Points (PDS): {pds_sips}\n\n"
        
        report += "="*80 + "\n"
        report += "Detailed Analysis:\n"
        report += "="*80 + "\n\n"
        
        for i, stmt in enumerate(self.sql_statements, 1):
            report += f"[SQL Statement {i}]\n"
            report += f"File: {stmt['file']}\n"
            report += f"Type: {self.determine_sql_type(stmt['original'])}\n"
            report += f"\nOriginal SQL:\n  {stmt['original'][:150]}"
            
            if len(stmt['original']) > 150:
                report += "..."
            report += "\n"
            
            report += f"\nSuspicious Injection Points Found: {len(stmt['sips'])}\n"
            
            if stmt['sips']:
                for sip in stmt['sips']:
                    source_name = ['CONSTANT', 'USER_INPUT', 'PDS'][sip['data_source']]
                    report += f"  • {sip['variable']} → Data Source: {source_name}"
                    
                    if sip['data_source'] == self.DATA_SOURCE_PDS:
                        report += " ⚠️ SECOND-ORDER RISK"
                    report += "\n"
            else:
                report += "  (No injection points detected)\n"
            
            report += f"\nReconstructed SQL:\n  {stmt['reconstructed'][:150]}"
            if len(stmt['reconstructed']) > 150:
                report += "..."
            report += "\n"
            
            report += "\n" + "-"*80 + "\n\n"
        
        return report
    
    def export_to_file(self, output_file: str):
        """
        Export analysis report to file
        
        Args:
            output_file: Output file path
        """
        report = self.generate_report()
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"[✓] Report exported to: {output_file}")
        except Exception as e:
            print(f"[ERROR] Failed to export report: {e}")

# Main execution
if __name__ == "__main__":
    import sys
    
    print("\nSQLPsdem Static Analyzer")
    print("=" * 80)
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python static_analyzer.py <php_file>           - Analyze single file")
        print("  python static_analyzer.py <directory>          - Analyze all PHP files in directory")
        print("\nExample:")
        print("  python static_analyzer.py change_password.php")
        print("  python static_analyzer.py vulnerable_app/")
        sys.exit(1)
    
    target = sys.argv[1]
    analyzer = StaticAnalyzer()
    
    # Check if target is file or directory
    if os.path.isfile(target):
        results = analyzer.analyze_file(target)
    elif os.path.isdir(target):
        results = analyzer.analyze_directory(target)
    else:
        print(f"[ERROR] Target not found: {target}")
        sys.exit(1)
    
    # Generate and print report
    print(analyzer.generate_report())
    
    # Ask to export
    export = input("\nExport report to file? (y/n): ").strip().lower()
    if export == 'y':
        output_file = input("Enter output filename (default: analysis_report.txt): ").strip()
        if not output_file:
            output_file = "analysis_report.txt"
        analyzer.export_to_file(output_file)