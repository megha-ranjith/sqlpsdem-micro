"""
SQLPsdem Attack Detector
Implements 5 detection rules covering 7 attack types (τ1-τ7)
""" 

import re
from enum import Enum
from typing import Optional, Tuple

class AttackType(Enum):
    """SQL Injection attack types"""
    TAUTOLOGY = 1        # τ1: OR 1=1, always true conditions
    UNION = 2            # τ2: UNION SELECT queries
    PIGGYBACK = 3        # τ3: ; DROP TABLE, multiple statements
    INFERENCE = 4        # τ4: SUBSTRING, SLEEP, blind injection
    ENCODING = 5         # τ5: 0x61646D696E, hex encoding
    ILLEGAL = 6          # τ6: Incorrect queries, error-based
    STORED_PROC = 7      # τ7: EXEC xp_cmdshell, stored procedures

class InjectionOrder(Enum):
    """Classification of injection order"""
    FIRST_ORDER = "first-order"      # Direct user input
    SECOND_ORDER = "second-order"    # From persistent data store
    BENIGN = "benign"                # No attack detected

class AttackDetector:
    """
    Implements detection rules from Section III-B-2 of the paper
    Uses pattern matching to identify SQL injection attacks
    """
    
    def __init__(self):
        """Initialize detection rules with regex patterns"""
        self.rules = {
            # Rule τ1: Tautology Detection
            # Detects always-true conditions like OR 1=1, OR 'a'='a'
            'tautology': [
                re.compile(r"OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", re.IGNORECASE),
                re.compile(r"OR\s+['\"][^'\"]+['\"]?\s*=\s*['\"]?[^'\"]+['\"]", re.IGNORECASE),
                re.compile(r"OR\s+\d+\s*=\s*\d+", re.IGNORECASE),
            ],
            
            # Rule τ2: Union Query Detection
            # Detects UNION SELECT attacks to combine queries
            'union': [
                re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE),
            ],
            
            # Rule τ3: Piggy-backed Query Detection
            # Detects multiple statements separated by semicolon
            'piggyback': [
                re.compile(r";\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER|EXEC|EXECUTE|SHUTDOWN)", re.IGNORECASE),
            ],
            
            # Rule τ4: Inference/Blind SQL Injection Detection
            # Detects time-based and boolean-based blind injection
            'inference': [
                re.compile(r"SUBSTRING\s*\(", re.IGNORECASE),
                re.compile(r"SLEEP\s*\(", re.IGNORECASE),
                re.compile(r"BENCHMARK\s*\(", re.IGNORECASE),
                re.compile(r"WAITFOR\s+DELAY", re.IGNORECASE),
                re.compile(r"IF\s*\(", re.IGNORECASE),
            ],
            
            # Rule τ5: Alternate Encoding Detection
            # Detects hex encoding and character functions
            'encoding': [
                re.compile(r"0x[0-9a-f]+", re.IGNORECASE),
                re.compile(r"CHAR\s*\(", re.IGNORECASE),
                re.compile(r"ASCII\s*\(", re.IGNORECASE),
                re.compile(r"CONCAT\s*\(", re.IGNORECASE),
            ],
            
            # Rule τ7: Stored Procedure Exploitation
            # Detects execution of system stored procedures
            'stored_proc': [
                re.compile(r"(EXEC|EXECUTE)\s+(xp_|sp_)", re.IGNORECASE),
            ],
            
            # SQL Comment Detection (common in all attacks)
            # Detects comment characters used to bypass authentication
            'comment': [
                re.compile(r"--"),
                re.compile(r"#"),
                re.compile(r"/\*.*?\*/", re.DOTALL),
            ]
        }
    
    def detect(self, query: str, data_source: int) -> Tuple[bool, Optional[AttackType], str, InjectionOrder]:
        """
        Detect SQL injection in query
        
        Args:
            query: SQL query string to analyze
            data_source: Variable data source classification
                        0 = constant (safe)
                        1 = user input (POST, GET) - first-order
                        2 = persistent data store (SESSION, DB) - second-order
        
        Returns:
            Tuple of (is_attack, attack_type, matched_pattern, injection_order)
        """
        
        # Check Rule τ1: Tautology
        for pattern in self.rules['tautology']:
            match = pattern.search(query)
            if match:
                order = InjectionOrder.SECOND_ORDER if data_source == 2 else InjectionOrder.FIRST_ORDER
                return True, AttackType.TAUTOLOGY, match.group(), order
        
        # Check Rule τ2: Union Query
        for pattern in self.rules['union']:
            match = pattern.search(query)
            if match:
                order = InjectionOrder.SECOND_ORDER if data_source == 2 else InjectionOrder.FIRST_ORDER
                return True, AttackType.UNION, match.group(), order
        
        # Check Rule τ3: Piggy-backed Query
        for pattern in self.rules['piggyback']:
            match = pattern.search(query)
            if match:
                order = InjectionOrder.SECOND_ORDER if data_source == 2 else InjectionOrder.FIRST_ORDER
                return True, AttackType.PIGGYBACK, match.group(), order
        
        # Check Rule τ4: Inference
        for pattern in self.rules['inference']:
            match = pattern.search(query)
            if match:
                order = InjectionOrder.SECOND_ORDER if data_source == 2 else InjectionOrder.FIRST_ORDER
                return True, AttackType.INFERENCE, match.group(), order
        
        # Check Rule τ5: Encoding
        for pattern in self.rules['encoding']:
            match = pattern.search(query)
            if match:
                order = InjectionOrder.SECOND_ORDER if data_source == 2 else InjectionOrder.FIRST_ORDER
                return True, AttackType.ENCODING, match.group(), order
        
        # Check Rule τ7: Stored Procedure
        for pattern in self.rules['stored_proc']:
            match = pattern.search(query)
            if match:
                order = InjectionOrder.SECOND_ORDER if data_source == 2 else InjectionOrder.FIRST_ORDER
                return True, AttackType.STORED_PROC, match.group(), order
        
        # Check for SQL comments
        for pattern in self.rules['comment']:
            match = pattern.search(query)
            if match:
                order = InjectionOrder.SECOND_ORDER if data_source == 2 else InjectionOrder.FIRST_ORDER
                return True, AttackType.TAUTOLOGY, match.group(), order
        
        # No attack detected
        return False, None, "", InjectionOrder.BENIGN
    
    def sanitize(self, query: str) -> str:
        """
        Sanitize malicious query using escaping and truncation
        Implements defense strategies from Table III in the paper
        
        Two strategies:
        1. Character escaping: Escape special characters
        2. Character truncation: Remove dangerous keywords
        
        Args:
            query: Malicious SQL query to sanitize
            
        Returns:
            Sanitized query string
        """
        sanitized = query
        
        # Strategy 1: Character Escaping (for string inputs)
        # Escape special characters that can change SQL semantics
        sanitized = sanitized.replace("\\", "\\\\")  # Escape backslash first
        sanitized = sanitized.replace("'", "\\'")     # Escape single quote
        sanitized = sanitized.replace('"', '\\"')     # Escape double quote
        
        # Strategy 2: Character Truncation (for numeric and other inputs)
        # Remove SQL comments that can bypass authentication
        sanitized = re.sub(r"--.*$", "", sanitized, flags=re.MULTILINE)
        sanitized = re.sub(r"#.*$", "", sanitized, flags=re.MULTILINE)
        sanitized = re.sub(r"/\*.*?\*/", "", sanitized, flags=re.DOTALL)
        
        # Remove dangerous keywords and operators
        dangerous_patterns = [
            r"\bUNION\s+(ALL\s+)?SELECT\b",
            r"\bDROP\s+TABLE\b",
            r"\bDELETE\s+FROM\b",
            r"\bEXEC\s+(xp_|sp_)",
            r"\bEXECUTE\s+(xp_|sp_)",
            r"\bSHUTDOWN\b",
            r"\bSLEEP\s*\(",
            r"\bBENCHMARK\s*\(",
            r"\bWAITFOR\s+DELAY",
        ]
        
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)
        
        return sanitized.strip()

# Test the detector if run directly
if __name__ == "__main__":
    print("SQLPsdem Attack Detector - Test Mode")
    print("=" * 60)
    
    detector = AttackDetector()
    
    # Test cases
    test_queries = [
        ("SELECT * FROM users WHERE id = 1", 1, "Safe query"),
        ("SELECT * FROM users WHERE username = 'admin' OR 1=1--'", 1, "Tautology attack"),
        ("SELECT * FROM users WHERE id = 1 UNION SELECT password FROM admin", 1, "Union attack"),
        ("SELECT * FROM users; DROP TABLE users--", 1, "Piggyback attack"),
        ("UPDATE users SET password = 'new' WHERE username = 'admin'--'", 2, "Second-order attack"),
    ]
    
    for query, data_source, description in test_queries:
        is_attack, attack_type, pattern, order = detector.detect(query, data_source)
        
        print(f"\n{description}:")
        print(f"Query: {query[:80]}...")
        print(f"Attack: {is_attack}")
        
        if is_attack:
            print(f"Type: {attack_type.name} (τ{attack_type.value})")
            print(f"Order: {order.value}")
            print(f"Pattern: {pattern}")
            print(f"Sanitized: {detector.sanitize(query)[:80]}...")
        
        print("-" * 60)
