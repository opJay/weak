"""
스캐너별 OWASP Top 10 및 CWE 매핑
OWASP Top 10 2025 RC1 기준
"""

# OWASP Top 10 2025 RC1 카테고리
OWASP_CATEGORIES = {
    'A01:2025': 'Broken Access Control',
    'A02:2025': 'Cryptographic Failures',
    'A03:2025': 'Injection',
    'A04:2025': 'Insecure Design',
    'A05:2025': 'Security Misconfiguration',
    'A06:2025': 'Vulnerable and Outdated Components',
    'A07:2025': 'Identification and Authentication Failures',
    'A08:2025': 'Software and Data Integrity Failures',
    'A09:2025': 'Security Logging and Monitoring Failures',
    'A10:2025': 'Server-Side Request Forgery (SSRF)'
}

# 스캐너별 OWASP 매핑
OWASP_MAPPING = {
    # Basic Security (Batch 1-2)
    'cookies': 'A07:2025',                    # Authentication
    'clickjacking': 'A04:2025',               # Insecure Design
    'sri': 'A08:2025',                        # Data Integrity
    'security_headers': 'A05:2025',           # Security Misconfiguration
    'xss': 'A03:2025',                        # Injection
    'sql_injection': 'A03:2025',              # Injection
    'csrf': 'A01:2025',                       # Broken Access Control
    'info_disclosure': 'A05:2025',            # Security Misconfiguration
    'mixed_content': 'A02:2025',              # Cryptographic Failures

    # Basic continued
    'cors': 'A01:2025',                       # Broken Access Control
    'ssl_tls': 'A02:2025',                    # Cryptographic Failures
    'http_methods': 'A05:2025',               # Security Misconfiguration
    'sensitive_files': 'A05:2025',            # Security Misconfiguration
    'directory_listing': 'A05:2025',          # Security Misconfiguration
    'open_redirect': 'A04:2025',              # Insecure Design

    # Advanced Security (Batch 3-5)
    'ssrf': 'A10:2025',                       # SSRF (dedicated category)
    'xxe': 'A03:2025',                        # Injection
    'command_injection': 'A03:2025',          # Injection
    'deserialization': 'A08:2025',            # Data Integrity Failures
    'file_upload': 'A04:2025',                # Insecure Design
    'path_traversal': 'A01:2025',             # Broken Access Control
    'jwt_security': 'A07:2025',               # Authentication Failures
    'template_injection': 'A03:2025',         # Injection
    'nosql_injection': 'A03:2025',            # Injection
    'ssl_tls_deep': 'A02:2025',               # Cryptographic Failures

    # API & Authentication (Batch 6)
    'rest_api_security': 'A01:2025',          # Broken Access Control
    'graphql_security': 'A01:2025',           # Broken Access Control
    'oauth_security': 'A07:2025',             # Authentication Failures
    'session_security': 'A07:2025',           # Authentication Failures
    'password_policy': 'A07:2025',            # Authentication Failures
    'rate_limiting': 'A04:2025',              # Insecure Design
    'ldap_injection': 'A03:2025',             # Injection
    'authorization': 'A01:2025',              # Broken Access Control

    # Business Logic (Batch 7)
    'price_manipulation': 'A04:2025',         # Insecure Design
    'race_condition': 'A04:2025',             # Insecure Design
    'workflow_bypass': 'A04:2025',            # Insecure Design
    'account_enumeration': 'A07:2025',        # Authentication Failures
    'resource_exhaustion': 'A04:2025',        # Insecure Design
    'logging_monitoring': 'A09:2025',         # Logging & Monitoring Failures
    'business_logic_anomaly': 'A04:2025',     # Insecure Design

    # Supply Chain (Batch 8)
    'supply_chain': 'A06:2025',               # Vulnerable Components
    'package_integrity': 'A08:2025',          # Data Integrity Failures
    'typosquatting': 'A06:2025',              # Vulnerable Components
    'outdated_dependency': 'A06:2025',        # Vulnerable Components
    'license_compliance': 'A06:2025',         # Vulnerable Components

    # Data Integrity (Batch 9)
    'jwt_advanced': 'A08:2025',               # Data Integrity Failures
    'serialization_integrity': 'A08:2025',    # Data Integrity Failures
    'api_integrity': 'A08:2025',              # Data Integrity Failures
    'checksum_validation': 'A08:2025',        # Data Integrity Failures

    # Exception Handling (Batch 10)
    'exception_handling': 'A09:2025'          # Logging & Monitoring Failures
}

# 스캐너별 CWE 매핑
CWE_MAPPING = {
    # Basic Security
    'cookies': ['CWE-614', 'CWE-1004'],           # Sensitive Cookie Without 'HttpOnly', Without 'Secure'
    'clickjacking': ['CWE-1021'],                 # Improper Restriction of Rendered UI Layers
    'sri': ['CWE-353'],                           # Missing Support for Integrity Check
    'security_headers': ['CWE-693'],              # Protection Mechanism Failure
    'xss': ['CWE-79', 'CWE-80'],                  # XSS
    'sql_injection': ['CWE-89'],                  # SQL Injection
    'csrf': ['CWE-352'],                          # CSRF
    'info_disclosure': ['CWE-200', 'CWE-209'],    # Information Exposure
    'mixed_content': ['CWE-311'],                 # Missing Encryption

    # Basic continued
    'cors': ['CWE-346', 'CWE-942'],               # Origin Validation Error
    'ssl_tls': ['CWE-311', 'CWE-326'],            # Missing/Inadequate Encryption
    'http_methods': ['CWE-650'],                  # Trusting HTTP Permission Methods
    'sensitive_files': ['CWE-538', 'CWE-552'],    # File and Directory Information Exposure
    'directory_listing': ['CWE-548'],             # Directory Listing
    'open_redirect': ['CWE-601'],                 # URL Redirection to Untrusted Site

    # Advanced Security
    'ssrf': ['CWE-918'],                          # Server-Side Request Forgery
    'xxe': ['CWE-611', 'CWE-776'],                # XXE, XML Document with Recursive Entity
    'command_injection': ['CWE-77', 'CWE-78'],    # Command Injection
    'deserialization': ['CWE-502'],               # Deserialization of Untrusted Data
    'file_upload': ['CWE-434'],                   # Unrestricted Upload
    'path_traversal': ['CWE-22', 'CWE-23'],       # Path Traversal
    'jwt_security': ['CWE-347'],                  # Improper Verification of Cryptographic Signature
    'template_injection': ['CWE-94', 'CWE-1336'], # Code Injection, Template Injection
    'nosql_injection': ['CWE-943'],               # NoSQL Injection
    'ssl_tls_deep': ['CWE-295', 'CWE-757'],       # Certificate Validation, Selection of Less-Secure Algorithm

    # API & Authentication
    'rest_api_security': ['CWE-284', 'CWE-285'],  # Improper Access Control
    'graphql_security': ['CWE-284', 'CWE-863'],   # Improper Access Control, Incorrect Authorization
    'oauth_security': ['CWE-287'],                # Improper Authentication
    'session_security': ['CWE-384', 'CWE-613'],   # Session Fixation, Insufficient Session Expiration
    'password_policy': ['CWE-521'],               # Weak Password Requirements
    'rate_limiting': ['CWE-770', 'CWE-307'],      # Resource Without Limits, Improper Restriction of Excessive Auth Attempts
    'ldap_injection': ['CWE-90'],                 # LDAP Injection
    'authorization': ['CWE-639', 'CWE-284'],      # Authorization Bypass, Improper Access Control

    # Business Logic
    'price_manipulation': ['CWE-639', 'CWE-642'], # Authorization Bypass, External Control of Critical State
    'race_condition': ['CWE-362', 'CWE-367'],     # Race Condition, TOCTOU
    'workflow_bypass': ['CWE-840', 'CWE-841'],    # Business Logic Errors
    'account_enumeration': ['CWE-204', 'CWE-203'], # Observable Response Discrepancy
    'resource_exhaustion': ['CWE-400', 'CWE-770'], # Uncontrolled Resource Consumption
    'logging_monitoring': ['CWE-778', 'CWE-223'],  # Insufficient Logging, Omission of Security-relevant Information
    'business_logic_anomaly': ['CWE-840'],         # Business Logic Errors

    # Supply Chain
    'supply_chain': ['CWE-1104', 'CWE-506'],       # Use of Unmaintained Third Party Components
    'package_integrity': ['CWE-494', 'CWE-353'],   # Download Without Integrity Check
    'typosquatting': ['CWE-506'],                  # Embedded Malicious Code
    'outdated_dependency': ['CWE-1104'],           # Use of Unmaintained Third Party Components
    'license_compliance': ['CWE-506'],             # Embedded Malicious Code

    # Data Integrity
    'jwt_advanced': ['CWE-347', 'CWE-345'],        # Improper Verification, Insufficient Verification of Data Authenticity
    'serialization_integrity': ['CWE-502', 'CWE-915'], # Deserialization, Improperly Controlled Modification
    'api_integrity': ['CWE-345', 'CWE-354'],       # Insufficient Verification, Improper Validation of Integrity Check
    'checksum_validation': ['CWE-353', 'CWE-354'], # Missing/Improper Integrity Check

    # Exception Handling
    'exception_handling': ['CWE-209', 'CWE-532']   # Information Exposure Through Error Messages, Insertion of Sensitive Info into Log
}

# 심각도 매핑 (CWE 기반)
SEVERITY_MAPPING = {
    'CWE-77': 'critical',   # Command Injection
    'CWE-78': 'critical',   # OS Command Injection
    'CWE-89': 'critical',   # SQL Injection
    'CWE-90': 'critical',   # LDAP Injection
    'CWE-94': 'critical',   # Code Injection
    'CWE-434': 'critical',  # Unrestricted Upload
    'CWE-502': 'critical',  # Deserialization
    'CWE-611': 'critical',  # XXE
    'CWE-918': 'high',     # SSRF
    'CWE-79': 'high',      # XSS
    'CWE-22': 'high',      # Path Traversal
    'CWE-352': 'high',     # CSRF
    'CWE-287': 'high',     # Improper Authentication
    'CWE-284': 'high',     # Improper Access Control
    'CWE-347': 'high',     # JWT Issues
    'CWE-362': 'high',     # Race Condition
    'CWE-601': 'medium',   # Open Redirect
    'CWE-614': 'medium',   # Sensitive Cookie
    'CWE-693': 'medium',   # Protection Mechanism Failure
    'CWE-200': 'medium',   # Information Exposure
    'CWE-311': 'medium',   # Missing Encryption
    'CWE-521': 'medium',   # Weak Password
    'CWE-538': 'low',      # File Information Exposure
    'CWE-548': 'low',      # Directory Listing
    'CWE-1021': 'low',     # Clickjacking
    'CWE-532': 'info'      # Information in Log Files
}

def get_owasp_category(scanner_id):
    """
    스캐너 ID에 해당하는 OWASP 카테고리 반환

    Args:
        scanner_id: 스캐너 식별자

    Returns:
        str: OWASP 카테고리 (예: 'A01:2025')
    """
    return OWASP_MAPPING.get(scanner_id, 'A04:2025')  # 기본값: Insecure Design

def get_cwe_ids(scanner_id):
    """
    스캐너 ID에 해당하는 CWE ID 목록 반환

    Args:
        scanner_id: 스캐너 식별자

    Returns:
        list: CWE ID 목록
    """
    return CWE_MAPPING.get(scanner_id, [])

def get_severity_from_cwe(cwe_id):
    """
    CWE ID에 해당하는 심각도 반환

    Args:
        cwe_id: CWE 식별자 (예: 'CWE-89')

    Returns:
        str: 심각도 (critical/high/medium/low/info)
    """
    return SEVERITY_MAPPING.get(cwe_id, 'medium')

def get_owasp_description(category):
    """
    OWASP 카테고리에 대한 설명 반환

    Args:
        category: OWASP 카테고리 (예: 'A01:2025')

    Returns:
        str: 카테고리 설명
    """
    return OWASP_CATEGORIES.get(category, 'Unknown Category')

def get_scanner_severity(scanner_id):
    """
    스캐너의 기본 심각도 반환

    Args:
        scanner_id: 스캐너 식별자

    Returns:
        str: 심각도
    """
    cwe_ids = get_cwe_ids(scanner_id)
    if not cwe_ids:
        return 'medium'

    # CWE 중 가장 높은 심각도 반환
    severities = [get_severity_from_cwe(cwe) for cwe in cwe_ids]
    severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    return max(severities, key=lambda x: severity_order.get(x, 0))