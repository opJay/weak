"""
pytest 설정 및 공통 픽스처 정의
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, List
from unittest.mock import Mock, MagicMock

import pytest
import django
from django.conf import settings

# Django 설정
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
sys.path.insert(0, str(Path(__file__).parent.parent))

# Django 초기화
django.setup()


# ==================== 공통 픽스처 ====================

@pytest.fixture
def mock_http_client():
    """Mock HTTP 클라이언트"""
    client = MagicMock()

    # 기본 응답 설정
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.content = b'<html><body>Test</body></html>'
    mock_response.text = '<html><body>Test</body></html>'
    mock_response.cookies = {}

    client.get.return_value = mock_response
    client.post.return_value = mock_response
    client.options.return_value = mock_response
    client.head.return_value = mock_response

    return client


@pytest.fixture
def secure_headers():
    """안전한 보안 헤더 세트"""
    return {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Content-Security-Policy': "default-src 'self'",
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }


@pytest.fixture
def vulnerable_headers():
    """취약한 헤더 세트 (보안 헤더 누락)"""
    return {
        'Server': 'Apache/2.4.1',
        'X-Powered-By': 'PHP/5.3.0'
    }


@pytest.fixture
def xss_vulnerable_html():
    """XSS 취약점이 있는 HTML"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Vulnerable Page</title>
    </head>
    <body>
        <h1>Search Results</h1>
        <div id="results">
            <!-- Reflected XSS: 사용자 입력이 그대로 출력 -->
            <p>You searched for: <script>alert('XSS')</script></p>
        </div>

        <!-- DOM XSS: JavaScript에서 안전하지 않은 처리 -->
        <script>
            var query = location.search.substring(1);
            document.write('Query: ' + query);
        </script>

        <!-- Stored XSS 시뮬레이션 -->
        <div class="comments">
            <div class="comment">
                <img src=x onerror=alert('XSS')>
            </div>
        </div>

        <!-- 안전하지 않은 이벤트 핸들러 -->
        <button onclick="eval(document.getElementById('input').value)">Execute</button>
        <input id="input" value="alert('XSS')">
    </body>
    </html>
    """


@pytest.fixture
def xss_safe_html():
    """XSS에 안전한 HTML"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Safe Page</title>
        <meta charset="utf-8">
    </head>
    <body>
        <h1>Search Results</h1>
        <div id="results">
            <!-- 이스케이프된 출력 -->
            <p>You searched for: &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
        </div>

        <!-- 안전한 DOM 조작 -->
        <script>
            var query = new URLSearchParams(location.search).get('q');
            var textNode = document.createTextNode('Query: ' + query);
            document.getElementById('results').appendChild(textNode);
        </script>
    </body>
    </html>
    """


@pytest.fixture
def sql_injection_vulnerable_html():
    """SQL Injection 취약점이 있는 HTML"""
    return """
    <!DOCTYPE html>
    <html>
    <body>
        <form action="/search" method="GET">
            <input name="id" value="1">
            <input name="category" value="products">
            <button type="submit">Search</button>
        </form>

        <!-- 에러 메시지 노출 -->
        <div class="error">
            Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1'' at line 1
        </div>
    </body>
    </html>
    """


@pytest.fixture
def csrf_vulnerable_form():
    """CSRF 토큰이 없는 취약한 폼"""
    return """
    <!DOCTYPE html>
    <html>
    <body>
        <form method="POST" action="/transfer">
            <input name="amount" value="1000">
            <input name="to_account" value="attacker">
            <button type="submit">Transfer</button>
        </form>

        <form method="POST" action="/delete">
            <input name="id" value="123">
            <button type="submit">Delete</button>
        </form>
    </body>
    </html>
    """


@pytest.fixture
def csrf_protected_form():
    """CSRF 토큰이 있는 안전한 폼"""
    return """
    <!DOCTYPE html>
    <html>
    <body>
        <form method="POST" action="/transfer">
            <input type="hidden" name="csrf_token" value="a1b2c3d4e5f6">
            <input name="amount" value="1000">
            <input name="to_account" value="recipient">
            <button type="submit">Transfer</button>
        </form>

        <form method="POST" action="/delete">
            <input type="hidden" name="_csrf" value="xyz789">
            <input name="id" value="123">
            <button type="submit">Delete</button>
        </form>
    </body>
    </html>
    """


@pytest.fixture
def mixed_content_html():
    """Mixed Content가 있는 HTML (HTTPS 페이지에 HTTP 리소스)"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <script src="http://insecure.com/script.js"></script>
        <link rel="stylesheet" href="http://insecure.com/style.css">
    </head>
    <body>
        <img src="http://insecure.com/image.jpg">
        <iframe src="http://insecure.com/frame"></iframe>
    </body>
    </html>
    """


@pytest.fixture
def sri_missing_html():
    """SRI가 누락된 외부 리소스를 포함하는 HTML"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js"></script>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css">
    </head>
    <body>
        <script src="/local/script.js"></script>
    </body>
    </html>
    """


@pytest.fixture
def sri_protected_html():
    """SRI가 적용된 안전한 HTML"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <script
            src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"
            integrity="sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK"
            crossorigin="anonymous">
        </script>
        <link
            rel="stylesheet"
            href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css"
            integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3"
            crossorigin="anonymous">
    </head>
    <body>
        <script src="/local/script.js"></script>
    </body>
    </html>
    """


@pytest.fixture
def sensitive_info_exposed_html():
    """민감정보가 노출된 HTML"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <script>
            var apiKey = "sk-1234567890abcdef";
            var password = "admin123";
            var dbConnection = "mysql://root:password@localhost/db";
        </script>
    </head>
    <body>
        <!-- 스택 트레이스 노출 -->
        <div class="error">
            Traceback (most recent call last):
              File "/app/views.py", line 42, in process
                result = db.query(user_input)
              File "/app/database.py", line 13, in query
                cursor.execute(sql)
            MySQLdb.Error: (1064, "You have an error in your SQL syntax")
        </div>

        <!-- 주석에 민감정보 -->
        <!-- TODO: Change admin password from 'admin123' to something secure -->
        <!-- API endpoint: /api/v1/secret?key=xyz123 -->
    </body>
    </html>
    """


# ==================== 테스트 데이터 생성기 ====================

class VulnerableHTMLGenerator:
    """취약점별 HTML 생성기"""

    @staticmethod
    def generate_xss_payloads() -> List[str]:
        """다양한 XSS 페이로드 생성"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<input onfocus=alert('XSS') autofocus>",
            "<details open ontoggle=alert('XSS')>",
            "<ScRiPt>alert('XSS')</sCrIpT>",  # 대소문자 혼용
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",  # HTML entity
            "%3Cscript%3Ealert('XSS')%3C/script%3E",  # URL encoding
        ]

    @staticmethod
    def generate_sql_payloads() -> List[str]:
        """다양한 SQL Injection 페이로드 생성"""
        return [
            "' OR '1'='1",
            "1' AND '1'='2",
            "admin'--",
            "' UNION SELECT * FROM users--",
            "'; DROP TABLE users--",
            "1' WAITFOR DELAY '00:00:05'--",  # Time-based
            "' OR 1=1--",
            "\" OR \"\"=\"",
            "' OR EXISTS(SELECT * FROM users)--",
        ]


class SecureHTMLGenerator:
    """보안이 적용된 HTML 생성기"""

    @staticmethod
    def generate_escaped_content() -> str:
        """이스케이프된 컨텐츠 생성"""
        return """
        &lt;script&gt;alert('XSS')&lt;/script&gt;
        &amp;lt;img src=x onerror=alert('XSS')&amp;gt;
        """

    @staticmethod
    def generate_csp_header() -> str:
        """강력한 CSP 헤더 생성"""
        return (
            "default-src 'self'; "
            "script-src 'self' 'strict-dynamic'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )


@pytest.fixture
def html_generator():
    """HTML 생성기 인스턴스"""
    return {
        'vulnerable': VulnerableHTMLGenerator(),
        'secure': SecureHTMLGenerator()
    }


# ==================== 테스트 헬퍼 함수 ====================

def assert_vulnerability_found(result: Dict[str, Any], min_count: int = 1):
    """취약점이 발견되었는지 확인"""
    vulnerabilities = result.get('vulnerabilities', [])
    issues = result.get('issues', [])
    total = result.get('total', 0)

    actual_count = len(vulnerabilities) + len(issues)
    assert actual_count >= min_count, (
        f"Expected at least {min_count} vulnerabilities, found {actual_count}"
    )
    assert total >= min_count, f"Total count mismatch: {total} < {min_count}"


def assert_no_vulnerability(result: Dict[str, Any]):
    """취약점이 발견되지 않았는지 확인"""
    vulnerabilities = result.get('vulnerabilities', [])
    issues = result.get('issues', [])
    total = result.get('total', 0)

    assert len(vulnerabilities) == 0, f"Unexpected vulnerabilities: {vulnerabilities}"
    assert len(issues) == 0, f"Unexpected issues: {issues}"
    assert total == 0, f"Total should be 0, got {total}"


def assert_severity(result: Dict[str, Any], expected_severity: str):
    """심각도 확인"""
    actual_severity = result.get('severity', 'unknown')
    assert actual_severity == expected_severity, (
        f"Expected severity '{expected_severity}', got '{actual_severity}'"
    )


# ==================== pytest 설정 ====================

def pytest_configure(config):
    """pytest 설정"""
    config.addinivalue_line(
        "markers",
        "unit: Unit tests for individual scanners"
    )
    config.addinivalue_line(
        "markers",
        "integration: Integration tests for scanner workflow"
    )
    config.addinivalue_line(
        "markers",
        "golden: Golden test verification"
    )
    config.addinivalue_line(
        "markers",
        "slow: Slow tests that may take longer"
    )