"""
스캐너 테스트 베이스 클래스 및 공통 유틸리티
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from typing import Dict, Any, Type
import requests
from bs4 import BeautifulSoup


class BaseScannerTestCase:
    """모든 스캐너 테스트의 베이스 클래스"""

    scanner_class: Type = None  # 서브클래스에서 정의
    scanner_id: str = None      # 서브클래스에서 정의

    @pytest.fixture
    def mock_session(self):
        """Mock HTTP 세션"""
        session = MagicMock(spec=requests.Session)
        session.headers = {}
        session.cookies = {}
        return session

    @pytest.fixture
    def mock_response(self):
        """Mock HTTP 응답"""
        response = Mock(spec=requests.Response)
        response.status_code = 200
        response.headers = {}
        response.text = ''
        response.content = b''
        response.json.return_value = {}
        response.url = 'http://test.com'
        response.elapsed.total_seconds.return_value = 0.5
        return response

    @pytest.fixture
    def scanner(self, mock_session):
        """스캐너 인스턴스"""
        if not self.scanner_class:
            pytest.skip("scanner_class not defined")

        scanner = self.scanner_class(
            url='http://test.com',
            session=mock_session
        )
        return scanner

    @pytest.fixture
    def vulnerable_html(self):
        """취약한 HTML 샘플"""
        return """
        <!DOCTYPE html>
        <html>
        <head><title>Test Page</title></head>
        <body>
            <form action="/login" method="post">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <button type="submit">Login</button>
            </form>
            <script>var data = 'USER_INPUT';</script>
            <a href="http://evil.com">Click me</a>
        </body>
        </html>
        """

    @pytest.fixture
    def secure_html(self):
        """안전한 HTML 샘플"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Test Page</title>
            <meta name="csrf-token" content="abc123" />
        </head>
        <body>
            <form action="/login" method="post">
                <input type="hidden" name="csrf_token" value="abc123" />
                <input type="text" name="username" />
                <input type="password" name="password" />
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
        """

    def test_metadata_required_fields(self):
        """필수 메타데이터 필드 검증"""
        if not self.scanner_class:
            pytest.skip("scanner_class not defined")

        required_fields = ['id', 'name', 'icon', 'description',
                          'weight', 'field', 'category']

        metadata = self.scanner_class.metadata
        for field in required_fields:
            assert field in metadata, f"Missing required field: {field}"

        # ID 일치 확인
        if self.scanner_id:
            assert metadata['id'] == self.scanner_id

    def test_metadata_category_valid(self):
        """카테고리 유효성 검증"""
        if not self.scanner_class:
            pytest.skip("scanner_class not defined")

        valid_categories = [
            'security_basic', 'security_advanced', 'api_auth',
            'business_logic', 'supply_chain', 'data_integrity'
        ]

        category = self.scanner_class.metadata.get('category')
        assert category in valid_categories, f"Invalid category: {category}"

    def test_weight_range(self):
        """가중치 범위 검증"""
        if not self.scanner_class:
            pytest.skip("scanner_class not defined")

        weight = self.scanner_class.metadata.get('weight', 1)
        assert 0.5 <= weight <= 2.0, f"Weight out of range: {weight}"

    def test_scanner_initialization(self, scanner):
        """스캐너 초기화 테스트"""
        assert scanner.url == 'http://test.com'
        assert hasattr(scanner, 'vulnerabilities')
        assert hasattr(scanner, 'session')
        assert hasattr(scanner, '_execute_scan')

    def test_scan_method_exists(self, scanner):
        """scan 메서드 존재 확인"""
        assert hasattr(scanner, 'scan')
        assert callable(scanner.scan)

    def test_execute_scan_method_exists(self, scanner):
        """_execute_scan 메서드 존재 확인"""
        assert hasattr(scanner, '_execute_scan')
        assert callable(scanner._execute_scan)

    def test_build_result_returns_dict(self, scanner):
        """결과가 딕셔너리 형태인지 확인"""
        with patch.object(scanner, '_execute_scan'):
            result = scanner.scan()
            assert isinstance(result, dict)

    def test_scan_handles_exceptions(self, scanner, mock_session):
        """예외 처리 테스트"""
        mock_session.get.side_effect = requests.RequestException("Network error")

        # 예외가 발생해도 크래시하지 않아야 함
        result = scanner.scan()
        assert isinstance(result, dict)

    def test_scan_with_timeout(self, scanner, mock_session):
        """타임아웃 처리 테스트"""
        mock_session.get.side_effect = requests.Timeout("Timeout")

        result = scanner.scan()
        assert isinstance(result, dict)
        # 타임아웃이 발생해도 결과를 반환해야 함


class VulnerabilityTestMixin:
    """취약점 탐지 테스트 믹스인"""

    def create_vulnerability(self, severity='high', type_name='Test Vulnerability'):
        """취약점 객체 생성 헬퍼"""
        return {
            'type': type_name,
            'severity': severity,
            'title': f'{type_name} detected',
            'description': 'Test vulnerability description',
            'location': 'http://test.com',
            'evidence': 'Test evidence',
            'remediation': 'Test remediation'
        }

    def assert_vulnerability_found(self, scanner, vuln_type=None):
        """취약점 발견 확인"""
        assert len(scanner.vulnerabilities) > 0, "No vulnerabilities found"

        if vuln_type:
            vuln_types = [v.get('type') for v in scanner.vulnerabilities]
            assert vuln_type in vuln_types, f"{vuln_type} not found in {vuln_types}"

    def assert_no_vulnerability(self, scanner):
        """취약점 없음 확인"""
        assert len(scanner.vulnerabilities) == 0, f"Unexpected vulnerabilities: {scanner.vulnerabilities}"

    def assert_severity(self, scanner, expected_severity):
        """심각도 확인"""
        if scanner.vulnerabilities:
            severities = [v.get('severity') for v in scanner.vulnerabilities]
            assert expected_severity in severities, f"{expected_severity} not in {severities}"


class MockResponseBuilder:
    """Mock 응답 빌더"""

    @staticmethod
    def html_response(html_content: str, status_code: int = 200) -> Mock:
        """HTML 응답 생성"""
        response = Mock(spec=requests.Response)
        response.status_code = status_code
        response.text = html_content
        response.content = html_content.encode('utf-8')
        response.headers = {'Content-Type': 'text/html'}
        response.url = 'http://test.com'
        return response

    @staticmethod
    def json_response(json_data: Dict[str, Any], status_code: int = 200) -> Mock:
        """JSON 응답 생성"""
        response = Mock(spec=requests.Response)
        response.status_code = status_code
        response.json.return_value = json_data
        response.text = str(json_data)
        response.headers = {'Content-Type': 'application/json'}
        response.url = 'http://test.com/api'
        return response

    @staticmethod
    def error_response(status_code: int = 500, error_message: str = "Internal Server Error") -> Mock:
        """에러 응답 생성"""
        response = Mock(spec=requests.Response)
        response.status_code = status_code
        response.text = error_message
        response.reason = error_message
        response.headers = {}
        response.url = 'http://test.com'
        return response

    @staticmethod
    def redirect_response(location: str, status_code: int = 302) -> Mock:
        """리다이렉트 응답 생성"""
        response = Mock(spec=requests.Response)
        response.status_code = status_code
        response.headers = {'Location': location}
        response.text = ''
        response.url = 'http://test.com'
        return response


# Fixtures for common test data
@pytest.fixture
def xss_payloads():
    """XSS 테스트 페이로드"""
    return [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "';alert(1);//",
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '<svg onload=alert(1)>'
    ]


@pytest.fixture
def sql_payloads():
    """SQL Injection 테스트 페이로드"""
    return [
        "' OR '1'='1",
        "1' AND '1'='2",
        "' UNION SELECT NULL--",
        "1; DROP TABLE users--",
        "admin'--",
        "' OR 1=1--"
    ]


@pytest.fixture
def secure_headers():
    """보안 헤더 샘플"""
    return {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000',
        'Content-Security-Policy': "default-src 'self'",
        'Referrer-Policy': 'no-referrer'
    }


@pytest.fixture
def insecure_headers():
    """보안 헤더 누락 샘플"""
    return {
        'Content-Type': 'text/html',
        'Server': 'Apache/2.4.1'
    }