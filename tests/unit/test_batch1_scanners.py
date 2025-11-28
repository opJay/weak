"""
Batch 1 스캐너들의 유닛 테스트
- CORSScanner
- CookieScanner
- ClickjackingScanner
- SubresourceIntegrityScanner

탐지 정확도 중심 테스트
"""

import pytest
from unittest.mock import Mock, MagicMock
from http.cookies import SimpleCookie

# 프로젝트 루트를 Python 경로에 추가
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanner.scanners_refactored import CORSScanner
from scanner.scanners_refactored_batch1 import (
    CookieScanner,
    ClickjackingScanner,
    SubresourceIntegrityScanner
)


class TestCORSScanner:
    """CORSScanner 탐지 능력 검증"""

    @pytest.mark.unit
    def test_detect_wildcard_with_credentials(self):
        """Critical: 와일드카드 + Credentials 탐지"""
        # Given
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        }

        # When
        scanner = CORSScanner(headers=headers)
        result = scanner.scan()

        # Then
        assert len(result['issues']) > 0, "Critical CORS 설정을 탐지해야 함"
        assert result['issues'][0]['severity'] == 'critical'
        assert 'Credentials: true' in result['issues'][0]['description']

    @pytest.mark.unit
    def test_detect_wildcard_without_credentials(self):
        """Medium: 와일드카드만 있는 경우"""
        # Given
        headers = {
            'Access-Control-Allow-Origin': '*'
        }

        # When
        scanner = CORSScanner(headers=headers)
        result = scanner.scan()

        # Then
        assert len(result['issues']) == 1
        assert result['issues'][0]['severity'] == 'medium'
        assert 'CORS Wildcard' in result['issues'][0]['type']

    @pytest.mark.unit
    def test_detect_null_origin(self):
        """null 오리진 허용 탐지"""
        # Given
        headers = {
            'Access-Control-Allow-Origin': 'null'
        }

        # When
        scanner = CORSScanner(headers=headers)
        result = scanner.scan()

        # Then
        assert len(result['issues']) > 0
        assert result['issues'][0]['severity'] == 'high'
        assert 'null' in result['issues'][0]['description']

    @pytest.mark.unit
    def test_no_false_positive_with_specific_origin(self):
        """특정 도메인만 허용하는 안전한 설정"""
        # Given
        headers = {
            'Access-Control-Allow-Origin': 'https://trusted.example.com'
        }

        # When
        scanner = CORSScanner(headers=headers)
        result = scanner.scan()

        # Then
        assert len(result['issues']) == 0, "안전한 CORS 설정은 문제없음"
        assert result['has_cors'] == True
        assert result['misconfigured'] == False

    @pytest.mark.unit
    def test_detect_dangerous_methods(self):
        """위험한 HTTP 메서드 허용 탐지"""
        # Given
        headers = {
            'Access-Control-Allow-Origin': 'https://example.com',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE'
        }

        # When
        scanner = CORSScanner(headers=headers)
        result = scanner.scan()

        # Then
        dangerous_issues = [i for i in result['issues'] if 'Dangerous Methods' in i['type']]
        assert len(dangerous_issues) > 0
        assert 'PUT' in dangerous_issues[0]['methods']
        assert 'DELETE' in dangerous_issues[0]['methods']


class TestCookieScanner:
    """CookieScanner 탐지 능력 검증"""

    @pytest.mark.unit
    def test_detect_missing_secure_flag(self):
        """Secure 플래그 누락 탐지"""
        # Given
        response = Mock()
        cookie = Mock()
        cookie.name = 'session_id'
        cookie.secure = False
        cookie.domain = '.example.com'
        cookie.path = '/'
        cookie.expires = None
        cookie._rest = {}
        response.cookies = [cookie]

        # When
        scanner = CookieScanner(response=response, url='https://example.com')
        result = scanner.scan()

        # Then
        assert len(result['issues']) > 0
        assert 'Secure 플래그가 없습니다' in result['issues'][0]['issues']

    @pytest.mark.unit
    def test_detect_missing_httponly_flag(self):
        """HttpOnly 플래그 누락 탐지"""
        # Given
        response = Mock()
        cookie = Mock()
        cookie.name = 'session_token'
        cookie.secure = True
        cookie.httponly = False  # HttpOnly 없음
        cookie.domain = '.example.com'
        cookie.path = '/'
        cookie.expires = None
        cookie._rest = {}
        response.cookies = [cookie]

        # When
        scanner = CookieScanner(response=response)
        result = scanner.scan()

        # Then
        assert len(result['issues']) > 0
        issues_text = ' '.join(result['issues'][0]['issues'])
        assert 'HttpOnly' in issues_text
        assert result['issues'][0]['severity'] == 'high'  # session 쿠키라서 high

    @pytest.mark.unit
    def test_detect_missing_samesite(self):
        """SameSite 속성 누락 탐지"""
        # Given
        response = Mock()
        cookie = Mock()
        cookie.name = 'auth_token'
        cookie.secure = True
        cookie.httponly = True
        cookie.samesite = None  # SameSite 없음
        cookie.domain = '.example.com'
        cookie.path = '/'
        cookie.expires = None
        cookie._rest = {}
        response.cookies = [cookie]

        # When
        scanner = CookieScanner(response=response)
        result = scanner.scan()

        # Then
        assert len(result['issues']) > 0
        assert 'SameSite' in ' '.join(result['issues'][0]['issues'])

    @pytest.mark.unit
    def test_no_false_positive_secure_cookie(self):
        """완전히 안전한 쿠키 설정"""
        # Given
        response = Mock()
        cookie = Mock()
        cookie.name = 'safe_cookie'
        cookie.secure = True
        cookie.httponly = True
        cookie.samesite = 'Strict'
        cookie.domain = '.example.com'
        cookie.path = '/'
        cookie.expires = None
        cookie._rest = {'HttpOnly': True, 'SameSite': 'Strict'}
        response.cookies = [cookie]

        # When
        scanner = CookieScanner(response=response)
        result = scanner.scan()

        # Then
        assert len(result['issues']) == 0, "안전한 쿠키는 문제없음"
        assert result['insecure_cookies'] == 0
        assert result['secure_percentage'] == 100

    @pytest.mark.unit
    def test_detect_sensitive_cookie_name(self):
        """민감한 정보가 포함된 쿠키 이름 탐지"""
        # Given
        response = Mock()
        cookie = Mock()
        cookie.name = 'user_password_hash'  # 민감한 이름
        cookie.secure = True
        cookie.httponly = True
        cookie.samesite = 'Strict'
        cookie.domain = '.example.com'
        cookie.path = '/'
        cookie.expires = None
        cookie._rest = {'HttpOnly': True, 'SameSite': 'Strict'}
        response.cookies = [cookie]

        # When
        scanner = CookieScanner(response=response)
        result = scanner.scan()

        # Then
        assert len(result['issues']) > 0
        assert result['issues'][0]['severity'] == 'high'
        assert 'password' in result['issues'][0]['issues'][0].lower()


class TestClickjackingScanner:
    """ClickjackingScanner 탐지 능력 검증"""

    @pytest.mark.unit
    def test_detect_missing_protection(self):
        """클릭재킹 방어가 전혀 없는 경우"""
        # Given
        headers = {}  # X-Frame-Options도, CSP도 없음

        # When
        scanner = ClickjackingScanner(headers=headers)
        result = scanner.scan()

        # Then
        assert len(result['issues']) > 0
        assert result['issues'][0]['severity'] == 'high'
        assert 'Missing Clickjacking Protection' in result['issues'][0]['type']
        assert result['protected'] == False

    @pytest.mark.unit
    def test_detect_xframe_deny(self):
        """X-Frame-Options: DENY 설정 인식"""
        # Given
        headers = {
            'X-Frame-Options': 'DENY'
        }

        # When
        scanner = ClickjackingScanner(headers=headers)
        result = scanner.scan()

        # Then
        assert len(result['issues']) == 0, "DENY는 안전한 설정"
        assert result['has_xfo'] == True
        assert result['protected'] == True

    @pytest.mark.unit
    def test_detect_deprecated_allow_from(self):
        """더 이상 사용되지 않는 ALLOW-FROM 탐지"""
        # Given
        headers = {
            'X-Frame-Options': 'ALLOW-FROM https://example.com'
        }

        # When
        scanner = ClickjackingScanner(headers=headers)
        result = scanner.scan()

        # Then
        deprecated = [i for i in result['issues'] if 'Deprecated' in i['type']]
        assert len(deprecated) > 0
        assert deprecated[0]['severity'] == 'low'
        assert 'CSP frame-ancestors' in deprecated[0]['recommendation']

    @pytest.mark.unit
    def test_detect_csp_frame_ancestors(self):
        """CSP frame-ancestors로 보호되는 경우"""
        # Given
        headers = {
            'Content-Security-Policy': "default-src 'self'; frame-ancestors 'self'"
        }

        # When
        scanner = ClickjackingScanner(headers=headers)
        result = scanner.scan()

        # Then
        assert len(result['issues']) == 0, "CSP frame-ancestors는 유효한 보호"
        assert result['has_csp_frame'] == True
        assert result['protected'] == True

    @pytest.mark.unit
    def test_detect_weak_frame_ancestors(self):
        """약한 frame-ancestors 설정 탐지"""
        # Given
        headers = {
            'Content-Security-Policy': "frame-ancestors '*'"
        }

        # When
        scanner = ClickjackingScanner(headers=headers)
        result = scanner.scan()

        # Then
        weak = [i for i in result['issues'] if 'Weak frame-ancestors' in i['type']]
        assert len(weak) > 0
        assert weak[0]['severity'] == 'medium'


class TestSubresourceIntegrityScanner:
    """SubresourceIntegrityScanner 탐지 능력 검증"""

    @pytest.mark.unit
    def test_detect_missing_sri_external_script(self):
        """외부 스크립트의 SRI 누락 탐지"""
        # Given
        html = """
        <html>
        <head>
            <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
        </head>
        </html>
        """

        # When
        scanner = SubresourceIntegrityScanner(html_content=html)
        result = scanner.scan()

        # Then
        assert len(result['issues']) > 0
        assert result['issues'][0]['type'] == 'Missing SRI'
        assert result['issues'][0]['is_cdn'] == True
        assert result['issues'][0]['severity'] == 'high'  # CDN이므로 high

    @pytest.mark.unit
    def test_detect_missing_sri_external_stylesheet(self):
        """외부 스타일시트의 SRI 누락 탐지"""
        # Given
        html = """
        <html>
        <head>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css">
        </head>
        </html>
        """

        # When
        scanner = SubresourceIntegrityScanner(html_content=html, url='https://example.com')
        result = scanner.scan()

        # Then
        assert len(result['issues']) > 0
        assert result['issues'][0]['resource_type'] == 'stylesheet'
        assert 'bootstrap' in result['issues'][0]['url']

    @pytest.mark.unit
    def test_no_false_positive_with_sri(self):
        """SRI가 올바르게 설정된 경우"""
        # Given
        html = """
        <html>
        <head>
            <script
                src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"
                integrity="sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK"
                crossorigin="anonymous">
            </script>
        </head>
        </html>
        """

        # When
        scanner = SubresourceIntegrityScanner(html_content=html)
        result = scanner.scan()

        # Then
        # integrity 있으므로 'Missing SRI' 이슈는 없어야 함
        missing_sri = [i for i in result['issues'] if i['type'] == 'Missing SRI']
        assert len(missing_sri) == 0, "SRI가 있으면 Missing SRI 이슈 없음"

    @pytest.mark.unit
    def test_ignore_internal_resources(self):
        """내부 리소스는 SRI 불필요"""
        # Given
        html = """
        <html>
        <head>
            <script src="/js/app.js"></script>
            <link rel="stylesheet" href="/css/style.css">
            <script src="./js/local.js"></script>
        </head>
        </html>
        """

        # When
        scanner = SubresourceIntegrityScanner(html_content=html)
        result = scanner.scan()

        # Then
        assert len(result['issues']) == 0, "내부 리소스는 SRI 불필요"

    @pytest.mark.unit
    def test_detect_weak_sri_hash(self):
        """약한 해시 알고리즘 사용 탐지"""
        # Given
        html = """
        <html>
        <head>
            <script
                src="https://cdn.example.com/script.js"
                integrity="sha1-abcdef123456"
                crossorigin="anonymous">
            </script>
        </head>
        </html>
        """

        # When
        scanner = SubresourceIntegrityScanner(html_content=html, url='https://mysite.com')
        result = scanner.scan()

        # Then
        weak_hash = [i for i in result['issues'] if 'Weak SRI Hash' in i['type']]
        assert len(weak_hash) > 0
        assert weak_hash[0]['hash_algorithm'] == 'sha1'

    @pytest.mark.unit
    def test_detect_missing_crossorigin(self):
        """SRI는 있지만 crossorigin 없는 경우"""
        # Given
        html = """
        <html>
        <head>
            <script
                src="https://cdn.example.com/script.js"
                integrity="sha384-abc123">
            </script>
        </head>
        </html>
        """

        # When
        scanner = SubresourceIntegrityScanner(html_content=html, url='https://mysite.com')
        result = scanner.scan()

        # Then
        missing_crossorigin = [i for i in result['issues'] if 'Missing Crossorigin' in i['type']]
        assert len(missing_crossorigin) > 0
        assert missing_crossorigin[0]['severity'] == 'low'


class TestBatch1Integration:
    """Batch 1 스캐너들의 통합 테스트"""

    @pytest.mark.unit
    def test_all_scanners_base_scanner_compatible(self):
        """모든 스캐너가 BaseScanner와 호환되는지"""
        scanners = [
            CORSScanner(headers={}),
            CookieScanner(response=Mock()),
            ClickjackingScanner(headers={}),
            SubresourceIntegrityScanner(html_content='')
        ]

        for scanner in scanners:
            # BaseScanner의 scan() 메서드 호출 가능
            result = scanner.scan()

            # 필수 필드 확인
            assert 'scanner_id' in result
            assert 'total' in result
            assert 'vulnerabilities' in result

    @pytest.mark.unit
    def test_error_handling(self):
        """에러 처리가 올바르게 되는지"""
        # 각 스캐너에 잘못된 입력
        scanners = [
            CORSScanner(headers=None),
            CookieScanner(response=None),
            ClickjackingScanner(headers=None),
            SubresourceIntegrityScanner(html_content=None)
        ]

        for scanner in scanners:
            result = scanner.scan()
            # 에러가 발생해도 결과 반환
            assert isinstance(result, dict)
            assert 'scanner_id' in result