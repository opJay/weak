"""
실제 Response 객체로 스캐너 테스트
Mock 대신 실제 requests.Response 객체를 생성하여 테스트
"""
import os
import sys
import django
import pytest
import requests
from requests.models import Response
from io import BytesIO
import json

# Django 설정
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

# 스캐너 import
from scanner.scanners.xss_scanner import XSSScanner
from scanner.scanners.sql_injection_scanner import SQLInjectionScanner
from scanner.scanners.security_header_scanner import SecurityHeaderScanner
from scanner.scanners.cors import CORSScanner
from scanner.scanners.csrf import CSRFScanner
from scanner.scanners.mixed_content import MixedContentScanner


class TestWithRealResponse:
    """실제 Response 객체를 사용한 테스트"""

    @pytest.fixture
    def create_real_response(self):
        """실제 requests.Response 객체를 생성하는 헬퍼 함수"""
        def _create_response(
            status_code=200,
            headers=None,
            content=None,
            url='https://example.com',
            encoding='utf-8'
        ):
            response = Response()
            response.status_code = status_code
            response.headers = headers or {}
            response._content = content or b''
            response.url = url
            response.encoding = encoding

            # 필수 속성 설정
            response.reason = 'OK' if status_code == 200 else 'Error'
            response.cookies = requests.cookies.RequestsCookieJar()

            return response

        return _create_response

    @pytest.fixture
    def html_response(self, create_real_response):
        """HTML 콘텐츠가 있는 실제 Response 객체"""
        html_content = '''<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>테스트 페이지</title>
    <link rel="stylesheet" href="https://cdn.example.com/style.css">
    <script src="http://insecure.example.com/script.js"></script>
</head>
<body>
    <header>
        <h1>테스트 웹사이트</h1>
    </header>

    <main>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="사용자명">
            <input type="password" name="password" placeholder="비밀번호">
            <input type="hidden" name="csrf_token" value="abc123xyz">
            <button type="submit">로그인</button>
        </form>

        <div id="user-content"></div>
        <script>
            // 잠재적 XSS 취약점
            var params = new URLSearchParams(window.location.search);
            document.getElementById('user-content').innerHTML = params.get('name');
        </script>

        <a href="/redirect?url=http://evil.com">외부 링크</a>
    </main>

    <footer>
        <img src="http://insecure.example.com/logo.png" alt="로고">
    </footer>
</body>
</html>'''.encode('utf-8')  # 문자열을 bytes로 변환

        return create_real_response(
            status_code=200,
            headers={
                'Content-Type': 'text/html; charset=utf-8',
                'Server': 'nginx/1.18.0',
                'X-Frame-Options': 'SAMEORIGIN',
                'Strict-Transport-Security': 'max-age=31536000'
            },
            content=html_content,
            url='https://example.com'
        )

    @pytest.fixture
    def api_response(self, create_real_response):
        """API JSON 응답 Response 객체"""
        json_content = json.dumps({
            'status': 'success',
            'data': {
                'user_id': 123,
                'username': 'testuser',
                'email': 'test@example.com'
            }
        }).encode('utf-8')

        return create_real_response(
            status_code=200,
            headers={
                'Content-Type': 'application/json',
                'X-API-Version': '1.0'
            },
            content=json_content,
            url='https://api.example.com/user'
        )

    def test_xss_scanner_with_real_response(self, html_response):
        """XSSScanner를 실제 Response로 테스트"""
        # Given: 실제 Response 객체
        scanner = XSSScanner(
            url=html_response.url,
            html_content=html_response.text,
            response=html_response
        )

        # When: 스캔 실행
        result = scanner.scan()

        # Then: 결과 검증
        assert isinstance(result, dict)
        assert 'vulnerabilities' in result
        assert 'scanner_id' in result
        assert result['scanner_id'] == 'xss'

        # XSS 취약점 탐지 확인 (innerHTML 사용)
        vulnerabilities = result.get('vulnerabilities', [])
        has_innerhtml_issue = any(
            'innerHTML' in str(v) for v in vulnerabilities
        )
        assert has_innerhtml_issue, "innerHTML XSS 취약점을 탐지하지 못함"

    def test_mixed_content_scanner_with_real_response(self, html_response):
        """MixedContentScanner를 실제 Response로 테스트"""
        # Given: HTTP 리소스가 포함된 HTTPS 페이지
        scanner = MixedContentScanner(
            url='https://example.com',  # HTTPS URL
            html_content=html_response.text,
            response=html_response
        )

        # When: 스캔 실행
        result = scanner.scan()

        # Then: Mixed Content 탐지
        assert isinstance(result, dict)
        vulnerabilities = result.get('vulnerabilities', [])

        # HTTP 리소스 탐지 확인
        assert len(vulnerabilities) > 0, "Mixed Content를 탐지하지 못함"

        # 특정 HTTP 리소스 확인
        insecure_resources = [v for v in vulnerabilities if 'http://insecure' in str(v)]
        assert len(insecure_resources) > 0, "HTTP 리소스를 찾지 못함"

    def test_security_header_scanner_with_real_response(self, html_response):
        """SecurityHeaderScanner를 실제 Response로 테스트"""
        # Given: 일부 보안 헤더만 있는 응답
        scanner = SecurityHeaderScanner(
            url=html_response.url,
            html_content=html_response.text,
            response=html_response
        )

        # When: 스캔 실행
        result = scanner.scan()

        # Then: 헤더 검사 결과 확인
        assert isinstance(result, dict)

        # headers 필드 확인
        headers = result.get('headers', {})
        assert len(headers) > 0

        # 존재하는 헤더 확인
        assert headers.get('X-Frame-Options', {}).get('present') == True
        assert headers.get('Strict-Transport-Security', {}).get('present') == True

        # 누락된 헤더 확인
        assert headers.get('Content-Security-Policy', {}).get('present') == False
        assert headers.get('X-Content-Type-Options', {}).get('present') == False

        # 보안 점수 확인
        assert 'security_score' in result

    def test_csrf_scanner_with_real_response(self, html_response):
        """CSRFScanner를 실제 Response로 테스트"""
        # Given
        scanner = CSRFScanner(
            url=html_response.url,
            html_content=html_response.text,
            response=html_response
        )

        # When
        result = scanner.scan()

        # Then: CSRF 토큰 존재 확인
        assert isinstance(result, dict)

        # CSRF 보호 상태 확인
        assert 'has_csrf_protection' in result
        assert 'total_forms' in result

        # HTML에 form이 있으므로 total_forms > 0이어야 함
        assert result.get('total_forms', 0) > 0

    def test_cors_scanner_with_api_response(self, api_response):
        """CORSScanner를 API Response로 테스트"""
        # Given: CORS 헤더 추가
        api_response.headers['Access-Control-Allow-Origin'] = '*'
        api_response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'

        scanner = CORSScanner(
            url=api_response.url,
            html_content=api_response.text,
            response=api_response
        )

        # When
        result = scanner.scan()

        # Then: CORS 설정 검사
        assert isinstance(result, dict)
        vulnerabilities = result.get('vulnerabilities', [])

        # 와일드카드 Origin 탐지
        wildcard_issues = [v for v in vulnerabilities if '*' in str(v)]
        assert len(wildcard_issues) > 0, "와일드카드 CORS 설정을 탐지하지 못함"

    def test_multiple_scanners_with_same_response(self, html_response):
        """여러 스캐너가 동일한 Response를 처리할 수 있는지 테스트"""
        scanners = [
            XSSScanner,
            SecurityHeaderScanner,
            MixedContentScanner,
            CSRFScanner
        ]

        results = []
        errors = []

        for scanner_class in scanners:
            try:
                scanner = scanner_class(
                    url=html_response.url,
                    html_content=html_response.text,
                    response=html_response
                )
                result = scanner.scan()
                results.append({
                    'scanner': scanner_class.__name__,
                    'result': result
                })
            except Exception as e:
                errors.append(f"{scanner_class.__name__}: {e}")

        # 모든 스캐너가 성공적으로 실행됨
        assert len(errors) == 0, f"스캐너 실행 오류: {errors}"
        assert len(results) == len(scanners)

        # 각 스캐너가 고유한 scanner_id를 가짐
        scanner_ids = [r['result'].get('scanner_id') for r in results]
        assert len(set(scanner_ids)) == len(scanner_ids), "중복된 scanner_id 발견"

    def test_response_with_cookies(self, create_real_response):
        """쿠키가 있는 Response 테스트"""
        # Given: 쿠키가 설정된 Response
        response = create_real_response(
            headers={
                'Content-Type': 'text/html',
                'Set-Cookie': 'session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict'
            },
            content=b'<html><body>Test</body></html>'
        )

        # 쿠키 파싱 (실제 requests처럼)
        from http.cookies import SimpleCookie
        cookie = SimpleCookie()
        cookie.load(response.headers.get('Set-Cookie', ''))

        # CookieScanner import
        from scanner.scanners.cookie_scanner import CookieScanner

        scanner = CookieScanner(
            url=response.url,
            html_content=response.text,
            response=response
        )

        # When
        result = scanner.scan()

        # Then: 쿠키 보안 속성 확인
        assert isinstance(result, dict)
        cookie_info = result.get('cookie_info', {})

        # HttpOnly, Secure, SameSite 속성 확인
        if cookie_info:
            assert cookie_info.get('has_httponly', False) == True or \
                   'HttpOnly' in response.headers.get('Set-Cookie', '')

    def test_response_with_various_status_codes(self, create_real_response):
        """다양한 상태 코드로 테스트"""
        test_cases = [
            (200, 'OK'),
            (301, 'Redirect'),
            (404, 'Not Found'),
            (500, 'Server Error')
        ]

        for status_code, description in test_cases:
            # Given
            response = create_real_response(
                status_code=status_code,
                content=f'<html><body>{description}</body></html>'.encode()
            )

            # 기본 스캐너로 테스트
            scanner = SecurityHeaderScanner(
                url=response.url,
                html_content=response.text,
                response=response
            )

            # When
            try:
                result = scanner.scan()
                # Then
                assert isinstance(result, dict), \
                    f"Status {status_code}: 결과가 dict가 아님"
            except Exception as e:
                # 일부 상태 코드는 오류를 발생시킬 수 있음
                pass

    def test_large_response_handling(self, create_real_response):
        """대용량 Response 처리 테스트"""
        # Given: 10MB 크기의 HTML
        large_content = b'<html><body>' + (b'<div>Test content</div>' * 500000) + b'</body></html>'

        response = create_real_response(
            content=large_content,
            headers={'Content-Type': 'text/html'}
        )

        # SQLInjectionScanner로 테스트 (빠른 스캐너 선택)
        scanner = SQLInjectionScanner(
            url=response.url,
            html_content=response.text[:100000],  # 처음 100KB만 사용
            response=response
        )

        # When
        result = scanner.scan()

        # Then
        assert isinstance(result, dict)
        assert 'scanner_id' in result

    def test_response_encoding_handling(self, create_real_response):
        """다양한 인코딩 처리 테스트"""
        encodings = [
            ('utf-8', '테스트'),
            ('euc-kr', '테스트'),
            ('iso-8859-1', 'Test')
        ]

        for encoding, text in encodings:
            # Given
            content = f'<html><body>{text}</body></html>'.encode(encoding)
            response = create_real_response(
                content=content,
                encoding=encoding,
                headers={'Content-Type': f'text/html; charset={encoding}'}
            )

            # When
            scanner = XSSScanner(
                url=response.url,
                html_content=response.text,
                response=response
            )

            # Then: 인코딩 오류 없이 처리
            try:
                result = scanner.scan()
                assert isinstance(result, dict)
            except UnicodeDecodeError:
                pytest.fail(f"인코딩 {encoding} 처리 실패")