"""
Batch 2 스캐너들의 유닛 테스트
- XSSScanner
- SQLInjectionScanner
- CSRFScanner
- InformationDisclosureScanner
- MixedContentScanner

탐지 정확도 중심 테스트 (True Positive, False Positive, False Negative)
"""

import pytest
from unittest.mock import Mock, MagicMock

# 프로젝트 루트를 Python 경로에 추가
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanner.scanners.xss_scanner import XSSScanner
from scanner.scanners.sql_injection_scanner import SQLInjectionScanner
from scanner.scanners.csrf import CSRFScanner
from scanner.scanners.information_disclosure import InformationDisclosureScanner
from scanner.scanners.mixed_content import MixedContentScanner


class TestXSSScanner:
    """XSSScanner 탐지 능력 검증"""

    @pytest.mark.unit
    def test_detect_reflected_xss_in_html(self):
        """Reflected XSS - URL 파라미터가 이스케이프 없이 출력"""
        # Given
        url = 'https://example.com/search?q=<script>alert(1)</script>'
        html = '''
        <html>
        <body>
            <h1>Search results for: <script>alert(1)</script></h1>
        </body>
        </html>
        '''

        # When
        scanner = XSSScanner(url=url, html_content=html)
        result = scanner.scan()

        # Then
        assert len(result['vulnerabilities']) > 0, "Reflected XSS를 탐지해야 함"
        xss_issues = [v for v in result['vulnerabilities'] if 'Reflected XSS' in v['type']]
        assert len(xss_issues) > 0
        assert xss_issues[0]['severity'] == 'high'
        assert xss_issues[0]['parameter'] == 'q'

    @pytest.mark.unit
    def test_detect_dom_xss_pattern(self):
        """DOM-based XSS - 위험한 sink와 source 조합"""
        # Given
        html = '''
        <html>
        <script>
            var userInput = location.hash;
            document.getElementById('output').innerHTML = userInput;
        </script>
        </html>
        '''

        # When
        scanner = XSSScanner(url='http://test.com', html_content=html)
        result = scanner.scan()

        # Then
        dom_xss = [v for v in result['vulnerabilities'] if 'DOM-based XSS' in v['type']]
        assert len(dom_xss) > 0, "DOM XSS 패턴을 탐지해야 함"
        assert dom_xss[0]['severity'] == 'high'
        assert 'innerHTML' in dom_xss[0]['sink']

    @pytest.mark.unit
    def test_detect_event_handlers(self):
        """이벤트 핸들러를 통한 XSS 가능성"""
        # Given
        html = '''
        <html>
        <body>
            <img src="x" onerror="alert('XSS')">
            <div onclick="eval(userInput)">Click me</div>
        </body>
        </html>
        '''

        # When
        scanner = XSSScanner(url='http://test.com', html_content=html)
        result = scanner.scan()

        # Then
        assert len(result['vulnerabilities']) > 0
        event_handler_issues = [v for v in result['vulnerabilities'] if 'event handler' in v.get('pattern', '')]
        assert len(event_handler_issues) > 0

    @pytest.mark.unit
    def test_no_false_positive_escaped_content(self):
        """이스케이프된 콘텐츠는 XSS로 보고하지 않음"""
        # Given
        url = 'https://example.com/search?q=<script>test</script>'
        html = '''
        <html>
        <body>
            <h1>Search: &lt;script&gt;test&lt;/script&gt;</h1>
        </body>
        </html>
        '''

        # When
        scanner = XSSScanner(url=url, html_content=html)
        result = scanner.scan()

        # Then
        reflected_xss = [v for v in result['vulnerabilities'] if 'Reflected XSS' in v['type'] and v.get('parameter') == 'q']
        assert len(reflected_xss) == 0, "이스케이프된 콘텐츠는 XSS가 아님"

    @pytest.mark.unit
    def test_detect_missing_csp_header(self):
        """CSP 헤더 누락 탐지"""
        # Given
        response = Mock()
        response.headers = {}
        response.text = '<html><body>Content</body></html>'

        # When
        scanner = XSSScanner(response=response)
        result = scanner.scan()

        # Then
        csp_issues = [v for v in result['vulnerabilities'] if 'Missing CSP' in v['type']]
        assert len(csp_issues) > 0
        assert csp_issues[0]['severity'] == 'medium'

    @pytest.mark.unit
    def test_detect_weak_csp_unsafe_inline(self):
        """약한 CSP (unsafe-inline) 탐지"""
        # Given
        response = Mock()
        response.headers = {'Content-Security-Policy': "default-src 'self' 'unsafe-inline'"}
        response.text = '<html><body>Content</body></html>'

        # When
        scanner = XSSScanner(response=response)
        result = scanner.scan()

        # Then
        weak_csp = [v for v in result['vulnerabilities'] if 'CSP Bypass Risk' in v['type']]
        assert len(weak_csp) > 0
        assert 'unsafe-inline' in weak_csp[0]['description']


class TestSQLInjectionScanner:
    """SQLInjectionScanner 탐지 능력 검증"""

    @pytest.mark.unit
    def test_detect_sql_error_messages(self):
        """SQL 에러 메시지 노출 탐지"""
        # Given
        html = '''
        <html>
        <body>
            <div class="error">
                MySQL Error: You have an error in your SQL syntax near WHERE id= at line 1
            </div>
        </body>
        </html>
        '''

        # When
        scanner = SQLInjectionScanner(url='http://test.com', html_content=html)
        result = scanner.scan()

        # Then
        assert len(result['vulnerabilities']) > 0
        error_exposure = [v for v in result['vulnerabilities'] if 'SQL Error Exposure' in v['type']]
        assert len(error_exposure) > 0
        assert error_exposure[0]['severity'] == 'critical'

    @pytest.mark.unit
    def test_detect_suspicious_url_parameters(self):
        """의심스러운 URL 파라미터 탐지"""
        # Given
        url = "https://example.com/product?id=123&user_id=456"

        # When
        scanner = SQLInjectionScanner(url=url)
        result = scanner.scan()

        # Then
        param_issues = [v for v in result['vulnerabilities'] if 'SQL Injection Risk' in v['type']]
        assert len(param_issues) > 0
        # id, user_id 같은 숫자 파라미터는 위험
        assert any('id' in v['parameter'] for v in param_issues)

    @pytest.mark.unit
    def test_detect_form_with_search_field(self):
        """검색 폼의 SQL Injection 위험"""
        # Given
        html = '''
        <html>
        <body>
            <form method="GET" action="/search">
                <input type="text" name="search" placeholder="Search products...">
                <input type="hidden" name="category_id" value="1">
                <button type="submit">Search</button>
            </form>
        </body>
        </html>
        '''

        # When
        scanner = SQLInjectionScanner(url='http://test.com', html_content=html)
        result = scanner.scan()

        # Then
        form_risks = [v for v in result['vulnerabilities'] if 'Form SQL Injection Risk' in v['type']]
        assert len(form_risks) > 0
        assert form_risks[0]['method'] == 'GET'
        assert any('search' in input['name'] for input in form_risks[0]['risky_inputs'])

    @pytest.mark.unit
    def test_detect_sql_keywords_in_html(self):
        """HTML에 SQL 키워드 노출 탐지"""
        # Given
        html = '''
        <html>
        <!-- Debug: SELECT * FROM users WHERE id=123 -->
        <body>
            <div>Welcome user</div>
        </body>
        </html>
        '''

        # When
        scanner = SQLInjectionScanner(url='http://test.com', html_content=html)
        result = scanner.scan()

        # Then
        sql_in_comments = [v for v in result['vulnerabilities'] if 'SQL Query in Comments' in v['type']]
        assert len(sql_in_comments) > 0
        assert sql_in_comments[0]['severity'] == 'medium'

    @pytest.mark.unit
    def test_no_false_positive_safe_forms(self):
        """안전한 폼은 문제로 보고하지 않음"""
        # Given
        html = '''
        <html>
        <body>
            <form method="POST" action="/submit">
                <input type="email" name="email" pattern="[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$">
                <input type="text" name="name" maxlength="50" pattern="[A-Za-z ]+">
                <button type="submit">Submit</button>
            </form>
        </body>
        </html>
        '''

        # When
        scanner = SQLInjectionScanner(url='http://test.com', html_content=html)
        result = scanner.scan()

        # Then
        # pattern이 있는 필드는 덜 위험하므로 낮은 심각도여야 함
        high_severity = [v for v in result['vulnerabilities'] if v.get('severity') in ['critical', 'high']]
        assert len(high_severity) == 0, "검증이 있는 폼은 높은 위험으로 표시하지 않음"


class TestCSRFScanner:
    """CSRFScanner 탐지 능력 검증"""

    @pytest.mark.unit
    def test_detect_missing_csrf_token_in_form(self):
        """POST 폼에 CSRF 토큰 누락 탐지"""
        # Given
        html = '''
        <html>
        <body>
            <form method="POST" action="/transfer">
                <input type="text" name="account" value="">
                <input type="number" name="amount" value="">
                <button type="submit">Transfer</button>
            </form>
        </body>
        </html>
        '''

        # When
        scanner = CSRFScanner(html_content=html)
        result = scanner.scan()

        # Then
        assert len(result['vulnerabilities']) > 0
        missing_token = [v for v in result['vulnerabilities'] if 'Missing CSRF Token' in v['type']]
        assert len(missing_token) > 0
        assert missing_token[0]['severity'] in ['high', 'critical']
        assert missing_token[0]['method'] == 'POST'

    @pytest.mark.unit
    def test_no_false_positive_with_csrf_token(self):
        """CSRF 토큰이 있는 폼은 안전"""
        # Given
        html = '''
        <html>
        <body>
            <form method="POST" action="/update">
                <input type="hidden" name="csrf_token" value="abc123xyz789">
                <input type="text" name="username">
                <button type="submit">Update</button>
            </form>
        </body>
        </html>
        '''

        # When
        scanner = CSRFScanner(html_content=html)
        result = scanner.scan()

        # Then
        missing_token = [v for v in result['vulnerabilities'] if 'Missing CSRF Token' in v['type']]
        assert len(missing_token) == 0, "CSRF 토큰이 있으면 안전"

    @pytest.mark.unit
    def test_detect_empty_csrf_token(self):
        """빈 CSRF 토큰 필드 탐지"""
        # Given
        html = '''
        <html>
        <body>
            <form method="POST" action="/delete">
                <input type="hidden" name="csrf_token" value="">
                <input type="hidden" name="item_id" value="123">
                <button type="submit">Delete</button>
            </form>
        </body>
        </html>
        '''

        # When
        scanner = CSRFScanner(html_content=html)
        result = scanner.scan()

        # Then
        empty_token = [v for v in result['vulnerabilities'] if 'Empty CSRF Token' in v['type']]
        assert len(empty_token) > 0
        assert empty_token[0]['severity'] == 'high'

    @pytest.mark.unit
    def test_detect_sensitive_action_without_protection(self):
        """민감한 작업에 CSRF 보호 없음"""
        # Given
        html = '''
        <html>
        <body>
            <form method="POST" action="/change-password">
                <input type="password" name="new_password">
                <input type="password" name="confirm_password">
                <button type="submit">Change Password</button>
            </form>
        </body>
        </html>
        '''

        # When
        scanner = CSRFScanner(html_content=html)
        result = scanner.scan()

        # Then
        issues = result['vulnerabilities']
        assert len(issues) > 0
        password_form_issue = [v for v in issues if 'password' in v.get('action', '')]
        assert len(password_form_issue) > 0
        assert password_form_issue[0]['is_sensitive'] == True
        assert password_form_issue[0]['severity'] == 'critical'

    @pytest.mark.unit
    def test_get_forms_not_flagged_for_csrf(self):
        """GET 폼은 CSRF 검사 대상 아님"""
        # Given
        html = '''
        <html>
        <body>
            <form method="GET" action="/search">
                <input type="text" name="q">
                <button type="submit">Search</button>
            </form>
        </body>
        </html>
        '''

        # When
        scanner = CSRFScanner(html_content=html)
        result = scanner.scan()

        # Then
        # GET 메서드는 상태 변경이 아니므로 CSRF 이슈 없음
        assert len(result['vulnerabilities']) == 0


class TestInformationDisclosureScanner:
    """InformationDisclosureScanner 탐지 능력 검증"""

    @pytest.mark.unit
    def test_detect_php_error_with_path(self):
        """PHP 에러 메시지와 경로 노출 탐지"""
        # Given
        html = '''
        <html>
        <body>
            Fatal error: Uncaught Exception in /var/www/html/app/controllers/UserController.php on line 42
        </body>
        </html>
        '''

        # When
        scanner = InformationDisclosureScanner(html_content=html)
        result = scanner.scan()

        # Then
        assert len(result['vulnerabilities']) > 0
        php_error = [v for v in result['vulnerabilities'] if 'PHP Fatal Error' in v.get('info_type', '')]
        assert len(php_error) > 0
        assert php_error[0]['severity'] == 'high'

    @pytest.mark.unit
    def test_detect_api_key_exposure(self):
        """API 키 노출 탐지"""
        # Given
        html = '''
        <html>
        <script>
            var config = {
                api_key: "sk_test_fake1234567890abcdefghijklmnop",
                endpoint: "https://api.example.com"
            };
        </script>
        </html>
        '''

        # When
        scanner = InformationDisclosureScanner(html_content=html)
        result = scanner.scan()

        # Then
        api_key_issues = [v for v in result['vulnerabilities'] if 'API Key' in v.get('info_type', '')]
        assert len(api_key_issues) > 0
        assert api_key_issues[0]['severity'] == 'critical'

    @pytest.mark.unit
    def test_detect_internal_ip_address(self):
        """내부 IP 주소 노출 탐지"""
        # Given
        html = '''
        <html>
        <body>
            <!-- Server: 192.168.1.100 -->
            <div>Connected to database at 10.0.0.5:3306</div>
        </body>
        </html>
        '''

        # When
        scanner = InformationDisclosureScanner(html_content=html)
        result = scanner.scan()

        # Then
        ip_issues = [v for v in result['vulnerabilities'] if 'Internal IP' in v.get('info_type', '')]
        assert len(ip_issues) > 0
        assert ip_issues[0]['severity'] == 'medium'

    @pytest.mark.unit
    def test_detect_server_headers(self):
        """서버 정보 노출 헤더 탐지"""
        # Given
        headers = {
            'Server': 'Apache/2.4.41 (Ubuntu)',
            'X-Powered-By': 'PHP/7.4.3'
        }

        # When
        scanner = InformationDisclosureScanner(headers=headers)
        result = scanner.scan()

        # Then
        header_issues = [v for v in result['vulnerabilities'] if 'Header Information Disclosure' in v['type']]
        assert len(header_issues) >= 2
        assert any('Server' in v['header'] for v in header_issues)
        assert any('X-Powered-By' in v['header'] for v in header_issues)

    @pytest.mark.unit
    def test_detect_debug_mode(self):
        """디버그 모드 활성화 탐지"""
        # Given
        html = '''
        <html>
        <script>
            var DEBUG = true;
            var ENV = 'development';
        </script>
        </html>
        '''

        # When
        scanner = InformationDisclosureScanner(html_content=html)
        result = scanner.scan()

        # Then
        debug_issues = [v for v in result['vulnerabilities'] if 'Debug Mode' in v['type']]
        assert len(debug_issues) > 0
        assert debug_issues[0]['severity'] == 'high'

    @pytest.mark.unit
    def test_no_false_positive_placeholder_api_keys(self):
        """플레이스홀더 API 키는 무시"""
        # Given
        html = '''
        <html>
        <script>
            var config = {
                api_key: "your-api-key-here",
                secret: "xxxx-xxxx-xxxx-xxxx"
            };
        </script>
        </html>
        '''

        # When
        scanner = InformationDisclosureScanner(html_content=html)
        result = scanner.scan()

        # Then
        # 플레이스홀더는 무시되어야 함
        api_issues = [v for v in result['vulnerabilities'] if 'API' in v.get('info_type', '')]
        assert len(api_issues) == 0, "플레이스홀더는 보고하지 않음"


class TestMixedContentScanner:
    """MixedContentScanner 탐지 능력 검증"""

    @pytest.mark.unit
    def test_detect_http_script_in_https_page(self):
        """HTTPS 페이지의 HTTP 스크립트 탐지 (Critical)"""
        # Given
        url = 'https://secure.example.com'
        html = '''
        <html>
        <head>
            <script src="http://cdn.example.com/jquery.js"></script>
        </head>
        </html>
        '''

        # When
        scanner = MixedContentScanner(url=url, html_content=html)
        result = scanner.scan()

        # Then
        assert result['has_mixed_content'] == True
        script_issues = [v for v in result['vulnerabilities'] if v.get('tag') == 'script']
        assert len(script_issues) > 0
        assert script_issues[0]['severity'] == 'high'
        assert script_issues[0]['category'] == 'blockable'

    @pytest.mark.unit
    def test_detect_http_image_in_https_page(self):
        """HTTPS 페이지의 HTTP 이미지 탐지 (Medium)"""
        # Given
        url = 'https://secure.example.com'
        html = '''
        <html>
        <body>
            <img src="http://images.example.com/logo.png" alt="Logo">
        </body>
        </html>
        '''

        # When
        scanner = MixedContentScanner(url=url, html_content=html)
        result = scanner.scan()

        # Then
        assert result['has_mixed_content'] == True
        img_issues = [v for v in result['vulnerabilities'] if v.get('tag') == 'img']
        assert len(img_issues) > 0
        assert img_issues[0]['severity'] == 'medium'
        assert img_issues[0]['category'] == 'optionally-blockable'

    @pytest.mark.unit
    def test_detect_http_form_action(self):
        """HTTPS 페이지에서 HTTP로 폼 전송 탐지 (Critical)"""
        # Given
        url = 'https://secure.example.com'
        html = '''
        <html>
        <body>
            <form method="POST" action="http://insecure.example.com/submit">
                <input type="password" name="password">
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
        '''

        # When
        scanner = MixedContentScanner(url=url, html_content=html)
        result = scanner.scan()

        # Then
        form_issues = [v for v in result['vulnerabilities'] if 'Form Submission' in v['type']]
        assert len(form_issues) > 0
        assert form_issues[0]['severity'] == 'critical'  # POST + HTTP = Critical
        assert form_issues[0]['method'] == 'POST'

    @pytest.mark.unit
    def test_no_scan_on_http_page(self):
        """HTTP 페이지에서는 Mixed Content 검사 안 함"""
        # Given
        url = 'http://example.com'
        html = '''
        <html>
        <head>
            <script src="http://cdn.example.com/script.js"></script>
        </head>
        </html>
        '''

        # When
        scanner = MixedContentScanner(url=url, html_content=html)
        result = scanner.scan()

        # Then
        assert result.get('scan_skipped') == True
        assert result.get('is_https') == False
        assert len(result['vulnerabilities']) == 0

    @pytest.mark.unit
    def test_no_false_positive_https_resources(self):
        """HTTPS 리소스는 문제 없음"""
        # Given
        url = 'https://secure.example.com'
        html = '''
        <html>
        <head>
            <script src="https://cdn.example.com/jquery.js"></script>
            <link rel="stylesheet" href="https://cdn.example.com/style.css">
        </head>
        <body>
            <img src="https://images.example.com/logo.png">
        </body>
        </html>
        '''

        # When
        scanner = MixedContentScanner(url=url, html_content=html)
        result = scanner.scan()

        # Then
        assert result['has_mixed_content'] == False
        assert len(result['vulnerabilities']) == 0

    @pytest.mark.unit
    def test_no_false_positive_relative_urls(self):
        """상대 URL은 문제 없음"""
        # Given
        url = 'https://secure.example.com'
        html = '''
        <html>
        <head>
            <script src="/js/app.js"></script>
            <link rel="stylesheet" href="/css/style.css">
        </head>
        <body>
            <img src="images/logo.png">
            <a href="/about">About</a>
        </body>
        </html>
        '''

        # When
        scanner = MixedContentScanner(url=url, html_content=html)
        result = scanner.scan()

        # Then
        assert result['has_mixed_content'] == False
        assert len(result['vulnerabilities']) == 0

    @pytest.mark.unit
    def test_detect_inline_style_http_url(self):
        """인라인 스타일의 HTTP URL 탐지"""
        # Given
        url = 'https://secure.example.com'
        html = '''
        <html>
        <body>
            <div style="background-image: url('http://images.example.com/bg.jpg')">Content</div>
        </body>
        </html>
        '''

        # When
        scanner = MixedContentScanner(url=url, html_content=html)
        result = scanner.scan()

        # Then
        style_issues = [v for v in result['vulnerabilities'] if 'Inline Style' in v['type']]
        assert len(style_issues) > 0
        assert style_issues[0]['severity'] == 'medium'

    @pytest.mark.unit
    def test_ignore_localhost_http(self):
        """localhost HTTP는 무시 (개발 환경)"""
        # Given
        url = 'https://secure.example.com'
        html = '''
        <html>
        <head>
            <script src="http://localhost:3000/dev.js"></script>
            <script src="http://127.0.0.1:8080/test.js"></script>
        </head>
        </html>
        '''

        # When
        scanner = MixedContentScanner(url=url, html_content=html)
        result = scanner.scan()

        # Then
        assert result['has_mixed_content'] == False
        assert len(result['vulnerabilities']) == 0


class TestBatch2Integration:
    """Batch 2 스캐너들의 통합 테스트"""

    @pytest.mark.unit
    def test_all_scanners_base_scanner_compatible(self):
        """모든 스캐너가 BaseScanner와 호환되는지"""
        scanners = [
            XSSScanner(url='http://test.com', html_content='<html></html>'),
            SQLInjectionScanner(url='http://test.com', html_content='<html></html>'),
            CSRFScanner(html_content='<html></html>'),
            InformationDisclosureScanner(html_content='<html></html>'),
            MixedContentScanner(url='https://example.com', html_content='<html></html>')
        ]

        for scanner in scanners:
            # BaseScanner의 scan() 메서드 호출 가능
            result = scanner.scan()

            # 필수 필드 확인
            assert 'scanner_id' in result
            assert 'total' in result
            assert 'vulnerabilities' in result
            assert isinstance(result['vulnerabilities'], list)

    @pytest.mark.unit
    def test_comprehensive_vulnerable_page(self):
        """여러 취약점이 있는 페이지 종합 테스트"""
        # Given: 여러 취약점이 있는 HTML
        url = 'https://vulnerable.example.com/search?id=1&q=test'
        html = '''
        <html>
        <head>
            <script src="http://cdn.example.com/jquery.js"></script>
        </head>
        <body>
            <!-- Debug: SELECT * FROM users WHERE id=1 -->
            <div class="error">MySQL Error: syntax error near 'WHERE'</div>

            <h1>Search: <script>alert('XSS')</script></h1>

            <form method="POST" action="/transfer">
                <input type="text" name="amount">
                <button>Transfer</button>
            </form>

            <script>
                var API_KEY = "sk_test_fake9876543210zyxwvutsrqpon";
                var userInput = location.hash;
                document.getElementById('output').innerHTML = userInput;
            </script>

            Fatal error: in /var/www/app.php on line 42
        </body>
        </html>
        '''

        # When: 모든 스캐너 실행
        xss_scanner = XSSScanner(url=url, html_content=html)
        sql_scanner = SQLInjectionScanner(url=url, html_content=html)
        csrf_scanner = CSRFScanner(html_content=html)
        info_scanner = InformationDisclosureScanner(html_content=html)
        mixed_scanner = MixedContentScanner(url=url, html_content=html)

        xss_result = xss_scanner.scan()
        sql_result = sql_scanner.scan()
        csrf_result = csrf_scanner.scan()
        info_result = info_scanner.scan()
        mixed_result = mixed_scanner.scan()

        # Then: 각 스캐너가 해당 취약점을 탐지
        assert xss_result['total'] > 0, "XSS 취약점 탐지"
        assert sql_result['total'] > 0, "SQL Injection 취약점 탐지"
        assert csrf_result['total'] > 0, "CSRF 취약점 탐지"
        assert info_result['total'] > 0, "정보 노출 탐지"
        assert mixed_result['total'] > 0, "Mixed Content 탐지"

    @pytest.mark.unit
    def test_clean_secure_page(self):
        """안전한 페이지에서 오탐(False Positive) 없음"""
        # Given: 안전한 HTML
        url = 'https://secure.example.com'
        html = '''
        <html>
        <head>
            <meta name="csrf-token" content="abc123">
            <script src="https://cdn.example.com/jquery.min.js"
                    integrity="sha384-abc123" crossorigin="anonymous"></script>
        </head>
        <body>
            <h1>Welcome</h1>
            <form method="POST" action="/update">
                <input type="hidden" name="csrf_token" value="abc123">
                <input type="text" name="name" maxlength="50" pattern="[A-Za-z ]+">
                <button type="submit">Update</button>
            </form>
        </body>
        </html>
        '''

        response = Mock()
        response.headers = {
            'Content-Security-Policy': "default-src 'self'; script-src 'self'",
            'X-Content-Type-Options': 'nosniff'
        }
        response.text = html

        # When
        xss_scanner = XSSScanner(url=url, response=response)
        csrf_scanner = CSRFScanner(html_content=html)
        mixed_scanner = MixedContentScanner(url=url, html_content=html)

        xss_result = xss_scanner.scan()
        csrf_result = csrf_scanner.scan()
        mixed_result = mixed_scanner.scan()

        # Then: 중요한 취약점 없음
        xss_critical = [v for v in xss_result['vulnerabilities'] if v.get('severity') in ['critical', 'high']]
        csrf_critical = [v for v in csrf_result['vulnerabilities'] if v.get('severity') in ['critical', 'high']]

        assert len(xss_critical) == 0, "안전한 페이지에서 XSS 오탐 없음"
        assert len(csrf_critical) == 0, "CSRF 토큰이 있으면 안전"
        assert mixed_result['has_mixed_content'] == False, "HTTPS 리소스만 사용"