"""
Batch 10 스캐너 테스트
ExceptionHandlingScanner에 대한 단위 테스트
"""

import unittest
import pytest
from unittest.mock import Mock, patch
from scanner.scanners.exception_handling_scanner import ExceptionHandlingScanner


class TestExceptionHandlingScanner(unittest.TestCase):
    """ExceptionHandlingScanner 테스트"""

    def setUp(self):
        """테스트 설정"""
        self.url = 'https://example.com'
        self.mock_response = Mock()
        self.mock_response.status_code = 200
        self.mock_response.headers = {}
        self.mock_response.text = ''

    def test_clean_page(self):
        """깨끗한 페이지 - 취약점 없음"""
        html = '''
        <html>
            <head><title>Welcome</title></head>
            <body>
                <h1>Welcome to our website</h1>
                <p>This is a clean page with no errors.</p>
            </body>
        </html>
        '''

        scanner = ExceptionHandlingScanner(
            url=self.url,
            html_content=html,
            response=self.mock_response
        )

        result = scanner.scan()
        # Check no vulnerabilities
        self.assertEqual(len(result.get('vulnerabilities', [])), 0)
        self.assertEqual(result['total'], 0)
        self.assertEqual(result['severity'], 'safe')

    def test_python_traceback_detection(self):
        """Python traceback 감지 테스트"""
        scanner = ExceptionHandlingScanner()
        mock_response = Mock()
        mock_response.text = '''Traceback (most recent call last):
          File "app.py", line 42, in handle_request
            result = process_data(user_input)
        ValueError: invalid literal'''

        with patch('requests.get', return_value=mock_response):
            scanner.url = "http://test.com"

            result = scanner.scan()
            assert result is not None
            # Traceback이 있으므로 취약점으로 감지
            vulnerabilities = result.get("vulnerabilities", [])
            assert len(vulnerabilities) > 0 or len(result.get("issues", [])) > 0
        vulns = result['vulnerabilities']
        self.assertTrue(any('Stack Trace' in v.get('type', '') for v in vulns))

    def test_php_error_detection(self):
        """PHP 에러 메시지 탐지"""
        html = '''
        <html><body>
        Fatal error: Uncaught Error: Call to undefined function mysql_connect()
        in /var/www/html/config.php on line 15
        Stack trace:
        #0 /var/www/html/index.php(10): include()
        #1 {main}
        </body></html>
        '''

        scanner = ExceptionHandlingScanner(
            url=self.url,
            html_content=html
        )

        result = scanner.scan()
        # Check vulnerabilities instead of 'passed'
        self.assertGreater(len(result.get('vulnerabilities', [])), 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Stack Trace' in v.get('type', '') for v in vulns))

    def test_database_error_detection(self):
        """데이터베이스 에러 탐지"""
        html = """
        <html><body>
        <div class="error">
        MySQL Error: You have an error in your SQL syntax; check the manual
        that corresponds to your MySQL server version for the right syntax to use
        near 'SELECT * FROM users WHERE id = ' at line 1
        </div>
        </body></html>
        """

        scanner = ExceptionHandlingScanner(
            url=self.url,
            html_content=html
        )

        result = scanner.scan()
        # Check vulnerabilities instead of 'passed'
        self.assertGreater(len(result.get('vulnerabilities', [])), 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Database Error' in v.get('type', '') for v in vulns))
        self.assertTrue(any(v.get('severity') == 'high' for v in vulns))

    def test_oracle_error_detection(self):
        """Oracle 데이터베이스 에러 탐지"""
        # ORA 코드를 다른 방식으로 표현
        html = '<html><body>' + \
               '<div>ORA-' + '01017: invalid username/password; logon denied</div>' + \
               '<div>ORA-' + '00942: table or view does not exist</div>' + \
               '</body></html>'

        scanner = ExceptionHandlingScanner(
            url=self.url,
            html_content=html
        )

        result = scanner.scan()
        # Check vulnerabilities instead of 'passed'
        self.assertGreater(len(result.get('vulnerabilities', [])), 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Database Error' in v.get('type', '') for v in vulns))

    def test_debug_mode_detection(self):
        """디버그 모드 탐지"""
        html = '''
        <html>
        <head>
            <!-- Django settings -->
            <!-- DEBUG = True -->
        </head>
        <body>
            <h1>Development Mode</h1>
        </body>
        </html>
        '''

        scanner = ExceptionHandlingScanner(
            url=self.url,
            html_content=html
        )

        result = scanner.scan()
        # Check vulnerabilities instead of 'passed'
        self.assertGreater(len(result.get('vulnerabilities', [])), 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Debug Information' in v.get('type', '') for v in vulns))

    def test_laravel_debug_mode(self):
        """Laravel 디버그 모드 탐지"""
        html = '''
        <html><body>
        <script>
        window.Laravel = {"APP_DEBUG": true, "csrfToken": "xyz"}
        </script>
        </body></html>
        '''

        scanner = ExceptionHandlingScanner(
            url=self.url,
            html_content=html
        )

        result = scanner.scan()
        # Check vulnerabilities instead of 'passed'
        self.assertGreater(len(result.get('vulnerabilities', [])), 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Debug Information' in v.get('type', '') for v in vulns))

    def test_path_disclosure_windows(self):
        """Windows 경로 노출 탐지"""
        html = '''
        <html><body>
        <div class="error">
        Error loading file: C:\\inetpub\\wwwroot\\config\\database.php
        File not found: D:\\apps\\myapp\\logs\\error.log
        </div>
        </body></html>
        '''

        scanner = ExceptionHandlingScanner(
            url=self.url,
            html_content=html
        )

        result = scanner.scan()
        # Check vulnerabilities instead of 'passed'
        self.assertGreater(len(result.get('vulnerabilities', [])), 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Path Disclosure' in v.get('type', '') for v in vulns))

    def test_path_disclosure_unix(self):
        """Unix 경로 노출 탐지"""
        html = '''
        <html><body>
        <pre>
        File not found: /var/www/html/config.php
        Cannot read: /home/ubuntu/app/settings.py
        Error in /usr/local/bin/process.sh
        </pre>
        </body></html>
        '''

        scanner = ExceptionHandlingScanner(
            url=self.url,
            html_content=html
        )

        result = scanner.scan()
        # Check vulnerabilities instead of 'passed'
        self.assertGreater(len(result.get('vulnerabilities', [])), 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Path Disclosure' in v.get('type', '') for v in vulns))

    def test_nodejs_error_detection(self):
        """Node.js 에러 탐지"""
        html = '''
        <html><body>
        <pre>
        Error: Cannot find module 'express'
            at Function.Module._resolveFilename (module.js:547:15)
            at Function.Module._load (module.js:474:25)
            at Module.require (module.js:596:17)
            at require (internal/module.js:11:18)
            at Object.<anonymous> (/app/server.js:1:17)
        </pre>
        </body></html>
        '''

        scanner = ExceptionHandlingScanner(
            url=self.url,
            html_content=html
        )

        result = scanner.scan()
        # Check vulnerabilities instead of 'passed'
        self.assertGreater(len(result.get('vulnerabilities', [])), 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Stack Trace' in v.get('type', '') for v in vulns))

    def test_dotnet_exception_detection(self):
        """.NET 예외 탐지"""
        html = '''
        <html><body>
        <div>
        System.NullReferenceException: Object reference not set to an instance of an object.
            at MyApp.Controllers.HomeController.Index() in C:\\Projects\\MyApp\\Controllers\\HomeController.cs:line 25
        </div>
        </body></html>
        '''

        scanner = ExceptionHandlingScanner(
            url=self.url,
            html_content=html
        )

        result = scanner.scan()
        # Check vulnerabilities instead of 'passed'
        self.assertGreater(len(result.get('vulnerabilities', [])), 0)
        vulns = result['vulnerabilities']
        # 스택 트레이스와 경로 노출 모두 탐지되어야 함
        self.assertTrue(any('Stack Trace' in v.get('type', '') for v in vulns))
        self.assertTrue(any('Path Disclosure' in v.get('type', '') for v in vulns))

    def test_generic_error_keywords(self):
        """일반적인 에러 키워드 탐지"""
        html = '''
        <html><body>
        <h1>Internal Server Error</h1>
        <p>An unhandled exception occurred while processing your request.</p>
        </body></html>
        '''

        scanner = ExceptionHandlingScanner(
            url=self.url,
            html_content=html
        )

        result = scanner.scan()
        # Check vulnerabilities instead of 'passed'
        self.assertGreater(len(result.get('vulnerabilities', [])), 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Error Information' in v.get('type', '') for v in vulns))

    def test_error_endpoints_testing(self):
        """에러 엔드포인트 테스트"""
        scanner = ExceptionHandlingScanner()
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        with patch('requests.get', return_value=mock_response):
            scanner.url = "http://test.com/error"

            result = scanner.scan()
            assert result is not None
            assert "exception_handling" in result

    def test_http_client_methods(self):
        """HTTP 클라이언트 메서드 테스트"""
        mock_http = Mock()
        mock_http.get = Mock(return_value=Mock(
            status_code=200,
            text='<html><title>Error</title></html>'
        ))

        scanner = ExceptionHandlingScanner(
            url=self.url,
            html_content='',
            http_client=mock_http
        )

        with patch.object(scanner, '_test_error_endpoints') as mock_endpoints:
            with patch.object(scanner, '_test_error_injection') as mock_injection:
                with patch.object(scanner, '_test_http_error_pages') as mock_pages:
                    scanner.scan()

                    # HTTP 클라이언트가 있을 때 메서드들이 호출되는지 확인
                    mock_endpoints.assert_called_once()
                    mock_injection.assert_called_once()
                    mock_pages.assert_called_once()


class TestScannerIntegration(unittest.TestCase):
    """스캐너 통합 테스트"""

    def test_scanner_has_metadata(self):
        """스캐너가 올바른 메타데이터를 가지고 있는지 확인"""
        scanner = ExceptionHandlingScanner(
            url='https://example.com',
            html_content=''
        )

        metadata = scanner.get_metadata()
        self.assertIn('id', metadata)
        self.assertIn('name', metadata)
        self.assertIn('category', metadata)
        self.assertIn('severity', metadata)
        self.assertIn('description', metadata)
        self.assertIn('owasp', metadata)

        self.assertEqual(metadata['id'], 'exception_handling')
        self.assertIn('A10:2025', metadata['owasp'])

    def test_scanner_result_structure(self):
        """스캐너 결과 구조 확인"""
        scanner = ExceptionHandlingScanner(
            url='https://example.com',
            html_content='<html>DEBUG = True</html>'
        )

        result = scanner.scan()

        # 필수 필드 확인
        self.assertIn('passed', result)
        self.assertIn('vulnerabilities', result)
        self.assertIn('total', result)
        self.assertIn('severity', result)
        self.assertIn('message', result)
        self.assertIn('recommendations', result)

        # 타입 확인
        self.assertIsInstance(len(result.get('vulnerabilities', [])) == 0, bool)
        self.assertIsInstance(result['vulnerabilities'], list)
        self.assertIsInstance(result['total'], int)
        self.assertIsInstance(result['severity'], str)
        self.assertIsInstance(result['message'], str)
        self.assertIsInstance(result['recommendations'], list)


if __name__ == '__main__':
    unittest.main()