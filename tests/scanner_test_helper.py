"""
테스트 헬퍼 - 스캐너 테스트를 위한 유틸리티
"""

from unittest.mock import Mock

class ScannerTestHelper:
    """스캐너 테스트 헬퍼"""

    @staticmethod
    def setup_sql_scanner_for_detection(scanner, vulnerability_type='error'):
        """SQL Injection 스캐너가 취약점을 찾도록 설정"""

        # 에러 테스트에서는 html_content를 설정하지 않음 (mock_session이 반환)
        if vulnerability_type == 'form':
            # 위험한 폼이 포함된 HTML
            scanner.html_content = """
            <form action="/search" method="GET">
                <input type="text" name="search" />
                <input type="hidden" name="id" value="123" />
            </form>
            """
        elif vulnerability_type == 'keyword':
            # SQL 키워드가 노출된 HTML
            scanner.html_content = """
            <!-- Debug: SELECT * FROM users WHERE id = 1 -->
            <div>Database query executed</div>
            """

        # URL 설정
        if vulnerability_type == 'error':
            scanner.url = 'http://test.com/page'
        else:
            scanner.url = 'http://test.com/search?id=1&search=test'

    @staticmethod
    def setup_xss_scanner_for_detection(scanner, vulnerability_type='reflected'):
        """XSS 스캐너가 취약점을 찾도록 설정"""

        if vulnerability_type == 'reflected':
            # 반사형 XSS 패턴
            scanner.html_content = """
            <div>Search result: <script>alert(1)</script></div>
            """
        elif vulnerability_type == 'dom':
            # DOM XSS 패턴
            scanner.html_content = """
            <script>
                var data = location.hash;
                document.getElementById('output').innerHTML = data;
            </script>
            """
        elif vulnerability_type == 'attribute':
            # 속성 XSS
            scanner.html_content = """
            <input type="text" value="test" onclick="alert(1)" />
            """

        # URL 설정 - XSS와 SQL 테스트를 구분
        if vulnerability_type in ['error', 'form', 'keyword', 'blind', 'time']:
            # SQL injection 관련 테스트는 URL 파라미터 체크가 우선되지 않도록
            scanner.url = 'http://test.com/page'
        else:
            # XSS 관련 테스트
            scanner.url = 'http://test.com/search?q=<script>alert(1)</script>'

    @staticmethod
    def create_vulnerable_response(vulnerability_type='sql'):
        """취약한 응답 생성"""

        response = Mock()
        response.status_code = 200
        response.headers = {}

        if vulnerability_type == 'sql':
            response.text = "Error: You have an error in your SQL syntax"
        elif vulnerability_type == 'xss':
            response.text = '<div><script>alert(1)</script></div>'
        else:
            response.text = '<div>Normal content</div>'

        response.url = 'http://test.com'
        response.elapsed = Mock()
        response.elapsed.total_seconds = Mock(return_value=0.5)

        return response
