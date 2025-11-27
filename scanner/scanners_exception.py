"""
Exception Handling Security Scanner
OWASP Top 10 2025 A10: Mishandling of Exceptional Conditions 대응
"""
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging

logger = logging.getLogger('scanner')


class ExceptionHandlingScanner:
    """
    예외 처리 보안 스캐너

    OWASP Top 10 2025 A10: Mishandling of Exceptional Conditions 대응
    - 스택 트레이스 노출 탐지
    - 상세 에러 메시지 노출 탐지
    - 기본 에러 페이지 노출 탐지
    - Exception 정보 유출 탐지
    """

    metadata = {
        'id': 'exception_handling',
        'name': 'Exception Handling 보안 검사',
        'icon': '⚠️',
        'description': '예외 처리 오류 및 에러 정보 노출 탐지',
        'weight': 1.5,
        'field': 'exception_handling_vulnerabilities'
    }

    # 스택 트레이스 패턴
    STACK_TRACE_PATTERNS = [
        # Python
        (r'Traceback \(most recent call last\):', 'Python Traceback'),
        (r'File ".*\.py", line \d+', 'Python Stack Trace'),
        (r'raise \w+Error:', 'Python Exception'),
        # Java
        (r'Exception in thread ".*"', 'Java Exception'),
        (r'at [\w\.$]+\(.*\.java:\d+\)', 'Java Stack Trace'),
        (r'Caused by: [\w\.]+:', 'Java Caused By'),
        (r'javax\.servlet\..*Exception', 'Java Servlet Exception'),
        # .NET/C#
        (r'System\..*Exception:', '.NET Exception'),
        (r'at .*\.cs:line \d+', 'C# Stack Trace'),
        (r'\[.*Exception: .*\]', '.NET Exception Detail'),
        # PHP
        (r'Fatal error:.*in .*\.php on line \d+', 'PHP Fatal Error'),
        (r'Warning:.*in .*\.php on line \d+', 'PHP Warning'),
        (r'Parse error:.*in .*\.php on line \d+', 'PHP Parse Error'),
        (r'Call Stack:.*#\d+ .*\.php\(\d+\)', 'PHP Call Stack'),
        # Ruby
        (r'.*\.rb:\d+:in `.*\'', 'Ruby Stack Trace'),
        (r'from .*\.rb:\d+:in `.*\'', 'Ruby Traceback'),
        # Node.js/JavaScript
        (r'Error: .*\n\s+at .*\.js:\d+:\d+', 'Node.js Stack Trace'),
        (r'at Object\.<anonymous> \(.*\.js:\d+:\d+\)', 'Node.js Error'),
        # ASP.NET
        (r'Server Error in \'\/\' Application', 'ASP.NET Error'),
        (r'Description: An unhandled exception', 'ASP.NET Unhandled Exception'),
    ]

    # 데이터베이스 에러 패턴
    DATABASE_ERROR_PATTERNS = [
        (r'SQL syntax.*MySQL', 'MySQL Syntax Error'),
        (r'PostgreSQL.*ERROR', 'PostgreSQL Error'),
        (r'ORA-\d{5}', 'Oracle Error'),
        (r'Microsoft SQL Server.*error', 'SQL Server Error'),
        (r'SQLite.*Error', 'SQLite Error'),
        (r'MongoDB.*Error', 'MongoDB Error'),
    ]

    # 개발 모드 / 디버그 정보
    DEBUG_INFO_PATTERNS = [
        (r'DEBUG = True', 'Django Debug Mode'),
        (r'APP_DEBUG.*true', 'Laravel Debug Mode'),
        (r'development mode', 'Development Mode'),
        (r'<title>Error</title>', 'Generic Error Page'),
        (r'X-Debug-Token', 'Symfony Debug Token'),
    ]

    # 내부 경로 노출
    PATH_DISCLOSURE_PATTERNS = [
        (r'[C-Z]:\\[\w\\]+', 'Windows Path'),
        (r'/(?:var|home|usr|opt)/[\w/]+', 'Unix Path'),
        (r'/Users/[\w/]+', 'macOS Path'),
    ]

    def __init__(self, url, response=None, html_content=None):
        """
        초기화

        Args:
            url: 스캔할 URL
            response: requests.Response 객체 (선택)
            html_content: HTML 콘텐츠 문자열 (선택)
        """
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """
        예외 처리 보안 스캔 실행

        Returns:
            dict: 취약점 정보
        """
        try:
            # 1. 현재 페이지에서 에러 패턴 검사
            if self.html_content:
                self._check_error_patterns(self.html_content, self.url)

            # 2. 일반적인 에러 엔드포인트 테스트
            self._test_error_endpoints()

            # 3. 잘못된 파라미터로 에러 유도
            self._test_error_injection()

            # 4. HTTP 에러 페이지 검사
            self._test_http_error_pages()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'Exception Handling Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _check_error_patterns(self, content, url):
        """콘텐츠에서 에러 패턴 검사"""

        # 스택 트레이스 검사
        for pattern, description in self.STACK_TRACE_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                # 첫 번째 매칭의 일부만 증거로 저장
                evidence = matches[0][:200] if matches else ''

                self.vulnerabilities.append({
                    'type': 'stack_trace_exposure',
                    'severity': 'high',
                    'title': f'스택 트레이스 노출: {description}',
                    'description': '애플리케이션 스택 트레이스가 노출되어 내부 구조를 파악할 수 있습니다.',
                    'url': url,
                    'evidence': evidence,
                    'recommendation': '프로덕션 환경에서는 상세 에러 메시지를 사용자에게 노출하지 마세요.'
                })
                break  # 한 가지 유형만 보고

        # 데이터베이스 에러 검사
        for pattern, description in self.DATABASE_ERROR_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'database_error_exposure',
                    'severity': 'high',
                    'title': f'데이터베이스 에러 노출: {description}',
                    'description': '데이터베이스 에러 메시지가 노출되어 DB 구조를 파악할 수 있습니다.',
                    'url': url,
                    'recommendation': '데이터베이스 에러는 로그에만 기록하고 사용자에게는 일반적인 에러 메시지를 표시하세요.'
                })
                break

        # 디버그 정보 검사
        for pattern, description in self.DEBUG_INFO_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'debug_info_exposure',
                    'severity': 'medium',
                    'title': f'디버그 정보 노출: {description}',
                    'description': '디버그 모드가 활성화되어 있거나 디버그 정보가 노출되어 있습니다.',
                    'url': url,
                    'recommendation': '프로덕션 환경에서는 디버그 모드를 비활성화하세요.'
                })

        # 내부 경로 노출 검사
        path_matches = []
        for pattern, description in self.PATH_DISCLOSURE_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                path_matches.extend(matches[:3])  # 최대 3개만

        if path_matches:
            self.vulnerabilities.append({
                'type': 'path_disclosure',
                'severity': 'low',
                'title': '내부 경로 노출',
                'description': '서버의 내부 파일 시스템 경로가 노출되어 있습니다.',
                'url': url,
                'evidence': list(set(path_matches)),  # 중복 제거
                'recommendation': '에러 메시지에서 절대 경로를 제거하세요.'
            })

    def _test_error_endpoints(self):
        """일반적인 에러 엔드포인트 테스트"""
        base_url = self.url.rstrip('/')

        # 테스트할 에러 엔드포인트들
        error_paths = [
            '/error',
            '/error.html',
            '/errors',
            '/500',
            '/500.html',
            '/404',
            '/404.html',
        ]

        for path in error_paths:
            try:
                test_url = base_url + path
                response = requests.get(test_url, timeout=5)

                # 200 OK로 에러 페이지가 반환되는 경우
                if response.status_code == 200:
                    if self._is_detailed_error_page(response.text):
                        self.vulnerabilities.append({
                            'type': 'exposed_error_page',
                            'severity': 'low',
                            'title': '에러 페이지 직접 접근 가능',
                            'description': f'에러 페이지({path})가 직접 접근 가능합니다.',
                            'url': test_url,
                            'recommendation': '에러 페이지는 실제 에러 발생 시에만 표시되어야 합니다.'
                        })

            except requests.RequestException:
                pass

    def _test_error_injection(self):
        """에러를 유도하는 파라미터 테스트"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        if not params:
            return

        # 각 파라미터에 에러를 유도하는 값 주입
        error_payloads = [
            "'",  # SQL Injection 시도
            "1/0",  # Division by zero
            "null",
            "undefined",
            "-1",
            "999999999",
        ]

        for param_name in list(params.keys())[:2]:  # 처음 2개 파라미터만 테스트
            for payload in error_payloads[:2]:  # 처음 2개 payload만 테스트
                test_params = params.copy()
                test_params[param_name] = [payload]

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))

                try:
                    response = requests.get(test_url, timeout=5)

                    if response.status_code == 500:
                        if self._is_detailed_error_page(response.text):
                            self.vulnerabilities.append({
                                'type': 'error_via_injection',
                                'severity': 'medium',
                                'title': '잘못된 입력으로 상세 에러 유도',
                                'description': f'파라미터 {param_name}에 특수 값을 주입하여 상세 에러를 유도할 수 있습니다.',
                                'url': test_url,
                                'evidence': f'payload: {payload}',
                                'recommendation': '모든 사용자 입력을 검증하고, 에러 발생 시 일반적인 메시지만 표시하세요.'
                            })
                            return  # 한 번만 보고

                except requests.RequestException:
                    pass

    def _test_http_error_pages(self):
        """HTTP 에러 페이지 검사"""
        base_url = self.url.rstrip('/')

        # 404 Not Found 테스트
        test_url = base_url + '/this-page-definitely-does-not-exist-12345'

        try:
            response = requests.get(test_url, timeout=5)

            if response.status_code == 404:
                if self._is_detailed_error_page(response.text):
                    self.vulnerabilities.append({
                        'type': 'detailed_404_page',
                        'severity': 'low',
                        'title': '상세한 404 에러 페이지',
                        'description': '404 에러 페이지가 서버 정보를 포함하고 있을 수 있습니다.',
                        'url': test_url,
                        'recommendation': '사용자 친화적인 커스텀 404 페이지를 사용하세요.'
                    })

        except requests.RequestException:
            pass

    def _is_detailed_error_page(self, content):
        """상세한 에러 페이지인지 확인"""
        # 간단한 휴리스틱: 특정 키워드가 있는지 확인
        indicators = [
            'stack trace',
            'traceback',
            'exception',
            'error in',
            'line number',
            'debug',
            'at Object',
            'in file',
        ]

        content_lower = content.lower()
        for indicator in indicators:
            if indicator in content_lower:
                return True

        return False

    def _calculate_severity(self):
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'low')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if severity_counts['critical'] > 0:
            return 'critical'
        elif severity_counts['high'] >= 2:
            return 'high'
        elif severity_counts['high'] >= 1 or severity_counts['medium'] >= 2:
            return 'medium'
        else:
            return 'low'

    def _get_recommendations(self):
        """보안 권장사항 반환"""
        recommendations = [
            '프로덕션 환경에서는 DEBUG 모드를 비활성화하세요.',
            '사용자에게는 일반적인 에러 메시지만 표시하고, 상세 정보는 로그에만 기록하세요.',
            '커스텀 에러 페이지를 구현하여 서버 정보 노출을 방지하세요.',
            '전역 예외 핸들러를 구현하여 처리되지 않은 예외를 안전하게 처리하세요.',
            '에러 로그는 안전한 위치에 저장하고 접근 권한을 제한하세요.',
            '모든 사용자 입력을 검증하고 sanitize하여 예외 발생을 최소화하세요.',
            'try-catch/try-except 블록을 사용하여 예상 가능한 예외를 처리하세요.',
        ]

        return recommendations
