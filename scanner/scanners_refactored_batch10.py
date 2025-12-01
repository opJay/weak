"""
리팩토링된 예외 처리 보안 스캐너
Batch 10: Exception Handling Scanner (1개)

OWASP Top 10 2025 RC1 - A10: Mishandling of Exceptional Conditions 대응
예외 처리 오류 및 에러 정보 노출 탐지
"""

import re
import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from scanner.base import BaseScanner

logger = logging.getLogger('scanner')


class ExceptionHandlingScanner(BaseScanner):
    """예외 처리 보안 스캐너 - OWASP A10:2025"""

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
        (r'Fatal error:', 'PHP Fatal Error'),
        (r'Warning:.*in .*\.php on line \d+', 'PHP Warning'),
        (r'Parse error:.*in .*\.php on line \d+', 'PHP Parse Error'),
        (r'Stack trace:', 'PHP Stack Trace'),
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
        (r'MySQL\s+Error', 'MySQL Error'),
        (r'SQL syntax.*MySQL', 'MySQL Syntax Error'),
        (r'PostgreSQL.*ERROR', 'PostgreSQL Error'),
        (r'ORA-\d{5}', 'Oracle Error'),
        (r'Microsoft SQL Server.*error', 'SQL Server Error'),
        (r'SQLite.*Error', 'SQLite Error'),
        (r'MongoDB.*Error', 'MongoDB Error'),
        (r'redis\.exceptions', 'Redis Error'),
        (r'cassandra\..*Error', 'Cassandra Error'),
    ]

    # 디버그 정보 패턴
    DEBUG_INFO_PATTERNS = [
        (r'DEBUG\s*=\s*True', 'Django Debug Mode'),
        (r'APP_DEBUG.*true', 'Laravel Debug Mode'),
        (r'development mode', 'Development Mode'),
        (r'<title>Error</title>', 'Generic Error Page'),
        (r'X-Debug-Token', 'Symfony Debug Token'),
        (r'WP_DEBUG.*true', 'WordPress Debug Mode'),
        (r'display_errors\s*=\s*On', 'PHP Display Errors'),
    ]

    # 내부 경로 노출 패턴
    PATH_DISCLOSURE_PATTERNS = [
        (r'[C-Z]:\\[\w\\]+', 'Windows Path'),
        (r'/(?:var|home|usr|opt)/[\w/]+', 'Unix Path'),
        (r'/Users/[\w/]+', 'macOS Path'),
        (r'/app/[\w/]+', 'Container Path'),
    ]

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None):
        """스캐너 초기화"""
        super().__init__(url=url or '', response=response,
                        html_content=html_content)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client
        self.vulnerabilities = []

    def get_metadata(self) -> Dict[str, Any]:
        return {
            'id': 'exception_handling',
            'name': 'Exception Handling Security',
            'category': 'exception',
            'severity': 'high',
            'description': '예외 처리 오류 및 에러 정보 노출 탐지',
            'owasp': ['A10:2025']
        }

    def _prepare(self):
        """스캔 준비"""
        pass

    def _execute_scan(self):
        """스캔 실행"""
        # 1. 현재 페이지에서 에러 패턴 검사
        if self.html_content:
            self._check_error_patterns()

        # 2. 스택 트레이스 노출 검사
        self._check_stack_traces()

        # 3. 데이터베이스 에러 노출 검사
        self._check_database_errors()

        # 4. 디버그 정보 노출 검사
        self._check_debug_info()

        # 5. 내부 경로 노출 검사
        self._check_path_disclosure()

        # 6. 에러 엔드포인트 테스트 (http_client가 있는 경우만)
        if self.http_client and hasattr(self.http_client, 'get'):
            self._test_error_endpoints()
            self._test_error_injection()
            self._test_http_error_pages()

    def _check_error_patterns(self):
        """기본 에러 패턴 검사"""
        if not self.html_content:
            return

        # 일반적인 에러 키워드
        error_keywords = [
            'fatal error',
            'uncaught exception',
            'unhandled exception',
            'internal server error',
            'database error',
            'parse error',
            'syntax error',
            'runtime error',
            'compilation error'
        ]

        content_lower = self.html_content.lower()
        for keyword in error_keywords:
            if keyword in content_lower:
                # 키워드 주변 컨텍스트 추출
                idx = content_lower.index(keyword)
                context = self.html_content[max(0, idx-50):min(len(self.html_content), idx+150)]

                self.vulnerabilities.append({
                    'type': 'Error Information Exposure',
                    'severity': 'medium',
                    'title': f'에러 정보 노출: {keyword}',
                    'description': '에러 메시지가 사용자에게 노출되고 있습니다.',
                    'evidence': context[:200],
                    'recommendation': '프로덕션 환경에서는 일반적인 에러 메시지만 표시하세요.'
                })
                break

    def _check_stack_traces(self):
        """스택 트레이스 노출 검사"""
        if not self.html_content:
            return

        for pattern, description in self.STACK_TRACE_PATTERNS:
            matches = re.findall(pattern, self.html_content, re.IGNORECASE | re.MULTILINE)
            if matches:
                evidence = matches[0][:200] if matches else ''

                self.vulnerabilities.append({
                    'type': 'Stack Trace Exposure',
                    'severity': 'high',
                    'title': f'스택 트레이스 노출: {description}',
                    'description': '애플리케이션 스택 트레이스가 노출되어 내부 구조를 파악할 수 있습니다.',
                    'evidence': evidence,
                    'recommendation': '프로덕션 환경에서는 스택 트레이스를 로그에만 기록하세요.'
                })
                break  # 한 가지 유형만 보고

    def _check_database_errors(self):
        """데이터베이스 에러 노출 검사"""
        if not self.html_content:
            return

        for pattern, description in self.DATABASE_ERROR_PATTERNS:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'Database Error Exposure',
                    'severity': 'high',
                    'title': f'데이터베이스 에러 노출: {description}',
                    'description': '데이터베이스 에러 메시지가 노출되어 DB 구조를 파악할 수 있습니다.',
                    'recommendation': '데이터베이스 에러는 로그에만 기록하고 일반적인 메시지를 표시하세요.'
                })
                break

    def _check_debug_info(self):
        """디버그 정보 노출 검사"""
        if not self.html_content:
            return

        for pattern, description in self.DEBUG_INFO_PATTERNS:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'Debug Information Exposure',
                    'severity': 'medium',
                    'title': f'디버그 정보 노출: {description}',
                    'description': '디버그 모드가 활성화되어 있거나 디버그 정보가 노출되어 있습니다.',
                    'recommendation': '프로덕션 환경에서는 디버그 모드를 비활성화하세요.'
                })

    def _check_path_disclosure(self):
        """내부 경로 노출 검사"""
        if not self.html_content:
            return

        path_matches = []
        for pattern, description in self.PATH_DISCLOSURE_PATTERNS:
            matches = re.findall(pattern, self.html_content)
            if matches:
                path_matches.extend([(match, description) for match in matches[:3]])

        if path_matches:
            # 중복 제거하고 첫 번째 경로만 보고
            unique_paths = list(set([match[0] for match in path_matches]))[:3]

            self.vulnerabilities.append({
                'type': 'Path Disclosure',
                'severity': 'low',
                'title': '내부 경로 노출',
                'description': '서버의 내부 파일 시스템 경로가 노출되어 있습니다.',
                'evidence': unique_paths,
                'recommendation': '에러 메시지에서 절대 경로를 제거하세요.'
            })

    def _test_error_endpoints(self):
        """일반적인 에러 엔드포인트 테스트"""
        if not self.http_client or not hasattr(self.http_client, 'get'):
            return

        base_url = self.url.rstrip('/') if self.url else ''
        if not base_url:
            return

        # 테스트할 에러 엔드포인트들
        error_paths = [
            '/error',
            '/errors',
            '/500',
            '/500.html',
            '/404',
            '/404.html',
            '/_error',
        ]

        for path in error_paths[:3]:  # 처음 3개만 테스트
            try:
                test_url = base_url + path
                response = self.http_client.get(test_url, timeout=5)

                if response and hasattr(response, 'status_code') and response.status_code == 200:
                    content = response.text if hasattr(response, 'text') else ''
                    if self._is_detailed_error_page(content):
                        self.vulnerabilities.append({
                            'type': 'Exposed Error Page',
                            'severity': 'low',
                            'title': '에러 페이지 직접 접근 가능',
                            'description': f'에러 페이지({path})가 직접 접근 가능합니다.',
                            'url': test_url,
                            'recommendation': '에러 페이지는 실제 에러 발생 시에만 표시되어야 합니다.'
                        })
                        break
            except:
                pass

    def _test_error_injection(self):
        """에러를 유도하는 파라미터 테스트"""
        if not self.http_client or not self.url:
            return

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        if not params:
            return

        # 각 파라미터에 에러를 유도하는 값 주입
        error_payloads = [
            "'",  # SQL Injection 시도
            "1/0",  # Division by zero
            "null",
            "-1",
        ]

        for param_name in list(params.keys())[:1]:  # 첫 번째 파라미터만
            for payload in error_payloads[:2]:  # 처음 2개 payload만
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
                    response = self.http_client.get(test_url, timeout=5)

                    if response and hasattr(response, 'status_code'):
                        if response.status_code == 500:
                            content = response.text if hasattr(response, 'text') else ''
                            if self._is_detailed_error_page(content):
                                self.vulnerabilities.append({
                                    'type': 'Error Via Injection',
                                    'severity': 'medium',
                                    'title': '잘못된 입력으로 상세 에러 유도',
                                    'description': f'파라미터 {param_name}에 특수 값을 주입하여 에러를 유도할 수 있습니다.',
                                    'evidence': f'payload: {payload}',
                                    'recommendation': '모든 사용자 입력을 검증하고 안전하게 처리하세요.'
                                })
                                return  # 한 번만 보고
                except:
                    pass

    def _test_http_error_pages(self):
        """HTTP 에러 페이지 검사"""
        if not self.http_client or not self.url:
            return

        base_url = self.url.rstrip('/') if self.url else ''
        if not base_url:
            return

        # 404 Not Found 테스트
        test_url = base_url + '/this-page-definitely-does-not-exist-12345'

        try:
            response = self.http_client.get(test_url, timeout=5)

            if response and hasattr(response, 'status_code'):
                if response.status_code == 404:
                    content = response.text if hasattr(response, 'text') else ''
                    if self._is_detailed_error_page(content):
                        self.vulnerabilities.append({
                            'type': 'Detailed 404 Page',
                            'severity': 'low',
                            'title': '상세한 404 에러 페이지',
                            'description': '404 에러 페이지가 서버 정보를 포함하고 있을 수 있습니다.',
                            'recommendation': '사용자 친화적인 커스텀 404 페이지를 사용하세요.'
                        })
        except:
            pass

    def _is_detailed_error_page(self, content: str) -> bool:
        """상세한 에러 페이지인지 확인"""
        if not content:
            return False

        indicators = [
            'stack trace',
            'traceback',
            'exception',
            'error in',
            'line number',
            'debug',
            'at Object',
            'in file',
            'at line',
            'source code',
        ]

        content_lower = content.lower()
        for indicator in indicators:
            if indicator in content_lower:
                return True

        return False

    def _build_result(self) -> Dict[str, Any]:
        """결과 생성"""
        passed = len(self.vulnerabilities) == 0

        return {
            'passed': passed,
            'vulnerabilities': self.vulnerabilities,
            'total': len(self.vulnerabilities),
            'severity': self._calculate_severity(),
            'message': self._generate_message(),
            'recommendations': self._get_recommendations()
        }

    def _calculate_severity(self) -> str:
        """심각도 계산"""
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

    def _generate_message(self) -> str:
        """메시지 생성"""
        if not self.vulnerabilities:
            return '예외 처리가 안전하게 구현되어 있습니다'

        issues = []
        vuln_types = set(v.get('type') for v in self.vulnerabilities)

        if 'Stack Trace Exposure' in vuln_types:
            issues.append('스택 트레이스 노출')
        if 'Database Error Exposure' in vuln_types:
            issues.append('DB 에러 노출')
        if 'Debug Information Exposure' in vuln_types:
            issues.append('디버그 정보 노출')
        if 'Path Disclosure' in vuln_types:
            issues.append('경로 노출')

        return f"예외 처리 문제 발견: {', '.join(issues)}"

    def _get_recommendations(self) -> List[str]:
        """보안 권장사항 반환"""
        recommendations = []

        if self.vulnerabilities:
            recommendations.extend([
                '프로덕션 환경에서는 DEBUG 모드를 비활성화하세요.',
                '사용자에게는 일반적인 에러 메시지만 표시하고, 상세 정보는 로그에만 기록하세요.',
                '커스텀 에러 페이지를 구현하여 서버 정보 노출을 방지하세요.',
                '전역 예외 핸들러를 구현하여 처리되지 않은 예외를 안전하게 처리하세요.',
                '에러 로그는 안전한 위치에 저장하고 접근 권한을 제한하세요.',
            ])

        return recommendations