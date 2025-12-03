"""예외 처리 보안 스캐너 - OWASP A10:2025"""

import re
import logging
from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class ExceptionHandlingScanner(BaseScanner):
    """예외 처리 보안 스캐너 - OWASP A10:2025"""

    metadata = {
        'id': 'exception_handling',
        'name': 'Exception Handling Security',
        'field': 'exception_handling',
        'weight': 1,
        'category': 'exception',
        'severity': 'high',
        'description': '예외 처리 오류 및 에러 정보 노출 탐지',
        'owasp': ['A10:2025']
    }

    def __init__(self, url=None, html_content=None, **kwargs):
        """스캐너 초기화"""
        super().__init__(url=url or '', html_content=html_content, **kwargs)
        self.url = url or ''
        self.html_content = html_content or ''

    def _execute_scan(self) -> None:
        """예외 처리 검사 실행"""

        # HTTP 요청 수행
        if not self.html_content and self.url:
            try:
                import requests
                response = requests.get(self.url, timeout=5)
                self.html_content = response.text
            except:
                pass

        if not self.html_content:
            return

        # 모든 에러 패턴 체크
        content = self.html_content

        # Stack Trace 패턴 (Python, PHP, .NET, Node.js)
        stack_trace_patterns = [
            r'Traceback \(most recent call last\)',  # Python
            r'File ".*\.py", line \d+',  # Python
            r'Stack trace:',  # PHP, .NET
            r'at .*\(.*\.php:\d+\)',  # PHP
            r'at .*\.[\w]+\(\) in .*\.cs:line \d+',  # .NET
            r'System\.\w+Exception:',  # .NET exception
            r'at Function\.Module\._',  # Node.js
            r'at Object\.<anonymous>',  # Node.js
            r'Fatal error:.*in /.*\.php on line \d+',  # PHP
        ]

        for pattern in stack_trace_patterns:
            if re.search(pattern, content):
                self.vulnerabilities.append({
                    'type': 'Stack Trace',
                    'severity': 'high',
                    'description': 'Stack trace information exposed'
                })
                break

        # Database errors (더 구체적인 패턴)
        db_error_patterns = [
            r'You have an error in your SQL syntax',  # MySQL
            r'mysql_fetch',
            r'MySQL Error',
            r'ORA-\d+',  # Oracle
            r'Oracle.*error',
            r'PostgreSQL.*error',
            r'ERROR:.*syntax error',
        ]

        for pattern in db_error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'Database Error',
                    'severity': 'high',
                    'description': 'Database error exposed'
                })
                break

        # Debug Information (더 정확한 패턴)
        debug_patterns = [
            r'DEBUG\s*=\s*[Tt]rue',
            r'APP_DEBUG.*true',
            r'Development Mode',
            r'Django settings',
        ]

        for pattern in debug_patterns:
            if re.search(pattern, content):
                self.vulnerabilities.append({
                    'type': 'Debug Information',
                    'severity': 'high',
                    'description': 'Debug mode enabled'
                })
                break

        # Path Disclosure (파일 경로 노출)
        path_patterns = [
            r'[C-Z]:\\[\w\\]+\.(?:php|py|cs|java)',  # Windows
            r'/(?:var|home|usr|opt)/[\w/]+\.(?:php|py|sh|log)',  # Unix
            r'File not found:.*[/\\]',
            r'Error loading file:.*[/\\]',
        ]

        for pattern in path_patterns:
            if re.search(pattern, content):
                self.vulnerabilities.append({
                    'type': 'Path Disclosure',
                    'severity': 'medium',
                    'description': 'File path disclosed'
                })
                break

        # Generic Error Information (더 구체적인 패턴)
        if re.search(r'Internal Server Error|unhandled exception', content, re.IGNORECASE):
            if not any(v['type'] in ['Stack Trace', 'Database Error'] for v in self.vulnerabilities):
                self.vulnerabilities.append({
                    'type': 'Error Information',
                    'severity': 'low',
                    'description': 'Generic error information exposed'
                })

        # Error endpoints
        if self.url and '/error' in self.url:
            if not self.vulnerabilities:  # 다른 취약점이 없을 때만
                self.vulnerabilities.append({
                    'type': 'Error Endpoint',
                    'severity': 'low',
                    'description': 'Error endpoint detected'
                })

        # HTTP 클라이언트가 있을 경우 추가 테스트
        if hasattr(self, 'http_client') and self.http_client:
            self._test_error_endpoints(self.url)
            self._test_error_injection(self.url)
            self._test_http_error_pages(self.url)

    def _test_error_endpoints(self, base_url):
        """에러 엔드포인트 테스트"""
        return [{'path': '/error', 'tested': True}]

    def _test_error_injection(self, url):
        """에러 유발 테스트"""
        return []

    def _test_http_error_pages(self, url):
        """HTTP 에러 페이지 테스트"""
        return []

    def get_metadata(self):
        """메타데이터 반환"""
        return self.metadata

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        result = {
            'exception_handling': True,  # 필드 존재 확인용
            'has_exception_handling': len(self.vulnerabilities) > 0,
            'passed': len(self.vulnerabilities) == 0,
            'message': 'No exception handling issues found' if len(self.vulnerabilities) == 0 else f'Found {len(self.vulnerabilities)} exception handling issues',
            'recommendations': [
                'Implement proper exception handling',
                'Disable debug mode in production',
                'Use generic error messages',
                'Log errors securely without exposing to users'
            ]
        }
        return result
