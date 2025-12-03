"""
InformationDisclosureScanner - 자동 수정됨

원본: scanners_refactored_batch2.py
"""

import logging
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
import requests
import json
import time
import hashlib
import base64

from scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class InformationDisclosureScanner(BaseScanner):
    """정보 노출 검사 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'information_disclosure',
        'name': '정보 노출 검사',
        'icon': '📝',
        'description': '민감한 정보 노출 탐지',
        'weight': 1,
        'field': 'disclosure',
        'category': 'security_basic',
        'OWASP': 'A05:2025',
    }

    # 민감한 정보 패턴 (확장 및 개선)
    SENSITIVE_PATTERNS = [
        # 에러 메시지
        (r'Fatal error:.*?in\s+.*?on line\s+\d+', 'PHP Fatal Error with path', 'high'),
        (r'Warning:.*?in\s+.*?on line\s+\d+', 'PHP Warning with path', 'medium'),
        (r'Notice:.*?in\s+.*?on line\s+\d+', 'PHP Notice with path', 'low'),
        (r'Parse error:.*?in\s+.*?on line\s+\d+', 'PHP Parse Error', 'high'),
        (r'Traceback \(most recent call last\):', 'Python Traceback', 'high'),
        (r'at\s+\w+\.\w+\(.*?\:\d+\)', 'Java Stack Trace', 'high'),
        (r'^\s*at\s+.*?\(.*?\.cs:\d+\)', 'C# Stack Trace', 'high'),

        # 파일 경로
        (r'[C-Z]:\\\\[^<>\s"]+', 'Windows file path', 'medium'),
        (r'/(?:usr|opt|var|home|root|etc)/[^<>\s"]+', 'Unix file path', 'medium'),
        (r'/Users/[^/\s<>"]+/', 'macOS user path', 'medium'),

        # 서버 정보
        (r'Server:\s*[^\r\n]+', 'Server header', 'low'),
        (r'X-Powered-By:\s*[^\r\n]+', 'X-Powered-By header', 'low'),
        (r'X-AspNet-Version:\s*[^\r\n]+', 'ASP.NET version', 'medium'),

        # 데이터베이스 정보
        (r'Database\s+name:\s*\w+', 'Database name', 'high'),
        (r'Table\s+\'[^\']+\'', 'Database table name', 'medium'),
        (r'Column\s+\'[^\']+\'', 'Database column name', 'medium'),

        # API 키/토큰 (더미 제외)
        (r'api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,}["\']', 'API Key', 'critical'),
        (r'api[_-]?secret["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,}["\']', 'API Secret', 'critical'),
        (r'["\']?token["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{20,}["\']', 'Access Token', 'high'),

        # AWS
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key', 'critical'),
        (r'[0-9a-zA-Z/+=]{40}', 'AWS Secret Key (potential)', 'high'),

        # 이메일 주소
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email address', 'low'),

        # IP 주소 (내부)
        (r'(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}', 'Internal IP address', 'medium'),

        # 버전 정보
        (r'(?:version|v)\s*[:=]?\s*\d+\.\d+(?:\.\d+)?', 'Version information', 'low'),

        # 주석의 TODO/FIXME
        (r'(?:TODO|FIXME|HACK|XXX):\s*[^\r\n]+', 'Development comment', 'low'),
    ]

    # 무시할 패턴 (False Positive 방지)
    IGNORE_PATTERNS = [
        r'example\.com',
        r'test@example\.com',
        r'your-api-key-here',
        r'xxxx-xxxx-xxxx-xxxx',
        r'placeholder',
        r'localhost',
        r'127\.0\.0\.1'
    ]

    def __init__(self, html_content: str = None, **kwargs):
        """
        Args:
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        url = kwargs.pop('url', '')
        super().__init__(url=url, html_content=html_content, **kwargs)

        # HTML 콘텐츠 설정
        if html_content:
            self.html_content = html_content
        elif hasattr(self, 'response') and self.response:
            self.html_content = getattr(self.response, 'text', '')
        else:
            self.html_content = ''

        # 헤더 설정
        if hasattr(self, 'response') and self.response:
            self.headers = getattr(self.response, 'headers', {})
        else:
            self.headers = kwargs.get('headers', {})

        self.issues = []

    def _execute_scan(self) -> None:
        """정보 노출 검사 실행"""
        # 1. HTML 콘텐츠에서 민감한 패턴 검색
        self._scan_sensitive_patterns()

        # 2. HTML 주석 검사
        self._scan_html_comments()

        # 3. 응답 헤더 검사
        self._scan_response_headers()

        # 4. 디버그 모드 감지
        self._detect_debug_mode()

        # 5. 소스 맵 파일 검사
        self._check_source_maps()

    def _scan_sensitive_patterns(self) -> None:
        """민감한 정보 패턴 검색"""
        if not self.html_content:
            return

        found_patterns = {}

        for pattern, desc, severity in self.SENSITIVE_PATTERNS:
            matches = re.findall(pattern, self.html_content, re.MULTILINE | re.IGNORECASE)

            if matches:
                # False positive 필터링
                filtered_matches = []
                for match in matches[:3]:  # 최대 3개만
                    is_ignored = False
                    for ignore_pattern in self.IGNORE_PATTERNS:
                        if re.search(ignore_pattern, match, re.IGNORECASE):
                            is_ignored = True
                            break

                    if not is_ignored:
                        filtered_matches.append(match)

                if filtered_matches:
                    # 같은 타입은 한 번만 보고
                    if desc not in found_patterns:
                        found_patterns[desc] = {
                            'type': 'Information Disclosure',
                            'severity': severity,
                            'info_type': desc,
                            'description': f'{desc} 정보가 노출되었습니다.',
                            'evidence': filtered_matches[0][:200],
                            'count': len(filtered_matches),
                            'recommendation': self._get_recommendation(desc)
                        }

        self.issues.extend(found_patterns.values())

    def _scan_html_comments(self) -> None:
        """HTML 주석에서 민감한 정보 검사"""
        if not self.html_content:
            return

        comments = re.findall(r'<!--(.*?)-->', self.html_content, re.DOTALL)

        sensitive_comments = []
        for comment in comments:
            # 민감한 키워드 확인
            sensitive_keywords = [
                'password', 'secret', 'token', 'api', 'key',
                'credential', 'private', 'admin', 'root',
                'TODO', 'FIXME', 'HACK', 'DEBUG'
            ]

            for keyword in sensitive_keywords:
                if keyword.lower() in comment.lower():
                    sensitive_comments.append({
                        'keyword': keyword,
                        'content': comment[:100]
                    })
                    break

        if sensitive_comments:
            self.issues.append({
                'type': 'Sensitive Comments',
                'severity': 'medium',
                'description': 'HTML 주석에 민감한 정보가 포함되어 있습니다.',
                'comments': sensitive_comments[:3],  # 최대 3개
                'recommendation': '프로덕션 환경에서는 민감한 주석을 제거하세요.'
            })

    def _scan_response_headers(self) -> None:
        """응답 헤더에서 정보 노출 검사"""
        if not self.headers:
            return

        # 정보를 노출하는 헤더들
        exposing_headers = {
            'Server': ('서버 소프트웨어 정보', 'low'),
            'X-Powered-By': ('프레임워크/언어 정보', 'low'),
            'X-AspNet-Version': ('ASP.NET 버전', 'medium'),
            'X-AspNetMvc-Version': ('ASP.NET MVC 버전', 'medium'),
            'X-Generator': ('생성 도구 정보', 'low'),
            'X-Drupal-Cache': ('Drupal CMS 정보', 'low'),
            'X-Varnish': ('Varnish 캐시 정보', 'low'),
            'Via': ('프록시 서버 정보', 'low'),
            'X-Debug-Token': ('디버그 토큰', 'high'),
            'X-Debug-Token-Link': ('디버그 링크', 'high'),
        }

        for header, (desc, severity) in exposing_headers.items():
            value = self.headers.get(header)
            if value:
                self.issues.append({
                    'type': 'Header Information Disclosure',
                    'severity': severity,
                    'header': header,
                    'value': value,
                    'description': f'{desc}가 헤더에 노출되었습니다.',
                    'recommendation': f'프로덕션 환경에서는 {header} 헤더를 제거하거나 최소화하세요.'
                })

    def _detect_debug_mode(self) -> None:
        """디버그 모드 감지"""
        if not self.html_content:
            return

        debug_indicators = [
            (r'debug\s*[=:]\s*true', 'Debug mode enabled'),
            (r'DEBUG\s*=\s*True', 'Python DEBUG=True'),
            (r'WP_DEBUG.*?true', 'WordPress debug mode'),
            (r'display_errors\s*=\s*On', 'PHP display_errors=On'),
            (r'RAILS_ENV\s*=\s*development', 'Rails development mode'),
            (r'NODE_ENV\s*=\s*development', 'Node.js development mode'),
        ]

        for pattern, desc in debug_indicators:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                self.issues.append({
                    'type': 'Debug Mode Enabled',
                    'severity': 'high',
                    'description': f'{desc} - 디버그 모드가 활성화되어 있습니다.',
                    'recommendation': '프로덕션 환경에서는 디버그 모드를 비활성화하세요.'
                })
                break

    def _check_source_maps(self) -> None:
        """소스 맵 파일 노출 검사"""
        if not self.html_content:
            return

        # 소스 맵 참조 찾기
        source_map_patterns = [
            r'//[#@]\s*sourceMappingURL=([^\s]+)',
            r'\.map["\']\s*\)',
            r'\.js\.map',
            r'\.css\.map'
        ]

        for pattern in source_map_patterns:
            matches = re.findall(pattern, self.html_content)
            if matches:
                self.issues.append({
                    'type': 'Source Map Exposure',
                    'severity': 'medium',
                    'description': '소스 맵 파일이 노출되어 있습니다.',
                    'evidence': matches[0] if matches else '',
                    'recommendation': '프로덕션 환경에서는 소스 맵 파일을 제거하세요.'
                })
                break

    def _get_recommendation(self, info_type: str) -> str:
        """정보 유형별 권장사항"""
        recommendations = {
            'PHP': 'display_errors를 Off로 설정하고, 에러 로깅을 사용하세요.',
            'Python': 'DEBUG=False로 설정하고, 적절한 에러 핸들링을 구현하세요.',
            'Java': '스택 트레이스를 로그 파일에만 기록하세요.',
            'API': 'API 키를 환경 변수로 관리하고, 클라이언트 코드에 포함하지 마세요.',
            'Database': '데이터베이스 구조 정보를 숨기고, 일반적인 에러 메시지를 사용하세요.',
            'path': '파일 시스템 경로를 노출하지 마세요.',
            'Email': '필요한 경우가 아니면 이메일 주소를 마스킹하세요.',
        }

        for key, rec in recommendations.items():
            if key.lower() in info_type.lower():
                return rec

        return '민감한 정보는 프로덕션 환경에서 숨기세요.'

    def _build_vulnerabilities(self) -> List[Dict[str, Any]]:
        """issues를 vulnerabilities 형식으로 변환"""
        return self.issues

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for issue in self.issues:
            severity = issue.get('severity', 'low')
            severity_counts[severity] += 1

        return {
            'has_disclosure': len(self.issues) > 0,
            'critical_count': severity_counts['critical'],
            'high_count': severity_counts['high'],
            'debug_mode': any('Debug Mode' in i['type'] for i in self.issues),
            'api_keys_exposed': any('API' in i.get('info_type', '') for i in self.issues)
        }



    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

