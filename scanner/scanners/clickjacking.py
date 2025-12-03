"""
ClickjackingScanner - 자동 수정됨

원본: scanners_refactored_batch1.py
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


class ClickjackingScanner(BaseScanner):
    """클릭재킹 방어 검사 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'clickjacking',
        'name': '클릭재킹 방어 검사',
        'icon': '🖱️',
        'description': 'Clickjacking 공격 방어 검증',
        'weight': 1,
        'field': 'clickjacking',
        'category': 'security_basic',
        'OWASP': 'A05:2025'
    }

    def __init__(self, headers: Dict[str, str] = None, html_content: str = None, **kwargs):
        """
        Args:
            headers: HTTP 응답 헤더
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        # BaseScanner 초기화
        url = kwargs.pop('url', '')
        super().__init__(url=url, html_content=html_content, **kwargs)

        # 헤더 설정
        if headers is not None:
            self.headers = headers
        elif hasattr(self, 'response') and self.response:
            self.headers = getattr(self.response, 'headers', {})
        else:
            self.headers = {}

        # HTML 콘텐츠 설정
        if html_content:
            self.html_content = html_content
        elif hasattr(self, 'response') and self.response:
            self.html_content = getattr(self.response, 'text', '')
        else:
            self.html_content = ''

        self.issues = []

    def _execute_scan(self) -> None:
        """클릭재킹 방어 검사 실행"""
        # 검사 항목: X-Frame-Options, CSP frame-ancestors
        self.checked = 2

        x_frame_options = self.headers.get('X-Frame-Options')
        csp = self.headers.get('Content-Security-Policy')

        # 1. X-Frame-Options 검사
        if x_frame_options:
            xfo_value = x_frame_options.upper()
            if xfo_value in ['DENY', 'SAMEORIGIN']:
                self._add_detail(
                    id='x_frame_options',
                    name='X-Frame-Options',
                    status='pass',
                    severity='info',
                    description=f'클릭재킹 방어 헤더가 올바르게 설정됨',
                    value=x_frame_options,
                    expected='DENY 또는 SAMEORIGIN',
                    recommendation=None
                )
            elif xfo_value.startswith('ALLOW-FROM'):
                self._add_detail(
                    id='x_frame_options',
                    name='X-Frame-Options',
                    status='warning',
                    severity='low',
                    description='ALLOW-FROM은 더 이상 권장되지 않음',
                    value=x_frame_options,
                    expected='DENY 또는 SAMEORIGIN',
                    recommendation='CSP frame-ancestors를 사용하세요.'
                )
                self.issues.append({
                    'type': 'Deprecated X-Frame-Options',
                    'severity': 'low',
                    'description': 'ALLOW-FROM은 더 이상 권장되지 않습니다.',
                    'recommendation': 'CSP frame-ancestors를 사용하세요.'
                })
            else:
                self._add_detail(
                    id='x_frame_options',
                    name='X-Frame-Options',
                    status='fail',
                    severity='high',
                    description=f'유효하지 않은 값: {x_frame_options}',
                    value=x_frame_options,
                    expected='DENY 또는 SAMEORIGIN',
                    recommendation='DENY, SAMEORIGIN 중 하나를 사용하세요.'
                )
                self.issues.append({
                    'type': 'Invalid X-Frame-Options',
                    'severity': 'high',
                    'description': f'유효하지 않은 X-Frame-Options 값: {x_frame_options}',
                    'recommendation': 'DENY, SAMEORIGIN 중 하나를 사용하세요.'
                })
        else:
            self._add_detail(
                id='x_frame_options',
                name='X-Frame-Options',
                status='fail',
                severity='high',
                description='X-Frame-Options 헤더가 설정되지 않음',
                value=None,
                expected='DENY 또는 SAMEORIGIN',
                recommendation='X-Frame-Options: DENY를 설정하세요.'
            )

        # 2. CSP frame-ancestors 검사
        if csp and 'frame-ancestors' in csp:
            frame_ancestors_result = self._analyze_frame_ancestors(csp)
            self._add_detail(
                id='csp_frame_ancestors',
                name='CSP frame-ancestors',
                status=frame_ancestors_result['status'],
                severity=frame_ancestors_result['severity'],
                description=frame_ancestors_result['description'],
                value=frame_ancestors_result.get('value'),
                expected="'self' 또는 특정 도메인",
                recommendation=frame_ancestors_result.get('recommendation')
            )
        else:
            self._add_detail(
                id='csp_frame_ancestors',
                name='CSP frame-ancestors',
                status='warning' if x_frame_options else 'fail',
                severity='medium' if x_frame_options else 'high',
                description='CSP frame-ancestors가 설정되지 않음',
                value=None,
                expected="frame-ancestors 'self'",
                recommendation="CSP에 frame-ancestors 'self' 추가를 권장합니다."
            )

        # 둘 다 없으면 취약점 추가
        if not x_frame_options and not (csp and 'frame-ancestors' in csp):
            self.issues.append({
                'type': 'Missing Clickjacking Protection',
                'severity': 'high',
                'description': 'X-Frame-Options 또는 CSP frame-ancestors가 설정되지 않았습니다.',
                'recommendation': 'X-Frame-Options: DENY 또는 CSP frame-ancestors를 설정하세요.'
            })

    def _analyze_frame_ancestors(self, csp: str) -> Dict[str, Any]:
        """frame-ancestors 디렉티브 분석"""
        import re
        match = re.search(r"frame-ancestors\s+([^;]+)", csp)
        if match:
            value = match.group(1).strip()
            if value == "'*'" or value == "*":
                self.issues.append({
                    'type': 'Weak frame-ancestors',
                    'severity': 'medium',
                    'description': 'frame-ancestors가 모든 도메인을 허용합니다.',
                    'recommendation': "frame-ancestors 'self' 또는 특정 도메인만 허용하세요."
                })
                return {
                    'status': 'warning',
                    'severity': 'medium',
                    'description': 'frame-ancestors가 모든 도메인을 허용함',
                    'value': value,
                    'recommendation': "frame-ancestors 'self' 또는 특정 도메인만 허용하세요."
                }
            elif "'none'" in value or "'self'" in value:
                return {
                    'status': 'pass',
                    'severity': 'info',
                    'description': 'frame-ancestors가 안전하게 설정됨',
                    'value': value
                }
            else:
                return {
                    'status': 'pass',
                    'severity': 'info',
                    'description': f'frame-ancestors 설정됨: {value}',
                    'value': value
                }
        return {
            'status': 'fail',
            'severity': 'high',
            'description': 'frame-ancestors 파싱 실패'
        }

    def _check_framebuster(self) -> None:
        """JavaScript framebuster 코드 검사"""
        framebuster_patterns = [
            r'if\s*\(\s*top\s*!=\s*self\s*\)',
            r'if\s*\(\s*parent\s*!=\s*self\s*\)',
            r'if\s*\(\s*window\.top\s*!==\s*window\.self\s*\)',
            r'X-Frame-Options',  # 메타 태그로 설정 시도
        ]

        for pattern in framebuster_patterns:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                # Framebuster 있지만 헤더가 더 안전
                logger.debug("Framebuster JavaScript 발견")
                break

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        x_frame_options = self.headers.get('X-Frame-Options')
        csp = self.headers.get('Content-Security-Policy')

        return {
            'has_xfo': x_frame_options is not None,
            'has_csp_frame': 'frame-ancestors' in csp if csp else False,
            'protected': (x_frame_options is not None) or ('frame-ancestors' in csp if csp else False),
            'xfo_value': x_frame_options
        }



    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

