"""
CORSScanner - 자동 수정됨

원본: scanners_refactored.py
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


class CORSScanner(BaseScanner):
    """CORS 설정 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'cors',
        'name': 'CORS 설정 검사',
        'icon': '🌐',
        'description': 'Cross-Origin Resource Sharing 설정 검증',
        'weight': 1,
        'field': 'cors_misconfiguration',
        'category': 'security_basic',
        'OWASP': 'A05:2025',
    }

    def __init__(self, url: str = None, headers: Dict[str, str] = None, **kwargs):
        """
        Args:
            url: URL (BaseScanner 호환)
            headers: HTTP 응답 헤더
            **kwargs: 추가 인자
        """
        # BaseScanner 초기화
        super().__init__(url=url or '', **kwargs)

        # 헤더 설정
        if headers is not None:
            self.headers = headers
        elif hasattr(self, 'response') and self.response:
            self.headers = getattr(self.response, 'headers', {})
        else:
            self.headers = {}

        # issues 사용 (vulnerabilities 대신)
        self.issues = []

    def _execute_scan(self) -> None:
        """CORS 설정 검사 실행"""
        acao = self.headers.get('Access-Control-Allow-Origin')
        acac = self.headers.get('Access-Control-Allow-Credentials')
        acam = self.headers.get('Access-Control-Allow-Methods')
        acah = self.headers.get('Access-Control-Allow-Headers')

        # 검사 항목 수: 4개 (Origin, Credentials, Methods, Headers)
        self.checked = 4

        # 1. Access-Control-Allow-Origin 검사
        self._check_origin(acao, acac)

        # 2. Access-Control-Allow-Credentials 검사
        self._check_credentials(acao, acac)

        # 3. Access-Control-Allow-Methods 검사
        self._check_methods(acam)

        # 4. Access-Control-Allow-Headers 검사
        self._check_headers(acah)

    def _check_origin(self, acao: str, acac: str) -> None:
        """Access-Control-Allow-Origin 검사"""
        if not acao:
            self._add_detail(
                id='acao',
                name='Access-Control-Allow-Origin',
                status='pass',
                severity='info',
                description='CORS 헤더 미설정 (Same-Origin Policy 적용)',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        # 와일드카드 + Credentials 조합 검사
        if acao == '*' and acac and acac.lower() == 'true':
            self._add_detail(
                id='acao',
                name='Access-Control-Allow-Origin',
                status='fail',
                severity='critical',
                description='와일드카드(*)와 Credentials: true 조합은 매우 위험',
                value=acao,
                expected='특정 도메인만 허용',
                recommendation='특정 도메인만 허용하거나 Credentials를 비활성화하세요.'
            )
            self.issues.append({
                'type': 'Critical CORS Misconfiguration',
                'severity': 'critical',
                'description': 'Access-Control-Allow-Origin: * 와 Credentials: true가 함께 설정됨',
                'recommendation': '특정 도메인만 허용하거나 Credentials를 비활성화하세요.'
            })
        elif acao == '*':
            self._add_detail(
                id='acao',
                name='Access-Control-Allow-Origin',
                status='warning',
                severity='medium',
                description='와일드카드(*) 사용 - 모든 도메인에서 접근 가능',
                value=acao,
                expected='특정 도메인만 허용',
                recommendation='가능한 특정 도메인만 허용하세요.'
            )
            self.issues.append({
                'type': 'CORS Wildcard',
                'severity': 'medium',
                'description': 'Access-Control-Allow-Origin: * 가 설정되어 있습니다.',
                'recommendation': '가능한 특정 도메인만 허용하세요.'
            })
        elif acao.lower() == 'null':
            self._add_detail(
                id='acao',
                name='Access-Control-Allow-Origin',
                status='fail',
                severity='high',
                description='null 오리진 허용 - sandboxed iframe 우회 가능',
                value=acao,
                expected='특정 도메인만 허용',
                recommendation='null 오리진을 허용하지 마세요.'
            )
            self.issues.append({
                'type': 'Null Origin Allowed',
                'severity': 'high',
                'description': 'null 오리진이 허용되고 있습니다.',
                'recommendation': 'null 오리진을 허용하지 마세요.'
            })
        else:
            self._add_detail(
                id='acao',
                name='Access-Control-Allow-Origin',
                status='pass',
                severity='info',
                description=f'특정 도메인 허용됨',
                value=acao,
                expected=None,
                recommendation=None
            )

    def _check_credentials(self, acao: str, acac: str) -> None:
        """Access-Control-Allow-Credentials 검사"""
        if not acac:
            self._add_detail(
                id='acac',
                name='Access-Control-Allow-Credentials',
                status='pass',
                severity='info',
                description='Credentials 헤더 미설정 (기본값: false)',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        if acac.lower() == 'true' and acao == '*':
            # 이미 origin에서 처리됨
            self._add_detail(
                id='acac',
                name='Access-Control-Allow-Credentials',
                status='fail',
                severity='critical',
                description='Credentials: true와 와일드카드 Origin 조합은 위험',
                value=acac,
                expected='false 또는 특정 Origin과 함께 사용',
                recommendation='Credentials 사용 시 특정 도메인만 허용하세요.'
            )
        else:
            self._add_detail(
                id='acac',
                name='Access-Control-Allow-Credentials',
                status='pass',
                severity='info',
                description='Credentials 설정됨',
                value=acac,
                expected=None,
                recommendation=None
            )

    def _check_methods(self, acam: str) -> None:
        """Access-Control-Allow-Methods 검사"""
        if not acam:
            self._add_detail(
                id='acam',
                name='Access-Control-Allow-Methods',
                status='pass',
                severity='info',
                description='Methods 헤더 미설정',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        dangerous_methods = ['PUT', 'DELETE', 'PATCH']
        allowed_methods = [m.strip() for m in acam.upper().split(',')]
        dangerous_found = [m for m in dangerous_methods if m in allowed_methods]

        if dangerous_found:
            self._add_detail(
                id='acam',
                name='Access-Control-Allow-Methods',
                status='warning',
                severity='medium',
                description=f'위험한 메서드 허용: {", ".join(dangerous_found)}',
                value=acam,
                expected='GET, POST 등 필요한 메서드만',
                recommendation='필요한 메서드만 허용하세요.'
            )
            self.issues.append({
                'type': 'Dangerous Methods in CORS',
                'severity': 'medium',
                'description': f'위험한 메서드가 허용됩니다: {", ".join(dangerous_found)}',
                'recommendation': '필요한 메서드만 허용하세요.'
            })
        else:
            self._add_detail(
                id='acam',
                name='Access-Control-Allow-Methods',
                status='pass',
                severity='info',
                description='허용된 메서드가 안전함',
                value=acam,
                expected=None,
                recommendation=None
            )

    def _check_headers(self, acah: str) -> None:
        """Access-Control-Allow-Headers 검사"""
        if not acah:
            self._add_detail(
                id='acah',
                name='Access-Control-Allow-Headers',
                status='pass',
                severity='info',
                description='Headers 헤더 미설정',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        sensitive_headers = ['Authorization', 'Cookie', 'X-API-Key']
        allowed_headers = [h.strip().lower() for h in acah.split(',')]
        sensitive_found = [h for h in sensitive_headers if h.lower() in allowed_headers]

        if sensitive_found:
            self._add_detail(
                id='acah',
                name='Access-Control-Allow-Headers',
                status='warning',
                severity='low',
                description=f'민감한 헤더 허용: {", ".join(sensitive_found)}',
                value=acah,
                expected='필요한 헤더만 허용',
                recommendation='꼭 필요한 경우가 아니면 민감한 헤더는 제한하세요.'
            )
            self.issues.append({
                'type': 'Sensitive Headers in CORS',
                'severity': 'low',
                'description': f'민감한 헤더가 허용됩니다: {", ".join(sensitive_found)}',
                'recommendation': '꼭 필요한 경우가 아니면 민감한 헤더는 제한하세요.'
            })
        else:
            self._add_detail(
                id='acah',
                name='Access-Control-Allow-Headers',
                status='pass',
                severity='info',
                description='허용된 헤더가 안전함',
                value=acah,
                expected=None,
                recommendation=None
            )

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        acao = self.headers.get('Access-Control-Allow-Origin')
        return {
            'has_cors': acao is not None,
            'misconfigured': len(self.issues) > 0,
            'origin': acao
        }

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

