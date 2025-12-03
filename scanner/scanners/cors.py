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

        if acao:
            self._check_wildcard_origin(acao, acac)
            self._check_null_origin(acao)
            self._check_reflected_origin(acao)

        # 추가 검사: 위험한 메서드 허용
        if acam:
            self._check_dangerous_methods(acam)

        # 추가 검사: 민감한 헤더 허용
        if acah:
            self._check_sensitive_headers(acah)

    def _check_wildcard_origin(self, acao: str, acac: str) -> None:
        """와일드카드 오리진 검사"""
        if acao == '*':
            if acac and acac.lower() == 'true':
                # Critical: 와일드카드 + credentials
                self.issues.append({
                    'type': 'Critical CORS Misconfiguration',
                    'severity': 'critical',
                    'description': 'Access-Control-Allow-Origin: * 와 Credentials: true가 함께 설정되어 있습니다.',
                    'details': '모든 도메인에서 인증된 요청을 보낼 수 있어 매우 위험합니다.',
                    'recommendation': '특정 도메인만 허용하거나 Credentials를 비활성화하세요.'
                })
            else:
                # Medium: 와일드카드만
                self.issues.append({
                    'type': 'CORS Wildcard',
                    'severity': 'medium',
                    'description': 'Access-Control-Allow-Origin: * 가 설정되어 있습니다.',
                    'details': '모든 도메인에서 리소스에 접근할 수 있습니다.',
                    'recommendation': '가능한 특정 도메인만 허용하세요.'
                })

    def _check_null_origin(self, acao: str) -> None:
        """null 오리진 허용 검사"""
        if acao.lower() == 'null':
            self.issues.append({
                'type': 'Null Origin Allowed',
                'severity': 'high',
                'description': 'null 오리진이 허용되고 있습니다.',
                'details': 'sandboxed iframe 등을 통한 우회 공격이 가능합니다.',
                'recommendation': 'null 오리진을 허용하지 마세요.'
            })

    def _check_reflected_origin(self, acao: str) -> None:
        """반사된 오리진 검사 (간접 추정)"""
        # URL에서 도메인 추출
        if self.url:
            parsed = urlparse(self.url)
            if parsed.netloc and parsed.netloc in acao and acao != parsed.netloc:
                self.issues.append({
                    'type': 'Potential Origin Reflection',
                    'severity': 'medium',
                    'description': '오리진이 동적으로 반사될 가능성이 있습니다.',
                    'details': 'Origin 헤더 값을 그대로 반사하면 보안 위험이 있습니다.',
                    'recommendation': '화이트리스트 기반으로 오리진을 검증하세요.'
                })

    def _check_dangerous_methods(self, acam: str) -> None:
        """위험한 HTTP 메서드 허용 검사"""
        dangerous_methods = ['PUT', 'DELETE', 'PATCH']
        allowed_methods = [m.strip() for m in acam.upper().split(',')]

        dangerous_found = [m for m in dangerous_methods if m in allowed_methods]
        if dangerous_found:
            self.issues.append({
                'type': 'Dangerous Methods in CORS',
                'severity': 'medium',
                'methods': dangerous_found,
                'description': f'위험한 메서드가 CORS에서 허용됩니다: {", ".join(dangerous_found)}',
                'recommendation': '필요한 메서드만 허용하세요.'
            })

    def _check_sensitive_headers(self, acah: str) -> None:
        """민감한 헤더 허용 검사"""
        sensitive_headers = ['Authorization', 'Cookie', 'X-API-Key']
        allowed_headers = acah.split(',')

        sensitive_found = []
        for header in sensitive_headers:
            if header.lower() in [h.strip().lower() for h in allowed_headers]:
                sensitive_found.append(header)

        if sensitive_found:
            self.issues.append({
                'type': 'Sensitive Headers in CORS',
                'severity': 'low',
                'headers': sensitive_found,
                'description': f'민감한 헤더가 허용됩니다: {", ".join(sensitive_found)}',
                'recommendation': '꼭 필요한 경우가 아니면 민감한 헤더는 제한하세요.'
            })

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

