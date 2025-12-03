"""
LDAPInjectionScanner - 자동 수정됨

원본: scanners_refactored_batch6.py
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


class LDAPInjectionScanner(BaseScanner):
    """LDAP Injection 취약점 스캐너 - 리팩토링 버전"""

    metadata = {
        'id': 'ldap_injection',
        'name': 'LDAP Injection 검사',
        'icon': '📖',
        'description': 'LDAP Injection 취약점 탐지',
        'weight': 1.5,
        'field': 'ldap_injection',
        'category': 'api_auth',
        'OWASP': 'A04:2025',
    }

    LDAP_PARAMS = ['username', 'user', 'uid', 'cn', 'email', 'mail', 'dn']
    LDAP_CHARS = ['(', ')', '*', '\\', '/', '|', '&', '=']

    def __init__(self, url: str = None, response: requests.Response = None,
                 html_content: str = None, **kwargs):
        """
        Args:
            url: 스캔 대상 URL
            response: HTTP 응답 객체
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', response=response,
                        html_content=html_content, **kwargs)

    def _execute_scan(self) -> None:
        """LDAP Injection 스캔 실행"""
        self._check_ldap_params()
        self._check_ldap_filters()
        self._check_ldap_authentication()
        self._check_error_messages()

    def _check_ldap_params(self) -> None:
        """LDAP 관련 파라미터 검사"""
        if not self.url:
            return

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        for param_name in params:
            if param_name.lower() in self.LDAP_PARAMS:
                param_value = params[param_name][0]

                # 위험한 LDAP 문자 검사
                if any(char in param_value for char in self.LDAP_CHARS):
                    self.vulnerabilities.append({
                        'type': 'LDAP Injection Characters',
                        'severity': 'high',
                        'parameter': param_name,
                        'description': f'파라미터 "{param_name}"에 LDAP 특수문자가 포함되어 있습니다.',
                        'recommendation': 'LDAP 쿼리 전에 입력값을 이스케이프 처리하세요.'
                    })

    def _check_ldap_filters(self) -> None:
        """LDAP 필터 패턴 검사"""
        if not self.html_content:
            return

        # LDAP 필터 패턴
        filter_patterns = [
            r'\(uid=.*\)',
            r'\(cn=.*\)',
            r'\(&\(.*\)\)',
            r'\(\|.*\)',
            r'objectClass='
        ]

        for pattern in filter_patterns:
            if re.search(pattern, self.html_content):
                self.vulnerabilities.append({
                    'type': 'LDAP Filter Pattern Detected',
                    'severity': 'medium',
                    'pattern': pattern,
                    'description': 'LDAP 필터 패턴이 HTML에 노출되어 있습니다.',
                    'recommendation': 'LDAP 필터를 클라이언트에 노출하지 마세요.'
                })
                break

    def _check_ldap_authentication(self) -> None:
        """LDAP 인증 관련 검사"""
        if not self.html_content:
            return

        # LDAP 인증 관련 패턴
        auth_patterns = [
            r'ldap.*bind',
            r'ldap.*auth',
            r'ldap.*login',
            r'distinguishedName'
        ]

        for pattern in auth_patterns:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'LDAP Authentication Detected',
                    'severity': 'low',
                    'description': 'LDAP 인증이 사용되고 있습니다.',
                    'recommendation': '안전한 LDAP 바인딩과 입력 검증을 구현하세요.'
                })
                break

    def _check_error_messages(self) -> None:
        """LDAP 에러 메시지 노출 검사"""
        if not self.html_content:
            return

        # LDAP 에러 메시지 패턴
        error_patterns = [
            r'LDAP.*error',
            r'Invalid DN syntax',
            r'No such object',
            r'LDAP bind failed'
        ]

        for pattern in error_patterns:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'LDAP Error Message Disclosure',
                    'severity': 'medium',
                    'pattern': pattern,
                    'description': 'LDAP 에러 메시지가 노출되어 있습니다.',
                    'recommendation': '상세한 에러 메시지를 숨기고 일반적인 메시지를 표시하세요.'
                })



    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

