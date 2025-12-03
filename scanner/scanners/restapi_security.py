"""
RESTAPISecurityScanner - 자동 수정됨

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


class RESTAPISecurityScanner(BaseScanner):
    """REST API 보안 취약점 스캐너 - 리팩토링 버전"""

    metadata = {
        'id': 'rest_api_security',
        'name': 'REST API 보안 검사',
        'icon': '🔌',
        'description': 'REST API 보안 취약점 탐지 (Rate Limit, Mass Assignment, Data Exposure)',
        'weight': 2,
        'field': 'rest_api_vulnerabilities',
        'category': 'api_auth',
        'OWASP': 'A01:2025',
    }

    API_INDICATORS = [
        '/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql',
        'application/json', 'application/xml'
    ]

    SENSITIVE_ENDPOINTS = [
        '/api/users', '/api/admin', '/api/config', '/api/settings',
        '/api/internal', '/api/debug', '/api/test'
    ]

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
        """REST API 보안 스캔 실행"""
        # API 엔드포인트 탐지
        if not self._detect_api():
            self.vulnerabilities = []
            return

        # 각 보안 검사 수행
        self._check_rate_limiting()
        self._check_excessive_data_exposure()
        self._check_mass_assignment()
        self._check_api_versioning()
        self._check_sensitive_endpoints()

    def _detect_api(self) -> bool:
        """API 사용 여부 탐지"""
        # URL 경로 검사
        if self.url and any(indicator in self.url.lower()
                           for indicator in self.API_INDICATORS[:6]):
            return True

        # Content-Type 검사
        if self.response and hasattr(self.response, 'headers'):
            content_type = self.response.headers.get('Content-Type', '')
            if any(indicator in content_type.lower()
                   for indicator in self.API_INDICATORS[6:]):
                return True

        # HTML에서 API 호출 패턴 찾기
        if self.html_content:
            api_patterns = [
                r'fetch\([\'"`]/api/',
                r'axios\.',
                r'XMLHttpRequest',
                r'ajax\('
            ]
            for pattern in api_patterns:
                if re.search(pattern, self.html_content):
                    return True

        return False

    def _check_rate_limiting(self) -> None:
        """Rate Limiting 검사"""
        if not self.response or not hasattr(self.response, 'headers'):
            return

        headers = self.response.headers
        rate_limit_headers = [
            'X-Rate-Limit-Limit',
            'X-RateLimit-Limit',
            'RateLimit-Limit'
        ]

        has_rate_limit = any(header in headers for header in rate_limit_headers)

        if not has_rate_limit:
            self.vulnerabilities.append({
                'type': 'Missing Rate Limiting',
                'severity': 'high',
                'description': 'API에 Rate Limiting이 설정되지 않았습니다.',
                'recommendation': 'API에 Rate Limiting을 구현하여 과도한 요청을 방지하세요.'
            })

    def _check_excessive_data_exposure(self) -> None:
        """과도한 데이터 노출 검사"""
        if not self.response:
            return

        try:
            # JSON 응답 분석
            if hasattr(self.response, 'text'):
                response_text = self.response.text
                if response_text.startswith('{') or response_text.startswith('['):
                    data = json.loads(response_text)

                    # 민감한 필드 검사
                    sensitive_fields = [
                        'password', 'secret', 'token', 'apikey', 'api_key',
                        'private_key', 'ssn', 'credit_card'
                    ]

                    def check_sensitive(obj, path=''):
                        if isinstance(obj, dict):
                            for key, value in obj.items():
                                lower_key = key.lower()
                                if any(field in lower_key for field in sensitive_fields):
                                    self.vulnerabilities.append({
                                        'type': 'Excessive Data Exposure',
                                        'severity': 'critical',
                                        'field': f'{path}.{key}' if path else key,
                                        'description': f'민감한 필드 "{key}"가 API 응답에 포함되어 있습니다.',
                                        'recommendation': '민감한 정보는 API 응답에서 제외하거나 마스킹 처리하세요.'
                                    })
                                check_sensitive(value, f'{path}.{key}' if path else key)
                        elif isinstance(obj, list):
                            for i, item in enumerate(obj[:3]):  # 처음 3개만 검사
                                check_sensitive(item, f'{path}[{i}]')

                    check_sensitive(data)
        except Exception:
            pass

    def _check_mass_assignment(self) -> None:
        """Mass Assignment 취약점 검사"""
        if not self.html_content:
            return

        # PUT/PATCH 메서드 사용 패턴 찾기
        patterns = [
            r'method\s*[:=]\s*[\'"`]PUT[\'"`]',
            r'method\s*[:=]\s*[\'"`]PATCH[\'"`]',
            r'\.put\(',
            r'\.patch\('
        ]

        for pattern in patterns:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'Potential Mass Assignment',
                    'severity': 'medium',
                    'description': 'PUT/PATCH 메서드 사용이 감지되었습니다. Mass Assignment 취약점 가능성이 있습니다.',
                    'recommendation': 'DTO나 화이트리스트를 사용하여 허용된 필드만 업데이트하도록 제한하세요.'
                })
                break

    def _check_api_versioning(self) -> None:
        """API 버전 관리 검사"""
        if not self.url:
            return

        # 버전 패턴 검사
        version_patterns = [r'/v\d+/', r'/api/v\d+/']
        has_version = any(re.search(pattern, self.url) for pattern in version_patterns)

        if not has_version and '/api/' in self.url:
            self.vulnerabilities.append({
                'type': 'Missing API Versioning',
                'severity': 'low',
                'description': 'API 버전 관리가 구현되지 않았습니다.',
                'recommendation': 'API 버전을 명시하여 하위 호환성을 유지하세요.'
            })

    def _check_sensitive_endpoints(self) -> None:
        """민감한 엔드포인트 검사"""
        if not self.url:
            return

        for endpoint in self.SENSITIVE_ENDPOINTS:
            if endpoint in self.url.lower():
                self.vulnerabilities.append({
                    'type': 'Sensitive Endpoint Exposed',
                    'severity': 'high',
                    'endpoint': endpoint,
                    'description': f'민감한 엔드포인트 "{endpoint}"가 노출되어 있습니다.',
                    'recommendation': '적절한 인증과 권한 검사를 구현하세요.'
                })



    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

