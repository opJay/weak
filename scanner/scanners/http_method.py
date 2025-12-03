"""
HTTPMethodScanner - 자동 수정됨

원본: scanners_refactored_batch3.py
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


class HTTPMethodScanner(BaseScanner):
    """안전하지 않은 HTTP 메서드 검사 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'http_method',
        'name': 'HTTP 메서드 검사',
        'icon': '📡',
        'description': '위험한 HTTP 메서드 활성화 검사',
        'weight': 0.5,
        'field': 'http_method',
        'category': 'security_basic',
        'OWASP': 'A05:2025',
    }

    # 위험한 HTTP 메서드
    DANGEROUS_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS']

    def __init__(self, url: str = None, session: requests.Session = None, **kwargs):
        """
        Args:
            url: 검사할 URL
            session: HTTP 세션 (선택적)
            **kwargs: BaseScanner 호환 인자
        """
        # BaseScanner 초기화
        super().__init__(url=url or '', **kwargs)

        # HTTP 클라이언트 설정
        if session is not None:
            self.http_client = session
        elif not hasattr(self, 'http_client'):
            self.http_client = requests.Session()

    def _execute_scan(self) -> None:
        """HTTP 메서드 검사 실행"""
        # 검사 항목: OPTIONS 메서드, TRACE 메서드
        self.checked = 2

        if not self.url:
            logger.warning("No URL provided for HTTP method scan")
            return

        # OPTIONS 요청으로 허용된 메서드 확인
        self._check_options_method()

        # TRACE 메서드 직접 테스트
        self._check_trace_method()

    def _check_options_method(self) -> None:
        """OPTIONS 요청으로 Allow 헤더 확인"""
        try:
            response = self.http_client.options(self.url, timeout=10)
            allowed_methods = response.headers.get('Allow', '')

            if not allowed_methods:
                logger.debug(f"No Allow header in OPTIONS response for {self.url}")
                self._add_detail(
                    id='options_method',
                    name='HTTP 메서드 허용 목록',
                    status='pass',
                    severity='info',
                    description='Allow 헤더가 없음 (기본 설정)',
                    value=None,
                    expected=None,
                    recommendation=None
                )
                return

            # 위험한 메서드 찾기
            dangerous_found = []
            for method in self.DANGEROUS_METHODS:
                if method in allowed_methods:
                    dangerous_found.append(method)

            if dangerous_found:
                self.issues.append({
                    'type': 'Dangerous HTTP Methods Allowed',
                    'severity': 'medium',
                    'methods': dangerous_found,
                    'description': f'위험한 HTTP 메서드가 허용되고 있습니다: {", ".join(dangerous_found)}',
                    'evidence': f'Allow: {allowed_methods}',
                    'recommendation': '불필요한 HTTP 메서드를 비활성화하세요.'
                })
                self._add_detail(
                    id='options_method',
                    name='HTTP 메서드 허용 목록',
                    status='warning',
                    severity='medium',
                    description=f'위험한 메서드 허용: {", ".join(dangerous_found)}',
                    value=allowed_methods,
                    expected='GET, POST, HEAD만 허용',
                    recommendation='불필요한 HTTP 메서드를 비활성화하세요.'
                )
            else:
                self._add_detail(
                    id='options_method',
                    name='HTTP 메서드 허용 목록',
                    status='pass',
                    severity='info',
                    description='위험한 HTTP 메서드가 허용되지 않음',
                    value=allowed_methods,
                    expected=None,
                    recommendation=None
                )

        except Exception as e:
            logger.debug(f"OPTIONS request failed: {str(e)}")
            self._add_detail(
                id='options_method',
                name='HTTP 메서드 허용 목록',
                status='pass',
                severity='info',
                description='OPTIONS 요청 불가 (일반적으로 안전)',
                value=None,
                expected=None,
                recommendation=None
            )

    def _check_trace_method(self) -> None:
        """TRACE 메서드 직접 테스트 (XST 공격 가능성)"""
        try:
            response = self.http_client.request('TRACE', self.url, timeout=10)

            # 405 Method Not Allowed가 아니면 TRACE가 활성화된 것
            if response.status_code != 405:
                self.issues.append({
                    'type': 'TRACE Method Enabled',
                    'severity': 'medium',
                    'status_code': response.status_code,
                    'description': 'TRACE 메서드가 활성화되어 있습니다. (XST 공격 가능)',
                    'evidence': f'TRACE request returned status {response.status_code}',
                    'recommendation': 'TRACE 메서드를 비활성화하세요.'
                })

                # TRACE 응답에 요청 헤더가 반사되는지 확인
                xst_vulnerable = response.text and 'TRACE' in response.text
                if xst_vulnerable:
                    self.issues.append({
                        'type': 'XST (Cross-Site Tracing) Vulnerable',
                        'severity': 'high',
                        'description': 'TRACE 메서드가 요청을 그대로 반사합니다.',
                        'recommendation': 'TRACE 메서드를 즉시 비활성화하세요.'
                    })

                self._add_detail(
                    id='trace_method',
                    name='TRACE 메서드 검사',
                    status='fail',
                    severity='high' if xst_vulnerable else 'medium',
                    description='TRACE 메서드 활성화됨' + (' (XST 취약)' if xst_vulnerable else ''),
                    value=f'Status: {response.status_code}',
                    expected='405 Method Not Allowed',
                    recommendation='TRACE 메서드를 비활성화하세요.'
                )
            else:
                self._add_detail(
                    id='trace_method',
                    name='TRACE 메서드 검사',
                    status='pass',
                    severity='info',
                    description='TRACE 메서드가 비활성화됨',
                    value='405 Method Not Allowed',
                    expected=None,
                    recommendation=None
                )

        except Exception as e:
            logger.debug(f"TRACE request failed: {str(e)}")
            self._add_detail(
                id='trace_method',
                name='TRACE 메서드 검사',
                status='pass',
                severity='info',
                description='TRACE 요청 불가 (일반적으로 안전)',
                value=None,
                expected=None,
                recommendation=None
            )

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_dangerous_methods': len(self.issues) > 0,
            'trace_enabled': any('TRACE' in issue.get('type', '') for issue in self.issues),
            'xst_vulnerable': any('XST' in issue.get('type', '') for issue in self.issues)
        }



    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

