"""
SessionSecurityScanner - session_security 스캐너

원본: scanners_refactored_batch6.py
자동 마이그레이션된 독립 스캐너 모듈
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

# core 패키지에서 BaseScanner import
from scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class SessionSecurityScanner(BaseScanner):
    """세션 보안 취약점 스캐너 - 리팩토링 버전"""
    # 스캐너 메타데이터
    metadata = {
        'id': 'session_security',
        'name': '세션 보안 검사',
        'icon': '🎫',
        'description': '세션 보안 검사',
        'weight': 1.5,
        'field': 'session_vulnerabilities',
        'category': 'api_auth',
        'enabled': True
    }

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
        """세션 보안 스캔 실행"""
        # 검사 항목: 쿠키 보안, Session Fixation, 타임아웃, 동시 세션
        self.checked = 4

        self._check_session_cookie_security()
        self._check_session_fixation()
        self._check_session_timeout()
        self._check_concurrent_sessions()

        # 결과 요약
        if self.vulnerabilities:
            high_count = len([v for v in self.vulnerabilities if v.get('severity') in ['critical', 'high']])
            self._add_detail(
                id='session_security_check',
                name='세션 보안 검사',
                status='fail',
                severity='high' if high_count > 0 else 'medium',
                description=f'{len(self.vulnerabilities)}개의 세션 보안 취약점 발견',
                value=f'High: {high_count}개',
                expected='세션 보안 취약점 없음',
                recommendation='HttpOnly, Secure 플래그 설정, 세션 타임아웃 구현하세요.'
            )
        else:
            self._add_detail(
                id='session_security_check',
                name='세션 보안 검사',
                status='pass',
                severity='info',
                description='세션 보안 취약점이 발견되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _check_session_cookie_security(self) -> None:
        """세션 쿠키 보안 설정 검사"""
        if not self.response or not hasattr(self.response, 'cookies'):
            return

        for cookie_name, cookie in self.response.cookies.items():
            # 세션 쿠키 식별
            if 'session' in cookie_name.lower() or 'sid' in cookie_name.lower():
                # HttpOnly 플래그 검사
                if not cookie.get('httponly'):
                    self.vulnerabilities.append({
                        'type': 'Session Cookie Missing HttpOnly',
                        'severity': 'high',
                        'cookie': cookie_name,
                        'description': f'세션 쿠키 "{cookie_name}"에 HttpOnly 플래그가 없습니다.',
                        'recommendation': 'HttpOnly 플래그를 설정하여 XSS 공격을 방지하세요.'
                    })

                # Secure 플래그 검사 (HTTPS인 경우)
                if self.url and self.url.startswith('https') and not cookie.get('secure'):
                    self.vulnerabilities.append({
                        'type': 'Session Cookie Missing Secure Flag',
                        'severity': 'medium',
                        'cookie': cookie_name,
                        'description': f'세션 쿠키 "{cookie_name}"에 Secure 플래그가 없습니다.',
                        'recommendation': 'Secure 플래그를 설정하여 HTTPS에서만 전송되도록 하세요.'
                    })

    def _check_session_fixation(self) -> None:
        """Session Fixation 취약점 검사"""
        if self.url:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            # URL에 세션 ID 전달
            session_params = ['sessionid', 'sid', 'session', 'phpsessid', 'jsessionid']
            for param in session_params:
                if param in params:
                    self.vulnerabilities.append({
                        'type': 'Session ID in URL',
                        'severity': 'high',
                        'parameter': param,
                        'description': f'세션 ID가 URL 파라미터 "{param}"에 노출되어 있습니다.',
                        'recommendation': '세션 ID는 쿠키를 통해서만 전달하세요.'
                    })

    def _check_session_timeout(self) -> None:
        """세션 타임아웃 설정 검사"""
        if self.html_content:
            # 자동 로그아웃 관련 스크립트 검색
            timeout_patterns = [
                r'setTimeout.*logout',
                r'session.*timeout',
                r'idle.*timeout'
            ]

            has_timeout = any(re.search(pattern, self.html_content, re.IGNORECASE)
                            for pattern in timeout_patterns)

            if not has_timeout:
                self.vulnerabilities.append({
                    'type': 'Missing Session Timeout',
                    'severity': 'low',
                    'description': '세션 타임아웃이 구현되지 않은 것으로 보입니다.',
                    'recommendation': '적절한 세션 타임아웃을 구현하세요.'
                })

    def _check_concurrent_sessions(self) -> None:
        """동시 세션 제한 검사"""
        # HTML에서 동시 세션 제한 관련 패턴 검색
        if self.html_content:
            concurrent_patterns = [
                r'concurrent.*session',
                r'multiple.*login',
                r'already.*logged'
            ]

            has_limit = any(re.search(pattern, self.html_content, re.IGNORECASE)
                          for pattern in concurrent_patterns)

            if not has_limit:
                self.vulnerabilities.append({
                    'type': 'No Concurrent Session Control',
                    'severity': 'low',
                    'description': '동시 세션 제한이 구현되지 않은 것으로 보입니다.',
                    'recommendation': '동시 로그인 세션 수를 제한하세요.'
                })


    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

