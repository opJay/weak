"""
OAuthSecurityScanner - oauth_security 스캐너

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


class OAuthSecurityScanner(BaseScanner):
    """OAuth 보안 취약점 스캐너 - 리팩토링 버전"""
    # 스캐너 메타데이터
    metadata = {
        'id': 'o_auth_security',
        'name': 'OAuth 보안 검사',
        'icon': '🔐',
        'description': 'OAuth 보안 검사',
        'weight': 1.5,
        'field': 'oauth_vulnerabilities',
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
        """OAuth 보안 스캔 실행"""
        # OAuth 사용 여부 탐지
        if not self._detect_oauth():
            self.vulnerabilities = []
            return

        # 각 보안 검사 수행
        self._check_state_parameter()
        self._check_redirect_uri_validation()
        self._check_token_exposure()
        self._check_implicit_flow()

    def _detect_oauth(self) -> bool:
        """OAuth 사용 여부 탐지"""
        # URL 파라미터 검사
        if self.url:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)
            oauth_params = ['client_id', 'redirect_uri', 'response_type', 'scope', 'state']
            if any(param in params for param in oauth_params):
                return True

        # HTML에서 OAuth 패턴 찾기
        if self.html_content:
            oauth_patterns = [
                r'oauth',
                r'authorization_code',
                r'client_id',
                r'redirect_uri',
                r'/authorize',
                r'/token'
            ]
            for pattern in oauth_patterns:
                if re.search(pattern, self.html_content, re.IGNORECASE):
                    return True

        return False

    def _check_state_parameter(self) -> None:
        """State 파라미터 CSRF 보호 검사"""
        if self.url:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            # OAuth flow에서 state 파라미터 누락
            if 'response_type' in params and 'state' not in params:
                self.vulnerabilities.append({
                    'type': 'Missing OAuth State Parameter',
                    'severity': 'high',
                    'description': 'OAuth state 파라미터가 없어 CSRF 공격에 취약합니다.',
                    'recommendation': '예측 불가능한 state 파라미터를 생성하고 검증하세요.'
                })

    def _check_redirect_uri_validation(self) -> None:
        """Redirect URI 검증 검사"""
        if self.url:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            if 'redirect_uri' in params:
                redirect_uri = params['redirect_uri'][0]

                # Open Redirect 가능성
                if redirect_uri.startswith('//') or redirect_uri.startswith('http'):
                    self.vulnerabilities.append({
                        'type': 'OAuth Open Redirect',
                        'severity': 'medium',
                        'description': 'redirect_uri가 외부 URL을 허용할 수 있습니다.',
                        'recommendation': '화이트리스트 방식으로 redirect_uri를 검증하세요.'
                    })

    def _check_token_exposure(self) -> None:
        """토큰 노출 검사"""
        if self.html_content:
            # URL Fragment에 토큰 노출 패턴
            token_patterns = [
                r'#access_token',
                r'#token',
                r'location\.hash',
                r'access_token'
            ]

            for pattern in token_patterns:
                if re.search(pattern, self.html_content, re.IGNORECASE):
                    self.vulnerabilities.append({
                        'type': 'Token Exposure in URL',
                        'severity': 'high',
                        'description': '액세스 토큰이 URL fragment에 노출될 수 있습니다.',
                        'recommendation': 'Authorization Code flow를 사용하고 토큰은 백엔드에서 처리하세요.'
                    })
                    break

    def _check_implicit_flow(self) -> None:
        """Implicit Flow 사용 검사"""
        if self.url:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            if params.get('response_type') == ['token']:
                self.vulnerabilities.append({
                    'type': 'Implicit Flow Usage',
                    'severity': 'medium',
                    'description': 'Implicit Flow는 보안상 권장되지 않습니다.',
                    'recommendation': 'PKCE를 사용한 Authorization Code flow로 마이그레이션하세요.'
                })


    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

