"""
RateLimitingScanner - rate_limiting 스캐너

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


class RateLimitingScanner(BaseScanner):
    """Rate Limiting 검사 스캐너 - 리팩토링 버전"""
    # 스캐너 메타데이터
    metadata = {
        'id': 'rate_limiting',
        'name': 'Rate Limiting 검사',
        'icon': '⏱️',
        'description': 'Rate Limiting 검사',
        'weight': 1,
        'field': 'rate_limiting',
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
        """Rate Limiting 스캔 실행"""
        self._check_rate_limit_headers()
        self._check_retry_after()
        self._check_api_rate_limits()
        self._check_login_rate_limits()

    def _check_rate_limit_headers(self) -> None:
        """Rate Limit 헤더 검사"""
        if not self.response or not hasattr(self.response, 'headers'):
            return

        headers = self.response.headers
        rate_headers = [
            'X-Rate-Limit-Limit',
            'X-RateLimit-Limit',
            'RateLimit-Limit'
        ]

        has_rate_limit = any(header in headers for header in rate_headers)

        if not has_rate_limit:
            self.vulnerabilities.append({
                'type': 'Missing Rate Limit Headers',
                'severity': 'medium',
                'description': 'Rate Limiting 헤더가 설정되지 않았습니다.',
                'recommendation': 'X-Rate-Limit-* 헤더를 구현하여 클라이언트에 제한 정보를 제공하세요.'
            })

    def _check_retry_after(self) -> None:
        """Retry-After 헤더 검사"""
        if not self.response or not hasattr(self.response, 'headers'):
            return

        if self.response.status_code == 429 and 'Retry-After' not in self.response.headers:
            self.vulnerabilities.append({
                'type': 'Missing Retry-After Header',
                'severity': 'low',
                'description': '429 응답에 Retry-After 헤더가 없습니다.',
                'recommendation': 'Rate limit 초과 시 Retry-After 헤더를 제공하세요.'
            })

    def _check_api_rate_limits(self) -> None:
        """API Rate Limiting 검사"""
        if self.url and '/api/' in self.url:
            if not self.response or not hasattr(self.response, 'headers'):
                return

            headers = self.response.headers
            if not any('rate' in h.lower() or 'limit' in h.lower() for h in headers):
                self.vulnerabilities.append({
                    'type': 'API Without Rate Limiting',
                    'severity': 'high',
                    'description': 'API 엔드포인트에 Rate Limiting이 구현되지 않았습니다.',
                    'recommendation': 'API에 적절한 Rate Limiting을 구현하세요.'
                })

    def _check_login_rate_limits(self) -> None:
        """로그인 Rate Limiting 검사"""
        if self.html_content:
            # 로그인 폼 탐지
            login_patterns = [
                r'<form.*login',
                r'<input.*type="password"',
                r'action="/login"'
            ]

            is_login_page = any(re.search(pattern, self.html_content, re.IGNORECASE)
                               for pattern in login_patterns)

            if is_login_page:
                # Rate limiting 관련 메시지 검색
                limit_patterns = [
                    r'too many attempts',
                    r'rate limit',
                    r'try again later'
                ]

                has_limit = any(re.search(pattern, self.html_content, re.IGNORECASE)
                              for pattern in limit_patterns)

                if not has_limit:
                    self.vulnerabilities.append({
                        'type': 'Login Without Rate Limiting',
                        'severity': 'high',
                        'description': '로그인 페이지에 Rate Limiting이 구현되지 않았습니다.',
                        'recommendation': '로그인 시도 횟수를 제한하세요.'
                    })


    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

