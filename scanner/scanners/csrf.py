"""
CSRFScanner - 자동 수정됨

원본: scanners_refactored_batch2.py
"""

import logging
import re
import warnings
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, urljoin

# BeautifulSoup 경고 무시
from bs4 import MarkupResemblesLocatorWarning
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
from bs4 import BeautifulSoup
import requests
import json
import time
import hashlib
import base64

from scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class CSRFScanner(BaseScanner):
    """CSRF (Cross-Site Request Forgery) 보호 검사 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'csrf',
        'name': 'CSRF 보호 검사',
        'icon': '🔒',
        'description': 'Cross-Site Request Forgery 방어 검증',
        'weight': 1.5,
        'field': 'csrf_protection',
        'category': 'security_basic',
        'OWASP': 'A01:2025',
    }

    # CSRF 토큰 패턴
    CSRF_TOKEN_PATTERNS = [
        r'csrf[_-]?token',
        r'authenticity[_-]?token',
        r'csrfmiddlewaretoken',
        r'__RequestVerificationToken',
        r'_csrf',
        r'x-csrf-token',
        r'x-xsrf-token'
    ]

    # 상태 변경 메서드
    STATE_CHANGING_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH']

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
        """CSRF 보호 검사 실행"""
        # 1. 폼의 CSRF 토큰 검사
        self._scan_forms_for_csrf()

        # 2. AJAX 요청의 CSRF 보호 검사
        self._scan_ajax_csrf_protection()

        # 3. SameSite 쿠키 속성 검사
        self._check_samesite_cookies()

        # 4. Referer/Origin 검증 힌트 검사
        self._check_referer_validation()

    def _scan_forms_for_csrf(self) -> None:
        """폼에서 CSRF 토큰 검사"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')
        forms = soup.find_all('form')

        for idx, form in enumerate(forms):
            method = form.get('method', 'GET').upper()
            action = form.get('action', '')

            # 상태 변경 메서드인 경우만 검사
            if method in self.STATE_CHANGING_METHODS:
                has_csrf_token = False
                csrf_field = None

                # CSRF 토큰 필드 찾기
                inputs = form.find_all('input')
                for input_field in inputs:
                    input_name = input_field.get('name', '').lower()
                    input_type = input_field.get('type', '')

                    # CSRF 토큰 패턴 매칭
                    for pattern in self.CSRF_TOKEN_PATTERNS:
                        if re.search(pattern, input_name, re.IGNORECASE):
                            has_csrf_token = True
                            csrf_field = input_name
                            # 토큰 값이 비어있는지 확인
                            if not input_field.get('value'):
                                self.issues.append({
                                    'type': 'Empty CSRF Token',
                                    'severity': 'high',
                                    'form_index': idx,
                                    'field': csrf_field,
                                    'description': 'CSRF 토큰 필드가 있지만 값이 비어있습니다.',
                                    'recommendation': '서버에서 고유한 CSRF 토큰을 생성하여 설정하세요.'
                                })
                            break

                if not has_csrf_token:
                    # 민감한 작업인지 확인
                    is_sensitive = self._is_sensitive_action(form)

                    self.issues.append({
                        'type': 'Missing CSRF Token',
                        'severity': 'critical' if is_sensitive else 'high',
                        'form_index': idx,
                        'method': method,
                        'action': action,
                        'is_sensitive': is_sensitive,
                        'description': f'{method} 폼에 CSRF 토큰이 없습니다.',
                        'recommendation': 'CSRF 토큰을 추가하여 요청의 정당성을 검증하세요.'
                    })

    def _scan_ajax_csrf_protection(self) -> None:
        """AJAX 요청의 CSRF 보호 검사"""
        if not self.html_content:
            return

        # JavaScript에서 CSRF 토큰 사용 패턴 찾기
        ajax_patterns = [
            r'XMLHttpRequest',
            r'\.ajax\(',
            r'fetch\(',
            r'axios\.'
        ]

        # CSRF 토큰이 헤더에 설정되는지 확인
        csrf_header_patterns = [
            r'setRequestHeader\s*\(\s*["\']X-CSRF',
            r'headers\s*:\s*{[^}]*csrf',
            r'["\']X-CSRF-Token["\']\s*:',
            r'["\']X-XSRF-Token["\']\s*:'
        ]

        has_ajax = any(re.search(p, self.html_content, re.IGNORECASE) for p in ajax_patterns)
        has_csrf_header = any(re.search(p, self.html_content, re.IGNORECASE) for p in csrf_header_patterns)

        if has_ajax and not has_csrf_header:
            # 메타 태그에서 CSRF 토큰 확인
            soup = BeautifulSoup(self.html_content, 'html.parser')
            csrf_meta = soup.find('meta', attrs={'name': re.compile('csrf', re.IGNORECASE)})

            if not csrf_meta:
                self.issues.append({
                    'type': 'AJAX CSRF Protection Missing',
                    'severity': 'high',
                    'description': 'AJAX 요청에 CSRF 토큰이 포함되지 않은 것 같습니다.',
                    'evidence': 'AJAX 사용은 감지되었으나 CSRF 헤더 설정이 없음',
                    'recommendation': 'AJAX 요청에 X-CSRF-Token 헤더를 추가하세요.'
                })

    def _check_samesite_cookies(self) -> None:
        """SameSite 쿠키 속성 검사"""
        # Set-Cookie 헤더 확인
        if self.headers:
            set_cookie = self.headers.get('Set-Cookie', '')
            if set_cookie:
                # SameSite 속성 확인
                if 'SameSite' not in set_cookie:
                    self.issues.append({
                        'type': 'Missing SameSite Cookie Attribute',
                        'severity': 'medium',
                        'description': '쿠키에 SameSite 속성이 설정되지 않았습니다.',
                        'recommendation': 'SameSite=Strict 또는 SameSite=Lax를 설정하여 CSRF를 방지하세요.'
                    })
                elif 'SameSite=None' in set_cookie:
                    self.issues.append({
                        'type': 'Weak SameSite Cookie',
                        'severity': 'medium',
                        'description': 'SameSite=None은 CSRF 보호를 제공하지 않습니다.',
                        'recommendation': 'SameSite=Strict 또는 Lax를 사용하세요.'
                    })

    def _check_referer_validation(self) -> None:
        """Referer/Origin 검증 힌트 찾기"""
        if not self.html_content:
            return

        # JavaScript에서 Referer/Origin 검증 패턴
        validation_patterns = [
            r'document\.referrer',
            r'origin\s*===',
            r'referer\s*===',
            r'window\.location\.origin'
        ]

        has_validation = any(re.search(p, self.html_content, re.IGNORECASE) for p in validation_patterns)

        # Referer 검증이 없고 CSRF 토큰도 없는 경우
        if not has_validation and len([i for i in self.issues if 'Missing CSRF Token' in i['type']]) > 0:
            self.issues.append({
                'type': 'No Secondary CSRF Protection',
                'severity': 'low',
                'description': 'CSRF 토큰 외에 추가적인 보호 메커니즘이 없습니다.',
                'recommendation': 'Referer/Origin 헤더 검증을 추가 보호 계층으로 구현하세요.'
            })

    def _is_sensitive_action(self, form) -> bool:
        """민감한 작업인지 판단"""
        sensitive_keywords = [
            'password', 'delete', 'remove', 'transfer', 'payment',
            'logout', 'account', 'profile', 'settings', 'admin',
            'update', 'change', 'modify', 'edit'
        ]

        form_str = str(form).lower()
        action = form.get('action', '').lower()

        return any(keyword in form_str or keyword in action for keyword in sensitive_keywords)

    def _build_vulnerabilities(self) -> List[Dict[str, Any]]:
        """issues를 vulnerabilities 형식으로 변환"""
        return self.issues

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_csrf_protection': len([i for i in self.issues if 'Missing' not in i['type']]) > 0,
            'missing_tokens': len([i for i in self.issues if 'Missing CSRF Token' in i['type']]),
            'sensitive_forms_unprotected': len([i for i in self.issues if i.get('is_sensitive', False)]),
            'total_forms': len(BeautifulSoup(self.html_content, 'html.parser').find_all('form')) if self.html_content else 0
        }



    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

