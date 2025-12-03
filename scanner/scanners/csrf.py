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
        if not self.html_content:
            self.checked = 0
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')
        forms = soup.find_all('form')
        state_changing_forms = [f for f in forms if f.get('method', 'GET').upper() in self.STATE_CHANGING_METHODS]

        # 검사 항목: 폼 CSRF, AJAX CSRF, SameSite 쿠키
        self.checked = len(state_changing_forms) + 2  # 폼 수 + AJAX + SameSite

        # 1. 폼의 CSRF 토큰 검사
        self._scan_forms_for_csrf(state_changing_forms)

        # 2. AJAX 요청의 CSRF 보호 검사
        self._scan_ajax_csrf_protection()

        # 3. SameSite 쿠키 속성 검사
        self._check_samesite_cookies()

    def _scan_forms_for_csrf(self, forms: list) -> None:
        """폼에서 CSRF 토큰 검사"""
        for idx, form in enumerate(forms):
            method = form.get('method', 'GET').upper()
            action = form.get('action', '')
            form_id = f'form_{idx}'
            form_name = action if action else f'Form #{idx + 1}'

            has_csrf_token = False
            csrf_field = None
            token_empty = False

            # CSRF 토큰 필드 찾기
            inputs = form.find_all('input')
            for input_field in inputs:
                input_name = input_field.get('name', '').lower()

                for pattern in self.CSRF_TOKEN_PATTERNS:
                    if re.search(pattern, input_name, re.IGNORECASE):
                        has_csrf_token = True
                        csrf_field = input_name
                        if not input_field.get('value'):
                            token_empty = True
                        break

            if has_csrf_token and not token_empty:
                self._add_detail(
                    id=form_id,
                    name=f'{method} {form_name}',
                    status='pass',
                    severity='info',
                    description=f'CSRF 토큰 발견: {csrf_field}',
                    value=csrf_field,
                    expected='CSRF 토큰 필드',
                    recommendation=None
                )
            elif has_csrf_token and token_empty:
                self._add_detail(
                    id=form_id,
                    name=f'{method} {form_name}',
                    status='warning',
                    severity='high',
                    description='CSRF 토큰 필드는 있지만 값이 비어있음',
                    value=f'{csrf_field}=(empty)',
                    expected='유효한 토큰 값',
                    recommendation='서버에서 고유한 CSRF 토큰을 생성하여 설정하세요.'
                )
                self.issues.append({
                    'type': 'Empty CSRF Token',
                    'severity': 'high',
                    'form_index': idx,
                    'description': 'CSRF 토큰 필드가 있지만 값이 비어있습니다.',
                    'recommendation': '서버에서 고유한 CSRF 토큰을 생성하여 설정하세요.'
                })
            else:
                is_sensitive = self._is_sensitive_action(form)
                severity = 'critical' if is_sensitive else 'high'
                self._add_detail(
                    id=form_id,
                    name=f'{method} {form_name}',
                    status='fail',
                    severity=severity,
                    description=f'CSRF 토큰 없음' + (' (민감한 작업)' if is_sensitive else ''),
                    value=None,
                    expected='CSRF 토큰 필드',
                    recommendation='CSRF 토큰을 추가하여 요청의 정당성을 검증하세요.'
                )
                self.issues.append({
                    'type': 'Missing CSRF Token',
                    'severity': severity,
                    'form_index': idx,
                    'method': method,
                    'action': action,
                    'description': f'{method} 폼에 CSRF 토큰이 없습니다.',
                    'recommendation': 'CSRF 토큰을 추가하여 요청의 정당성을 검증하세요.'
                })

    def _scan_ajax_csrf_protection(self) -> None:
        """AJAX 요청의 CSRF 보호 검사"""
        ajax_patterns = [
            r'XMLHttpRequest',
            r'\.ajax\(',
            r'fetch\(',
            r'axios\.'
        ]

        csrf_header_patterns = [
            r'setRequestHeader\s*\(\s*["\']X-CSRF',
            r'headers\s*:\s*{[^}]*csrf',
            r'["\']X-CSRF-Token["\']\s*:',
            r'["\']X-XSRF-Token["\']\s*:'
        ]

        has_ajax = any(re.search(p, self.html_content, re.IGNORECASE) for p in ajax_patterns)
        has_csrf_header = any(re.search(p, self.html_content, re.IGNORECASE) for p in csrf_header_patterns)

        if not has_ajax:
            self._add_detail(
                id='ajax_csrf',
                name='AJAX CSRF 보호',
                status='pass',
                severity='info',
                description='AJAX 요청이 감지되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )
        elif has_csrf_header:
            self._add_detail(
                id='ajax_csrf',
                name='AJAX CSRF 보호',
                status='pass',
                severity='info',
                description='AJAX 요청에 CSRF 헤더 설정 감지됨',
                value='X-CSRF-Token 헤더 사용',
                expected='CSRF 헤더',
                recommendation=None
            )
        else:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            csrf_meta = soup.find('meta', attrs={'name': re.compile('csrf', re.IGNORECASE)})

            if csrf_meta:
                self._add_detail(
                    id='ajax_csrf',
                    name='AJAX CSRF 보호',
                    status='pass',
                    severity='info',
                    description='CSRF 메타 태그 발견',
                    value=csrf_meta.get('content', '')[:50],
                    expected='CSRF 토큰',
                    recommendation=None
                )
            else:
                self._add_detail(
                    id='ajax_csrf',
                    name='AJAX CSRF 보호',
                    status='fail',
                    severity='high',
                    description='AJAX 사용 감지되었으나 CSRF 보호 없음',
                    value=None,
                    expected='X-CSRF-Token 헤더 또는 메타 태그',
                    recommendation='AJAX 요청에 X-CSRF-Token 헤더를 추가하세요.'
                )
                self.issues.append({
                    'type': 'AJAX CSRF Protection Missing',
                    'severity': 'high',
                    'description': 'AJAX 요청에 CSRF 토큰이 포함되지 않은 것 같습니다.',
                    'recommendation': 'AJAX 요청에 X-CSRF-Token 헤더를 추가하세요.'
                })

    def _check_samesite_cookies(self) -> None:
        """SameSite 쿠키 속성 검사"""
        set_cookie = self.headers.get('Set-Cookie', '') if self.headers else ''

        if not set_cookie:
            self._add_detail(
                id='samesite_cookie',
                name='SameSite 쿠키',
                status='pass',
                severity='info',
                description='Set-Cookie 헤더 없음',
                value=None,
                expected=None,
                recommendation=None
            )
        elif 'SameSite=Strict' in set_cookie or 'SameSite=Lax' in set_cookie:
            self._add_detail(
                id='samesite_cookie',
                name='SameSite 쿠키',
                status='pass',
                severity='info',
                description='SameSite 속성이 안전하게 설정됨',
                value='Strict' if 'Strict' in set_cookie else 'Lax',
                expected='Strict 또는 Lax',
                recommendation=None
            )
        elif 'SameSite=None' in set_cookie:
            self._add_detail(
                id='samesite_cookie',
                name='SameSite 쿠키',
                status='warning',
                severity='medium',
                description='SameSite=None은 CSRF 보호를 제공하지 않음',
                value='None',
                expected='Strict 또는 Lax',
                recommendation='SameSite=Strict 또는 Lax를 사용하세요.'
            )
            self.issues.append({
                'type': 'Weak SameSite Cookie',
                'severity': 'medium',
                'description': 'SameSite=None은 CSRF 보호를 제공하지 않습니다.',
                'recommendation': 'SameSite=Strict 또는 Lax를 사용하세요.'
            })
        else:
            self._add_detail(
                id='samesite_cookie',
                name='SameSite 쿠키',
                status='warning',
                severity='medium',
                description='SameSite 속성이 설정되지 않음',
                value=None,
                expected='SameSite=Strict 또는 Lax',
                recommendation='SameSite=Strict 또는 SameSite=Lax를 설정하세요.'
            )
            self.issues.append({
                'type': 'Missing SameSite Cookie Attribute',
                'severity': 'medium',
                'description': '쿠키에 SameSite 속성이 설정되지 않았습니다.',
                'recommendation': 'SameSite=Strict 또는 SameSite=Lax를 설정하여 CSRF를 방지하세요.'
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

