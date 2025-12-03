"""
PasswordPolicyScanner - password_policy 스캐너

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


class PasswordPolicyScanner(BaseScanner):
    """비밀번호 정책 검사 스캐너 - 리팩토링 버전"""
    # 스캐너 메타데이터
    metadata = {
        'id': 'password_policy',
        'name': '비밀번호 정책 검사',
        'icon': '🔒',
        'description': '비밀번호 정책 검사',
        'weight': 1,
        'field': 'password_policy',
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
        """비밀번호 정책 스캔 실행"""
        self._check_password_fields()
        self._check_password_complexity()
        self._check_brute_force_protection()
        self._check_password_reset()

    def _check_password_fields(self) -> None:
        """비밀번호 입력 필드 검사"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')
        password_fields = soup.find_all('input', {'type': 'password'})

        for field in password_fields:
            # 자동완성 허용 검사
            if field.get('autocomplete') != 'off':
                self.vulnerabilities.append({
                    'type': 'Password Autocomplete Enabled',
                    'severity': 'low',
                    'field': field.get('name', 'unknown'),
                    'description': '비밀번호 필드에 자동완성이 활성화되어 있습니다.',
                    'recommendation': 'autocomplete="off" 속성을 추가하세요.'
                })

            # 최소 길이 검사
            minlength = field.get('minlength')
            if not minlength or int(minlength) < 8:
                self.vulnerabilities.append({
                    'type': 'Weak Password Length',
                    'severity': 'medium',
                    'field': field.get('name', 'unknown'),
                    'description': '비밀번호 최소 길이가 8자 미만입니다.',
                    'recommendation': '최소 8자 이상의 비밀번호를 요구하세요.'
                })

    def _check_password_complexity(self) -> None:
        """비밀번호 복잡도 검사"""
        if not self.html_content:
            return

        # 패스워드 검증 패턴 찾기
        complexity_patterns = [
            r'(?=.*[A-Z])',  # 대문자
            r'(?=.*[0-9])',   # 숫자
            r'(?=.*[!@#$%])', # 특수문자
            r'pattern\s*=\s*["\'].*(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])'
        ]

        # 패스워드 필드가 있는지 확인
        has_password_field = re.search(r'type\s*=\s*["\']password["\']', self.html_content)

        if has_password_field:
            has_complexity = any(re.search(pattern, self.html_content)
                               for pattern in complexity_patterns)

            if not has_complexity:
                self.vulnerabilities.append({
                    'type': 'No Password Complexity Requirements',
                    'severity': 'medium',
                    'description': '비밀번호 복잡도 요구사항이 구현되지 않았습니다.',
                    'recommendation': '대/소문자, 숫자, 특수문자를 포함하도록 요구하세요.'
                })

    def _check_brute_force_protection(self) -> None:
        """Brute Force 방어 메커니즘 검사"""
        if not self.html_content:
            return

        # CAPTCHA 또는 Rate Limiting 패턴 찾기
        protection_patterns = [
            r'captcha',
            r'recaptcha',
            r'rate.*limit',
            r'too.*many.*attempts',
            r'account.*locked'
        ]

        has_protection = any(re.search(pattern, self.html_content, re.IGNORECASE)
                           for pattern in protection_patterns)

        if not has_protection:
            self.vulnerabilities.append({
                'type': 'No Brute Force Protection',
                'severity': 'high',
                'description': 'Brute Force 공격 방어 메커니즘이 감지되지 않았습니다.',
                'recommendation': 'CAPTCHA, 계정 잠금, Rate Limiting을 구현하세요.'
            })

    def _check_password_reset(self) -> None:
        """비밀번호 재설정 보안 검사"""
        if not self.html_content:
            return

        # 비밀번호 재설정 관련 패턴
        reset_patterns = [
            r'forgot.*password',
            r'reset.*password',
            r'password.*recovery'
        ]

        has_reset = any(re.search(pattern, self.html_content, re.IGNORECASE)
                       for pattern in reset_patterns)

        if has_reset:
            # 보안 질문 사용 검사
            if re.search(r'security.*question', self.html_content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'Weak Password Reset',
                    'severity': 'medium',
                    'description': '보안 질문은 약한 비밀번호 재설정 방법입니다.',
                    'recommendation': '이메일 또는 SMS 기반의 안전한 재설정 방법을 사용하세요.'
                })


    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

