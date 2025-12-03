"""
AccountEnumerationScanner - account_enumeration 스캐너

원본: scanners_refactored_batch7.py
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


class AccountEnumerationScanner(BaseScanner):
    """계정 열거 취약점 스캐너

    OWASP Top 10 2025 A06 + A07 대응
    - 사용자명/이메일 존재 여부 유출
    - 응답 차이 분석
    """
    # 스캐너 메타데이터
    metadata = {
        'id': 'account_enumeration',
        'name': '계정 열거 검사',
        'icon': '👥',
        'description': '계정 열거 검사',
        'weight': 1,
        'field': 'account_enumeration_vulnerabilities',
        'category': 'business_logic',
        'enabled': True
    }

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None):
        """스캐너 초기화"""
        super().__init__(url=url or '', response=response,
                        html_content=html_content)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client
        self.vulnerabilities = []

    def _prepare(self) -> None:
        """스캔 준비"""
        self.vulnerabilities = []

    def _execute_scan(self) -> None:
        """실제 스캔 로직 실행"""
        # 검사 항목: 로그인 폼, 에러 메시지 차이
        self.checked = 2

        # 1. 로그인 폼 탐지
        if self.html_content:
            self._detect_login_forms()

        # 2. 에러 메시지 차이 탐지
        self._check_error_message_differences()

        # 결과 요약
        if self.vulnerabilities:
            medium_count = len([v for v in self.vulnerabilities if v.get('severity') == 'medium'])
            self._add_detail(
                id='account_enumeration_check',
                name='계정 열거 검사',
                status='fail',
                severity='medium' if medium_count > 0 else 'low',
                description=f'{len(self.vulnerabilities)}개의 계정 열거 취약점 발견',
                value=f'Medium: {medium_count}개',
                expected='계정 열거 취약점 없음',
                recommendation='존재하지 않는 계정과 잘못된 비밀번호에 대해 동일한 에러 메시지를 표시하세요.'
            )
        else:
            self._add_detail(
                id='account_enumeration_check',
                name='계정 열거 검사',
                status='pass',
                severity='info',
                description='계정 열거 취약점이 발견되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _build_result(self) -> Dict[str, Any]:
        """결과 구성"""
        return {
            'vulnerabilities': self.vulnerabilities,
            'total': len(self.vulnerabilities),
            'severity': self._calculate_severity(),
            'recommendations': self._get_recommendations(),
            'has_account_enumeration': len(self.vulnerabilities) > 0
        }

    def _detect_login_forms(self) -> None:
        """로그인 폼 탐지"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 로그인 폼 또는 비밀번호 입력이 있는 폼 찾기
        login_indicators = ['login', 'signin', 'password', 'email', 'username']

        for form in soup.find_all('form'):
            form_text = str(form).lower()
            if any(indicator in form_text for indicator in login_indicators):
                self.vulnerabilities.append({
                    'type': 'Login Form Detected',
                    'severity': 'low',
                    'description': '로그인 폼이 발견되었습니다. 계정 열거 취약점 테스트가 필요합니다.',
                    'recommendation': '존재하지 않는 계정과 잘못된 비밀번호에 대해 동일한 에러 메시지를 표시하세요.'
                })
                break

    def _check_error_message_differences(self) -> None:
        """에러 메시지 차이 탐지"""
        if not self.html_content:
            return

        # 계정 존재 여부를 알려주는 메시지 패턴
        enumeration_patterns = [
            r'user.*not.*found',
            r'email.*not.*exist',
            r'invalid.*username',
            r'account.*does.*not.*exist',
            r'사용자.*없음',
            r'이메일.*존재.*않',
        ]

        content_lower = self.html_content.lower()

        for pattern in enumeration_patterns:
            if re.search(pattern, content_lower):
                self.vulnerabilities.append({
                    'type': 'Account Enumeration Message',
                    'severity': 'medium',
                    'description': '계정 존재 여부를 알려주는 에러 메시지가 발견되었습니다.',
                    'recommendation': '"잘못된 이메일 또는 비밀번호입니다"와 같은 일반적인 메시지를 사용하세요.'
                })
                break

    def _calculate_severity(self) -> str:
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        if any(v.get('severity') == 'medium' for v in self.vulnerabilities):
            return 'medium'
        else:
            return 'low'

    def _get_recommendations(self) -> List[str]:
        """보안 권장사항"""
        return [
            '계정 존재 여부와 비밀번호 오류에 대해 동일한 에러 메시지를 표시하세요.',
            '응답 시간도 일정하게 유지하세요 (타이밍 공격 방지).',
            '비밀번호 재설정 시에도 계정 존재 여부를 알려주지 마세요.',
            'CAPTCHA를 사용하여 자동화된 계정 열거를 방지하세요.'
        ]


    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

