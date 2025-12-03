"""
AuthorizationScanner - authorization 스캐너

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


class AuthorizationScanner(BaseScanner):
    """인가(Authorization) 취약점 스캐너 - 리팩토링 버전"""
    # 스캐너 메타데이터
    metadata = {
        'id': 'authorization',
        'name': '인가 검사',
        'icon': '🚪',
        'description': '인가 검사',
        'weight': 2,
        'field': 'authorization_issues',
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
        """인가 취약점 스캔 실행"""
        self._check_direct_object_references()
        self._check_predictable_ids()
        self._check_admin_interfaces()
        self._check_function_level_access()

    def _check_direct_object_references(self) -> None:
        """직접 객체 참조(IDOR) 검사"""
        if not self.url:
            return

        # URL에서 ID 패턴 찾기
        id_patterns = [
            r'/user/(\d+)',
            r'/profile/(\d+)',
            r'/document/(\d+)',
            r'/order/(\d+)',
            r'[?&]id=(\d+)',
            r'[?&]uid=(\d+)'
        ]

        for pattern in id_patterns:
            match = re.search(pattern, self.url)
            if match:
                id_value = match.group(1)
                if id_value and id_value.isdigit():
                    self.vulnerabilities.append({
                        'type': 'Direct Object Reference',
                        'severity': 'high',
                        'pattern': pattern,
                        'value': id_value,
                        'description': '직접 객체 참조(IDOR) 패턴이 감지되었습니다.',
                        'recommendation': '적절한 권한 검증을 구현하고 UUID 사용을 고려하세요.'
                    })

    def _check_predictable_ids(self) -> None:
        """예측 가능한 ID 패턴 검사"""
        if not self.html_content:
            return

        # 연속적인 ID 패턴 찾기
        sequential_patterns = [
            r'id["\']?\s*[:=]\s*["\']?\d{1,6}["\']?',
            r'userId["\']?\s*[:=]\s*["\']?\d{1,6}["\']?',
            r'recordId["\']?\s*[:=]\s*["\']?\d{1,6}["\']?'
        ]

        for pattern in sequential_patterns:
            matches = re.findall(pattern, self.html_content)
            if len(matches) > 2:
                self.vulnerabilities.append({
                    'type': 'Predictable Resource IDs',
                    'severity': 'medium',
                    'description': '예측 가능한 연속적인 ID가 사용되고 있습니다.',
                    'recommendation': 'UUID나 랜덤한 식별자를 사용하세요.'
                })
                break

    def _check_admin_interfaces(self) -> None:
        """관리자 인터페이스 접근 제어 검사"""
        admin_patterns = [
            '/admin', '/administrator', '/management',
            '/control-panel', '/dashboard/admin'
        ]

        # URL 검사
        if self.url:
            for pattern in admin_patterns:
                if pattern in self.url.lower():
                    # 인증 관련 헤더 확인
                    if self.response and hasattr(self.response, 'status_code'):
                        if self.response.status_code == 200:
                            self.vulnerabilities.append({
                                'type': 'Admin Interface Exposed',
                                'severity': 'critical',
                                'url': self.url,
                                'description': '관리자 인터페이스가 노출되어 있습니다.',
                                'recommendation': '강력한 인증 및 IP 제한을 구현하세요.'
                            })

    def _check_function_level_access(self) -> None:
        """함수 레벨 접근 제어 검사"""
        if not self.html_content:
            return

        # 민감한 기능 패턴
        sensitive_functions = [
            r'deleteUser',
            r'modifyRole',
            r'updatePermission',
            r'exportData',
            r'resetPassword'
        ]

        for func in sensitive_functions:
            if re.search(func, self.html_content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'Function Level Access Control',
                    'severity': 'high',
                    'function': func,
                    'description': f'민감한 기능 "{func}"이 클라이언트에 노출되어 있습니다.',
                    'recommendation': '서버 측에서 적절한 권한 검증을 구현하세요.'
                })

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata