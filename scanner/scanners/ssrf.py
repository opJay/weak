"""
SSRFScanner - 자동 수정됨

원본: scanners_refactored_batch4.py
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


class SSRFScanner(BaseScanner):
    """SSRF (Server-Side Request Forgery) 취약점 스캐너"""

    metadata = {
        'id': 'ssrf',
        'name': 'SSRF 취약점 스캔',
        'icon': '🌐',
        'description': '서버가 공격자가 지정한 URL로 요청을 보내는 취약점 탐지',
        'weight': 2,
        'field': 'ssrf_vulnerabilities',
        'category': 'security_advanced',
        'OWASP': 'A04:2025',
    }

    # 내부 IP 대역
    INTERNAL_IPS = [
        '127.0.0.1', '0.0.0.0', 'localhost',
        '10.0.0.1', '192.168.1.1', '172.16.0.1'
    ]

    # Cloud Metadata 엔드포인트
    CLOUD_METADATA = [
        '169.254.169.254',  # AWS, Azure, GCP
    ]

    # SSRF 관련 파라미터
    SSRF_PARAMS = [
        'url', 'uri', 'path', 'dest', 'redirect', 'link',
        'file', 'document', 'folder', 'root', 'page', 'proxy',
        'callback', 'return', 'feed', 'host', 'port', 'to', 'out'
    ]

    def __init__(self, url: str = None, html_content: str = None, **kwargs):
        """
        Args:
            url: 검사할 URL
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        # BaseScanner 초기화
        super().__init__(url=url or '', **kwargs)
        self.html_content = html_content or ''

    def _execute_scan(self) -> None:
        """SSRF 취약점 검사 실행"""
        # 검사 항목: URL 파라미터, 폼 입력, URL 입력 필드
        self.checked = 3

        if self.url:
            self._scan_url_parameters()

        if self.html_content:
            self._scan_forms()
            self._scan_url_inputs()

        # 결과 요약
        if self.issues:
            critical_count = len([i for i in self.issues if i.get('severity') == 'critical'])
            self._add_detail(
                id='ssrf_check',
                name='SSRF 취약점 검사',
                status='fail',
                severity='critical' if critical_count > 0 else 'high',
                description=f'{len(self.issues)}개의 SSRF 취약점 발견',
                value=f'Critical: {critical_count}개',
                expected='SSRF 취약점 없음',
                recommendation='사용자 입력 URL을 화이트리스트로 제한하고 내부 IP를 차단하세요.'
            )
        else:
            self._add_detail(
                id='ssrf_check',
                name='SSRF 취약점 검사',
                status='pass',
                severity='info',
                description='SSRF 취약점이 발견되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _scan_url_parameters(self) -> None:
        """URL 파라미터에서 SSRF 취약점 검사"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param_name in params.keys():
                if param_name.lower() in self.SSRF_PARAMS:
                    param_value = params[param_name][0] if params[param_name] else ''

                    # URL 형식인지 확인
                    if param_value.startswith(('http://', 'https://', '//')):
                        self.issues.append({
                            'type': 'SSRF (Potential)',
                            'severity': 'critical',
                            'parameter': param_name,
                            'value': param_value,
                            'description': f'파라미터 "{param_name}"가 SSRF 공격에 취약할 수 있습니다.',
                            'attack_vectors': [
                                '내부 네트워크 접근: http://localhost:8080',
                                'Cloud Metadata 접근: http://169.254.169.254/latest/meta-data/',
                                'File Protocol: file:///etc/passwd'
                            ],
                            'recommendation': '사용자 입력 URL을 화이트리스트로 제한하고 내부 IP를 차단하세요.'
                        })
        except Exception as e:
            logger.debug(f"SSRF URL parameter scan error: {str(e)}")

    def _scan_forms(self) -> None:
        """폼 입력 필드에서 SSRF 취약점 검사"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                inputs = form.find_all('input')
                for input_field in inputs:
                    input_name = input_field.get('name', '')
                    input_type = input_field.get('type', 'text')

                    if input_name.lower() in self.SSRF_PARAMS or input_type == 'url':
                        self.issues.append({
                            'type': 'SSRF (Form Input)',
                            'severity': 'high',
                            'input_name': input_name,
                            'input_type': input_type,
                            'form_action': form.get('action', ''),
                            'description': f'폼 입력 "{input_name}"이 SSRF 공격에 취약할 수 있습니다.',
                            'recommendation': '서버 사이드에서 URL 검증 및 내부 IP 차단을 구현하세요.'
                        })
        except Exception as e:
            logger.debug(f"SSRF form scan error: {str(e)}")

    def _scan_url_inputs(self) -> None:
        """URL 입력 필드 검사"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            url_inputs = soup.find_all('input', type='url')

            for url_input in url_inputs:
                self.issues.append({
                    'type': 'SSRF (URL Input Field)',
                    'severity': 'medium',
                    'input_name': url_input.get('name', 'unknown'),
                    'description': 'URL 입력 필드가 SSRF 공격에 사용될 수 있습니다.',
                    'recommendation': 'URL 입력을 검증하고 내부 네트워크 접근을 차단하세요.'
                })
        except Exception as e:
            logger.debug(f"SSRF URL input scan error: {str(e)}")

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_ssrf': len(self.issues) > 0
        }



    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

