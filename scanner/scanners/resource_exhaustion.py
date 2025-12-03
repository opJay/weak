"""
ResourceExhaustionScanner - resource_exhaustion 스캐너

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


class ResourceExhaustionScanner(BaseScanner):
    """리소스 소진 취약점 스캐너

    OWASP Top 10 2025 A06: Insecure Design 대응
    - 과도한 리소스 사용 탐지
    - 제한 없는 파일 업로드
    """
    # 스캐너 메타데이터
    metadata = {
        'id': 'resource_exhaustion',
        'name': '리소스 소진 검사',
        'icon': '📈',
        'description': '리소스 소진 검사',
        'weight': 1.5,
        'field': 'resource_exhaustion_vulnerabilities',
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
        # 1. 파일 업로드 폼 검사
        if self.html_content:
            self._check_file_upload_limits()

        # 2. API 크기 제한 검사
        self._check_request_size_limits()

    def _build_result(self) -> Dict[str, Any]:
        """결과 구성"""
        return {
            'vulnerabilities': self.vulnerabilities,
            'total': len(self.vulnerabilities),
            'severity': self._calculate_severity(),
            'recommendations': self._get_recommendations(),
            'has_resource_exhaustion': len(self.vulnerabilities) > 0
        }

    def _check_file_upload_limits(self) -> None:
        """파일 업로드 제한 검사"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 파일 업로드 input 찾기
        file_inputs = soup.find_all('input', type='file')

        for file_input in file_inputs:
            # maxsize 속성 확인
            if not file_input.get('maxsize'):
                self.vulnerabilities.append({
                    'type': 'No File Size Limit',
                    'severity': 'medium',
                    'description': '파일 업로드에 크기 제한이 명시되지 않아 대용량 파일 업로드가 가능할 수 있습니다.',
                    'recommendation': '파일 크기를 클라이언트와 서버 양쪽에서 제한하세요.'
                })
                break

    def _check_request_size_limits(self) -> None:
        """요청 크기 제한 검사"""
        if self.response:
            headers = self.response.headers if hasattr(self.response, 'headers') else {}

            # Rate limiting 관련 헤더 확인
            rate_limit_headers = ['X-RateLimit-Limit', 'RateLimit-Limit']
            if not any(h in headers for h in rate_limit_headers):
                self.vulnerabilities.append({
                    'type': 'No Rate Limiting Headers',
                    'severity': 'low',
                    'description': 'Rate limiting 관련 응답 헤더가 없어 리소스 제한이 없을 수 있습니다.',
                    'recommendation': 'API Rate Limiting을 구현하고 X-RateLimit-* 헤더를 반환하세요.'
                })

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
            '파일 업로드는 크기와 개수를 제한하세요 (예: 10MB, 5개).',
            'API 요청은 크기를 제한하세요 (예: 1MB).',
            'Rate Limiting을 구현하여 과도한 요청을 차단하세요.',
            '타임아웃을 설정하여 무한 루프를 방지하세요.',
            '리소스 사용량을 모니터링하고 임계값을 설정하세요.'
        ]


    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

