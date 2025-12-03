"""
SubresourceIntegrityScanner - 자동 수정됨

원본: scanners_refactored_batch1.py
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


class SubresourceIntegrityScanner(BaseScanner):
    """SRI (Subresource Integrity) 검사 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'sri',
        'name': 'SRI 검사',
        'icon': '🔒',
        'description': 'Subresource Integrity 검증',
        'weight': 0.5,
        'field': 'subresource_integrity',
        'category': 'security_basic',
        'OWASP': 'A08:2025',
    }

    def __init__(self, html_content: str = None, **kwargs):
        """
        Args:
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        # BaseScanner 초기화
        url = kwargs.pop('url', '')
        super().__init__(url=url, html_content=html_content, **kwargs)

        # HTML 콘텐츠 설정
        if html_content:
            self.html_content = html_content
        elif hasattr(self, 'response') and self.response:
            self.html_content = getattr(self.response, 'text', '')
        else:
            self.html_content = ''

        self.issues = []

    def _execute_scan(self) -> None:
        """SRI 검사 실행"""
        if not self.html_content:
            self.checked = 0
            self._add_detail(
                id='sri_check',
                name='SRI 검사',
                status='pass',
                severity='info',
                description='검사할 HTML 콘텐츠 없음',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 외부 리소스 수 계산 (검사 대상)
        scripts = soup.find_all('script', src=True)
        stylesheets = soup.find_all('link', rel='stylesheet', href=True)
        external_count = 0
        for resource in scripts + stylesheets:
            url = resource.get('src') or resource.get('href')
            if self._is_external_resource(url):
                external_count += 1
        self.checked = external_count if external_count > 0 else 1

        # 스크립트 태그 검사
        scripts = soup.find_all('script', src=True)
        self._check_resources(scripts, 'script')

        # 링크(스타일시트) 태그 검사
        stylesheets = soup.find_all('link', rel='stylesheet', href=True)
        self._check_resources(stylesheets, 'stylesheet')

        # 전체 결과 요약
        missing_sri = len([i for i in self.issues if i.get('type') == 'Missing SRI'])
        cdn_missing = len([i for i in self.issues if i.get('type') == 'Missing SRI' and i.get('is_cdn')])

        if missing_sri > 0:
            severity = 'high' if cdn_missing > 0 else 'medium'
            self._add_detail(
                id='sri_check',
                name='SRI 검사',
                status='fail',
                severity=severity,
                description=f'{missing_sri}개 외부 리소스에 SRI 없음 (CDN: {cdn_missing}개)',
                value=f'총 외부 리소스: {external_count}개',
                expected='모든 외부 리소스에 integrity 속성',
                recommendation='외부 스크립트/스타일시트에 integrity 속성을 추가하세요.'
            )
        elif external_count > 0:
            self._add_detail(
                id='sri_check',
                name='SRI 검사',
                status='pass',
                severity='info',
                description=f'{external_count}개 외부 리소스 모두 SRI 적용됨',
                value=None,
                expected=None,
                recommendation=None
            )
        else:
            self._add_detail(
                id='sri_check',
                name='SRI 검사',
                status='pass',
                severity='info',
                description='외부 리소스 없음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _check_resources(self, resources: List, resource_type: str) -> None:
        """리소스들의 SRI 검사"""
        for resource in resources:
            url_attr = 'src' if resource_type == 'script' else 'href'
            url = resource.get(url_attr, '')

            # 외부 리소스인지 확인
            if self._is_external_resource(url):
                integrity = resource.get('integrity')
                crossorigin = resource.get('crossorigin')

                if not integrity:
                    # CDN 리소스인지 확인
                    is_cdn = self._is_cdn_resource(url)

                    self.issues.append({
                        'type': 'Missing SRI',
                        'severity': 'high' if is_cdn else 'medium',
                        'resource_type': resource_type,
                        'url': url,
                        'is_cdn': is_cdn,
                        'description': f'외부 {resource_type}에 SRI가 없습니다.',
                        'details': f'리소스: {url}',
                        'recommendation': 'integrity 속성을 추가하여 리소스 무결성을 검증하세요.'
                    })
                else:
                    # SRI는 있지만 추가 검증
                    self._validate_sri(integrity, url, resource_type)

                    # crossorigin 속성 확인
                    if not crossorigin:
                        self.issues.append({
                            'type': 'Missing Crossorigin',
                            'severity': 'low',
                            'resource_type': resource_type,
                            'url': url,
                            'description': 'SRI가 있지만 crossorigin 속성이 없습니다.',
                            'recommendation': 'crossorigin="anonymous" 속성을 추가하세요.'
                        })

    def _is_external_resource(self, url: str) -> bool:
        """외부 리소스인지 확인"""
        if not url:
            return False

        # 절대 URL인 경우
        if url.startswith(('http://', 'https://', '//')):
            # 현재 도메인과 비교
            if self.url:
                current_domain = urlparse(self.url).netloc
                resource_domain = urlparse(url).netloc
                return current_domain != resource_domain
            return True

        # 상대 경로는 내부 리소스
        return False

    def _is_cdn_resource(self, url: str) -> bool:
        """CDN 리소스인지 확인"""
        cdn_patterns = [
            'cdn.jsdelivr.net',
            'cdnjs.cloudflare.com',
            'ajax.googleapis.com',
            'maxcdn.bootstrapcdn.com',
            'code.jquery.com',
            'unpkg.com',
            'cdn.bootcss.com',
            'stackpath.bootstrapcdn.com',
            'cdn.staticfile.org'
        ]

        return any(cdn in url for cdn in cdn_patterns)

    def _validate_sri(self, integrity: str, url: str, resource_type: str) -> None:
        """SRI 해시 검증"""
        # 약한 해시 알고리즘 체크
        if integrity.startswith('sha256-'):
            # SHA256은 현재 권장 최소 수준
            pass
        elif integrity.startswith('sha384-') or integrity.startswith('sha512-'):
            # 더 강력한 해시
            pass
        elif integrity.startswith('sha1-') or integrity.startswith('md5-'):
            self.issues.append({
                'type': 'Weak SRI Hash',
                'severity': 'medium',
                'resource_type': resource_type,
                'url': url,
                'hash_algorithm': integrity.split('-')[0],
                'description': '약한 해시 알고리즘을 사용하고 있습니다.',
                'recommendation': 'SHA256 이상의 해시 알고리즘을 사용하세요.'
            })

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        total_external = 0
        missing_sri = 0

        if self.html_content:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            scripts = soup.find_all('script', src=True)
            stylesheets = soup.find_all('link', rel='stylesheet', href=True)

            for resource in scripts + stylesheets:
                url = resource.get('src') or resource.get('href')
                if self._is_external_resource(url):
                    total_external += 1
                    if not resource.get('integrity'):
                        missing_sri += 1

        return {
            'total_external_resources': total_external,
            'missing_sri_count': missing_sri,
            'sri_coverage': ((total_external - missing_sri) / total_external * 100) if total_external else 100
        }

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

