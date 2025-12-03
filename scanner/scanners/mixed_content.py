"""
MixedContentScanner - 자동 수정됨

원본: scanners_refactored_batch2.py
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


class MixedContentScanner(BaseScanner):
    """Mixed Content 검사 스캐너 - 리팩토링 버전
    HTTPS 페이지에서 HTTP 리소스를 로드하는 보안 취약점 탐지
    """

    # 스캐너 메타데이터
    metadata = {
        'id': 'mixed_content',
        'name': 'Mixed Content 검사',
        'icon': '🔗',
        'description': 'HTTPS 페이지의 HTTP 리소스 검사',
        'weight': 0.5,
        'field': 'mixed_content',
        'category': 'security_basic',
        'OWASP': 'A02:2025',
    }

    # Mixed Content 카테고리
    CATEGORIES = {
        'blockable': {
            'severity': 'high',
            'resources': ['script', 'iframe', 'object', 'embed'],
            'description': '능동적 혼합 콘텐츠 (브라우저가 차단)'
        },
        'optionally-blockable': {
            'severity': 'medium',
            'resources': ['img', 'audio', 'video'],
            'description': '수동적 혼합 콘텐츠 (경고만 표시)'
        },
        'upgradeable': {
            'severity': 'low',
            'resources': ['link', 'a'],
            'description': '업그레이드 가능한 리소스'
        }
    }

    def __init__(self, url: str = '', html_content: str = None, **kwargs):
        """
        Args:
            url: 페이지 URL (HTTPS 여부 확인용)
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url, html_content=html_content, **kwargs)

        # HTML 콘텐츠 설정
        if html_content:
            self.html_content = html_content
        elif hasattr(self, 'response') and self.response:
            self.html_content = getattr(self.response, 'text', '')
        else:
            self.html_content = ''

        self.issues = []
        self.is_https = self.url.startswith('https://') if self.url else False

    def _execute_scan(self) -> None:
        """Mixed Content 검사 실행"""
        # 검사 항목: HTML 리소스, 인라인 스타일, JS 리소스, Form action
        self.checked = 4

        # HTTPS 페이지가 아니면 검사 불필요
        if not self.is_https:
            logger.debug(f"Non-HTTPS URL, skipping mixed content scan: {self.url}")
            self._add_detail(
                id='mixed_content_summary',
                name='Mixed Content 검사',
                status='pass',
                severity='info',
                description='HTTPS가 아닌 페이지 (검사 불필요)',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        if not self.html_content:
            self._add_detail(
                id='mixed_content_summary',
                name='Mixed Content 검사',
                status='pass',
                severity='info',
                description='검사할 HTML 콘텐츠 없음',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        # 1. HTML 태그의 HTTP 리소스 검사
        self._scan_html_resources()

        # 2. 인라인 스타일의 HTTP 리소스 검사
        self._scan_inline_styles()

        # 3. JavaScript의 동적 HTTP 리소스 검사
        self._scan_javascript_resources()

        # 4. Form action의 HTTP 검사
        self._scan_form_actions()

        # 5. CSP upgrade-insecure-requests 확인
        self._check_csp_upgrade_directive()

        # 전체 결과 요약
        if self.issues:
            blockable = len([i for i in self.issues if 'blockable' in i.get('category', '')])
            severity = 'high' if blockable > 0 else 'medium'
            self._add_detail(
                id='mixed_content_summary',
                name='Mixed Content 검사',
                status='fail',
                severity=severity,
                description=f'{len(self.issues)}개의 Mixed Content 발견',
                value=f'Blockable: {blockable}개',
                expected='HTTP 리소스 없음',
                recommendation='모든 리소스를 HTTPS로 변경하세요.'
            )
        else:
            self._add_detail(
                id='mixed_content_summary',
                name='Mixed Content 검사',
                status='pass',
                severity='info',
                description='Mixed Content가 발견되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _scan_html_resources(self) -> None:
        """HTML 태그에서 HTTP 리소스 검사"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 검사할 태그와 속성
        tag_attributes = {
            'script': 'src',
            'link': 'href',
            'img': 'src',
            'iframe': 'src',
            'video': 'src',
            'audio': 'src',
            'source': 'src',
            'embed': 'src',
            'object': 'data',
            'form': 'action',
            'a': 'href'
        }

        for tag_name, attr_name in tag_attributes.items():
            elements = soup.find_all(tag_name)

            for element in elements:
                url = element.get(attr_name, '')

                if self._is_http_resource(url):
                    # 카테고리 결정
                    category = self._get_resource_category(tag_name)
                    category_name = self._get_category_name(tag_name)

                    # 이미지는 너무 많을 수 있으므로 제한
                    if tag_name == 'img' and len([i for i in self.issues if 'img' in i.get('tag', '')]) >= 3:
                        continue

                    self.issues.append({
                        'type': f'Mixed Content - {category["description"]}',
                        'severity': category['severity'],
                        'tag': tag_name,
                        'attribute': attr_name,
                        'url': url[:200],  # URL 길이 제한
                        'category': category_name,
                        'description': f'HTTP 리소스가 HTTPS 페이지에서 로드됨: <{tag_name}>',
                        'recommendation': self._get_recommendation(tag_name)
                    })

    def _scan_inline_styles(self) -> None:
        """인라인 스타일에서 HTTP URL 검사"""
        # style 속성에서 HTTP URL 찾기
        # 다양한 형태의 style 속성 매칭
        style_patterns = [
            r'style\s*=\s*"([^"]+)"',
            r'style\s*=\s*\'([^\']+)\'',
            r'style\s*=\s*([^>\s]+)',
        ]

        for pattern in style_patterns:
            styles = re.findall(pattern, self.html_content, re.IGNORECASE | re.DOTALL)
            for style in styles:
                # url() 안의 HTTP URL 찾기
                http_url_patterns = [
                    r'url\s*\(\s*["\']?(http://[^"\'\)]+)',
                    r'url\s*\(\s*(http://[^\)]+)',
                ]

                for url_pattern in http_url_patterns:
                    http_urls = re.findall(url_pattern, style, re.IGNORECASE)
                    if http_urls:
                        self.issues.append({
                            'type': 'Mixed Content - Inline Style',
                            'severity': 'medium',
                            'description': '인라인 스타일에서 HTTP 리소스 참조',
                            'url': http_urls[0][:200],
                            'evidence': style[:100],
                            'recommendation': 'HTTPS URL을 사용하거나 프로토콜 상대 URL(//)을 사용하세요.'
                        })
                        return  # 하나만 찾으면 종료

    def _scan_javascript_resources(self) -> None:
        """JavaScript에서 동적으로 로드하는 HTTP 리소스 검사"""
        # JavaScript에서 HTTP URL 패턴
        js_patterns = [
            r'["\']http://[^"\']+["\']',
            r'createElement\s*\(\s*["\'](?:script|img|iframe)["\']',
            r'\.src\s*=\s*["\']http://',
            r'XMLHttpRequest.*?http://',
            r'fetch\s*\(\s*["\']http://'
        ]

        scripts = re.findall(r'<script[^>]*>(.*?)</script>', self.html_content, re.DOTALL | re.IGNORECASE)

        found_dynamic_http = False
        for script in scripts:
            for pattern in js_patterns:
                if re.search(pattern, script, re.IGNORECASE):
                    if not found_dynamic_http:  # 한 번만 보고
                        self.issues.append({
                            'type': 'Mixed Content - Dynamic Loading',
                            'severity': 'high',
                            'description': 'JavaScript에서 HTTP 리소스를 동적으로 로드',
                            'evidence': re.search(pattern, script, re.IGNORECASE).group()[:100],
                            'recommendation': 'HTTPS를 사용하거나 프로토콜을 동적으로 결정하세요 (location.protocol 사용).'
                        })
                        found_dynamic_http = True
                    break

    def _scan_form_actions(self) -> None:
        """Form action의 HTTP URL 검사"""
        soup = BeautifulSoup(self.html_content, 'html.parser')
        forms = soup.find_all('form')

        for idx, form in enumerate(forms):
            action = form.get('action', '')

            if self._is_http_resource(action):
                method = form.get('method', 'GET').upper()

                # POST 폼이 HTTP로 전송되는 것은 매우 위험
                severity = 'critical' if method == 'POST' else 'high'

                self.issues.append({
                    'type': 'Mixed Content - Form Submission',
                    'severity': severity,
                    'form_index': idx,
                    'action': action[:200],
                    'method': method,
                    'description': f'{method} 폼이 HTTP로 데이터를 전송합니다.',
                    'recommendation': 'Form action을 HTTPS URL로 변경하세요. 민감한 데이터가 노출될 수 있습니다.'
                })

    def _check_csp_upgrade_directive(self) -> None:
        """CSP upgrade-insecure-requests 지시자 확인"""
        if hasattr(self, 'response') and self.response:
            headers = getattr(self.response, 'headers', {})
            csp = headers.get('Content-Security-Policy', '')

            if csp and 'upgrade-insecure-requests' in csp:
                # 좋은 설정이지만 근본 해결은 아님
                self.issues.append({
                    'type': 'CSP Upgrade Directive',
                    'severity': 'info',
                    'description': 'upgrade-insecure-requests CSP 지시자가 설정되어 있습니다.',
                    'note': 'HTTP 리소스를 자동으로 HTTPS로 업그레이드하지만, 모든 브라우저가 지원하지 않습니다.',
                    'recommendation': '근본적으로는 모든 리소스를 HTTPS로 변경하는 것이 좋습니다.'
                })

    def _is_http_resource(self, url: str) -> bool:
        """HTTP 리소스인지 확인"""
        if not url:
            return False

        # 명시적 HTTP URL
        if url.startswith('http://'):
            # localhost나 127.0.0.1은 제외 (개발 환경)
            if 'localhost' in url or '127.0.0.1' in url:
                return False
            return True

        # 프로토콜 상대 URL은 현재 프로토콜 따라감
        if url.startswith('//'):
            return False

        # 절대 경로나 상대 경로는 현재 프로토콜 사용
        return False

    def _get_resource_category(self, tag_name: str) -> Dict:
        """리소스의 카테고리 결정"""
        for category_name, category_info in self.CATEGORIES.items():
            if tag_name in category_info['resources']:
                return category_info
        return {'severity': 'low', 'description': '기타 혼합 콘텐츠'}

    def _get_category_name(self, tag_name: str) -> str:
        """리소스의 카테고리 이름 반환"""
        for category_name, category_info in self.CATEGORIES.items():
            if tag_name in category_info['resources']:
                return category_name
        return 'other'

    def _get_recommendation(self, tag_name: str) -> str:
        """태그별 권장사항"""
        recommendations = {
            'script': 'HTTPS를 사용하세요. 스크립트는 페이지 전체를 제어할 수 있습니다.',
            'iframe': 'HTTPS iframe을 사용하거나 sandbox 속성을 추가하세요.',
            'form': 'Form action을 HTTPS로 변경하세요. 데이터가 암호화되지 않습니다.',
            'img': '이미지도 HTTPS로 제공하여 중간자 공격을 방지하세요.',
            'link': '스타일시트를 HTTPS로 제공하세요.',
            'default': 'HTTP 대신 HTTPS를 사용하거나 프로토콜 상대 URL(//)을 사용하세요.'
        }
        return recommendations.get(tag_name, recommendations['default'])

    def _build_vulnerabilities(self) -> List[Dict[str, Any]]:
        """issues를 vulnerabilities 형식으로 변환"""
        return self.issues

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        if not self.is_https:
            return {
                'is_https': False,
                'scan_skipped': True,
                'reason': 'Not an HTTPS page'
            }

        # 카테고리별 집계
        category_counts = {'blockable': 0, 'optionally-blockable': 0, 'upgradeable': 0, 'other': 0}
        for issue in self.issues:
            category = issue.get('category', 'other')
            if category in category_counts:
                category_counts[category] += 1

        return {
            'is_https': True,
            'has_mixed_content': len(self.issues) > 0,
            'blockable_count': category_counts['blockable'],
            'optionally_blockable_count': category_counts['optionally-blockable'],
            'upgradeable_count': category_counts['upgradeable'],
            'total_mixed': len(self.issues)
        }

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

