"""
Batch 1 스캐너들 - CookieScanner, ClickjackingScanner, SubresourceIntegrityScanner

별도 파일로 작성하여 관리 용이성 확보
"""

import logging
import re
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

from .base import BaseScanner

logger = logging.getLogger(__name__)


class CookieScanner(BaseScanner):
    """쿠키 보안 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'cookie_security',
        'name': '쿠키 보안 검사',
        'icon': '🍪',
        'description': '쿠키 보안 속성 검증',
        'weight': 1,
        'field': 'sensitive_data_exposure'
    }

    def __init__(self, response=None, **kwargs):
        """
        Args:
            response: HTTP 응답 객체
            **kwargs: BaseScanner 호환 인자
        """
        # BaseScanner 초기화
        url = kwargs.pop('url', '')
        super().__init__(url=url, response=response, **kwargs)

        # 쿠키 설정
        if response and hasattr(response, 'cookies'):
            self.cookies = response.cookies
        else:
            self.cookies = []

        # issues 사용
        self.issues = []

    def _execute_scan(self) -> None:
        """쿠키 보안 검사 실행"""
        if not self.cookies:
            return

        for cookie in self.cookies:
            cookie_issues = []
            severity = 'low'  # 기본 심각도

            # Secure 플래그 검사
            if not cookie.secure:
                cookie_issues.append('Secure 플래그가 없습니다')
                # HTTPS에서 Secure 없으면 높은 위험
                if self.url and self.url.startswith('https://'):
                    severity = 'medium'

            # HttpOnly 플래그 검사
            # 쿠키 객체 속성 확인 방법이 다를 수 있음
            http_only = getattr(cookie, 'httponly', None)
            if http_only is None:
                # 대체 방법: _rest 속성에서 확인
                http_only = cookie._rest.get('HttpOnly') if hasattr(cookie, '_rest') else False

            if not http_only:
                cookie_issues.append('HttpOnly 플래그가 없습니다')
                # 세션 쿠키인 경우 더 위험
                if 'session' in cookie.name.lower():
                    severity = 'high'

            # SameSite 속성 검사
            same_site = getattr(cookie, 'samesite', None)
            if same_site is None and hasattr(cookie, '_rest'):
                same_site = cookie._rest.get('SameSite')

            if not same_site:
                cookie_issues.append('SameSite 속성이 없습니다')
            elif same_site.lower() == 'none':
                cookie_issues.append('SameSite=None은 보안상 위험할 수 있습니다')
                severity = 'medium'

            # 쿠키 만료 시간 검사 (세션 쿠키 vs 영구 쿠키)
            if cookie.expires:
                # 너무 긴 만료 시간 체크 (1년 이상)
                import time
                if cookie.expires > time.time() + (365 * 24 * 60 * 60):
                    cookie_issues.append('만료 기간이 너무 깁니다 (1년 이상)')

            # 민감한 정보 쿠키 이름 체크
            sensitive_names = ['password', 'pwd', 'token', 'api', 'secret', 'key']
            for sensitive in sensitive_names:
                if sensitive in cookie.name.lower():
                    cookie_issues.append(f'쿠키 이름에 민감한 정보 포함: {sensitive}')
                    severity = 'high'
                    break

            if cookie_issues:
                self.issues.append({
                    'type': 'Insecure Cookie',
                    'severity': severity,
                    'cookie_name': cookie.name,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'issues': cookie_issues,
                    'description': f'쿠키 "{cookie.name}"의 보안 설정이 부족합니다.',
                    'recommendation': 'Secure, HttpOnly, SameSite 속성을 설정하고, 적절한 만료 시간을 지정하세요.'
                })

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'total_cookies': len(self.cookies),
            'insecure_cookies': len(self.issues),
            'secure_percentage': ((len(self.cookies) - len(self.issues)) / len(self.cookies) * 100) if self.cookies else 100
        }


class ClickjackingScanner(BaseScanner):
    """클릭재킹 방어 검사 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'clickjacking',
        'name': '클릭재킹 방어 검사',
        'icon': '🖱️',
        'description': 'Clickjacking 공격 방어 검증',
        'weight': 1,
        'field': 'clickjacking'
    }

    def __init__(self, headers: Dict[str, str] = None, html_content: str = None, **kwargs):
        """
        Args:
            headers: HTTP 응답 헤더
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        # BaseScanner 초기화
        url = kwargs.pop('url', '')
        super().__init__(url=url, html_content=html_content, **kwargs)

        # 헤더 설정
        if headers is not None:
            self.headers = headers
        elif hasattr(self, 'response') and self.response:
            self.headers = getattr(self.response, 'headers', {})
        else:
            self.headers = {}

        # HTML 콘텐츠 설정
        if html_content:
            self.html_content = html_content
        elif hasattr(self, 'response') and self.response:
            self.html_content = getattr(self.response, 'text', '')
        else:
            self.html_content = ''

        self.issues = []

    def _execute_scan(self) -> None:
        """클릭재킹 방어 검사 실행"""
        x_frame_options = self.headers.get('X-Frame-Options')
        csp = self.headers.get('Content-Security-Policy')

        has_xfo = False
        has_csp_frame = False
        xfo_value = None

        # X-Frame-Options 검사
        if x_frame_options:
            xfo_value = x_frame_options.upper()
            if xfo_value in ['DENY', 'SAMEORIGIN']:
                has_xfo = True
            elif xfo_value.startswith('ALLOW-FROM'):
                has_xfo = True
                self.issues.append({
                    'type': 'Deprecated X-Frame-Options',
                    'severity': 'low',
                    'value': x_frame_options,
                    'description': 'ALLOW-FROM은 더 이상 권장되지 않습니다.',
                    'details': '최신 브라우저에서 지원하지 않을 수 있습니다.',
                    'recommendation': 'CSP frame-ancestors를 사용하세요.'
                })
            else:
                # 잘못된 값
                self.issues.append({
                    'type': 'Invalid X-Frame-Options',
                    'severity': 'high',
                    'value': x_frame_options,
                    'description': f'유효하지 않은 X-Frame-Options 값: {x_frame_options}',
                    'recommendation': 'DENY, SAMEORIGIN 중 하나를 사용하세요.'
                })

        # CSP frame-ancestors 검사
        if csp:
            if 'frame-ancestors' in csp:
                has_csp_frame = True
                # frame-ancestors 값 분석
                self._analyze_frame_ancestors(csp)

        # 둘 다 없으면 취약
        if not has_xfo and not has_csp_frame:
            self.issues.append({
                'type': 'Missing Clickjacking Protection',
                'severity': 'high',
                'description': 'X-Frame-Options 또는 CSP frame-ancestors가 설정되지 않았습니다.',
                'details': '악의적인 사이트가 iframe으로 이 페이지를 포함할 수 있습니다.',
                'recommendation': 'X-Frame-Options: DENY 또는 CSP frame-ancestors를 설정하세요.'
            })

        # HTML에서 JavaScript framebuster 검사 (추가 보호)
        if self.html_content:
            self._check_framebuster()

    def _analyze_frame_ancestors(self, csp: str) -> None:
        """frame-ancestors 디렉티브 분석"""
        import re
        match = re.search(r"frame-ancestors\s+([^;]+)", csp)
        if match:
            value = match.group(1).strip()
            if value == "'*'" or value == "*":
                self.issues.append({
                    'type': 'Weak frame-ancestors',
                    'severity': 'medium',
                    'value': value,
                    'description': 'frame-ancestors가 모든 도메인을 허용합니다.',
                    'recommendation': "frame-ancestors 'self' 또는 특정 도메인만 허용하세요."
                })

    def _check_framebuster(self) -> None:
        """JavaScript framebuster 코드 검사"""
        framebuster_patterns = [
            r'if\s*\(\s*top\s*!=\s*self\s*\)',
            r'if\s*\(\s*parent\s*!=\s*self\s*\)',
            r'if\s*\(\s*window\.top\s*!==\s*window\.self\s*\)',
            r'X-Frame-Options',  # 메타 태그로 설정 시도
        ]

        for pattern in framebuster_patterns:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                # Framebuster 있지만 헤더가 더 안전
                logger.debug("Framebuster JavaScript 발견")
                break

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        x_frame_options = self.headers.get('X-Frame-Options')
        csp = self.headers.get('Content-Security-Policy')

        return {
            'has_xfo': x_frame_options is not None,
            'has_csp_frame': 'frame-ancestors' in csp if csp else False,
            'protected': (x_frame_options is not None) or ('frame-ancestors' in csp if csp else False),
            'xfo_value': x_frame_options
        }


class SubresourceIntegrityScanner(BaseScanner):
    """SRI (Subresource Integrity) 검사 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'sri',
        'name': 'SRI 검사',
        'icon': '🔒',
        'description': 'Subresource Integrity 검증',
        'weight': 0.5,
        'field': 'sri_check'
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
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 스크립트 태그 검사
        scripts = soup.find_all('script', src=True)
        self._check_resources(scripts, 'script')

        # 링크(스타일시트) 태그 검사
        stylesheets = soup.find_all('link', rel='stylesheet', href=True)
        self._check_resources(stylesheets, 'stylesheet')

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