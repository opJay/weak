"""
SoftwareSupplyChainScanner - 소프트웨어 공급망 보안 검사 스캐너

OWASP Top 10 2025 A03: Software Supply Chain 대응
- 종속성 파일 노출 검사
- SRI (Subresource Integrity) 검사
- 취약한 CDN 라이브러리 검사
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from scanner.base import BaseScanner


class SoftwareSupplyChainScanner(BaseScanner):
    """소프트웨어 공급망 기본 보안 검사 스캐너"""

    # 메타데이터 정의
    metadata = {
        'id': 'software_supply_chain',
        'name': '소프트웨어 공급망 보안',
        'icon': '📦',
        'description': '소프트웨어 공급망 보안 검사 (종속성 노출, SRI, 취약한 라이브러리)',
        'weight': 2,
        'field': 'software_supply_chain_vulnerabilities',
        'category': 'supply_chain',
        'severity': 'high',
        'owasp': ['A03:2025'],
        'CWE': ['CWE-829', 'CWE-1104']
    }

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None, **kwargs):
        super().__init__(url=url or '', response=response,
                        html_content=html_content, **kwargs)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client or kwargs.get('session')
        self.vulnerabilities = []

        # 스캔에 필요한 속성들 초기화
        self.dependency_files = [
            'package.json', 'package-lock.json', 'yarn.lock',
            'requirements.txt', 'Pipfile', 'Pipfile.lock',
            'Gemfile', 'Gemfile.lock', 'composer.json', 'composer.lock',
            'go.mod', 'go.sum', 'pom.xml', 'build.gradle'
        ]
        self.vulnerable_cdns = {
            'jquery': {
                '1.': 'jQuery 1.x는 여러 알려진 XSS 취약점이 있습니다',
                '2.0': 'jQuery 2.0.x는 XSS 취약점이 있습니다',
                '2.1': 'jQuery 2.1.x는 XSS 취약점이 있습니다'
            },
            'angular': {
                '1.0': 'AngularJS 1.0.x는 CSP 우회 취약점이 있습니다',
                '1.1': 'AngularJS 1.1.x는 CSP 우회 취약점이 있습니다',
                '1.2': 'AngularJS 1.2.x는 CSP 우회 취약점이 있습니다'
            },
            'bootstrap': {
                '3.0': 'Bootstrap 3.0.x는 XSS 취약점이 있습니다',
                '3.1': 'Bootstrap 3.1.x는 XSS 취약점이 있습니다',
                '3.2': 'Bootstrap 3.2.x는 XSS 취약점이 있습니다',
                '3.3': 'Bootstrap 3.3.x는 XSS 취약점이 있습니다',
                '4.0': 'Bootstrap 4.0.x는 XSS 취약점이 있습니다'
            }
        }

    def _prepare(self):
        """스캔 준비"""
        # 모든 속성은 __init__에서 초기화됨
        pass

    def _execute_scan(self):
        """스캔 실행"""
        # 검사 항목: 종속성 노출, SRI, 취약한 라이브러리
        self.checked = 3

        # 1. 종속성 파일 노출 검사
        self._check_exposed_dependencies()

        # 2. SRI (Subresource Integrity) 검사
        self._check_sri()

        # 3. 취약한 CDN 라이브러리 검사
        self._check_vulnerable_libraries()

        # 결과 요약
        if self.vulnerabilities:
            critical_count = len([v for v in self.vulnerabilities if v.get('severity') == 'critical'])
            self._add_detail(
                id='supply_chain_check',
                name='소프트웨어 공급망 보안 검사',
                status='fail',
                severity='critical' if critical_count > 0 else 'high',
                description=f'{len(self.vulnerabilities)}개의 공급망 보안 취약점 발견',
                value=f'Critical: {critical_count}개',
                expected='공급망 보안 취약점 없음',
                recommendation='종속성 파일 노출을 차단하고 SRI를 적용하세요.'
            )
        else:
            self._add_detail(
                id='supply_chain_check',
                name='소프트웨어 공급망 보안 검사',
                status='pass',
                severity='info',
                description='공급망 보안 취약점이 발견되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _check_exposed_dependencies(self):
        """종속성 파일 노출 검사"""
        if not self.http_client:
            return

        base_url = self.url.rstrip('/')

        for dep_file in self.dependency_files:
            try:
                response = self.http_client.get(f"{base_url}/{dep_file}")
                if response and hasattr(response, 'status_code') and response.status_code == 200:
                    content = response.text if hasattr(response, 'text') else str(response.content)

                    # 민감한 정보 패턴 검사
                    sensitive_patterns = [
                        (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']', 'API 키'),
                        (r'["\']?secret["\']?\s*[:=]\s*["\'][^"\']+["\']', 'Secret'),
                        (r'["\']?token["\']?\s*[:=]\s*["\'][^"\']+["\']', 'Token'),
                        (r'["\']?password["\']?\s*[:=]\s*["\'][^"\']+["\']', 'Password'),
                        (r'github\.com[:/][^/\s]+/[^/\s]+\.git', 'Private Git Repository')
                    ]

                    for pattern, info_type in sensitive_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            self.vulnerabilities.append({
                                'type': 'sensitive_info_in_dependencies',
                                'file': dep_file,
                                'info_type': info_type,
                                'severity': 'critical',
                                'message': f'{dep_file}에서 {info_type} 노출 발견'
                            })

                    # 파일 자체 노출도 취약점
                    self.vulnerabilities.append({
                        'type': 'exposed_dependency_file',
                        'file': dep_file,
                        'severity': 'medium',
                        'message': f'종속성 파일 {dep_file}이(가) 공개적으로 접근 가능합니다'
                    })
            except:
                pass

    def _check_sri(self):
        """SRI (Subresource Integrity) 검사"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 외부 스크립트 검사
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src', '')
            if src and (src.startswith('http://') or src.startswith('https://') or src.startswith('//')):
                # 외부 리소스인데 SRI가 없는 경우
                if not script.get('integrity'):
                    # CDN인지 확인
                    cdn_patterns = [
                        'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com',
                        'ajax.googleapis.com', 'maxcdn.bootstrapcdn.com',
                        'code.jquery.com', 'stackpath.bootstrapcdn.com'
                    ]

                    is_cdn = any(cdn in src for cdn in cdn_patterns)

                    if is_cdn:
                        self.vulnerabilities.append({
                            'type': 'missing_sri',
                            'resource': src,
                            'resource_type': 'script',
                            'severity': 'high',
                            'message': f'CDN 스크립트에 SRI가 없습니다: {src}'
                        })

        # 외부 스타일시트 검사
        links = soup.find_all('link', rel='stylesheet', href=True)
        for link in links:
            href = link.get('href', '')
            if href and (href.startswith('http://') or href.startswith('https://') or href.startswith('//')):
                if not link.get('integrity'):
                    cdn_patterns = [
                        'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com',
                        'maxcdn.bootstrapcdn.com', 'stackpath.bootstrapcdn.com'
                    ]

                    is_cdn = any(cdn in href for cdn in cdn_patterns)

                    if is_cdn:
                        self.vulnerabilities.append({
                            'type': 'missing_sri',
                            'resource': href,
                            'resource_type': 'stylesheet',
                            'severity': 'medium',
                            'message': f'CDN 스타일시트에 SRI가 없습니다: {href}'
                        })

    def _check_vulnerable_libraries(self):
        """취약한 라이브러리 버전 검사"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 스크립트 태그 검사
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src', '').lower()

            # jQuery 버전 검사
            if 'jquery' in src:
                for version, vuln_desc in self.vulnerable_cdns.get('jquery', {}).items():
                    if f'jquery-{version}' in src or f'jquery/{version}' in src:
                        self.vulnerabilities.append({
                            'type': 'vulnerable_library',
                            'library': 'jQuery',
                            'version': version,
                            'resource': script.get('src'),
                            'severity': 'high',
                            'message': vuln_desc
                        })

            # AngularJS 버전 검사
            elif 'angular' in src:
                for version, vuln_desc in self.vulnerable_cdns.get('angular', {}).items():
                    # 다양한 CDN 패턴 지원: angular-1.2, angular/1.2, angularjs/1.2
                    if (f'angular-{version}' in src or
                        f'angular/{version}' in src or
                        f'angularjs/{version}' in src or
                        (f'/{version}' in src and 'angular' in src.lower())):
                        self.vulnerabilities.append({
                            'type': 'vulnerable_library',
                            'library': 'AngularJS',
                            'version': version,
                            'resource': script.get('src'),
                            'severity': 'high',
                            'message': vuln_desc
                        })

            # Bootstrap 버전 검사
            elif 'bootstrap' in src:
                for version, vuln_desc in self.vulnerable_cdns.get('bootstrap', {}).items():
                    # 다양한 CDN 패턴 지원: bootstrap-3.3, bootstrap/3.3
                    if (f'bootstrap-{version}' in src or
                        f'bootstrap/{version}' in src or
                        (f'/{version}' in src and 'bootstrap' in src.lower())):
                        self.vulnerabilities.append({
                            'type': 'vulnerable_library',
                            'library': 'Bootstrap',
                            'version': version,
                            'resource': script.get('src'),
                            'severity': 'medium',
                            'message': vuln_desc
                        })

    def _build_result(self) -> Dict[str, Any]:
        """결과 생성"""
        passed = len(self.vulnerabilities) == 0

        return {
            'passed': passed,
            'vulnerabilities': self.vulnerabilities,
            'severity': 'low' if passed else self._calculate_severity(),
            'message': self._generate_message(),
            'scanner_id': self.metadata['id']
        }

    def _calculate_severity(self) -> str:
        """심각도 계산"""
        if any(v.get('severity') == 'critical' for v in self.vulnerabilities):
            return 'critical'
        elif any(v.get('severity') == 'high' for v in self.vulnerabilities):
            return 'high'
        elif any(v.get('severity') == 'medium' for v in self.vulnerabilities):
            return 'medium'
        return 'low'

    def _generate_message(self) -> str:
        """메시지 생성"""
        if not self.vulnerabilities:
            return '공급망 보안 검사를 통과했습니다'

        issues = []
        vuln_types = set(v.get('type') for v in self.vulnerabilities)

        if 'sensitive_info_in_dependencies' in vuln_types:
            issues.append('종속성 파일에서 민감한 정보 노출')
        if 'exposed_dependency_file' in vuln_types:
            issues.append('종속성 파일 공개 접근 가능')
        if 'missing_sri' in vuln_types:
            issues.append('SRI 누락')
        if 'vulnerable_library' in vuln_types:
            issues.append('취약한 라이브러리 버전 사용')

        return f"공급망 보안 문제 발견: {', '.join(issues)}"

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata