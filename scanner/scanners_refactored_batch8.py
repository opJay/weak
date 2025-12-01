"""
Batch 8: Supply Chain Security Scanners
공급망 보안 스캐너 (OWASP A03:2025)

Includes:
1. SoftwareSupplyChainScanner - 소프트웨어 공급망 기본 검사
2. PackageIntegrityScanner - 패키지 무결성 검증
3. TyposquattingScanner - 타이포스쿼팅 탐지
4. OutdatedDependencyScanner - 오래된 종속성 검사
5. LicenseComplianceScanner - 라이선스 준수 검사
"""

import re
import json
import hashlib
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from scanner.base import BaseScanner


class SoftwareSupplyChainScanner(BaseScanner):
    """소프트웨어 공급망 기본 보안 검사 스캐너"""

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None):
        super().__init__(url=url or '', response=response,
                        html_content=html_content)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client
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

    def get_metadata(self) -> Dict[str, Any]:
        return {
            'id': 'supply_chain',
            'name': 'Software Supply Chain',
            'category': 'supply_chain',
            'severity': 'high',
            'description': '소프트웨어 공급망 보안 검사 (종속성 노출, SRI, 취약한 라이브러리)',
            'owasp': ['A03:2025']
        }

    def _prepare(self):
        """스캔 준비"""
        # 모든 속성은 __init__에서 초기화됨
        pass

    def _execute_scan(self):
        """스캔 실행"""
        # 1. 종속성 파일 노출 검사
        self._check_exposed_dependencies()

        # 2. SRI (Subresource Integrity) 검사
        self._check_sri()

        # 3. 취약한 CDN 라이브러리 검사
        self._check_vulnerable_libraries()

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
            'message': self._generate_message()
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


class PackageIntegrityScanner(BaseScanner):
    """패키지 무결성 검증 스캐너"""

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None):
        super().__init__(url=url or '', response=response,
                        html_content=html_content)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client
        self.vulnerabilities = []

        # 스캔에 필요한 속성들 초기화
        self.lockfiles = {
            'package-lock.json': 'npm',
            'yarn.lock': 'yarn',
            'Pipfile.lock': 'pipenv',
            'poetry.lock': 'poetry',
            'composer.lock': 'composer',
            'Gemfile.lock': 'bundler',
            'go.sum': 'go modules'
        }

    def get_metadata(self) -> Dict[str, Any]:
        return {
            'id': 'package_integrity',
            'name': 'Package Integrity',
            'category': 'supply_chain',
            'severity': 'high',
            'description': '패키지 무결성 검증 (lockfile 해시, SHA-512 검증)',
            'owasp': ['A03:2025', 'A08:2025']
        }

    def _prepare(self):
        """스캔 준비"""
        # 모든 속성은 __init__에서 초기화됨
        pass

    def _execute_scan(self):
        """스캔 실행"""
        # 1. Lockfile 무결성 검사
        self._check_lockfile_integrity()

        # 2. SRI 해시 강도 검사
        self._check_sri_strength()

        # 3. 패키지 체크섬 검증
        self._check_package_checksums()

    def _check_lockfile_integrity(self):
        """Lockfile 무결성 검사"""
        if not self.http_client:
            return

        base_url = self.url.rstrip('/')

        for lockfile, manager in self.lockfiles.items():
            try:
                response = self.http_client.get(f"{base_url}/{lockfile}")
                if response and hasattr(response, 'status_code') and response.status_code == 200:
                    content = response.text if hasattr(response, 'text') else str(response.content)

                    # 해시/무결성 필드 검사
                    integrity_patterns = {
                        'npm': r'"integrity":\s*"sha\d+-[^"]+',
                        'yarn': r'integrity\s+sha\d+-[^"]+',
                        'pipenv': r'"hash":\s*"sha256:[^"]+',
                        'poetry': r'content-hash\s*=\s*"[^"]+',
                        'composer': r'"content-hash":\s*"[^"]+',
                        'bundler': r'sha256:[a-f0-9]+',
                        'go modules': r'h1:[A-Za-z0-9+/]+=*'
                    }

                    pattern = integrity_patterns.get(manager)
                    if pattern:
                        matches = re.findall(pattern, content)

                        # SHA-1 사용 검사 (약한 해시)
                        if manager in ['npm', 'yarn']:
                            sha1_count = len([m for m in matches if 'sha1-' in m])
                            if sha1_count > 0:
                                self.vulnerabilities.append({
                                    'type': 'weak_hash_algorithm',
                                    'file': lockfile,
                                    'algorithm': 'SHA-1',
                                    'count': sha1_count,
                                    'severity': 'medium',
                                    'message': f'{lockfile}에서 약한 SHA-1 해시 사용 ({sha1_count}개 패키지)'
                                })

                        # 무결성 필드가 전혀 없는 경우
                        if len(matches) == 0:
                            self.vulnerabilities.append({
                                'type': 'missing_integrity',
                                'file': lockfile,
                                'manager': manager,
                                'severity': 'high',
                                'message': f'{lockfile}에 무결성 해시가 없습니다'
                            })
            except:
                pass

    def _check_sri_strength(self):
        """SRI 해시 강도 검사"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')

        # integrity 속성이 있는 모든 요소 검사
        elements_with_integrity = soup.find_all(attrs={'integrity': True})

        for elem in elements_with_integrity:
            integrity = elem.get('integrity', '')

            # SHA-256 미만 알고리즘 검사
            if 'sha256-' not in integrity and 'sha384-' not in integrity and 'sha512-' not in integrity:
                resource = elem.get('src') or elem.get('href') or 'unknown'
                self.vulnerabilities.append({
                    'type': 'weak_sri_algorithm',
                    'resource': resource,
                    'integrity': integrity,
                    'severity': 'medium',
                    'message': f'약한 SRI 해시 알고리즘: {integrity[:20]}...'
                })

            # 다중 해시가 없는 경우 (fallback 없음)
            hash_count = len(integrity.split())
            if hash_count == 1:
                resource = elem.get('src') or elem.get('href') or 'unknown'
                self.vulnerabilities.append({
                    'type': 'single_sri_hash',
                    'resource': resource,
                    'severity': 'low',
                    'message': f'단일 SRI 해시만 사용 (fallback 없음): {resource}'
                })

    def _check_package_checksums(self):
        """패키지 체크섬 파일 검사"""
        if not self.http_client:
            return

        base_url = self.url.rstrip('/')
        checksum_files = [
            'SHA256SUMS', 'SHA512SUMS', 'MD5SUMS',
            'checksums.txt', 'CHECKSUMS'
        ]

        for checksum_file in checksum_files:
            try:
                response = self.http_client.get(f"{base_url}/{checksum_file}")
                if response and hasattr(response, 'status_code') and response.status_code == 200:
                    content = response.text if hasattr(response, 'text') else str(response.content)

                    # MD5 체크섬 사용 검사
                    if 'MD5' in checksum_file.upper() or re.search(r'[a-f0-9]{32}\s+\S+', content):
                        self.vulnerabilities.append({
                            'type': 'weak_checksum_algorithm',
                            'file': checksum_file,
                            'algorithm': 'MD5',
                            'severity': 'medium',
                            'message': f'약한 MD5 체크섬 사용: {checksum_file}'
                        })

                    # SHA-1 체크섬 사용 검사
                    elif re.search(r'[a-f0-9]{40}\s+\S+', content):
                        self.vulnerabilities.append({
                            'type': 'weak_checksum_algorithm',
                            'file': checksum_file,
                            'algorithm': 'SHA-1',
                            'severity': 'medium',
                            'message': f'약한 SHA-1 체크섬 사용: {checksum_file}'
                        })
            except:
                pass

    def _build_result(self) -> Dict[str, Any]:
        """결과 생성"""
        passed = len(self.vulnerabilities) == 0

        return {
            'passed': passed,
            'vulnerabilities': self.vulnerabilities,
            'severity': 'low' if passed else self._calculate_severity(),
            'message': self._generate_message()
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
            return '패키지 무결성 검증을 통과했습니다'

        issues = []
        vuln_types = set(v.get('type') for v in self.vulnerabilities)

        if 'weak_hash_algorithm' in vuln_types:
            issues.append('약한 해시 알고리즘 사용')
        if 'missing_integrity' in vuln_types:
            issues.append('무결성 해시 누락')
        if 'weak_sri_algorithm' in vuln_types:
            issues.append('약한 SRI 알고리즘')
        if 'weak_checksum_algorithm' in vuln_types:
            issues.append('약한 체크섬 알고리즘')

        return f"패키지 무결성 문제 발견: {', '.join(issues)}"


class TyposquattingScanner(BaseScanner):
    """타이포스쿼팅 탐지 스캐너"""

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None):
        super().__init__(url=url or '', response=response,
                        html_content=html_content)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client
        self.vulnerabilities = []

        # 스캔에 필요한 속성들 초기화
        # 유명 패키지와 타이포스쿼팅 변형
        self.typosquatting_patterns = {
            # JavaScript/npm
            'react': ['raect', 'reakt', 'rreact', 'react-js', 'reactjs'],
            'lodash': ['lodahs', 'lodas', 'loadash', 'lodash-js'],
            'express': ['expres', 'exress', 'expresss', 'express-js'],
            'axios': ['axois', 'axio', 'axioss', 'axios-js'],
            'vue': ['vuee', 'veu', 'vue-js', 'vuejs'],

            # Python/pip
            'requests': ['request', 'requestss', 'requets', 'reqests'],
            'django': ['djnago', 'djagno', 'djangoo', 'django-py'],
            'numpy': ['numpi', 'numpyy', 'nunpy', 'numpy-py'],
            'pandas': ['panda', 'pandass', 'padnas', 'pandas-py'],
            'flask': ['flaks', 'flaskk', 'falsk', 'flask-py'],

            # Ruby/gem
            'rails': ['rail', 'railss', 'rials', 'rails-rb'],
            'bundler': ['bundlerr', 'bunlder', 'bundlar'],

            # PHP/composer
            'symfony': ['symfoni', 'symfonny', 'synfony'],
            'laravel': ['larvael', 'laravell', 'laraval']
        }

        # 의심스러운 패키지명 패턴
        self.suspicious_patterns = [
            r'-dev$', r'-test$', r'-demo$', r'-sample$',
            r'^test-', r'^demo-', r'^sample-', r'^example-',
            r'\d{6,}',  # 긴 숫자
            r'[0-9a-f]{32}',  # 해시처럼 보이는 이름
            r'temp[_-]?', r'tmp[_-]?'
        ]

    def get_metadata(self) -> Dict[str, Any]:
        return {
            'id': 'typosquatting',
            'name': 'Typosquatting Detection',
            'category': 'supply_chain',
            'severity': 'high',
            'description': '타이포스쿼팅 공격 탐지 (유사 패키지명, 의심스러운 패턴)',
            'owasp': ['A03:2025']
        }

    def _prepare(self):
        """스캔 준비"""
        # 모든 속성은 __init__에서 초기화됨
        pass

    def _execute_scan(self):
        """스캔 실행"""
        # 1. 종속성 파일에서 타이포스쿼팅 검사
        self._check_dependency_typosquatting()

        # 2. HTML에서 로드되는 스크립트 검사
        self._check_script_typosquatting()

        # 3. 의심스러운 패키지명 패턴 검사
        self._check_suspicious_patterns()

    def _check_dependency_typosquatting(self):
        """종속성 파일에서 타이포스쿼팅 검사"""
        if not self.http_client:
            return

        base_url = self.url.rstrip('/')
        dependency_files = [
            ('package.json', r'"([^"]+)":\s*"[^"]*"'),
            ('requirements.txt', r'^([a-zA-Z0-9_-]+)'),
            ('Gemfile', r'gem\s+[\'"]([^\'"]+)'),
            ('composer.json', r'"([^"]+)":\s*"[^"]*"')
        ]

        for dep_file, pattern in dependency_files:
            try:
                response = self.http_client.get(f"{base_url}/{dep_file}")
                if response and hasattr(response, 'status_code') and response.status_code == 200:
                    content = response.text if hasattr(response, 'text') else str(response.content)

                    packages = re.findall(pattern, content, re.MULTILINE)

                    for package in packages:
                        package_lower = package.lower()

                        # 타이포스쿼팅 패턴 검사
                        for original, variants in self.typosquatting_patterns.items():
                            if package_lower in variants:
                                self.vulnerabilities.append({
                                    'type': 'typosquatting',
                                    'file': dep_file,
                                    'package': package,
                                    'original': original,
                                    'severity': 'critical',
                                    'message': f'타이포스쿼팅 의심: {package} (원본: {original})'
                                })

                        # 의심스러운 패턴 검사
                        for suspicious_pattern in self.suspicious_patterns:
                            if re.search(suspicious_pattern, package_lower):
                                self.vulnerabilities.append({
                                    'type': 'suspicious_package_name',
                                    'file': dep_file,
                                    'package': package,
                                    'pattern': suspicious_pattern,
                                    'severity': 'medium',
                                    'message': f'의심스러운 패키지명: {package}'
                                })
                                break
            except:
                pass

    def _check_script_typosquatting(self):
        """HTML 스크립트에서 타이포스쿼팅 검사"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')
        scripts = soup.find_all('script', src=True)

        for script in scripts:
            src = script.get('src', '').lower()

            # CDN URL에서 패키지명 추출
            package_patterns = [
                r'/([^/]+)@[\d.]+',  # unpkg.com/package@version
                r'/npm/([^/@]+)',    # jsdelivr.net/npm/package
                r'/ajax/libs/([^/]+)',  # cdnjs.cloudflare.com/ajax/libs/package
            ]

            for pattern in package_patterns:
                match = re.search(pattern, src)
                if match:
                    package = match.group(1)

                    # 타이포스쿼팅 검사
                    for original, variants in self.typosquatting_patterns.items():
                        if package in variants:
                            self.vulnerabilities.append({
                                'type': 'cdn_typosquatting',
                                'resource': script.get('src'),
                                'package': package,
                                'original': original,
                                'severity': 'critical',
                                'message': f'CDN 타이포스쿼팅 의심: {package} (원본: {original})'
                            })
                    break  # 첫 패턴 매칭 후 중단하여 중복 방지

    def _check_suspicious_patterns(self):
        """의심스러운 패키지명 패턴 추가 검사"""
        if not self.html_content:
            return

        # HTML 내용에서 import/require 문 검사
        import_patterns = [
            r'import\s+.*?from\s+[\'"]([^\'"]+)',
            r'require\s*\([\'"]([^\'"]+)',
            r'import\s*\([\'"]([^\'"]+)'
        ]

        for pattern in import_patterns:
            matches = re.findall(pattern, self.html_content)
            for match in matches:
                package = match.split('/')[0] if '/' in match else match
                package_lower = package.lower()

                # 의심스러운 패턴 검사
                for suspicious_pattern in self.suspicious_patterns:
                    if re.search(suspicious_pattern, package_lower):
                        self.vulnerabilities.append({
                            'type': 'suspicious_import',
                            'package': package,
                            'pattern': suspicious_pattern,
                            'severity': 'medium',
                            'message': f'의심스러운 import/require: {package}'
                        })
                        break

    def _build_result(self) -> Dict[str, Any]:
        """결과 생성"""
        passed = len(self.vulnerabilities) == 0

        return {
            'passed': passed,
            'vulnerabilities': self.vulnerabilities,
            'severity': 'low' if passed else self._calculate_severity(),
            'message': self._generate_message()
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
            return '타이포스쿼팅 위험이 발견되지 않았습니다'

        issues = []
        vuln_types = set(v.get('type') for v in self.vulnerabilities)

        if 'typosquatting' in vuln_types:
            issues.append('타이포스쿼팅 패키지 발견')
        if 'cdn_typosquatting' in vuln_types:
            issues.append('CDN 타이포스쿼팅')
        if 'suspicious_package_name' in vuln_types:
            issues.append('의심스러운 패키지명')
        if 'suspicious_import' in vuln_types:
            issues.append('의심스러운 import/require')

        return f"타이포스쿼팅 위험 발견: {', '.join(issues)}"


class OutdatedDependencyScanner(BaseScanner):
    """오래된 종속성 검사 스캐너"""

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None):
        super().__init__(url=url or '', response=response,
                        html_content=html_content)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client
        self.vulnerabilities = []

        # EOL(End-of-Life) 버전 정보
        self.eol_versions = {
            # Node.js
            'node': ['0.', '4.', '6.', '8.', '10.', '12.', '14.'],

            # Python
            'python': ['2.', '3.0', '3.1', '3.2', '3.3', '3.4', '3.5', '3.6', '3.7'],

            # PHP
            'php': ['5.', '7.0', '7.1', '7.2', '7.3'],

            # jQuery
            'jquery': ['1.', '2.'],

            # AngularJS
            'angular': ['1.'],

            # React (매우 오래된 버전)
            'react': ['0.', '15.', '16.0', '16.1', '16.2']
        }

        # 알려진 취약한 버전 (CVE 패턴)
        self.vulnerable_versions = {
            'lodash': {
                'pattern': r'[0-3]\.',
                'cve': 'CVE-2019-10744',
                'description': 'Prototype pollution vulnerability'
            },
            'minimist': {
                'pattern': r'[0]\.|1\.[0-1]\.',
                'cve': 'CVE-2020-7598',
                'description': 'Prototype pollution vulnerability'
            },
            'serialize-javascript': {
                'pattern': r'[0-2]\.',
                'cve': 'CVE-2019-16769',
                'description': 'Code injection vulnerability'
            },
            'axios': {
                'pattern': r'0\.[0-1][0-8]\.',
                'cve': 'CVE-2019-10742',
                'description': 'SSRF vulnerability'
            }
        }

    def get_metadata(self) -> Dict[str, Any]:
        return {
            'id': 'outdated_dependencies',
            'name': 'Outdated Dependencies',
            'category': 'supply_chain',
            'severity': 'high',
            'description': '오래된 종속성 및 EOL 패키지 검사',
            'owasp': ['A03:2025', 'A06:2025']
        }

    def _prepare(self):
        """스캔 준비"""
        # 모든 속성은 __init__에서 초기화됨
        pass

    def _execute_scan(self):
        """스캔 실행"""
        # 1. 종속성 파일에서 버전 검사
        self._check_dependency_versions()

        # 2. CDN 라이브러리 버전 검사
        self._check_cdn_versions()

        # 3. Runtime 버전 검사
        self._check_runtime_versions()

    def _check_dependency_versions(self):
        """종속성 파일에서 버전 검사"""
        if not self.http_client:
            return

        base_url = self.url.rstrip('/')

        # package.json 검사
        try:
            response = self.http_client.get(f"{base_url}/package.json")
            if response and hasattr(response, 'status_code') and response.status_code == 200:
                content = response.text if hasattr(response, 'text') else str(response.content)

                # dependencies와 devDependencies 추출
                deps_pattern = r'"([^"]+)":\s*"([^"]+)"'
                matches = re.findall(deps_pattern, content)

                for package, version in matches:
                    # 취약한 버전 검사
                    if package in self.vulnerable_versions:
                        vuln_info = self.vulnerable_versions[package]
                        if re.search(vuln_info['pattern'], version):
                            self.vulnerabilities.append({
                                'type': 'vulnerable_dependency',
                                'package': package,
                                'version': version,
                                'cve': vuln_info['cve'],
                                'description': vuln_info['description'],
                                'severity': 'critical',
                                'message': f'{package}@{version}에 {vuln_info["cve"]} 취약점'
                            })

                    # 매우 오래된 메이저 버전 검사 (0.x.x)
                    if re.match(r'^[\^~]?0\.', version):
                        self.vulnerabilities.append({
                            'type': 'pre_release_version',
                            'package': package,
                            'version': version,
                            'severity': 'medium',
                            'message': f'{package}@{version}는 프리릴리즈 버전입니다'
                        })
        except:
            pass

        # requirements.txt 검사 (Python)
        try:
            response = self.http_client.get(f"{base_url}/requirements.txt")
            if response and hasattr(response, 'status_code') and response.status_code == 200:
                content = response.text if hasattr(response, 'text') else str(response.content)

                # 패키지==버전 패턴
                deps_pattern = r'^([a-zA-Z0-9_-]+)==([\d.]+)'
                matches = re.findall(deps_pattern, content, re.MULTILINE)

                for package, version in matches:
                    # Django 1.x 검사
                    if package.lower() == 'django' and version.startswith('1.'):
                        self.vulnerabilities.append({
                            'type': 'eol_dependency',
                            'package': package,
                            'version': version,
                            'severity': 'high',
                            'message': f'Django {version}는 EOL 버전입니다'
                        })

                    # Flask 0.x 검사
                    elif package.lower() == 'flask' and version.startswith('0.'):
                        self.vulnerabilities.append({
                            'type': 'outdated_dependency',
                            'package': package,
                            'version': version,
                            'severity': 'medium',
                            'message': f'Flask {version}는 매우 오래된 버전입니다'
                        })
        except:
            pass

    def _check_cdn_versions(self):
        """CDN 라이브러리 버전 검사"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')
        scripts = soup.find_all('script', src=True)

        for script in scripts:
            src = script.get('src', '')

            # 버전 패턴 추출 (npm @ 형식 포함)
            version_patterns = [
                (r'jquery[@/-](\d+\.\d+(?:\.\d+)?)', 'jquery'),
                (r'angular[@/-](\d+\.\d+(?:\.\d+)?)', 'angular'),
                (r'react[@/-](\d+\.\d+(?:\.\d+)?)', 'react'),
                (r'vue[@/-](\d+\.\d+(?:\.\d+)?)', 'vue'),
                (r'bootstrap[@/-](\d+\.\d+(?:\.\d+)?)', 'bootstrap'),
                (r'@(\d+\.\d+(?:\.\d+)?)', None)  # npm 스타일 버전
            ]

            for pattern, library in version_patterns:
                match = re.search(pattern, src)
                if match:
                    version = match.group(1)

                    # 라이브러리 이름 추출 (없으면 URL에서 추정)
                    if not library:
                        lib_match = re.search(r'/([^/@]+)@', src)
                        if lib_match:
                            library = lib_match.group(1).lower()

                    if library:
                        # EOL 버전 검사
                        if library in self.eol_versions:
                            for eol_version in self.eol_versions[library]:
                                if version.startswith(eol_version):
                                    self.vulnerabilities.append({
                                        'type': 'eol_cdn_library',
                                        'library': library,
                                        'version': version,
                                        'resource': src,
                                        'severity': 'high',
                                        'message': f'{library} {version}는 EOL 버전입니다'
                                    })
                                    break

    def _check_runtime_versions(self):
        """Runtime 환경 버전 검사"""
        if not self.http_client:
            return

        base_url = self.url.rstrip('/')

        # .nvmrc (Node.js 버전)
        try:
            response = self.http_client.get(f"{base_url}/.nvmrc")
            if response and hasattr(response, 'status_code') and response.status_code == 200:
                content = response.text if hasattr(response, 'text') else str(response.content)
                version = content.strip()

                for eol_version in self.eol_versions.get('node', []):
                    if version.startswith(eol_version):
                        self.vulnerabilities.append({
                            'type': 'eol_runtime',
                            'runtime': 'Node.js',
                            'version': version,
                            'severity': 'high',
                            'message': f'Node.js {version}는 EOL 버전입니다'
                        })
                        break
        except:
            pass

        # .python-version
        try:
            response = self.http_client.get(f"{base_url}/.python-version")
            if response and hasattr(response, 'status_code') and response.status_code == 200:
                content = response.text if hasattr(response, 'text') else str(response.content)
                version = content.strip()

                for eol_version in self.eol_versions.get('python', []):
                    if version.startswith(eol_version):
                        self.vulnerabilities.append({
                            'type': 'eol_runtime',
                            'runtime': 'Python',
                            'version': version,
                            'severity': 'high',
                            'message': f'Python {version}는 EOL 버전입니다'
                        })
                        break
        except:
            pass

    def _build_result(self) -> Dict[str, Any]:
        """결과 생성"""
        passed = len(self.vulnerabilities) == 0

        return {
            'passed': passed,
            'vulnerabilities': self.vulnerabilities,
            'severity': 'low' if passed else self._calculate_severity(),
            'message': self._generate_message()
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
            return '모든 종속성이 최신 상태입니다'

        issues = []
        vuln_types = set(v.get('type') for v in self.vulnerabilities)

        if 'vulnerable_dependency' in vuln_types:
            issues.append('취약한 종속성')
        if 'eol_dependency' in vuln_types or 'eol_cdn_library' in vuln_types:
            issues.append('EOL 버전')
        if 'eol_runtime' in vuln_types:
            issues.append('EOL 런타임')
        if 'outdated_dependency' in vuln_types:
            issues.append('오래된 종속성')
        if 'pre_release_version' in vuln_types:
            issues.append('프리릴리즈 버전')

        return f"오래된 종속성 발견: {', '.join(issues)}"


class LicenseComplianceScanner(BaseScanner):
    """라이선스 준수 검사 스캐너"""

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None):
        super().__init__(url=url or '', response=response,
                        html_content=html_content)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client
        self.vulnerabilities = []

        # Copyleft 라이선스 (강한 제약)
        self.copyleft_licenses = [
            'GPL', 'GPLv2', 'GPLv3', 'GPL-2.0', 'GPL-3.0',
            'AGPL', 'AGPLv3', 'AGPL-3.0',
            'LGPL', 'LGPLv2', 'LGPLv3', 'LGPL-2.1', 'LGPL-3.0'
        ]

        # 상업적 사용 제한 라이선스
        self.commercial_restricted = [
            'CC-BY-NC', 'CC-BY-NC-SA', 'CC-BY-NC-ND',
            'NonCommercial', 'NC', 'Educational',
            'Academic', 'Research'
        ]

        # 일반적으로 호환성 문제가 있는 조합
        self.incompatible_combinations = [
            ('MIT', 'GPL'),
            ('Apache', 'GPL'),
            ('BSD', 'GPL')
        ]

    def get_metadata(self) -> Dict[str, Any]:
        return {
            'id': 'license_compliance',
            'name': 'License Compliance',
            'category': 'supply_chain',
            'severity': 'medium',
            'description': '라이선스 준수 검사 (GPL, AGPL, 상업적 사용 제한)',
            'owasp': ['A03:2025']
        }

    def _prepare(self):
        """스캔 준비"""
        # 모든 속성은 __init__에서 초기화됨
        pass

    def _execute_scan(self):
        """스캔 실행"""
        # 1. 라이선스 파일 검사
        self._check_license_files()

        # 2. 종속성 라이선스 검사
        self._check_dependency_licenses()

        # 3. 라이선스 호환성 검사
        self._check_license_compatibility()

    def _check_license_files(self):
        """라이선스 파일 검사"""
        if not self.http_client:
            return

        base_url = self.url.rstrip('/')
        license_files = ['LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING']

        license_found = False
        project_license = None

        for license_file in license_files:
            try:
                response = self.http_client.get(f"{base_url}/{license_file}")
                if response and hasattr(response, 'status_code') and response.status_code == 200:
                    content = response.text if hasattr(response, 'text') else str(response.content)
                    license_found = True

                    # Copyleft 라이선스 검사
                    for copyleft in self.copyleft_licenses:
                        if copyleft.upper() in content.upper():
                            project_license = copyleft
                            self.vulnerabilities.append({
                                'type': 'copyleft_license',
                                'file': license_file,
                                'license': copyleft,
                                'severity': 'medium',
                                'message': f'Copyleft 라이선스 {copyleft} 사용 (코드 공개 의무)'
                            })
                            break

                    # 상업적 사용 제한 검사
                    for restricted in self.commercial_restricted:
                        if restricted.upper() in content.upper():
                            self.vulnerabilities.append({
                                'type': 'commercial_restriction',
                                'file': license_file,
                                'license': restricted,
                                'severity': 'high',
                                'message': f'상업적 사용 제한 라이선스: {restricted}'
                            })
                            break  # 첫 매칭 후 중단하여 중복 방지

                    break
            except:
                pass

        # 라이선스 파일이 없는 경우
        if not license_found:
            self.vulnerabilities.append({
                'type': 'missing_license',
                'severity': 'low',
                'message': '프로젝트 라이선스 파일이 없습니다'
            })

    def _check_dependency_licenses(self):
        """종속성 라이선스 검사"""
        if not self.http_client:
            return

        base_url = self.url.rstrip('/')

        # package.json에서 라이선스 검사
        try:
            response = self.http_client.get(f"{base_url}/package.json")
            if response and hasattr(response, 'status_code') and response.status_code == 200:
                content = response.text if hasattr(response, 'text') else str(response.content)

                try:
                    import json
                    package_data = json.loads(content)

                    # 프로젝트 자체 라이선스
                    project_license = package_data.get('license', '')

                    # dependencies 검사
                    dependencies = package_data.get('dependencies', {})

                    # 각 종속성의 라이선스 검사 (package-lock.json이 필요)
                    try:
                        lock_response = self.http_client.get(f"{base_url}/package-lock.json")
                        if lock_response and hasattr(lock_response, 'status_code') and lock_response.status_code == 200:
                            lock_content = lock_response.text if hasattr(lock_response, 'text') else str(lock_response.content)
                            lock_data = json.loads(lock_content)

                            packages = lock_data.get('packages', {})
                            copyleft_deps = []
                            restricted_deps = []

                            for pkg_name, pkg_info in packages.items():
                                if isinstance(pkg_info, dict):
                                    license_field = pkg_info.get('license', '')

                                    # Copyleft 검사
                                    for copyleft in self.copyleft_licenses:
                                        if copyleft.upper() in str(license_field).upper():
                                            copyleft_deps.append((pkg_name, copyleft))
                                            break

                                    # 상업적 제한 검사
                                    for restricted in self.commercial_restricted:
                                        if restricted.upper() in str(license_field).upper():
                                            restricted_deps.append((pkg_name, restricted))
                                            break

                            # Copyleft 종속성 보고
                            if copyleft_deps:
                                self.vulnerabilities.append({
                                    'type': 'copyleft_dependencies',
                                    'count': len(copyleft_deps),
                                    'examples': copyleft_deps[:3],
                                    'severity': 'medium',
                                    'message': f'{len(copyleft_deps)}개의 Copyleft 종속성 발견'
                                })

                            # 상업적 제한 종속성 보고
                            if restricted_deps:
                                self.vulnerabilities.append({
                                    'type': 'restricted_dependencies',
                                    'count': len(restricted_deps),
                                    'examples': restricted_deps[:3],
                                    'severity': 'high',
                                    'message': f'{len(restricted_deps)}개의 상업적 사용 제한 종속성'
                                })
                    except:
                        pass
                except:
                    pass
        except:
            pass

    def _check_license_compatibility(self):
        """라이선스 호환성 검사"""
        if not self.http_client:
            return

        base_url = self.url.rstrip('/')

        # package.json에서 프로젝트 라이선스 가져오기
        try:
            response = self.http_client.get(f"{base_url}/package.json")
            if response and hasattr(response, 'status_code') and response.status_code == 200:
                content = response.text if hasattr(response, 'text') else str(response.content)

                try:
                    import json
                    package_data = json.loads(content)
                    project_license = package_data.get('license', '').upper()

                    # MIT/Apache/BSD와 GPL 종속성 혼합 검사
                    if any(lic in project_license for lic in ['MIT', 'APACHE', 'BSD']):
                        # package-lock.json에서 GPL 종속성 찾기
                        try:
                            lock_response = self.http_client.get(f"{base_url}/package-lock.json")
                            if lock_response and hasattr(lock_response, 'status_code') and lock_response.status_code == 200:
                                lock_content = lock_response.text if hasattr(lock_response, 'text') else str(lock_response.content)

                                if 'GPL' in lock_content.upper() and 'LGPL' not in lock_content.upper():
                                    self.vulnerabilities.append({
                                        'type': 'license_incompatibility',
                                        'project_license': project_license,
                                        'conflicting': 'GPL',
                                        'severity': 'medium',
                                        'message': f'{project_license}와 GPL 라이선스 호환성 문제'
                                    })
                        except:
                            pass
                except:
                    pass
        except:
            pass

    def _build_result(self) -> Dict[str, Any]:
        """결과 생성"""
        passed = len(self.vulnerabilities) == 0

        return {
            'passed': passed,
            'vulnerabilities': self.vulnerabilities,
            'severity': 'low' if passed else self._calculate_severity(),
            'message': self._generate_message()
        }

    def _calculate_severity(self) -> str:
        """심각도 계산"""
        if any(v.get('severity') == 'high' for v in self.vulnerabilities):
            return 'high'
        elif any(v.get('severity') == 'medium' for v in self.vulnerabilities):
            return 'medium'
        return 'low'

    def _generate_message(self) -> str:
        """메시지 생성"""
        if not self.vulnerabilities:
            return '라이선스 준수 문제가 발견되지 않았습니다'

        issues = []
        vuln_types = set(v.get('type') for v in self.vulnerabilities)

        if 'missing_license' in vuln_types:
            issues.append('라이선스 파일 누락')
        if 'copyleft_license' in vuln_types or 'copyleft_dependencies' in vuln_types:
            issues.append('Copyleft 라이선스')
        if 'commercial_restriction' in vuln_types or 'restricted_dependencies' in vuln_types:
            issues.append('상업적 사용 제한')
        if 'license_incompatibility' in vuln_types:
            issues.append('라이선스 호환성 문제')

        return f"라이선스 준수 문제 발견: {', '.join(issues)}"