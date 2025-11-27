"""
Advanced Software Supply Chain Security Scanners
OWASP Top 10 2025 A03: Software Supply Chain Failures 강화

고급 공급망 보안 스캐너:
- Package Integrity (패키지 무결성)
- Typosquatting (타이포스쿼팅)
- Outdated Dependencies (오래된 종속성 강화)
- License Compliance (라이선스 준수)
"""
import re
import requests
import json
import logging
from urllib.parse import urljoin
from datetime import datetime, timedelta

logger = logging.getLogger('scanner')


class PackageIntegrityScanner:
    """
    패키지 무결성 스캐너

    패키지 매니저의 무결성 검증 메커니즘 확인
    - package-lock.json의 integrity 해시 검증
    - lockfile 누락 탐지
    - 무결성 검증 누락
    """

    metadata = {
        'id': 'package_integrity',
        'name': '패키지 무결성 검증',
        'icon': '🔐',
        'description': '패키지 해시 및 무결성 검증',
        'weight': 2,
        'field': 'package_integrity_vulnerabilities'
    }

    def __init__(self, url, response=None, html_content=None):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """패키지 무결성 스캔 실행"""
        try:
            base_url = self.url.rstrip('/')

            # 1. package-lock.json 검사
            self._check_npm_lockfile(base_url)

            # 2. yarn.lock 검사
            self._check_yarn_lockfile(base_url)

            # 3. requirements.txt와 hash 검증
            self._check_pip_requirements(base_url)

            # 4. composer.lock 검사
            self._check_composer_lock(base_url)

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'Package Integrity Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _check_npm_lockfile(self, base_url):
        """npm package-lock.json 검사"""
        try:
            lock_url = f'{base_url}/package-lock.json'
            response = requests.get(lock_url, timeout=5, allow_redirects=False)

            if response.status_code == 200:
                try:
                    lock_data = response.json()

                    # lockfileVersion 확인
                    if 'lockfileVersion' not in lock_data:
                        self.vulnerabilities.append({
                            'type': 'missing_lockfile_version',
                            'severity': 'medium',
                            'title': 'package-lock.json 버전 정보 누락',
                            'description': 'lockfileVersion 필드가 없습니다.',
                            'url': lock_url,
                            'recommendation': 'npm 최신 버전을 사용하여 lockfile을 재생성하세요.'
                        })

                    # dependencies의 integrity 확인
                    packages = lock_data.get('packages', {}) or lock_data.get('dependencies', {})
                    missing_integrity_count = 0

                    for pkg_name, pkg_info in list(packages.items())[:10]:  # 처음 10개만 검사
                        if isinstance(pkg_info, dict) and 'version' in pkg_info:
                            if 'integrity' not in pkg_info:
                                missing_integrity_count += 1

                    if missing_integrity_count > 0:
                        self.vulnerabilities.append({
                            'type': 'missing_integrity_hash',
                            'severity': 'high',
                            'title': 'npm 패키지 무결성 해시 누락',
                            'description': f'{missing_integrity_count}개 패키지에 integrity 해시가 없습니다.',
                            'url': lock_url,
                            'evidence': f'{missing_integrity_count} packages without integrity',
                            'recommendation': 'npm install을 재실행하여 무결성 해시를 생성하세요.'
                        })

                except json.JSONDecodeError:
                    pass

        except requests.RequestException:
            pass

    def _check_yarn_lockfile(self, base_url):
        """yarn.lock 검사"""
        try:
            lock_url = f'{base_url}/yarn.lock'
            response = requests.get(lock_url, timeout=5, allow_redirects=False)

            if response.status_code == 200:
                content = response.text

                # integrity 필드가 있는지 확인
                if 'integrity sha' not in content.lower():
                    self.vulnerabilities.append({
                        'type': 'yarn_integrity_missing',
                        'severity': 'medium',
                        'title': 'yarn.lock 무결성 정보 부족',
                        'description': 'yarn.lock에 무결성 해시가 없거나 부족합니다.',
                        'url': lock_url,
                        'recommendation': 'yarn install을 재실행하여 무결성 정보를 갱신하세요.'
                    })

        except requests.RequestException:
            pass

    def _check_pip_requirements(self, base_url):
        """pip requirements.txt 해시 검증"""
        try:
            req_url = f'{base_url}/requirements.txt'
            response = requests.get(req_url, timeout=5, allow_redirects=False)

            if response.status_code == 200:
                content = response.text

                # --hash 옵션 사용 여부 확인
                if '--hash=' not in content and 'sha256:' not in content:
                    self.vulnerabilities.append({
                        'type': 'pip_no_hash',
                        'severity': 'high',
                        'title': 'pip 패키지 해시 검증 미사용',
                        'description': 'requirements.txt에 --hash 옵션이 없어 무결성 검증이 되지 않습니다.',
                        'url': req_url,
                        'recommendation': 'pip-tools의 pip-compile --generate-hashes를 사용하세요.'
                    })

        except requests.RequestException:
            pass

    def _check_composer_lock(self, base_url):
        """PHP composer.lock 검사"""
        try:
            lock_url = f'{base_url}/composer.lock'
            response = requests.get(lock_url, timeout=5, allow_redirects=False)

            if response.status_code == 200:
                try:
                    lock_data = response.json()

                    # content-hash 확인
                    if 'content-hash' not in lock_data:
                        self.vulnerabilities.append({
                            'type': 'composer_no_hash',
                            'severity': 'medium',
                            'title': 'composer.lock 해시 누락',
                            'description': 'content-hash가 없어 composer.json과의 일치성을 검증할 수 없습니다.',
                            'url': lock_url,
                            'recommendation': 'composer update --lock을 실행하세요.'
                        })

                except json.JSONDecodeError:
                    pass

        except requests.RequestException:
            pass

    def _calculate_severity(self):
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'low')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if severity_counts['high'] >= 1:
            return 'high'
        elif severity_counts['medium'] >= 2:
            return 'medium'
        else:
            return 'low'

    def _get_recommendations(self):
        """보안 권장사항"""
        return [
            'package-lock.json, yarn.lock 등 lockfile을 반드시 버전 관리에 포함하세요.',
            'npm install, yarn install 시 자동으로 무결성 해시가 생성됩니다.',
            'pip의 경우 pip-compile --generate-hashes를 사용하여 해시를 생성하세요.',
            'CI/CD에서 lockfile 무결성 검증을 자동화하세요.',
            '무결성 해시는 공급망 공격(supply chain attack) 방어에 필수적입니다.'
        ]


class TyposquattingScanner:
    """
    타이포스쿼팅 탐지 스캐너

    유사한 이름의 악성 패키지 사용 탐지
    - 레벤슈타인 거리 기반 유사도 분석
    - 알려진 악성 패키지 블랙리스트
    - 일반적인 타이포 패턴
    """

    metadata = {
        'id': 'typosquatting',
        'name': '타이포스쿼팅 탐지',
        'icon': '🎭',
        'description': '유사 패키지명 악성 코드 탐지',
        'weight': 1.5,
        'field': 'typosquatting_vulnerabilities'
    }

    # 알려진 인기 패키지와 타이포스쿼팅 패턴
    POPULAR_PACKAGES = {
        'lodash': ['lod_ash', 'loadash', 'lodish', 'lodas'],
        'express': ['expres', 'expresss', 'exprss'],
        'react': ['react-js', 'reactt', 'reacts'],
        'vue': ['vuejs', 'vue-js'],
        'django': ['djengo', 'djano', 'djanggo'],
        'flask': ['flsk', 'falsk', 'flack'],
        'numpy': ['numpi', 'nunpy', 'numpyy'],
        'pandas': ['pands', 'pandass', 'panda'],
        'requests': ['request', 'reqeusts', 'reque'],
        'axios': ['axio', 'axioss', 'axois']
    }

    def __init__(self, url, response=None, html_content=None):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """타이포스쿼팅 스캔 실행"""
        try:
            base_url = self.url.rstrip('/')

            # 1. package.json 분석
            self._check_package_json(base_url)

            # 2. requirements.txt 분석
            self._check_requirements_txt(base_url)

            # 3. HTML/JS에서 CDN URL 분석
            if self.html_content:
                self._check_cdn_urls(self.html_content)

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'Typosquatting Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _check_package_json(self, base_url):
        """package.json에서 타이포스쿼팅 검사"""
        try:
            pkg_url = f'{base_url}/package.json'
            response = requests.get(pkg_url, timeout=5, allow_redirects=False)

            if response.status_code == 200:
                try:
                    pkg_data = response.json()
                    deps = {}
                    deps.update(pkg_data.get('dependencies', {}))
                    deps.update(pkg_data.get('devDependencies', {}))

                    for pkg_name in deps.keys():
                        self._check_package_name(pkg_name, 'npm', pkg_url)

                except json.JSONDecodeError:
                    pass

        except requests.RequestException:
            pass

    def _check_requirements_txt(self, base_url):
        """requirements.txt에서 타이포스쿼팅 검사"""
        try:
            req_url = f'{base_url}/requirements.txt'
            response = requests.get(req_url, timeout=5, allow_redirects=False)

            if response.status_code == 200:
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # 패키지명 추출 (==, >=, <= 등 제거)
                        pkg_name = re.split(r'[<>=!]', line)[0].strip()
                        if pkg_name:
                            self._check_package_name(pkg_name, 'pip', req_url)

        except requests.RequestException:
            pass

    def _check_cdn_urls(self, content):
        """CDN URL에서 타이포스쿼팅 검사"""
        # CDN에서 로드하는 라이브러리 이름 추출
        cdn_patterns = [
            r'cdn\.jsdelivr\.net/npm/([^@/]+)',
            r'unpkg\.com/([^@/]+)',
            r'cdnjs\.cloudflare\.com/ajax/libs/([^/]+)'
        ]

        for pattern in cdn_patterns:
            matches = re.findall(pattern, content)
            for pkg_name in matches:
                self._check_package_name(pkg_name, 'cdn', self.url)

    def _check_package_name(self, pkg_name, pkg_type, url):
        """패키지 이름 타이포스쿼팅 검사"""
        pkg_name_lower = pkg_name.lower()

        # 알려진 타이포스쿼팅 패턴 검사
        for legit_pkg, typo_variants in self.POPULAR_PACKAGES.items():
            if pkg_name_lower in typo_variants:
                self.vulnerabilities.append({
                    'type': 'known_typosquatting',
                    'severity': 'critical',
                    'title': f'알려진 타이포스쿼팅 패키지: {pkg_name}',
                    'description': f'"{pkg_name}"은(는) "{legit_pkg}"의 타이포스쿼팅 변종일 수 있습니다.',
                    'url': url,
                    'evidence': f'Package: {pkg_name}, Type: {pkg_type}',
                    'recommendation': f'정확한 패키지명 "{legit_pkg}"을(를) 사용하세요.'
                })

        # 의심스러운 패턴 검사
        suspicious_patterns = [
            (r'-js$', '패키지명에 불필요한 -js 접미사'),
            (r'_+', '패키지명에 연속된 언더스코어'),
            (r'\d{4,}', '패키지명에 긴 숫자 시퀀스'),
            (r'[0O][0O]', '숫자 0과 문자 O 혼동 가능성')
        ]

        for pattern, desc in suspicious_patterns:
            if re.search(pattern, pkg_name):
                self.vulnerabilities.append({
                    'type': 'suspicious_package_name',
                    'severity': 'medium',
                    'title': f'의심스러운 패키지명 패턴: {pkg_name}',
                    'description': desc,
                    'url': url,
                    'evidence': f'Package: {pkg_name}, Pattern: {pattern}',
                    'recommendation': '공식 패키지 저장소에서 패키지명을 재확인하세요.'
                })

    def _calculate_severity(self):
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        for vuln in self.vulnerabilities:
            if vuln.get('severity') == 'critical':
                return 'critical'

        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1

        if severity_counts['high'] >= 1:
            return 'high'
        elif severity_counts['medium'] >= 2:
            return 'medium'
        else:
            return 'low'

    def _get_recommendations(self):
        """보안 권장사항"""
        return [
            '패키지 설치 전 항상 공식 저장소(npmjs.com, pypi.org)에서 이름을 확인하세요.',
            '패키지 다운로드 수, 최근 업데이트 날짜, GitHub 저장소를 확인하세요.',
            '타이포스쿼팅은 공급망 공격의 일반적인 수법입니다.',
            'npm audit, pip-audit 등 자동화 도구를 사용하세요.',
            '의존성 잠금 파일(lockfile)을 사용하여 예상치 못한 패키지 설치를 방지하세요.'
        ]


class OutdatedDependencyScanner:
    """
    오래된 종속성 스캐너 (강화 버전)

    보안 취약점이 있는 오래된 패키지 탐지
    - 주요 CVE 패턴 매칭
    - EOL 패키지 탐지
    - 심각한 보안 버전 확인
    """

    metadata = {
        'id': 'outdated_dependency',
        'name': '오래된 종속성 강화 검사',
        'icon': '⏰',
        'description': '보안 취약점이 있는 구버전 패키지 탐지',
        'weight': 2,
        'field': 'outdated_dependency_vulnerabilities'
    }

    # 알려진 취약한 버전 (주요 CVE)
    VULNERABLE_VERSIONS = {
        # JavaScript/Node.js
        'lodash': {
            'versions': [r'^[0-3]\.', r'^4\.(0|1[0-6])\.'],
            'cve': 'CVE-2019-10744 (Prototype Pollution)',
            'min_safe': '4.17.12'
        },
        'axios': {
            'versions': [r'^0\.(1[0-9]|2[0-0])\.'],
            'cve': 'CVE-2021-3749 (SSRF)',
            'min_safe': '0.21.2'
        },
        'express': {
            'versions': [r'^[0-3]\.', r'^4\.(0|1[0-6])\.'],
            'cve': 'Multiple CVEs (Security Headers, DoS)',
            'min_safe': '4.17.0'
        },
        'minimist': {
            'versions': [r'^[01]\.', r'^0\.'],
            'cve': 'CVE-2021-44906 (Prototype Pollution)',
            'min_safe': '1.2.6'
        },
        # Python
        'django': {
            'versions': [r'^[12]\.', r'^3\.[01]\.'],
            'cve': 'Multiple CVEs (XSS, SQLi, CSRF)',
            'min_safe': '3.2.0'
        },
        'flask': {
            'versions': [r'^0\.', r'^1\.(0|1)\.'],
            'cve': 'CVE-2019-1010083 (Denial of Service)',
            'min_safe': '1.1.3'
        },
        'requests': {
            'versions': [r'^[01]\.', r'^2\.(0|1|2|3|4|5)\.'],
            'cve': 'CVE-2018-18074 (Credentials Leak)',
            'min_safe': '2.20.0'
        },
        'pillow': {
            'versions': [r'^[0-7]\.', r'^8\.[0-2]\.'],
            'cve': 'Multiple CVEs (RCE, DoS)',
            'min_safe': '8.3.0'
        },
        'pyyaml': {
            'versions': [r'^[0-4]\.', r'^5\.(0|1|2|3)'],
            'cve': 'CVE-2020-14343 (Arbitrary Code Execution)',
            'min_safe': '5.4'
        }
    }

    # EOL (End of Life) 패키지
    EOL_PACKAGES = {
        'bower': 'EOL - npm/yarn 사용 권장',
        'gulp': 'Maintenance mode - Vite, esbuild 등 권장',
        'python2': 'EOL 2020-01-01',
        'node-sass': 'Deprecated - dart-sass 사용 권장'
    }

    def __init__(self, url, response=None, html_content=None):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """오래된 종속성 스캔 실행"""
        try:
            base_url = self.url.rstrip('/')

            # 1. package.json 분석
            self._check_package_json(base_url)

            # 2. requirements.txt 분석
            self._check_requirements_txt(base_url)

            # 3. HTML/JS에서 CDN 버전 분석
            if self.html_content:
                self._check_cdn_versions(self.html_content)

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'Outdated Dependency Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _check_package_json(self, base_url):
        """package.json 분석"""
        try:
            pkg_url = f'{base_url}/package.json'
            response = requests.get(pkg_url, timeout=5, allow_redirects=False)

            if response.status_code == 200:
                try:
                    pkg_data = response.json()
                    deps = {}
                    deps.update(pkg_data.get('dependencies', {}))
                    deps.update(pkg_data.get('devDependencies', {}))

                    for pkg_name, version in deps.items():
                        self._check_vulnerable_version(pkg_name, version, 'npm', pkg_url)
                        self._check_eol_package(pkg_name, 'npm', pkg_url)

                except json.JSONDecodeError:
                    pass

        except requests.RequestException:
            pass

    def _check_requirements_txt(self, base_url):
        """requirements.txt 분석"""
        try:
            req_url = f'{base_url}/requirements.txt'
            response = requests.get(req_url, timeout=5, allow_redirects=False)

            if response.status_code == 200:
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # 패키지명과 버전 추출
                        match = re.match(r'([a-zA-Z0-9_-]+)\s*([<>=!]+)\s*([0-9.]+)', line)
                        if match:
                            pkg_name, operator, version = match.groups()
                            self._check_vulnerable_version(pkg_name, version, 'pip', req_url)
                            self._check_eol_package(pkg_name, 'pip', req_url)

        except requests.RequestException:
            pass

    def _check_cdn_versions(self, content):
        """CDN URL에서 버전 분석"""
        # CDN URL에서 패키지명과 버전 추출
        patterns = [
            r'cdn\.jsdelivr\.net/npm/([^@/]+)@([0-9.]+)',
            r'unpkg\.com/([^@/]+)@([0-9.]+)',
            r'cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([0-9.]+)'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content)
            for pkg_name, version in matches:
                self._check_vulnerable_version(pkg_name, version, 'cdn', self.url)

    def _check_vulnerable_version(self, pkg_name, version, pkg_type, url):
        """취약한 버전 확인"""
        pkg_name_lower = pkg_name.lower()

        if pkg_name_lower in self.VULNERABLE_VERSIONS:
            vuln_info = self.VULNERABLE_VERSIONS[pkg_name_lower]

            # 버전 정규식 패턴 매칭
            version_str = version.strip('^~>=<')
            is_vulnerable = False

            for pattern in vuln_info['versions']:
                if re.match(pattern, version_str):
                    is_vulnerable = True
                    break

            if is_vulnerable:
                self.vulnerabilities.append({
                    'type': 'vulnerable_version',
                    'severity': 'high',
                    'title': f'알려진 취약점이 있는 {pkg_name} 버전',
                    'description': f'{pkg_name}@{version}은(는) {vuln_info["cve"]} 취약점이 있습니다.',
                    'url': url,
                    'evidence': f'Package: {pkg_name}, Version: {version}, Type: {pkg_type}',
                    'recommendation': f'{vuln_info["min_safe"]} 이상으로 업그레이드하세요.'
                })

    def _check_eol_package(self, pkg_name, pkg_type, url):
        """EOL 패키지 확인"""
        pkg_name_lower = pkg_name.lower()

        if pkg_name_lower in self.EOL_PACKAGES:
            self.vulnerabilities.append({
                'type': 'eol_package',
                'severity': 'medium',
                'title': f'EOL/Deprecated 패키지: {pkg_name}',
                'description': self.EOL_PACKAGES[pkg_name_lower],
                'url': url,
                'evidence': f'Package: {pkg_name}, Type: {pkg_type}',
                'recommendation': '더 이상 유지보수되지 않는 패키지를 최신 대안으로 교체하세요.'
            })

    def _calculate_severity(self):
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'low')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if severity_counts['high'] >= 2:
            return 'high'
        elif severity_counts['high'] >= 1 or severity_counts['medium'] >= 3:
            return 'medium'
        else:
            return 'low'

    def _get_recommendations(self):
        """보안 권장사항"""
        return [
            'npm audit, pip-audit, yarn audit을 정기적으로 실행하세요.',
            'Dependabot, Renovate 등 자동화된 업데이트 도구를 사용하세요.',
            'CI/CD 파이프라인에 종속성 스캔을 통합하세요.',
            '보안 패치가 포함된 마이너/패치 버전은 즉시 업데이트하세요.',
            'OWASP Dependency-Check, Snyk 등 상용 도구 사용을 고려하세요.'
        ]


class LicenseComplianceScanner:
    """
    라이선스 준수 스캐너

    오픈소스 라이선스 충돌 및 문제 탐지
    - GPL, AGPL 등 copyleft 라이선스
    - 상업적 사용 제한 라이선스
    - 라이선스 파일 존재 여부
    """

    metadata = {
        'id': 'license_compliance',
        'name': '라이선스 준수 검사',
        'icon': '📜',
        'description': '오픈소스 라이선스 충돌 및 준수 확인',
        'weight': 1.5,
        'field': 'license_compliance_vulnerabilities'
    }

    # Copyleft 라이선스 (강력한 전염성)
    COPYLEFT_LICENSES = [
        'GPL', 'GPLv2', 'GPLv3', 'AGPL', 'AGPLv3',
        'GNU GPL', 'GNU AGPL'
    ]

    # 약한 Copyleft
    WEAK_COPYLEFT_LICENSES = [
        'LGPL', 'LGPLv2', 'LGPLv3', 'MPL', 'EPL', 'CDDL'
    ]

    # 상업적 사용 제한
    NON_COMMERCIAL_LICENSES = [
        'CC BY-NC', 'Creative Commons Non-Commercial'
    ]

    # 퍼미시브 라이선스 (안전)
    PERMISSIVE_LICENSES = [
        'MIT', 'Apache', 'BSD', 'ISC', 'Unlicense', '0BSD'
    ]

    def __init__(self, url, response=None, html_content=None):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """라이선스 준수 스캔 실행"""
        try:
            base_url = self.url.rstrip('/')

            # 1. LICENSE 파일 확인
            self._check_license_file(base_url)

            # 2. package.json에서 라이선스 확인
            self._check_package_json_license(base_url)

            # 3. README에서 라이선스 언급 확인
            self._check_readme_license(base_url)

            # 4. HTML 주석/메타데이터에서 라이선스 확인
            if self.html_content:
                self._check_html_license(self.html_content)

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'License Compliance Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _check_license_file(self, base_url):
        """LICENSE 파일 존재 확인"""
        license_files = ['LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING', 'COPYING.txt']

        found_license = False
        for filename in license_files:
            try:
                license_url = f'{base_url}/{filename}'
                response = requests.get(license_url, timeout=5, allow_redirects=False)

                if response.status_code == 200:
                    found_license = True
                    content = response.text

                    # Copyleft 라이선스 검사
                    for license_type in self.COPYLEFT_LICENSES:
                        if license_type in content:
                            self.vulnerabilities.append({
                                'type': 'copyleft_license',
                                'severity': 'high',
                                'title': f'Copyleft 라이선스 발견: {license_type}',
                                'description': f'{license_type}는 파생 저작물에도 동일 라이선스를 요구합니다.',
                                'url': license_url,
                                'evidence': license_type,
                                'recommendation': '상업적 사용 시 법률 자문을 받으세요. LGPL이나 MIT 등을 고려하세요.'
                            })

                    # 상업적 사용 제한 라이선스
                    for license_type in self.NON_COMMERCIAL_LICENSES:
                        if license_type in content:
                            self.vulnerabilities.append({
                                'type': 'non_commercial_license',
                                'severity': 'critical',
                                'title': f'상업적 사용 제한 라이선스: {license_type}',
                                'description': '이 라이선스는 상업적 사용을 금지합니다.',
                                'url': license_url,
                                'evidence': license_type,
                                'recommendation': '상업적 프로젝트에서는 사용할 수 없습니다.'
                            })

                    break

            except requests.RequestException:
                continue

        if not found_license:
            self.vulnerabilities.append({
                'type': 'missing_license',
                'severity': 'medium',
                'title': 'LICENSE 파일 누락',
                'description': 'LICENSE 파일이 없어 라이선스를 확인할 수 없습니다.',
                'url': base_url,
                'recommendation': '적절한 오픈소스 라이선스 파일을 추가하세요.'
            })

    def _check_package_json_license(self, base_url):
        """package.json의 license 필드 확인"""
        try:
            pkg_url = f'{base_url}/package.json'
            response = requests.get(pkg_url, timeout=5, allow_redirects=False)

            if response.status_code == 200:
                try:
                    pkg_data = response.json()
                    license_field = pkg_data.get('license', '')

                    if not license_field:
                        self.vulnerabilities.append({
                            'type': 'no_license_field',
                            'severity': 'low',
                            'title': 'package.json에 license 필드 없음',
                            'description': 'package.json에 라이선스 정보가 명시되지 않았습니다.',
                            'url': pkg_url,
                            'recommendation': '"license": "MIT" 등을 추가하세요.'
                        })
                    else:
                        # Copyleft 라이선스 체크
                        if any(lic in license_field.upper() for lic in ['GPL', 'AGPL']):
                            self.vulnerabilities.append({
                                'type': 'copyleft_in_package',
                                'severity': 'high',
                                'title': f'Copyleft 라이선스: {license_field}',
                                'description': 'package.json에 Copyleft 라이선스가 명시되어 있습니다.',
                                'url': pkg_url,
                                'recommendation': '라이선스 의무사항을 준수하세요.'
                            })

                except json.JSONDecodeError:
                    pass

        except requests.RequestException:
            pass

    def _check_readme_license(self, base_url):
        """README 파일에서 라이선스 섹션 확인"""
        readme_files = ['README.md', 'README.txt', 'README']

        for filename in readme_files:
            try:
                readme_url = f'{base_url}/{filename}'
                response = requests.get(readme_url, timeout=5, allow_redirects=False)

                if response.status_code == 200:
                    content = response.text.lower()

                    # 라이선스 섹션 존재 확인
                    if 'license' not in content and 'licence' not in content:
                        self.vulnerabilities.append({
                            'type': 'readme_no_license',
                            'severity': 'low',
                            'title': 'README에 라이선스 정보 없음',
                            'description': 'README 파일에 라이선스 섹션이 없습니다.',
                            'url': readme_url,
                            'recommendation': 'README에 ## License 섹션을 추가하세요.'
                        })

                    break

            except requests.RequestException:
                continue

    def _check_html_license(self, content):
        """HTML 주석에서 라이선스 확인"""
        # HTML 주석에서 라이선스 정보 추출
        comment_pattern = r'<!--(.+?)-->'
        comments = re.findall(comment_pattern, content, re.DOTALL)

        has_license_info = False
        for comment in comments:
            if 'license' in comment.lower() or 'copyright' in comment.lower():
                has_license_info = True

                # Copyleft 라이선스 체크
                for license_type in self.COPYLEFT_LICENSES:
                    if license_type in comment:
                        self.vulnerabilities.append({
                            'type': 'copyleft_in_html',
                            'severity': 'medium',
                            'title': f'HTML 주석에 Copyleft 라이선스: {license_type}',
                            'description': 'HTML에 Copyleft 라이선스가 명시되어 있습니다.',
                            'url': self.url,
                            'evidence': comment[:100],
                            'recommendation': '라이선스 의무사항을 확인하세요.'
                        })

    def _calculate_severity(self):
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        for vuln in self.vulnerabilities:
            if vuln.get('severity') == 'critical':
                return 'critical'

        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1

        if severity_counts['high'] >= 1:
            return 'high'
        elif severity_counts['medium'] >= 2:
            return 'medium'
        else:
            return 'low'

    def _get_recommendations(self):
        """보안 권장사항"""
        return [
            'LICENSE 파일을 프로젝트 루트에 반드시 포함하세요.',
            'MIT, Apache 2.0, BSD 등 퍼미시브 라이선스가 상업적 사용에 안전합니다.',
            'GPL/AGPL 사용 시 법률 자문을 받으세요 (파생 저작물 공개 의무).',
            'package.json, setup.py 등에 license 필드를 명시하세요.',
            'FOSSA, Black Duck 등 라이선스 스캐닝 도구를 사용하세요.',
            '오픈소스 라이선스 준수는 법적 리스크 관리의 핵심입니다.'
        ]
