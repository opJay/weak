"""
Software Supply Chain Security Scanner
OWASP Top 10 2025 A03: Software Supply Chain Failures 대응
"""
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger('scanner')


class SoftwareSupplyChainScanner:
    """
    소프트웨어 공급망 보안 스캐너

    OWASP Top 10 2025 A03: Software Supply Chain Failures 대응
    - 종속성 파일 노출 탐지
    - 오래된/취약한 패키지 탐지
    - SRI (Subresource Integrity) 미사용 탐지
    - 무결성 검증 누락 탐지
    """

    metadata = {
        'id': 'supply_chain',
        'name': 'Software Supply Chain 보안 검사',
        'icon': '📦',
        'description': '공급망 보안 취약점 탐지 (종속성, SRI, 무결성 검증)',
        'weight': 2,
        'field': 'supply_chain_vulnerabilities'
    }

    # 탐지할 종속성 파일들
    DEPENDENCY_FILES = {
        'package.json': 'npm (Node.js)',
        'package-lock.json': 'npm lock file',
        'yarn.lock': 'Yarn lock file',
        'requirements.txt': 'pip (Python)',
        'Pipfile': 'Pipenv (Python)',
        'Pipfile.lock': 'Pipenv lock file',
        'pom.xml': 'Maven (Java)',
        'build.gradle': 'Gradle (Java)',
        'Gemfile': 'Bundler (Ruby)',
        'Gemfile.lock': 'Bundler lock file',
        'go.mod': 'Go modules',
        'go.sum': 'Go sum file',
        'composer.json': 'Composer (PHP)',
        'composer.lock': 'Composer lock file',
        'Cargo.toml': 'Cargo (Rust)',
        'Cargo.lock': 'Cargo lock file',
    }

    # 오래되었거나 취약한 패키지 패턴 (예시)
    VULNERABLE_PATTERNS = [
        # jQuery 구버전
        (r'jquery[/-]([12]\.|3\.[0-4]\.)', 'jQuery 구버전 (3.5.0 이상 권장)'),
        # Bootstrap 구버전
        (r'bootstrap[/-]([1-3]\.|4\.[0-5]\.)', 'Bootstrap 구버전 (4.6.0 이상 권장)'),
        # Angular 구버전
        (r'angular[/-]([1-9]\.|10\.)', 'Angular 구버전 (11+ 권장)'),
        # React 구버전
        (r'react[/-](1[0-5]\.|16\.[0-8]\.)', 'React 구버전 (16.9+ 권장)'),
        # Lodash 구버전
        (r'lodash[/-]([0-3]\.|4\.[0-16]\.)', 'Lodash 구버전 (4.17.0+ 권장)'),
    ]

    def __init__(self, url, response=None, html_content=None):
        """
        초기화

        Args:
            url: 스캔할 URL
            response: requests.Response 객체 (선택)
            html_content: HTML 콘텐츠 문자열 (선택)
        """
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """
        공급망 보안 스캔 실행

        Returns:
            dict: 취약점 정보
        """
        try:
            # 1. 종속성 파일 노출 검사
            self._check_dependency_files()

            # 2. 외부 리소스 SRI 검사
            self._check_sri()

            # 3. CDN 리소스 취약점 검사
            self._check_cdn_vulnerabilities()

            # 4. 서브리소스 무결성 검증
            self._check_resource_integrity()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'Supply Chain Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _check_dependency_files(self):
        """종속성 파일 노출 검사"""
        base_url = self.url.rstrip('/')

        for filename, tech_name in self.DEPENDENCY_FILES.items():
            file_url = f'{base_url}/{filename}'

            try:
                response = requests.get(file_url, timeout=5, allow_redirects=False)

                if response.status_code == 200:
                    # 종속성 파일이 공개적으로 접근 가능
                    self.vulnerabilities.append({
                        'type': 'exposed_dependency_file',
                        'severity': 'high',
                        'title': f'종속성 파일 노출: {filename}',
                        'description': f'{tech_name} 종속성 파일이 공개적으로 접근 가능합니다.',
                        'url': file_url,
                        'evidence': f'HTTP {response.status_code}',
                        'recommendation': '웹 서버 설정을 통해 종속성 파일에 대한 공개 접근을 차단하세요.'
                    })

                    # 파일 내용 분석 (간단한 예시)
                    if filename == 'package.json':
                        self._analyze_package_json(response.text, file_url)

            except requests.RequestException:
                # 파일이 존재하지 않거나 접근 불가 (정상)
                pass

    def _analyze_package_json(self, content, file_url):
        """package.json 내용 분석"""
        try:
            import json
            data = json.loads(content)

            # dependencies 확인
            deps = data.get('dependencies', {})
            dev_deps = data.get('devDependencies', {})

            if deps or dev_deps:
                self.vulnerabilities.append({
                    'type': 'dependency_info_leak',
                    'severity': 'medium',
                    'title': 'package.json에서 종속성 정보 노출',
                    'description': f'{len(deps) + len(dev_deps)}개의 종속성 정보가 노출되었습니다.',
                    'url': file_url,
                    'evidence': f'dependencies: {len(deps)}, devDependencies: {len(dev_deps)}',
                    'recommendation': '종속성 정보가 공개되면 공격자가 특정 버전의 취약점을 악용할 수 있습니다.'
                })

        except Exception as e:
            logger.debug(f'package.json 분석 실패: {e}')

    def _check_sri(self):
        """외부 리소스 SRI (Subresource Integrity) 검사"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')

        # CDN에서 로드되는 스크립트 찾기
        external_scripts = []
        for script in soup.find_all('script', src=True):
            src = script.get('src', '')
            if self._is_external_resource(src):
                integrity = script.get('integrity')
                if not integrity:
                    external_scripts.append(src)

        # CDN에서 로드되는 스타일시트 찾기
        external_styles = []
        for link in soup.find_all('link', rel='stylesheet'):
            href = link.get('href', '')
            if self._is_external_resource(href):
                integrity = link.get('integrity')
                if not integrity:
                    external_styles.append(href)

        if external_scripts or external_styles:
            self.vulnerabilities.append({
                'type': 'missing_sri',
                'severity': 'medium',
                'title': 'SRI (Subresource Integrity) 미사용',
                'description': f'외부 CDN 리소스 {len(external_scripts) + len(external_styles)}개가 무결성 검증 없이 로드됩니다.',
                'evidence': {
                    'scripts_without_sri': external_scripts[:5],  # 처음 5개만
                    'styles_without_sri': external_styles[:5],
                    'total_count': len(external_scripts) + len(external_styles)
                },
                'recommendation': 'integrity 속성을 사용하여 외부 리소스의 무결성을 검증하세요.'
            })

    def _check_cdn_vulnerabilities(self):
        """CDN 리소스의 알려진 취약점 검사"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 모든 외부 리소스 URL 수집
        resource_urls = []

        for script in soup.find_all('script', src=True):
            src = script.get('src', '')
            if self._is_external_resource(src):
                resource_urls.append(src)

        for link in soup.find_all('link', href=True):
            href = link.get('href', '')
            if self._is_external_resource(href):
                resource_urls.append(href)

        # 취약한 버전 패턴 검사
        for url in resource_urls:
            for pattern, description in self.VULNERABLE_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    self.vulnerabilities.append({
                        'type': 'vulnerable_library',
                        'severity': 'high',
                        'title': '취약한 라이브러리 버전 사용',
                        'description': description,
                        'url': url,
                        'evidence': f'패턴 매칭: {pattern}',
                        'recommendation': '최신 버전으로 업데이트하세요.'
                    })

    def _check_resource_integrity(self):
        """서브리소스 무결성 검증"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')

        # crossorigin 속성 없이 integrity를 사용하는 경우
        for tag in soup.find_all(['script', 'link'], integrity=True):
            if not tag.get('crossorigin'):
                resource = tag.get('src') or tag.get('href', '')

                self.vulnerabilities.append({
                    'type': 'sri_without_crossorigin',
                    'severity': 'low',
                    'title': 'SRI 사용 시 crossorigin 속성 누락',
                    'description': 'integrity 속성은 crossorigin 속성과 함께 사용해야 합니다.',
                    'evidence': resource,
                    'recommendation': 'crossorigin="anonymous" 속성을 추가하세요.'
                })

    def _is_external_resource(self, url):
        """외부 리소스인지 확인"""
        if not url or url.startswith('data:') or url.startswith('#'):
            return False

        # 절대 URL인 경우
        if url.startswith('http://') or url.startswith('https://'):
            parsed = urlparse(url)
            base_parsed = urlparse(self.url)
            return parsed.netloc != base_parsed.netloc

        # 프로토콜 상대 URL (//cdn.example.com/...)
        if url.startswith('//'):
            return True

        return False

    def _calculate_severity(self):
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'low')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if severity_counts['critical'] > 0:
            return 'critical'
        elif severity_counts['high'] >= 2:
            return 'high'
        elif severity_counts['high'] >= 1 or severity_counts['medium'] >= 3:
            return 'medium'
        else:
            return 'low'

    def _get_recommendations(self):
        """보안 권장사항 반환"""
        recommendations = [
            '종속성 파일(.json, .lock, .txt 등)에 대한 공개 접근을 차단하세요.',
            '외부 CDN 리소스에는 반드시 SRI(Subresource Integrity)를 사용하세요.',
            '라이브러리를 최신 버전으로 유지하고, 보안 권고사항을 정기적으로 확인하세요.',
            'npm audit, pip-audit 등 종속성 취약점 스캔 도구를 CI/CD에 통합하세요.',
            'Lock 파일(package-lock.json, yarn.lock)을 사용하여 종속성 버전을 고정하세요.',
            'SBOM(Software Bill of Materials)을 생성하여 공급망을 투명하게 관리하세요.'
        ]

        return recommendations
