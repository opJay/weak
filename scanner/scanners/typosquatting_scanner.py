"""타이포스쿼팅 탐지 스캐너"""

import re
from typing import Dict, Any
from bs4 import BeautifulSoup
from scanner.base import BaseScanner


class TyposquattingScanner(BaseScanner):
    """타이포스쿼팅 탐지 스캐너"""

    metadata = {
        'id': 'typosquatting',
        'name': 'Typosquatting Detection',
        'field': 'typosquatting',
        'weight': 1,
        'category': 'supply_chain',
        'severity': 'high',
        'description': '타이포스쿼팅 공격 탐지 (유사 패키지명, 의심스러운 패턴)',
        'owasp': ['A03:2025']
    }

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None):
        super().__init__(url=url or '', response=response,
                        html_content=html_content)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client
        self.vulnerabilities = []

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

    def _prepare(self):
        """스캔 준비"""
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

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

