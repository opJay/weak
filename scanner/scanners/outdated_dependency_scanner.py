"""오래된 종속성 검사 스캐너"""

import re
from typing import Dict, Any
from bs4 import BeautifulSoup
from scanner.base import BaseScanner


class OutdatedDependencyScanner(BaseScanner):
    """오래된 종속성 검사 스캐너"""

    metadata = {
        'id': 'outdated_dependencies',
        'name': 'Outdated Dependencies',
        'field': 'outdated_dependencies',
        'weight': 1,
        'category': 'supply_chain',
        'severity': 'high',
        'description': '오래된 종속성 및 EOL 패키지 검사',
        'owasp': ['A03:2025', 'A06:2025']
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

    def _prepare(self):
        """스캔 준비"""
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

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

