"""
PackageIntegrityScanner - 패키지 무결성 검증 스캐너

OWASP Top 10 2025 A03/A08: Software Supply Chain & Data Integrity 대응
- Lockfile 무결성 검사
- SRI 해시 강도 검사
- 패키지 체크섬 검증
"""

import re
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup
from scanner.base import BaseScanner


class PackageIntegrityScanner(BaseScanner):
    """패키지 무결성 검증 스캐너"""

    # 메타데이터 정의
    metadata = {
        'id': 'package_integrity',
        'name': '패키지 무결성 검증',
        'icon': '🔐',
        'description': '패키지 무결성 검증 (lockfile 해시, SHA-512 검증)',
        'weight': 2,
        'field': 'package_integrity_vulnerabilities',
        'category': 'supply_chain',
        'severity': 'high',
        'owasp': ['A03:2025'],
        'cwe': ['CWE-354', 'CWE-494']
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
        self.lockfiles = {
            'package-lock.json': 'npm',
            'yarn.lock': 'yarn',
            'Pipfile.lock': 'pipenv',
            'poetry.lock': 'poetry',
            'composer.lock': 'composer',
            'Gemfile.lock': 'bundler',
            'go.sum': 'go modules'
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


    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

        return f"패키지 무결성 문제 발견: {', '.join(issues)}"