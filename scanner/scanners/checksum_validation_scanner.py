"""체크섬 검증 스캐너"""

import re
from typing import Dict, Any
from bs4 import BeautifulSoup
from scanner.base import BaseScanner


class ChecksumValidationScanner(BaseScanner):
    """체크섬 검증 스캐너"""

    metadata = {
        'id': 'checksum_validation',
        'name': 'Checksum Validation',
        'field': 'checksum_validation',
        'weight': 1,
        'category': 'data_integrity',
        'severity': 'medium',
        'description': '체크섬 검증 (약한 해시 알고리즘, SHA256SUMS, MD5SUMS)',
        'owasp': ['A08:2025']
    }

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None):
        super().__init__(url=url or '', response=response,
                        html_content=html_content)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client or {}
        self.vulnerabilities = []

    def _prepare(self):
        """스캔 준비"""
        pass

    def _execute_scan(self):
        """스캔 실행"""
        # 1. 다운로드 링크와 체크섬 검사
        self._check_download_checksums()

        # 2. 체크섬 파일 검사
        self._check_checksum_files()

        # 3. 인라인 체크섬 검사
        self._check_inline_checksums()

        # 4. 파일 업로드 체크섬 검사
        self._check_upload_checksums()

    def _check_download_checksums(self):
        """다운로드 링크와 체크섬 검사"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 다운로드 링크 찾기
        download_links = []
        for link in soup.find_all('a', href=True):
            href = link.get('href', '')
            if any(ext in href.lower() for ext in ['.zip', '.tar', '.gz', '.exe', '.dmg', '.deb', '.rpm']):
                download_links.append(link)

        if download_links:
            # 체크섬 정보 찾기
            checksum_patterns = [
                r'MD5:\s*([a-f0-9]{32})',
                r'SHA1:\s*([a-f0-9]{40})',
                r'SHA256:\s*([a-f0-9]{64})',
                r'SHA512:\s*([a-f0-9]{128})',
            ]

            has_checksum = False
            weak_checksum = False

            for pattern in checksum_patterns:
                if re.search(pattern, self.html_content, re.IGNORECASE):
                    has_checksum = True
                    if 'MD5' in pattern or 'SHA1' in pattern:
                        weak_checksum = True

            if not has_checksum:
                self.vulnerabilities.append({
                    'type': 'No Download Checksums',
                    'severity': 'medium',
                    'description': '다운로드 파일에 대한 체크섬이 제공되지 않습니다.',
                    'recommendation': 'SHA-256 이상의 체크섬을 제공하세요.'
                })

            elif weak_checksum:
                self.vulnerabilities.append({
                    'type': 'Weak Checksum Algorithm',
                    'severity': 'medium',
                    'description': 'MD5 또는 SHA-1과 같은 약한 체크섬 알고리즘이 사용됩니다.',
                    'recommendation': 'SHA-256 이상의 강력한 해시 알고리즘을 사용하세요.'
                })

    def _check_checksum_files(self):
        """체크섬 파일 검사"""
        if not self.http_client or not hasattr(self.http_client, 'get'):
            return

        checksum_files = [
            'MD5SUMS',
            'SHA256SUMS',
            'SHA512SUMS',
            'CHECKSUMS',
            'checksums.txt',
            'SHA256SUMS.asc',  # PGP signed
        ]

        base_url = self.url.rstrip('/') if self.url else ''
        if not base_url:
            base_url = 'https://example.com'

        for checksum_file in checksum_files:
            try:
                url = f"{base_url}/{checksum_file}"
                response = self.http_client.get(url, timeout=5) if hasattr(self.http_client, 'get') else self.http_client.get(url)

                if response and hasattr(response, 'status_code') and response.status_code == 200:
                    content = response.text if hasattr(response, 'text') else str(response.content)

                    # 약한 알고리즘 사용 확인
                    if 'MD5' in checksum_file.upper():
                        self.vulnerabilities.append({
                            'type': 'MD5 Checksum File',
                            'severity': 'medium',
                            'file': checksum_file,
                            'description': f'MD5 체크섬 파일 {checksum_file}이(가) 사용됩니다.',
                            'recommendation': 'SHA256SUMS 파일을 대신 제공하세요.'
                        })

                    # PGP 서명 확인
                    if checksum_file.endswith('.asc'):
                        self.vulnerabilities.append({
                            'type': 'PGP Signed Checksums',
                            'severity': 'info',
                            'file': checksum_file,
                            'description': 'PGP 서명된 체크섬 파일이 제공됩니다.',
                            'recommendation': '좋은 보안 관행입니다. 검증 방법을 문서화하세요.'
                        })
                        return

                    # 서명되지 않은 체크섬 파일
                    if not checksum_file.endswith('.asc'):
                        self.vulnerabilities.append({
                            'type': 'Unsigned Checksum File',
                            'severity': 'low',
                            'file': checksum_file,
                            'description': f'체크섬 파일 {checksum_file}이(가) 서명되지 않았습니다.',
                            'recommendation': 'PGP 서명을 추가하여 체크섬 파일의 무결성을 보장하세요.'
                        })

                    break
            except Exception as e:
                continue

    def _check_inline_checksums(self):
        """인라인 체크섬 검사"""
        if not self.html_content:
            return

        # data-* 속성에서 체크섬 찾기
        data_checksum_patterns = [
            r'data-md5="([a-f0-9]{32})"',
            r'data-sha1="([a-f0-9]{40})"',
            r'data-sha256="([a-f0-9]{64})"',
            r'data-checksum="([a-f0-9]+)"',
        ]

        for pattern in data_checksum_patterns:
            matches = re.findall(pattern, self.html_content, re.IGNORECASE)
            if matches:
                if 'md5' in pattern or 'sha1' in pattern:
                    self.vulnerabilities.append({
                        'type': 'Weak Inline Checksum',
                        'severity': 'low',
                        'description': 'HTML에 약한 체크섬 알고리즘이 인라인으로 포함되어 있습니다.',
                        'recommendation': 'SHA-256 이상을 사용하세요.'
                    })
                    break

        # JavaScript에서 체크섬 검증 코드 찾기
        if 'checksum' in self.html_content.lower() or 'hash' in self.html_content.lower():
            md5_usage = re.search(r'MD5|md5|CryptoJS\.MD5', self.html_content)
            sha1_usage = re.search(r'SHA1|sha1|CryptoJS\.SHA1', self.html_content)

            if md5_usage or sha1_usage:
                self.vulnerabilities.append({
                    'type': 'Weak Hash in JavaScript',
                    'severity': 'medium',
                    'algorithm': 'MD5' if md5_usage else 'SHA1',
                    'description': 'JavaScript에서 약한 해시 알고리즘이 사용됩니다.',
                    'recommendation': 'Web Crypto API와 SHA-256을 사용하세요.'
                })

    def _check_upload_checksums(self):
        """파일 업로드 체크섬 검사"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 파일 업로드 폼 찾기
        file_inputs = soup.find_all('input', {'type': 'file'})

        if file_inputs:
            # 클라이언트 측 체크섬 검증 코드 찾기
            checksum_validation_patterns = [
                r'FileReader',
                r'calculateHash',
                r'verifyChecksum',
                r'file\.hash',
                r'crypto\.subtle\.digest',
            ]

            has_client_validation = any(re.search(pattern, self.html_content, re.IGNORECASE)
                                       for pattern in checksum_validation_patterns)

            if not has_client_validation:
                self.vulnerabilities.append({
                    'type': 'No Upload Checksum Validation',
                    'severity': 'medium',
                    'description': '파일 업로드 시 클라이언트 측 체크섬 검증이 없습니다.',
                    'recommendation': '업로드 전 파일 체크섬을 계산하고 서버와 검증하세요.'
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
        if any(v.get('severity') == 'high' for v in self.vulnerabilities):
            return 'high'
        elif any(v.get('severity') == 'medium' for v in self.vulnerabilities):
            return 'medium'
        return 'low'

    def _generate_message(self) -> str:
        """메시지 생성"""
        if not self.vulnerabilities:
            return '체크섬 검증이 적절히 구현되어 있습니다'

        issues = []
        vuln_types = set(v.get('type') for v in self.vulnerabilities)

        if 'No Download Checksums' in vuln_types:
            issues.append('체크섬 없음')
        if 'Weak Checksum Algorithm' in vuln_types or 'MD5 Checksum File' in vuln_types:
            issues.append('약한 알고리즘')
        if 'Unsigned Checksum File' in vuln_types:
            issues.append('서명되지 않은 체크섬')
        if 'No Upload Checksum Validation' in vuln_types:
            issues.append('업로드 검증 없음')

        return f"체크섬 검증 문제 발견: {', '.join(issues)}"

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

