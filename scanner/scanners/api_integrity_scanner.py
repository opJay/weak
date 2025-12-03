"""API 응답 무결성 검사 스캐너"""

import re
from typing import Dict, Any
from scanner.base import BaseScanner


class APIIntegrityScanner(BaseScanner):
    """API 응답 무결성 검사 스캐너"""

    metadata = {
        'id': 'api_integrity',
        'name': 'API Response Integrity',
        'field': 'api_integrity',
        'weight': 1,
        'category': 'data_integrity',
        'severity': 'medium',
        'description': 'API 응답 무결성 검사 (X-Signature, ETag, Content-MD5, SRI)',
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
        # 검사 항목: 응답 서명, ETag, Content-MD5, API SRI, API 버전
        self.checked = 5

        # 1. 응답 서명 헤더 검사
        self._check_response_signature()

        # 2. ETag 및 캐시 무결성 검사
        self._check_etag_integrity()

        # 3. Content-MD5 헤더 검사
        self._check_content_md5()

        # 4. API 응답 SRI 검사
        self._check_api_sri()

        # 5. API 버전 관리 검사
        self._check_api_versioning()

        # 결과 요약
        if self.vulnerabilities:
            medium_count = len([v for v in self.vulnerabilities if v.get('severity') == 'medium'])
            self._add_detail(
                id='api_integrity_check',
                name='API 응답 무결성 검사',
                status='fail',
                severity='medium' if medium_count > 0 else 'low',
                description=f'{len(self.vulnerabilities)}개의 API 무결성 취약점 발견',
                value=f'Medium: {medium_count}개',
                expected='API 무결성 취약점 없음',
                recommendation='응답 서명, ETag, SHA-256 다이제스트를 사용하세요.'
            )
        else:
            self._add_detail(
                id='api_integrity_check',
                name='API 응답 무결성 검사',
                status='pass',
                severity='info',
                description='API 응답 무결성 취약점이 발견되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _check_response_signature(self):
        """응답 서명 헤더 검사"""
        if not self.response or not hasattr(self.response, 'headers'):
            return

        # 일반적인 서명 헤더들
        signature_headers = [
            'X-Signature',
            'X-Content-Signature',
            'X-HMAC-Signature',
            'X-Response-Signature',
            'Digest'
        ]

        has_signature = any(header in self.response.headers for header in signature_headers)

        # JSON 응답인지 확인
        content_type = self.response.headers.get('Content-Type', '')
        is_json_api = 'application/json' in content_type

        if is_json_api and not has_signature:
            self.vulnerabilities.append({
                'type': 'No API Response Signature',
                'severity': 'medium',
                'description': 'API 응답에 디지털 서명이 없습니다.',
                'recommendation': 'X-Signature 헤더를 사용하여 응답에 서명하세요.'
            })

        # Digest 헤더가 있지만 약한 알고리즘 사용
        digest_header = self.response.headers.get('Digest', '')
        if digest_header:
            if digest_header.startswith('MD5=') or digest_header.startswith('SHA-1='):
                self.vulnerabilities.append({
                    'type': 'Weak Digest Algorithm',
                    'severity': 'medium',
                    'algorithm': digest_header.split('=')[0],
                    'description': f'약한 다이제스트 알고리즘 사용: {digest_header.split("=")[0]}',
                    'recommendation': 'SHA-256 이상의 강력한 해시 알고리즘을 사용하세요.'
                })

    def _check_etag_integrity(self):
        """ETag 무결성 검사"""
        if not self.response or not hasattr(self.response, 'headers'):
            return

        etag = self.response.headers.get('ETag', '')

        if etag:
            # Weak ETag 검사 (W/ prefix)
            if etag.startswith('W/'):
                self.vulnerabilities.append({
                    'type': 'Weak ETag',
                    'severity': 'low',
                    'description': 'Weak ETag가 사용되고 있습니다.',
                    'recommendation': 'Strong ETag를 사용하여 정확한 캐시 검증을 보장하세요.'
                })

            # ETag 길이가 너무 짧은 경우 (충돌 가능성)
            etag_value = etag.strip('"').replace('W/', '')
            if len(etag_value) < 32:
                self.vulnerabilities.append({
                    'type': 'Short ETag',
                    'severity': 'low',
                    'description': 'ETag 값이 너무 짧아 충돌 가능성이 있습니다.',
                    'recommendation': '최소 32자 이상의 ETag 값을 사용하세요.'
                })
        else:
            # API 응답인데 ETag가 없는 경우
            content_type = self.response.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                self.vulnerabilities.append({
                    'type': 'Missing ETag',
                    'severity': 'low',
                    'description': 'API 응답에 ETag가 없습니다.',
                    'recommendation': 'ETag를 추가하여 캐시 검증을 구현하세요.'
                })

    def _check_content_md5(self):
        """Content-MD5 헤더 검사"""
        if not self.response or not hasattr(self.response, 'headers'):
            return

        content_md5 = self.response.headers.get('Content-MD5', '')

        if content_md5:
            self.vulnerabilities.append({
                'type': 'Deprecated Content-MD5',
                'severity': 'medium',
                'description': 'Content-MD5 헤더는 deprecated되었고 MD5는 약한 알고리즘입니다.',
                'recommendation': 'Digest 헤더와 SHA-256을 사용하세요.'
            })

    def _check_api_sri(self):
        """API 응답에 대한 SRI 검사"""
        if not self.html_content:
            return

        # API 호출 패턴 찾기
        api_patterns = [
            r'fetch\(["\']([^"\']+)',
            r'axios\.[get|post|put|delete]\(["\']([^"\']+)',
            r'\$\.ajax\(\{[^}]*url\s*:\s*["\']([^"\']+)',
        ]

        has_api_calls = False
        for pattern in api_patterns:
            if re.search(pattern, self.html_content):
                has_api_calls = True
                break

        if has_api_calls:
            # integrity 체크 여부 확인
            integrity_patterns = [
                r'integrity\s*:',
                r'\.integrity\s*=',
                r'checkIntegrity',
                r'verifyResponse',
            ]

            has_integrity_check = any(re.search(pattern, self.html_content, re.IGNORECASE)
                                     for pattern in integrity_patterns)

            if not has_integrity_check:
                self.vulnerabilities.append({
                    'type': 'No API Response Integrity Check',
                    'severity': 'medium',
                    'description': 'API 응답에 대한 무결성 검증이 없습니다.',
                    'recommendation': 'API 응답을 검증하는 로직을 구현하세요.'
                })

    def _check_api_versioning(self):
        """API 버전 관리 검사"""
        if not self.url:
            return

        # URL에서 API 버전 패턴 찾기
        version_patterns = [
            r'/v\d+/',           # /v1/, /v2/
            r'/api/v\d+/',       # /api/v1/
            r'\?version=\d+',    # ?version=1
            r'\?v=\d+',          # ?v=1
        ]

        has_versioning = any(re.search(pattern, self.url) for pattern in version_patterns)

        # 헤더에서 버전 확인
        if self.response and hasattr(self.response, 'headers'):
            api_version_header = self.response.headers.get('API-Version') or \
                               self.response.headers.get('X-API-Version')
            if api_version_header:
                has_versioning = True

        # API처럼 보이는 URL인데 버전이 없는 경우
        if '/api/' in self.url and not has_versioning:
            self.vulnerabilities.append({
                'type': 'No API Versioning',
                'severity': 'low',
                'description': 'API 버전 관리가 구현되지 않았습니다.',
                'recommendation': 'URL 경로나 헤더에 API 버전을 명시하세요.'
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
            return 'API 응답 무결성 검사를 통과했습니다'

        issues = []
        vuln_types = set(v.get('type') for v in self.vulnerabilities)

        if 'No API Response Signature' in vuln_types:
            issues.append('응답 서명 없음')
        if 'Weak Digest Algorithm' in vuln_types:
            issues.append('약한 다이제스트')
        if 'Missing ETag' in vuln_types:
            issues.append('ETag 누락')
        if 'No API Response Integrity Check' in vuln_types:
            issues.append('무결성 검증 없음')

        return f"API 무결성 문제 발견: {', '.join(issues)}"

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

