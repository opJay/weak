"""직렬화 무결성 검증 스캐너"""

import re
import base64
from typing import Dict, Any
from scanner.base import BaseScanner


class SerializationIntegrityScanner(BaseScanner):
    """직렬화 무결성 검증 스캐너"""

    metadata = {
        'id': 'serialization_integrity',
        'name': 'Serialization Integrity',
        'field': 'serialization_integrity',
        'weight': 1,
        'category': 'data_integrity',
        'severity': 'high',
        'description': '직렬화 무결성 검증 (서명 없는 직렬화, Pickle/PHP/Java 직렬화 탐지)',
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
        # 1. 서명되지 않은 쿠키/세션 검사
        self._check_unsigned_cookies()

        # 2. 위험한 직렬화 포맷 탐지
        self._check_dangerous_serialization()

        # 3. Base64 인코딩된 객체 검사
        self._check_base64_objects()

        # 4. JSON 무결성 검사
        self._check_json_integrity()

    def _check_unsigned_cookies(self):
        """서명되지 않은 쿠키 검사"""
        if not self.response or not hasattr(self.response, 'headers'):
            return

        # Set-Cookie 헤더 검사
        set_cookie = self.response.headers.get('Set-Cookie', '')
        cookies = set_cookie.split(';') if set_cookie else []

        for cookie in cookies:
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                name = name.strip()

                # 세션 관련 쿠키 확인
                if any(session in name.lower() for session in ['session', 'sess', 'sid']):
                    # 서명 패턴 확인 (일반적으로 . 또는 : 포함)
                    if '.' not in value and ':' not in value and '--' not in value:
                        self.vulnerabilities.append({
                            'type': 'Unsigned Session Cookie',
                            'severity': 'high',
                            'cookie': name,
                            'description': f'세션 쿠키 {name}이(가) 서명되지 않았습니다.',
                            'recommendation': 'HMAC 또는 디지털 서명을 사용하여 쿠키를 보호하세요.'
                        })

    def _check_dangerous_serialization(self):
        """위험한 직렬화 포맷 탐지"""
        if not self.html_content:
            return

        # Python Pickle 패턴
        pickle_patterns = [
            rb'\x80\x03',  # Pickle protocol 3
            rb'\x80\x04',  # Pickle protocol 4
            rb'\x80\x05',  # Pickle protocol 5
            b'gASV',       # Base64 encoded pickle
            b'(dp',        # Old pickle format
        ]

        # PHP 직렬화 패턴
        php_patterns = [
            r'[aOC]:\d+:',  # PHP serialization
            r's:\d+:"[^"]+";',
            r'a:\d+:\{',
            r'O:\d+:"[^"]+":',
        ]

        # Java 직렬화 패턴
        java_patterns = [
            b'\xac\xed\x00\x05',  # Java serialization magic bytes
            b'rO0AB',              # Base64 encoded Java object
        ]

        content_bytes = self.html_content.encode('utf-8', errors='ignore')

        # Pickle 검사
        for pattern in pickle_patterns:
            if pattern in content_bytes or (isinstance(pattern, bytes) and
                                           base64.b64encode(pattern).decode() in self.html_content):
                self.vulnerabilities.append({
                    'type': 'Python Pickle Detected',
                    'severity': 'critical',
                    'description': 'Python Pickle 직렬화가 탐지되었습니다.',
                    'recommendation': 'Pickle 대신 JSON을 사용하세요.'
                })
                break

        # Base64로 인코딩된 pickle 추가 검사
        base64_pickle_patterns = ['gAN9', 'gAJ9', 'gAV9', 'gAR9', 'gANd']

        for pattern in base64_pickle_patterns:
            if pattern in self.html_content:
                self.vulnerabilities.append({
                    'type': 'Python Pickle Detected',
                    'severity': 'critical',
                    'description': 'Python Pickle 직렬화가 탐지되었습니다.',
                    'recommendation': 'Pickle 대신 JSON을 사용하세요.'
                })
                break

        # PHP 직렬화 검사
        for pattern in php_patterns:
            if re.search(pattern, self.html_content):
                self.vulnerabilities.append({
                    'type': 'PHP Serialization Detected',
                    'severity': 'critical',
                    'description': 'PHP 직렬화가 탐지되었습니다.',
                    'recommendation': 'unserialize() 사용을 피하고 JSON을 사용하세요.'
                })
                break

        # Java 직렬화 검사
        for pattern in java_patterns:
            if pattern in content_bytes or (isinstance(pattern, bytes) and
                                           base64.b64encode(pattern).decode() in self.html_content):
                self.vulnerabilities.append({
                    'type': 'Java Serialization Detected',
                    'severity': 'critical',
                    'description': 'Java 직렬화가 탐지되었습니다.',
                    'recommendation': 'ObjectInputStream 사용을 피하고 JSON을 사용하세요.'
                })
                break

    def _check_base64_objects(self):
        """Base64 인코딩된 객체 검사"""
        if not self.html_content:
            return

        # Base64 패턴 찾기
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(base64_pattern, self.html_content)

        for match in matches[:10]:  # 최대 10개만 검사
            try:
                decoded = base64.b64decode(match)

                # 직렬화된 객체 시그니처 확인
                if decoded.startswith(b'\x80') or decoded.startswith(b'O:') or decoded.startswith(b'\xac\xed'):
                    self.vulnerabilities.append({
                        'type': 'Base64 Serialized Object',
                        'severity': 'high',
                        'description': 'Base64로 인코딩된 직렬화 객체가 발견되었습니다.',
                        'recommendation': '직렬화된 데이터에 서명을 추가하거나 JSON을 사용하세요.'
                    })
                    break
            except:
                pass

    def _check_json_integrity(self):
        """JSON 데이터 무결성 검사"""
        if not self.html_content:
            return

        # JavaScript에서 JSON 처리 패턴 찾기
        unsafe_patterns = [
            r'eval\s*\([^)]*JSON',
            r'Function\s*\([^)]*JSON',
            r'new\s+Function\s*\([^)]*JSON',
        ]

        for pattern in unsafe_patterns:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'Unsafe JSON Parsing',
                    'severity': 'high',
                    'description': 'eval() 또는 Function()으로 JSON을 파싱하고 있습니다.',
                    'recommendation': 'JSON.parse()를 사용하세요.'
                })
                break

        # 서명되지 않은 JSON 데이터 전송 패턴
        if 'JSON.stringify' in self.html_content and 'signature' not in self.html_content.lower():
            if re.search(r'fetch|axios|ajax|XMLHttpRequest', self.html_content):
                self.vulnerabilities.append({
                    'type': 'Unsigned JSON Data',
                    'severity': 'medium',
                    'description': 'JSON 데이터가 서명 없이 전송되고 있습니다.',
                    'recommendation': 'HMAC 또는 JWS를 사용하여 JSON 데이터에 서명하세요.'
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
            return '직렬화 무결성 검사를 통과했습니다'

        issues = []
        vuln_types = set(v.get('type') for v in self.vulnerabilities)

        if 'Unsigned Session Cookie' in vuln_types:
            issues.append('서명되지 않은 쿠키')
        if 'Python Pickle Detected' in vuln_types:
            issues.append('Python Pickle')
        if 'PHP Serialization Detected' in vuln_types:
            issues.append('PHP 직렬화')
        if 'Java Serialization Detected' in vuln_types:
            issues.append('Java 직렬화')
        if 'Unsafe JSON Parsing' in vuln_types:
            issues.append('안전하지 않은 JSON 파싱')

        return f"직렬화 무결성 문제 발견: {', '.join(issues)}"

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

