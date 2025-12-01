"""
Batch 9: Data Integrity Security Scanners
데이터 무결성 보안 스캐너 (OWASP A08:2025)

Includes:
1. JWTAdvancedScanner - JWT 고급 보안 검증
2. SerializationIntegrityScanner - 직렬화 무결성 검증
3. APIIntegrityScanner - API 응답 무결성 검사
4. ChecksumValidationScanner - 체크섬 검증
"""

import re
import json
import base64
import hashlib
import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from scanner.base import BaseScanner

logger = logging.getLogger('scanner')


class JWTAdvancedScanner(BaseScanner):
    """JWT 고급 보안 검증 스캐너"""

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None):
        super().__init__(url=url or '', response=response,
                        html_content=html_content)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client or {}
        self.vulnerabilities = []

        # 약한 HMAC secrets
        self.WEAK_SECRETS = [
            'secret', 'password', 'key', '123456', 'your-256-bit-secret',
            'your-secret-key', 'jwt-secret', 'mysecret'
        ]

        # 안전하지 않은 알고리즘
        self.UNSAFE_ALGORITHMS = ['none', 'None', 'NONE', 'HS256']

    def get_metadata(self) -> Dict[str, Any]:
        return {
            'id': 'jwt_advanced',
            'name': 'JWT Advanced Security',
            'category': 'data_integrity',
            'severity': 'high',
            'description': 'JWT 고급 보안 검증 (알고리즘 혼동, weak secret, claims 검증)',
            'owasp': ['A08:2025']
        }

    def _prepare(self):
        """스캔 준비"""
        pass

    def _execute_scan(self):
        """스캔 실행"""
        # JWT 토큰 수집
        tokens = self._collect_jwt_tokens()

        if tokens:
            # 각 토큰 분석
            for token in tokens[:5]:  # 최대 5개만 분석
                self._analyze_jwt(token)

        # JWK 노출 확인
        self._check_jwk_exposure()

        # /.well-known/jwks.json 확인
        self._check_jwks_endpoint()

    def _collect_jwt_tokens(self):
        """JWT 토큰 수집"""
        tokens = []

        # HTML에서 JWT 패턴 찾기
        if self.html_content:
            # JWT 패턴: header.payload.signature
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
            found_tokens = re.findall(jwt_pattern, self.html_content)
            tokens.extend(found_tokens)

            # JavaScript 변수에서 토큰 찾기
            js_token_patterns = [
                r'token["\']?\s*[:=]\s*["\']([^"\']+)',
                r'jwt["\']?\s*[:=]\s*["\']([^"\']+)',
                r'authorization["\']?\s*[:=]\s*["\']Bearer\s+([^"\']+)',
            ]

            for pattern in js_token_patterns:
                matches = re.findall(pattern, self.html_content, re.IGNORECASE)
                for match in matches:
                    if re.match(jwt_pattern, match):
                        tokens.append(match)

        # Response 헤더에서 토큰 찾기
        if self.response and hasattr(self.response, 'headers'):
            auth_header = self.response.headers.get('Authorization', '')
            if 'Bearer ' in auth_header:
                token = auth_header.replace('Bearer ', '').strip()
                if re.match(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+', token):
                    tokens.append(token)

        return list(set(tokens))  # 중복 제거

    def _analyze_jwt(self, token):
        """JWT 토큰 분석"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return

            # Header 디코딩
            header = self._decode_jwt_part(parts[0])
            if header:
                # 알고리즘 검사
                alg = header.get('alg', '').upper()

                if alg in ['NONE', '']:
                    self.vulnerabilities.append({
                        'type': 'JWT No Algorithm',
                        'severity': 'critical',
                        'description': 'JWT가 서명되지 않았습니다 (alg: none)',
                        'recommendation': 'RS256 또는 ES256과 같은 강력한 알고리즘을 사용하세요.'
                    })

                elif alg == 'HS256':
                    # 약한 시크릿 테스트
                    for secret in self.WEAK_SECRETS:
                        if self._verify_jwt_with_secret(token, secret):
                            self.vulnerabilities.append({
                                'type': 'JWT Weak Secret',
                                'severity': 'critical',
                                'secret': secret,
                                'description': f'JWT가 약한 시크릿으로 서명되었습니다: {secret}',
                                'recommendation': '강력한 랜덤 시크릿을 사용하세요.'
                            })
                            break

                # kid 인젝션 가능성 검사
                if 'kid' in header:
                    kid = header['kid']
                    if '../' in kid or '\\' in kid or '/' in kid:
                        self.vulnerabilities.append({
                            'type': 'JWT Kid Injection',
                            'severity': 'high',
                            'description': 'JWT kid 헤더에 경로 순회 가능성이 있습니다.',
                            'recommendation': 'kid 값을 엄격하게 검증하세요.'
                        })

            # Payload 디코딩
            payload = self._decode_jwt_part(parts[1])
            if payload:
                # Claims 검증
                self._check_jwt_claims(payload)

        except Exception as e:
            logger.debug(f'JWT analysis error: {e}')

    def _decode_jwt_part(self, encoded):
        """JWT 파트 디코딩"""
        try:
            # Base64 URL 디코딩
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += '=' * (4 - missing_padding)

            decoded = base64.urlsafe_b64decode(encoded)
            return json.loads(decoded)
        except:
            return None

    def _verify_jwt_with_secret(self, token, secret):
        """약한 시크릿으로 JWT 검증 시도"""
        try:
            import hmac

            parts = token.split('.')
            if len(parts) != 3:
                return False

            message = f"{parts[0]}.{parts[1]}"
            signature = parts[2]

            # HMAC SHA256으로 서명 생성
            expected_signature = base64.urlsafe_b64encode(
                hmac.new(
                    secret.encode('utf-8'),
                    message.encode('utf-8'),
                    hashlib.sha256
                ).digest()
            ).decode('utf-8').rstrip('=')

            return signature == expected_signature
        except:
            return False

    def _check_jwt_claims(self, payload):
        """JWT claims 검증"""
        import time

        current_time = time.time()

        # 만료 시간 검사
        if 'exp' in payload:
            exp = payload['exp']
            if exp < current_time:
                self.vulnerabilities.append({
                    'type': 'JWT Expired',
                    'severity': 'medium',
                    'description': 'JWT 토큰이 만료되었습니다.',
                    'recommendation': '토큰 갱신 메커니즘을 구현하세요.'
                })
        else:
            self.vulnerabilities.append({
                'type': 'JWT No Expiration',
                'severity': 'medium',
                'description': 'JWT에 만료 시간이 설정되지 않았습니다.',
                'recommendation': 'exp claim을 설정하여 토큰 수명을 제한하세요.'
            })

        # iss (issuer) 검사
        if 'iss' not in payload:
            self.vulnerabilities.append({
                'type': 'JWT No Issuer',
                'severity': 'low',
                'description': 'JWT에 발급자(iss) 정보가 없습니다.',
                'recommendation': 'iss claim을 설정하여 토큰 출처를 명확히 하세요.'
            })

        # aud (audience) 검사
        if 'aud' not in payload:
            self.vulnerabilities.append({
                'type': 'JWT No Audience',
                'severity': 'low',
                'description': 'JWT에 수신자(aud) 정보가 없습니다.',
                'recommendation': 'aud claim을 설정하여 토큰 사용처를 제한하세요.'
            })

    def _check_jwk_exposure(self):
        """JWK 노출 확인"""
        if not self.html_content:
            return

        # JWK 패턴 찾기
        jwk_patterns = [
            r'"kty"\s*:\s*"[^"]+',  # Key Type
            r'"kid"\s*:\s*"[^"]+',  # Key ID
            r'"use"\s*:\s*"sig"',   # Key Use
            r'"n"\s*:\s*"[^"]+',    # RSA Modulus
            r'"e"\s*:\s*"[^"]+',    # RSA Exponent
        ]

        jwk_count = sum(1 for pattern in jwk_patterns
                       if re.search(pattern, self.html_content))

        if jwk_count >= 3:
            self.vulnerabilities.append({
                'type': 'JWK Exposure',
                'severity': 'high',
                'description': 'JWK (JSON Web Key) 정보가 HTML에 노출되어 있습니다.',
                'recommendation': 'JWK를 안전한 서버 측 저장소에 보관하세요.'
            })

    def _check_jwks_endpoint(self):
        """JWKS 엔드포인트 확인"""
        if not self.http_client or not hasattr(self.http_client, 'get'):
            return

        try:
            jwks_url = urljoin(self.url, '/.well-known/jwks.json')
            response = self.http_client.get(jwks_url, timeout=5)

            if response and hasattr(response, 'status_code') and response.status_code == 200:
                try:
                    jwks_data = response.json()
                    if 'keys' in jwks_data:
                        self.vulnerabilities.append({
                            'type': 'JWKS Endpoint Exposed',
                            'severity': 'info',
                            'description': 'JWKS 엔드포인트가 공개되어 있습니다.',
                            'recommendation': '필요한 경우에만 공개하고 적절한 접근 제어를 구현하세요.'
                        })
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
            return 'JWT 보안 검사를 통과했습니다'

        issues = []
        vuln_types = set(v.get('type') for v in self.vulnerabilities)

        if 'JWT No Algorithm' in vuln_types:
            issues.append('서명 없음')
        if 'JWT Weak Secret' in vuln_types:
            issues.append('약한 시크릿')
        if 'JWT Kid Injection' in vuln_types:
            issues.append('Kid 인젝션')
        if 'JWT Expired' in vuln_types:
            issues.append('만료된 토큰')
        if 'JWK Exposure' in vuln_types:
            issues.append('JWK 노출')

        return f"JWT 보안 문제 발견: {', '.join(issues)}"


class SerializationIntegrityScanner(BaseScanner):
    """직렬화 무결성 검증 스캐너"""

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None):
        super().__init__(url=url or '', response=response,
                        html_content=html_content)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client or {}
        self.vulnerabilities = []

    def get_metadata(self) -> Dict[str, Any]:
        return {
            'id': 'serialization_integrity',
            'name': 'Serialization Integrity',
            'category': 'data_integrity',
            'severity': 'high',
            'description': '직렬화 무결성 검증 (서명 없는 직렬화, Pickle/PHP/Java 직렬화 탐지)',
            'owasp': ['A08:2025']
        }

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
        # Pickle protocol 3의 Base64 인코딩 패턴들
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


class APIIntegrityScanner(BaseScanner):
    """API 응답 무결성 검사 스캐너"""

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None):
        super().__init__(url=url or '', response=response,
                        html_content=html_content)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client or {}
        self.vulnerabilities = []

    def get_metadata(self) -> Dict[str, Any]:
        return {
            'id': 'api_integrity',
            'name': 'API Response Integrity',
            'category': 'data_integrity',
            'severity': 'medium',
            'description': 'API 응답 무결성 검사 (X-Signature, ETag, Content-MD5, SRI)',
            'owasp': ['A08:2025']
        }

    def _prepare(self):
        """스캔 준비"""
        pass

    def _execute_scan(self):
        """스캔 실행"""
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


class ChecksumValidationScanner(BaseScanner):
    """체크섬 검증 스캐너"""

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None):
        super().__init__(url=url or '', response=response,
                        html_content=html_content)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client or {}
        self.vulnerabilities = []

    def get_metadata(self) -> Dict[str, Any]:
        return {
            'id': 'checksum_validation',
            'name': 'Checksum Validation',
            'category': 'data_integrity',
            'severity': 'medium',
            'description': '체크섬 검증 (약한 해시 알고리즘, SHA256SUMS, MD5SUMS)',
            'owasp': ['A08:2025']
        }

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
                        return  # 서명된 체크섬이 있으면 OK

                    # 서명되지 않은 체크섬 파일
                    if not checksum_file.endswith('.asc'):
                        self.vulnerabilities.append({
                            'type': 'Unsigned Checksum File',
                            'severity': 'low',
                            'file': checksum_file,
                            'description': f'체크섬 파일 {checksum_file}이(가) 서명되지 않았습니다.',
                            'recommendation': 'PGP 서명을 추가하여 체크섬 파일의 무결성을 보장하세요.'
                        })

                    break  # 첫 번째 체크섬 파일만 확인
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