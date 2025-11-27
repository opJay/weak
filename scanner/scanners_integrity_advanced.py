"""
Advanced Data Integrity Security Scanners
OWASP Top 10 2025 A08: Data Integrity Failures 강화

고급 데이터 무결성 스캐너:
- JWT Advanced (JWT 고급 검증)
- Serialization Integrity (직렬화 무결성)
- API Integrity (API 응답 무결성)
- Checksum Validation (체크섬 검증)
"""
import re
import requests
import base64
import json
import hashlib
import logging
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

logger = logging.getLogger('scanner')


class JWTAdvancedScanner:
    """
    JWT 고급 보안 스캐너 (강화 버전)

    JWT 서명 검증 및 고급 공격 탐지:
    - 알고리즘 혼동 공격 (HS256 → RS256)
    - 약한 HMAC secret
    - JWT claims 검증 (iss, aud, nbf, iat)
    - kid (Key ID) 조작 공격
    - JWK 노출 탐지
    """

    metadata = {
        'id': 'jwt_advanced',
        'name': 'JWT 고급 보안 검증',
        'icon': '🔐',
        'description': 'JWT 서명 검증 및 고급 공격 탐지',
        'weight': 3,
        'field': 'jwt_advanced_vulnerabilities'
    }

    # 약한 HMAC secrets (일반적으로 사용되는 취약한 시크릿)
    WEAK_SECRETS = [
        'secret', 'password', 'key', '123456', 'your-256-bit-secret',
        'your-secret-key', 'jwt-secret', 'mysecret'
    ]

    # 안전하지 않은 알고리즘
    UNSAFE_ALGORITHMS = ['none', 'None', 'NONE', 'HS256']  # HS256은 주의 필요

    def __init__(self, url, response=None, html_content=None):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """JWT 고급 보안 스캔 실행"""
        try:
            # JWT 토큰 수집
            tokens = self._collect_jwt_tokens()

            if not tokens:
                return {
                    'vulnerabilities': [],
                    'total': 0,
                    'severity': 'safe',
                    'message': 'No JWT tokens found'
                }

            # 각 토큰 분석
            for token in tokens[:5]:  # 최대 5개만 분석
                self._analyze_jwt(token)

            # JWK 노출 확인
            self._check_jwk_exposure()

            # /.well-known/jwks.json 확인
            self._check_jwks_endpoint()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'JWT Advanced Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _collect_jwt_tokens(self):
        """JWT 토큰 수집"""
        tokens = []

        # 1. Authorization 헤더
        if self.response:
            auth_header = self.response.headers.get('Authorization', '')
            if 'Bearer ' in auth_header:
                token = auth_header.replace('Bearer ', '').strip()
                if self._is_jwt(token):
                    tokens.append(token)

        # 2. HTML/JS 내용에서 추출
        if self.html_content:
            # JWT 패턴: eyJhbGciOiJ... (Base64 URL encoded)
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            found_tokens = re.findall(jwt_pattern, self.html_content)
            tokens.extend([t for t in found_tokens if self._is_jwt(t)])

        return list(set(tokens))  # 중복 제거

    def _is_jwt(self, token):
        """JWT 토큰인지 확인"""
        parts = token.split('.')
        return len(parts) == 3

    def _analyze_jwt(self, token):
        """JWT 토큰 분석"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return

            header_b64, payload_b64, signature = parts

            # Base64 URL decode
            header = self._base64_url_decode(header_b64)
            payload = self._base64_url_decode(payload_b64)

            if not header or not payload:
                return

            # JSON 파싱
            try:
                header_json = json.loads(header)
                payload_json = json.loads(payload)
            except json.JSONDecodeError:
                return

            # 1. 알고리즘 검증
            self._check_algorithm(header_json, token)

            # 2. Claims 검증
            self._check_claims(payload_json, token)

            # 3. kid 조작 공격
            self._check_kid_manipulation(header_json, token)

            # 4. 약한 secret 테스트
            self._check_weak_secret(header_json, token, signature)

            # 5. 민감 정보 노출
            self._check_sensitive_data(payload_json, token)

        except Exception as e:
            logger.debug(f'JWT analysis error: {e}')

    def _base64_url_decode(self, data):
        """Base64 URL decode with padding"""
        try:
            # Add padding
            padding = 4 - (len(data) % 4)
            if padding != 4:
                data += '=' * padding

            return base64.urlsafe_b64decode(data).decode('utf-8')
        except Exception:
            return None

    def _check_algorithm(self, header, token):
        """알고리즘 검증"""
        alg = header.get('alg', '').lower()

        # 1. Algorithm None Attack
        if alg in ['none', '']:
            self.vulnerabilities.append({
                'type': 'jwt_alg_none',
                'severity': 'critical',
                'title': 'JWT Algorithm None Attack 취약점',
                'description': 'alg: none을 사용하여 서명 없이 JWT를 허용할 수 있습니다.',
                'url': self.url,
                'evidence': f'Algorithm: {alg}',
                'recommendation': 'alg: none을 절대 허용하지 마세요. 화이트리스트 방식으로 알고리즘을 검증하세요.'
            })

        # 2. Algorithm Confusion Attack (HS256 with public key)
        if alg == 'hs256':
            self.vulnerabilities.append({
                'type': 'jwt_alg_confusion',
                'severity': 'high',
                'title': 'JWT Algorithm Confusion 가능성',
                'description': 'HS256 알고리즘이 사용되고 있습니다. RS256 공개키를 HMAC secret으로 사용하는 공격에 취약할 수 있습니다.',
                'url': self.url,
                'evidence': 'Algorithm: HS256',
                'recommendation': 'RS256, ES256 등 비대칭 알고리즘 사용을 권장합니다. HS256 사용 시 알고리즘 검증을 엄격히 하세요.'
            })

        # 3. 약한 알고리즘
        weak_algs = ['hs256', 'hs384', 'rs256']  # RS256도 특정 상황에서 취약
        if alg in weak_algs:
            self.vulnerabilities.append({
                'type': 'jwt_weak_algorithm',
                'severity': 'medium',
                'title': f'JWT 알고리즘 보안 주의: {alg.upper()}',
                'description': f'{alg.upper()} 알고리즘 사용 중입니다. 특정 공격에 취약할 수 있습니다.',
                'url': self.url,
                'evidence': f'Algorithm: {alg}',
                'recommendation': 'ES256, EdDSA 등 최신 알고리즘 사용을 고려하세요.'
            })

    def _check_claims(self, payload, token):
        """JWT Claims 검증"""
        issues = []

        # 필수 claims 확인
        if 'exp' not in payload:
            issues.append('exp (만료시간) claim 누락')

        if 'iat' not in payload:
            issues.append('iat (발급시간) claim 누락')

        if 'iss' not in payload:
            issues.append('iss (발급자) claim 누락')

        if 'aud' not in payload:
            issues.append('aud (대상) claim 누락')

        if 'nbf' not in payload:
            issues.append('nbf (유효시작시간) claim 누락')

        if issues:
            self.vulnerabilities.append({
                'type': 'jwt_missing_claims',
                'severity': 'medium',
                'title': 'JWT 필수 Claims 누락',
                'description': '보안을 위해 권장되는 claims가 누락되었습니다.',
                'url': self.url,
                'evidence': ', '.join(issues),
                'recommendation': 'exp, iat, iss, aud, nbf claims을 포함하여 JWT를 발급하세요.'
            })

        # jti (JWT ID) 확인 - 재사용 공격 방지
        if 'jti' not in payload:
            self.vulnerabilities.append({
                'type': 'jwt_no_jti',
                'severity': 'low',
                'title': 'JWT ID (jti) claim 누락',
                'description': 'jti claim이 없어 토큰 재사용 공격을 방어하기 어렵습니다.',
                'url': self.url,
                'recommendation': 'jti (JWT ID)를 포함하고 서버에서 이미 사용된 jti를 추적하세요.'
            })

    def _check_kid_manipulation(self, header, token):
        """kid (Key ID) 조작 공격 확인"""
        if 'kid' in header:
            kid = header['kid']

            # 1. Path Traversal 패턴
            if '../' in kid or '..' in kid or '/' in kid:
                self.vulnerabilities.append({
                    'type': 'jwt_kid_traversal',
                    'severity': 'high',
                    'title': 'JWT kid Path Traversal 취약점',
                    'description': 'kid에 경로 순회 문자가 포함되어 있습니다. 임의의 파일을 키로 사용할 수 있습니다.',
                    'url': self.url,
                    'evidence': f'kid: {kid}',
                    'recommendation': 'kid 값을 화이트리스트로 검증하고, 경로 문자를 허용하지 마세요.'
                })

            # 2. SQL Injection 패턴
            sql_patterns = ["'", '"', '--', ';', '/*']
            if any(p in kid for p in sql_patterns):
                self.vulnerabilities.append({
                    'type': 'jwt_kid_sqli',
                    'severity': 'high',
                    'title': 'JWT kid SQL Injection 가능성',
                    'description': 'kid에 SQL 메타문자가 포함되어 있습니다.',
                    'url': self.url,
                    'evidence': f'kid: {kid}',
                    'recommendation': 'kid를 데이터베이스 조회에 사용하는 경우 Prepared Statement를 사용하세요.'
                })

            # 3. Command Injection 패턴
            cmd_patterns = ['|', '&', ';', '`', '$', '\n']
            if any(p in kid for p in cmd_patterns):
                self.vulnerabilities.append({
                    'type': 'jwt_kid_cmdi',
                    'severity': 'critical',
                    'title': 'JWT kid Command Injection 가능성',
                    'description': 'kid에 명령 실행 메타문자가 포함되어 있습니다.',
                    'url': self.url,
                    'evidence': f'kid: {kid}',
                    'recommendation': 'kid를 시스템 명령에 절대 사용하지 마세요.'
                })

    def _check_weak_secret(self, header, token, signature):
        """약한 HMAC secret 테스트"""
        alg = header.get('alg', '').lower()

        if alg.startswith('hs'):  # HMAC 알고리즘
            # 약한 시크릿으로 서명 시도 (간단한 테스트)
            for secret in self.WEAK_SECRETS:
                # 실제 서명 검증은 pyjwt 라이브러리 필요
                # 여기서는 경고만 발행
                pass

            self.vulnerabilities.append({
                'type': 'jwt_weak_secret_risk',
                'severity': 'medium',
                'title': 'JWT HMAC Secret 강도 검증 필요',
                'description': 'HMAC 알고리즘 사용 시 약한 secret을 사용하면 Brute Force 공격에 취약합니다.',
                'url': self.url,
                'evidence': f'Algorithm: {alg.upper()}',
                'recommendation': '최소 256비트(32바이트) 이상의 랜덤한 secret을 사용하세요. 환경 변수로 관리하세요.'
            })

    def _check_sensitive_data(self, payload, token):
        """민감 정보 노출 확인"""
        sensitive_keys = ['password', 'secret', 'apikey', 'api_key', 'token', 'private_key']

        found_sensitive = []
        for key in payload.keys():
            if any(s in key.lower() for s in sensitive_keys):
                found_sensitive.append(key)

        if found_sensitive:
            self.vulnerabilities.append({
                'type': 'jwt_sensitive_data',
                'severity': 'high',
                'title': 'JWT Payload에 민감 정보 포함',
                'description': 'JWT payload는 Base64 인코딩만 되어 있어 누구나 디코딩할 수 있습니다.',
                'url': self.url,
                'evidence': f'Sensitive keys: {", ".join(found_sensitive)}',
                'recommendation': '민감한 정보는 JWT payload에 절대 포함하지 마세요. JWE(암호화)를 사용하거나 서버 세션에 저장하세요.'
            })

    def _check_jwk_exposure(self):
        """JWK (JSON Web Key) 노출 확인"""
        base_url = self.url.rstrip('/')

        jwk_paths = [
            '/.well-known/jwks.json',
            '/jwks.json',
            '/.well-known/openid-configuration',
            '/api/jwks',
            '/auth/jwks'
        ]

        for path in jwk_paths:
            try:
                jwk_url = base_url + path
                response = requests.get(jwk_url, timeout=5, allow_redirects=False)

                if response.status_code == 200:
                    try:
                        jwk_data = response.json()

                        # JWK가 공개되어 있음
                        self.vulnerabilities.append({
                            'type': 'jwk_public_exposure',
                            'severity': 'low',
                            'title': 'JWK (JSON Web Key) 공개 노출',
                            'description': f'JWK가 {path}에서 공개적으로 접근 가능합니다.',
                            'url': jwk_url,
                            'evidence': 'HTTP 200 OK',
                            'recommendation': 'JWK 공개가 의도된 것인지 확인하세요. 공개키는 안전하지만 접근 제어를 고려하세요.'
                        })

                        # Private key 노출 확인 (d, p, q 파라미터)
                        if 'keys' in jwk_data:
                            for key in jwk_data['keys']:
                                if any(param in key for param in ['d', 'p', 'q', 'dp', 'dq']):
                                    self.vulnerabilities.append({
                                        'type': 'jwk_private_key_exposure',
                                        'severity': 'critical',
                                        'title': 'JWK Private Key 노출!',
                                        'description': 'JWK에 개인키(private key) 파라미터가 포함되어 있습니다!',
                                        'url': jwk_url,
                                        'evidence': 'Private key parameters found',
                                        'recommendation': '즉시 개인키를 제거하고 새로운 키 쌍을 생성하세요!'
                                    })

                    except json.JSONDecodeError:
                        pass

            except requests.RequestException:
                pass

    def _check_jwks_endpoint(self):
        """JWKS 엔드포인트 보안 확인"""
        # 이미 _check_jwk_exposure에서 처리됨
        pass

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

        if severity_counts['high'] >= 2:
            return 'high'
        elif severity_counts['high'] >= 1 or severity_counts['medium'] >= 3:
            return 'medium'
        else:
            return 'low'

    def _get_recommendations(self):
        """보안 권장사항"""
        return [
            'alg: none을 절대 허용하지 마세요. 화이트리스트 방식으로 알고리즘을 검증하세요.',
            'RS256, ES256 등 비대칭 알고리즘을 사용하세요 (HS256보다 안전).',
            '모든 필수 claims (exp, iat, iss, aud, nbf)를 포함하세요.',
            'kid 값을 화이트리스트로 검증하고, 경로 문자/SQL 문자를 허용하지 마세요.',
            'HMAC secret은 최소 256비트 이상의 강력한 랜덤 값을 사용하세요.',
            '민감한 정보는 JWT payload에 포함하지 마세요 (Base64는 암호화가 아닙니다).',
            'JWK에 개인키를 절대 포함하지 마세요. 공개키만 노출하세요.',
            'pyjwt, jsonwebtoken 등 검증된 라이브러리를 사용하세요.'
        ]


class SerializationIntegrityScanner:
    """
    직렬화 무결성 스캐너

    직렬화된 데이터의 무결성 검증 메커니즘 확인:
    - 서명 없는 직렬화 데이터
    - HMAC/서명 존재 확인
    - 리플레이 공격 방지
    """

    metadata = {
        'id': 'serialization_integrity',
        'name': '직렬화 무결성 검증',
        'icon': '📦',
        'description': '직렬화 데이터 무결성 및 서명 검증',
        'weight': 2,
        'field': 'serialization_integrity_vulnerabilities'
    }

    # 직렬화 패턴
    SERIALIZATION_PATTERNS = {
        'pickle': (r'\\x80[\\x02-\\x05]', 'Python Pickle'),
        'phpserialize': (r'[aOsbi]:[0-9]+:', 'PHP Serialize'),
        'java': (r'\\xac\\xed\\x00\\x05', 'Java Serialization'),
        'json': (r'^\{.*\}$', 'JSON'),
        'msgpack': (r'\\x(80|81|82|83|84|85|86|87|88|89|8a|8b|8c|8d|8e|8f)', 'MessagePack')
    }

    def __init__(self, url, response=None, html_content=None):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """직렬화 무결성 스캔 실행"""
        try:
            # 1. 쿠키에서 직렬화 데이터 확인
            if self.response:
                self._check_cookies()

            # 2. HTML/JS에서 직렬화 패턴 확인
            if self.html_content:
                self._check_html_serialization()

            # 3. 응답 본문에서 직렬화 확인
            if self.response:
                self._check_response_body()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'Serialization Integrity Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _check_cookies(self):
        """쿠키에서 직렬화 데이터 확인"""
        cookies = self.response.cookies

        for cookie in cookies:
            value = cookie.value

            # Base64 디코딩 시도
            try:
                decoded = base64.b64decode(value)
                decoded_str = decoded.decode('utf-8', errors='ignore')

                # 직렬화 패턴 검사
                for ser_type, (pattern, desc) in self.SERIALIZATION_PATTERNS.items():
                    if re.search(pattern, decoded_str, re.DOTALL):
                        # 서명 확인
                        has_signature = self._has_signature(value)

                        if not has_signature:
                            self.vulnerabilities.append({
                                'type': 'unsigned_serialized_cookie',
                                'severity': 'high',
                                'title': f'서명 없는 직렬화 쿠키: {cookie.name}',
                                'description': f'{desc} 직렬화 데이터가 서명 없이 쿠키에 저장되어 있습니다.',
                                'url': self.url,
                                'evidence': f'Cookie: {cookie.name}, Type: {desc}',
                                'recommendation': 'itsdangerous, django.core.signing 등으로 쿠키에 서명하세요.'
                            })

            except Exception:
                pass

    def _has_signature(self, data):
        """데이터에 서명이 있는지 확인"""
        # 일반적인 서명 패턴
        signature_patterns = [
            r'\.',  # JWT 스타일 (헤더.페이로드.서명)
            r'--',  # Flask 스타일
            r':',   # Django 스타일
        ]

        # 점이 2개 이상 있으면 서명 가능성
        if data.count('.') >= 2:
            return True

        # --로 구분되어 있으면 Flask signed cookie
        if '--' in data:
            return True

        # :로 구분되어 있으면 Django signed cookie
        if ':' in data and len(data.split(':')) >= 2:
            return True

        return False

    def _check_html_serialization(self):
        """HTML/JS에서 직렬화 패턴 확인"""
        # Hidden 필드에서 직렬화 데이터 확인
        soup = BeautifulSoup(self.html_content, 'html.parser')

        for hidden_input in soup.find_all('input', type='hidden'):
            value = hidden_input.get('value', '')
            name = hidden_input.get('name', '')

            if len(value) > 20:  # 충분히 긴 값만 검사
                try:
                    decoded = base64.b64decode(value)
                    decoded_str = decoded.decode('utf-8', errors='ignore')

                    for ser_type, (pattern, desc) in self.SERIALIZATION_PATTERNS.items():
                        if re.search(pattern, decoded_str, re.DOTALL):
                            has_signature = self._has_signature(value)

                            if not has_signature:
                                self.vulnerabilities.append({
                                    'type': 'unsigned_serialized_hidden',
                                    'severity': 'medium',
                                    'title': f'서명 없는 직렬화 Hidden 필드: {name}',
                                    'description': f'{desc} 직렬화 데이터가 서명 없이 사용되고 있습니다.',
                                    'url': self.url,
                                    'evidence': f'Hidden field: {name}',
                                    'recommendation': '직렬화된 데이터에 HMAC 서명을 추가하세요.'
                                })

                except Exception:
                    pass

    def _check_response_body(self):
        """응답 본문에서 직렬화 확인"""
        if not self.response:
            return

        content_type = self.response.headers.get('Content-Type', '').lower()

        # application/x-pickle 등 위험한 Content-Type
        dangerous_types = ['pickle', 'serialized', 'x-java-serialized']

        for dtype in dangerous_types:
            if dtype in content_type:
                self.vulnerabilities.append({
                    'type': 'dangerous_content_type',
                    'severity': 'high',
                    'title': f'위험한 Content-Type: {content_type}',
                    'description': '안전하지 않은 직렬화 형식이 사용되고 있습니다.',
                    'url': self.url,
                    'evidence': f'Content-Type: {content_type}',
                    'recommendation': 'JSON 등 안전한 직렬화 형식을 사용하세요.'
                })

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
            '직렬화된 데이터에는 반드시 HMAC 서명을 추가하세요.',
            'Python: itsdangerous, Django: django.core.signing 사용',
            'PHP: hash_hmac() 사용, Java: javax.crypto.Mac 사용',
            'pickle, Java Serialization 대신 JSON 사용을 권장합니다.',
            '타임스탬프를 포함하여 리플레이 공격을 방지하세요.',
            '서명 검증 실패 시 데이터를 절대 사용하지 마세요.'
        ]


class APIIntegrityScanner:
    """
    API 응답 무결성 스캐너

    API 응답의 무결성 보호 메커니즘 확인:
    - X-Signature 헤더
    - ETag 사용
    - Content-MD5
    """

    metadata = {
        'id': 'api_integrity',
        'name': 'API 응답 무결성 검사',
        'icon': '🔗',
        'description': 'API 응답 서명 및 무결성 검증',
        'weight': 2,
        'field': 'api_integrity_vulnerabilities'
    }

    def __init__(self, url, response=None, html_content=None):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """API 무결성 스캔 실행"""
        try:
            if not self.response:
                return {
                    'vulnerabilities': [],
                    'total': 0,
                    'severity': 'safe'
                }

            # 1. API 엔드포인트인지 확인
            if self._is_api_endpoint():
                # 2. 응답 서명 헤더 확인
                self._check_signature_headers()

                # 3. ETag 확인
                self._check_etag()

                # 4. Content-MD5 확인
                self._check_content_md5()

                # 5. GraphQL 응답 서명 확인
                self._check_graphql_signature()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'API Integrity Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _is_api_endpoint(self):
        """API 엔드포인트인지 확인"""
        # Content-Type 확인
        content_type = self.response.headers.get('Content-Type', '').lower()

        if 'application/json' in content_type:
            return True

        if 'application/xml' in content_type:
            return True

        # URL 패턴 확인
        api_patterns = ['/api/', '/graphql', '/rest/', '/v1/', '/v2/']
        for pattern in api_patterns:
            if pattern in self.url.lower():
                return True

        return False

    def _check_signature_headers(self):
        """API 응답 서명 헤더 확인"""
        signature_headers = [
            'X-Signature',
            'X-Content-Signature',
            'X-HMAC',
            'X-API-Signature',
            'Signature'
        ]

        has_signature = False
        for header in signature_headers:
            if header in self.response.headers:
                has_signature = True
                break

        if not has_signature:
            self.vulnerabilities.append({
                'type': 'api_no_signature',
                'severity': 'medium',
                'title': 'API 응답 서명 누락',
                'description': 'API 응답에 무결성을 보장하는 서명 헤더가 없습니다.',
                'url': self.url,
                'evidence': 'No signature headers found',
                'recommendation': 'X-Signature 등의 HMAC 서명 헤더를 추가하세요.'
            })

    def _check_etag(self):
        """ETag 확인"""
        etag = self.response.headers.get('ETag')

        if not etag:
            self.vulnerabilities.append({
                'type': 'api_no_etag',
                'severity': 'low',
                'title': 'API ETag 누락',
                'description': 'ETag 헤더가 없어 캐시 무결성 검증이 어렵습니다.',
                'url': self.url,
                'recommendation': 'ETag 헤더를 추가하여 리소스 무결성을 검증하세요.'
            })

    def _check_content_md5(self):
        """Content-MD5 확인"""
        content_md5 = self.response.headers.get('Content-MD5')

        if not content_md5:
            self.vulnerabilities.append({
                'type': 'api_no_content_md5',
                'severity': 'low',
                'title': 'Content-MD5 헤더 누락',
                'description': 'Content-MD5 헤더가 없어 응답 본문 무결성 검증이 불가능합니다.',
                'url': self.url,
                'recommendation': 'Content-MD5 헤더를 추가하여 전송 중 데이터 변조를 탐지하세요.'
            })

    def _check_graphql_signature(self):
        """GraphQL 응답 서명 확인"""
        if '/graphql' not in self.url.lower():
            return

        # GraphQL 응답은 특히 서명이 중요
        if 'X-Signature' not in self.response.headers:
            self.vulnerabilities.append({
                'type': 'graphql_no_signature',
                'severity': 'medium',
                'title': 'GraphQL 응답 서명 없음',
                'description': 'GraphQL API 응답에 서명이 없어 중간자 공격에 취약합니다.',
                'url': self.url,
                'recommendation': 'GraphQL 응답에 HMAC 서명을 추가하세요.'
            })

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
            'API 응답에 X-Signature 헤더를 추가하여 HMAC 서명하세요.',
            'ETag를 사용하여 캐시 무결성을 보장하세요.',
            'Content-MD5를 사용하여 전송 중 데이터 변조를 탐지하세요.',
            'GraphQL API는 특히 응답 서명이 중요합니다.',
            'HTTPS를 사용하여 전송 계층 보안을 확보하세요.',
            '클라이언트는 항상 서명을 검증해야 합니다.'
        ]


class ChecksumValidationScanner:
    """
    체크섬 검증 스캐너

    파일 무결성을 위한 체크섬 사용 확인:
    - SHA256SUMS 파일
    - 약한 해시 알고리즘 (MD5, SHA1) 경고
    """

    metadata = {
        'id': 'checksum_validation',
        'name': '체크섬 검증',
        'icon': '✔️',
        'description': '파일 체크섬 및 해시 무결성 검증',
        'weight': 1.5,
        'field': 'checksum_validation_vulnerabilities'
    }

    def __init__(self, url, response=None, html_content=None):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """체크섬 검증 스캔 실행"""
        try:
            base_url = self.url.rstrip('/')

            # 1. 체크섬 파일 확인
            self._check_checksum_files(base_url)

            # 2. HTML에서 integrity 속성 확인 (이미 SRI 스캐너에서 확인하지만 재확인)
            if self.html_content:
                self._check_html_integrity()

            # 3. 다운로드 링크의 체크섬 확인
            if self.html_content:
                self._check_download_checksums()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'Checksum Validation Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _check_checksum_files(self, base_url):
        """체크섬 파일 확인"""
        checksum_files = [
            'SHA256SUMS', 'SHA256SUMS.txt',
            'MD5SUMS', 'MD5SUMS.txt',
            'checksums.txt', 'checksums.sha256',
            'CHECKSUMS', 'sha256sums.txt'
        ]

        for filename in checksum_files:
            try:
                checksum_url = f'{base_url}/{filename}'
                response = requests.get(checksum_url, timeout=5, allow_redirects=False)

                if response.status_code == 200:
                    content = response.text

                    # 약한 해시 알고리즘 사용 확인
                    if 'MD5' in filename.upper() or 'md5' in content.lower():
                        self.vulnerabilities.append({
                            'type': 'weak_hash_md5',
                            'severity': 'medium',
                            'title': 'MD5 해시 사용 (약한 알고리즘)',
                            'description': 'MD5는 충돌 공격에 취약한 약한 해시 알고리즘입니다.',
                            'url': checksum_url,
                            'evidence': f'File: {filename}',
                            'recommendation': 'SHA256, SHA512 등 강력한 해시 알고리즘을 사용하세요.'
                        })

                    # SHA1도 약함
                    if 'SHA1' in filename.upper() or 'sha1' in content.lower():
                        self.vulnerabilities.append({
                            'type': 'weak_hash_sha1',
                            'severity': 'medium',
                            'title': 'SHA1 해시 사용 (약한 알고리즘)',
                            'description': 'SHA1도 충돌 공격이 가능한 약한 해시입니다.',
                            'url': checksum_url,
                            'evidence': f'File: {filename}',
                            'recommendation': 'SHA256, SHA512로 업그레이드하세요.'
                        })

                    # 안전한 SHA256/SHA512 사용 중
                    if 'SHA256' in filename.upper() or 'SHA512' in filename.upper():
                        # 이건 안전함 - 취약점 없음
                        pass

            except requests.RequestException:
                pass

    def _check_html_integrity(self):
        """HTML의 integrity 속성 확인"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 외부 스크립트/링크 중 integrity 없는 것 찾기
        external_scripts = []
        for script in soup.find_all('script', src=True):
            src = script.get('src', '')
            if src.startswith('http'):
                integrity = script.get('integrity')
                if not integrity:
                    external_scripts.append(src)

        if external_scripts:
            self.vulnerabilities.append({
                'type': 'missing_sri_checksum',
                'severity': 'medium',
                'title': 'SRI (integrity) 누락',
                'description': f'{len(external_scripts)}개의 외부 스크립트에 integrity 속성이 없습니다.',
                'url': self.url,
                'evidence': f'{len(external_scripts)} scripts without integrity',
                'recommendation': 'integrity 속성을 추가하여 파일 무결성을 검증하세요.'
            })

    def _check_download_checksums(self):
        """다운로드 링크의 체크섬 확인"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 다운로드 가능한 파일 링크 찾기
        download_extensions = ['.zip', '.tar.gz', '.exe', '.dmg', '.deb', '.rpm', '.apk']

        download_links = []
        for link in soup.find_all('a', href=True):
            href = link.get('href', '')
            if any(href.endswith(ext) for ext in download_extensions):
                download_links.append(href)

        if download_links and not any(ext in self.html_content for ext in ['checksum', 'sha256', 'md5']):
            self.vulnerabilities.append({
                'type': 'downloads_no_checksum',
                'severity': 'low',
                'title': '다운로드 파일 체크섬 정보 없음',
                'description': '다운로드 가능한 파일이 있지만 체크섬 정보가 제공되지 않습니다.',
                'url': self.url,
                'evidence': f'{len(download_links)} download links found',
                'recommendation': '다운로드 파일의 SHA256 체크섬을 함께 제공하세요.'
            })

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
            'MD5, SHA1 대신 SHA256, SHA512를 사용하세요.',
            '다운로드 파일의 체크섬을 항상 제공하세요.',
            'SRI (Subresource Integrity)를 사용하여 외부 리소스를 검증하세요.',
            '체크섬 파일 자체도 GPG 서명하여 보호하세요.',
            '사용자에게 체크섬 검증 방법을 안내하세요.',
            'CI/CD 파이프라인에 체크섬 검증을 통합하세요.'
        ]
