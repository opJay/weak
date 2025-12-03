"""JWT 고급 보안 검증 스캐너"""

import re
import json
import base64
import hashlib
import logging
from typing import Dict, Any
from urllib.parse import urljoin
from scanner.base import BaseScanner

logger = logging.getLogger('scanner')


class JWTAdvancedScanner(BaseScanner):
    """JWT 고급 보안 검증 스캐너"""

    metadata = {
        'id': 'jwt_advanced',
        'name': 'JWT Advanced Security',
        'field': 'jwt_advanced',
        'weight': 2,
        'category': 'data_integrity',
        'severity': 'high',
        'description': 'JWT 고급 보안 검증 (알고리즘 혼동, weak secret, claims 검증)',
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

        # 약한 HMAC secrets
        self.WEAK_SECRETS = [
            'secret', 'password', 'key', '123456', 'your-256-bit-secret',
            'your-secret-key', 'jwt-secret', 'mysecret'
        ]

        # 안전하지 않은 알고리즘
        self.UNSAFE_ALGORITHMS = ['none', 'None', 'NONE', 'HS256']

    def _prepare(self):
        """스캔 준비"""
        pass

    def _execute_scan(self):
        """스캔 실행"""
        # 검사 항목: JWT 토큰 분석, JWK 노출, JWKS 엔드포인트
        self.checked = 3

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

        # 결과 요약
        if not tokens and not self.vulnerabilities:
            self._add_detail(
                id='jwt_advanced_check',
                name='JWT 고급 보안 검사',
                status='pass',
                severity='info',
                description='JWT 토큰이 발견되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )
        elif self.vulnerabilities:
            critical_count = len([v for v in self.vulnerabilities if v.get('severity') == 'critical'])
            self._add_detail(
                id='jwt_advanced_check',
                name='JWT 고급 보안 검사',
                status='fail',
                severity='critical' if critical_count > 0 else 'high',
                description=f'{len(self.vulnerabilities)}개의 JWT 취약점 발견',
                value=f'Critical: {critical_count}개',
                expected='JWT 취약점 없음',
                recommendation='강력한 알고리즘, 랜덤 시크릿, exp claim을 사용하세요.'
            )
        else:
            self._add_detail(
                id='jwt_advanced_check',
                name='JWT 고급 보안 검사',
                status='pass',
                severity='info',
                description='JWT 고급 보안 취약점이 발견되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

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

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

