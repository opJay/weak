"""
JWTSecurityScanner - 자동 수정됨

원본: scanners_refactored_batch5.py
"""

import logging
import re
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
import requests
import json
import time
import hashlib
import base64

from scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class JWTSecurityScanner(BaseScanner):
    """JWT 보안 취약점 스캐너"""

    metadata = {
        'id': 'jwt_security',
        'name': 'JWT 보안 검사',
        'icon': '🔑',
        'description': 'JSON Web Token 보안 취약점 탐지',
        'weight': 2,
        'field': 'jwt_vulnerabilities',
        'category': 'security_advanced',
        'OWASP': 'A07:2025',
    }

    def __init__(self, response: requests.Response = None, html_content: str = None, url: str = None, **kwargs):
        """JWTSecurityScanner 초기화"""
        super().__init__(url=url or '', response=response, html_content=html_content, **kwargs)
        self.response = response
        self.html_content = html_content or ''
        self.vulnerabilities = []
        self.tokens: List[Tuple[str, str]] = []

    def _execute_scan(self) -> None:
        """JWT 보안 스캔 실행"""
        # 검사 항목: JWT 토큰 탐지 및 분석
        self.checked = 1

        try:
            # 1. JWT 토큰 탐지
            self._find_jwt_tokens()

            # 2. 각 토큰 분석
            for token_info in self.tokens[:5]:  # 최대 5개만 분석
                self._analyze_jwt(token_info)

        except Exception as e:
            logger.error(f"JWT security scan error: {str(e)}")

        # 결과 요약
        if not self.tokens:
            self._add_detail(
                id='jwt_check',
                name='JWT 보안 검사',
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
                id='jwt_check',
                name='JWT 보안 검사',
                status='fail',
                severity='critical' if critical_count > 0 else 'high',
                description=f'{len(self.vulnerabilities)}개의 JWT 취약점 발견 ({len(self.tokens)}개 토큰 분석)',
                value=f'Critical: {critical_count}개',
                expected='JWT 취약점 없음',
                recommendation='JWT 알고리즘, 만료 시간, 민감정보 저장 여부를 점검하세요.'
            )
        else:
            self._add_detail(
                id='jwt_check',
                name='JWT 보안 검사',
                status='pass',
                severity='info',
                description=f'{len(self.tokens)}개 JWT 토큰 검사 완료, 취약점 없음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _find_jwt_tokens(self) -> None:
        """JWT 토큰 찾기"""
        try:
            # Authorization 헤더에서
            if self.response:
                auth_header = self.response.headers.get('Authorization', '')
                if 'Bearer' in auth_header:
                    token = auth_header.replace('Bearer ', '').strip()
                    if self._is_jwt(token):
                        self.tokens.append(('Authorization Header', token))

                # 쿠키에서
                for cookie in self.response.cookies:
                    if self._is_jwt(cookie.value):
                        self.tokens.append((f'Cookie: {cookie.name}', cookie.value))

            # HTML/JS에서 JWT 패턴 찾기
            if self.html_content:
                jwt_pattern = r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
                matches = re.findall(jwt_pattern, self.html_content)
                for match in matches[:3]:
                    self.tokens.append(('HTML/JS', match))

        except Exception as e:
            logger.debug(f"JWT token finding error: {str(e)}")

    def _is_jwt(self, token: str) -> bool:
        """JWT 형식인지 확인"""
        parts = token.split('.')
        return len(parts) == 3 and all(len(part) > 0 for part in parts)

    def _analyze_jwt(self, token_info: Tuple[str, str]) -> None:
        """JWT 토큰 분석"""
        try:
            location, token = token_info
            parts = token.split('.')

            if len(parts) != 3:
                return

            # 헤더 디코딩
            try:
                header_decoded = base64.urlsafe_b64decode(parts[0] + '==')
                header = json.loads(header_decoded)

                # 1. Algorithm None Attack
                alg = header.get('alg', '').lower()
                if alg == 'none':
                    self.vulnerabilities.append({
                        'type': 'JWT Algorithm None',
                        'severity': 'critical',
                        'location': location,
                        'description': 'JWT가 "alg: none"을 사용하고 있어 서명 검증을 우회할 수 있습니다.',
                        'recommendation': '서버에서 "alg: none"을 거부하도록 설정하세요.'
                    })

                # 2. Weak Algorithm
                elif alg == 'hs256':
                    self.vulnerabilities.append({
                        'type': 'JWT Weak Algorithm',
                        'severity': 'medium',
                        'location': location,
                        'algorithm': alg,
                        'description': 'JWT가 HS256(HMAC)을 사용합니다. 약한 secret key 사용 시 취약할 수 있습니다.',
                        'recommendation': 'RS256(RSA) 알고리즘 사용을 고려하고, 충분히 긴 secret key를 사용하세요.'
                    })

                # Payload 디코딩
                payload_decoded = base64.urlsafe_b64decode(parts[1] + '==')
                payload = json.loads(payload_decoded)

                # 3. No Expiration
                if 'exp' not in payload:
                    self.vulnerabilities.append({
                        'type': 'JWT No Expiration',
                        'severity': 'high',
                        'location': location,
                        'description': 'JWT에 만료 시간(exp)이 설정되지 않았습니다.',
                        'recommendation': '반드시 exp claim을 설정하여 토큰 만료를 구현하세요.'
                    })

                # 4. Sensitive Data in JWT
                sensitive_keys = ['password', 'secret', 'key', 'ssn', 'credit_card']
                found_sensitive = [key for key in payload.keys()
                                 if any(s in key.lower() for s in sensitive_keys)]

                if found_sensitive:
                    self.vulnerabilities.append({
                        'type': 'JWT Sensitive Data',
                        'severity': 'high',
                        'location': location,
                        'sensitive_fields': found_sensitive,
                        'description': f'JWT에 민감한 정보가 포함되어 있을 수 있습니다: {", ".join(found_sensitive)}',
                        'recommendation': 'JWT에 민감한 정보를 저장하지 마세요. JWT는 암호화되지 않습니다.'
                    })

            except Exception as e:
                logger.debug(f"JWT analysis error: {str(e)}")

        except Exception as e:
            logger.debug(f"JWT token analysis error: {str(e)}")

    def _build_result(self) -> Dict[str, Any]:
        """스캔 결과 빌드"""
        result = super()._build_result()
        result.update({
            'vulnerabilities': self.vulnerabilities,
            'total': len(self.vulnerabilities),
            'has_jwt': len(self.tokens) > 0,
            'tokens_found': len(self.tokens),
            'scanner_id': self.metadata['id']
        })

        if not self.tokens:
            result['message'] = 'JWT 토큰이 발견되지 않았습니다.'

        return result



    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

