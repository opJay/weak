"""
Batch 5: 고급 보안 스캐너 리팩토링
Deserialization, JWT, Template Injection, NoSQL Injection, SSL/TLS Deep 스캐너
"""

import re
import json
import base64
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List, Optional, Tuple
from bs4 import BeautifulSoup
import requests
import logging

from .base import BaseScanner

logger = logging.getLogger(__name__)


class DeserializationScanner(BaseScanner):
    """Insecure Deserialization 취약점 스캐너"""

    metadata = {
        'id': 'deserialization',
        'name': '역직렬화 취약점 스캔',
        'icon': '📦',
        'description': 'Insecure Deserialization 취약점 탐지',
        'weight': 2,
        'field': 'deserialization'
    }

    SERIALIZATION_INDICATORS = [
        # Python
        ('pickle', 'Python Pickle', 'critical'),
        ('cPickle', 'Python cPickle', 'critical'),
        ('yaml.load', 'PyYAML unsafe load', 'critical'),
        ('marshal.loads', 'Python Marshal', 'high'),

        # Java
        ('ObjectInputStream', 'Java Serialization', 'critical'),
        ('readObject', 'Java readObject', 'critical'),
        ('XMLDecoder', 'Java XMLDecoder', 'high'),

        # PHP
        ('unserialize', 'PHP unserialize', 'critical'),
        ('__wakeup', 'PHP Magic Method', 'high'),

        # .NET
        ('BinaryFormatter', '.NET BinaryFormatter', 'critical'),
        ('NetDataContractSerializer', '.NET Serialization', 'high'),
    ]

    def __init__(self, response: requests.Response = None, html_content: str = None, **kwargs):
        """DeserializationScanner 초기화"""
        super().__init__(url='', **kwargs)  # BaseScanner는 url 필요
        self.response = response
        self.html_content = html_content or ''
        self.vulnerabilities = []

    def _execute_scan(self) -> None:
        """Deserialization 취약점 스캔 실행"""
        try:
            # 1. 쿠키에서 직렬화된 데이터 확인
            if self.response:
                self._scan_cookies()

            # 2. HTML/JS에서 직렬화 함수 사용 확인
            if self.html_content:
                self._scan_serialization_functions()
                # 3. Base64 인코딩된 직렬화 데이터 탐지
                self._scan_encoded_data()

        except Exception as e:
            logger.error(f"Deserialization scan error: {str(e)}")

    def _scan_cookies(self) -> None:
        """쿠키에서 직렬화된 데이터 확인"""
        try:
            if not self.response:
                return

            cookies = self.response.cookies

            for cookie in cookies:
                value = cookie.value

                # Base64 디코딩 시도
                try:
                    decoded = base64.b64decode(value)
                    decoded_str = decoded.decode('utf-8', errors='ignore')

                    # Pickle magic bytes 확인
                    if decoded.startswith(b'\x80') or 'pickle' in decoded_str.lower():
                        self.vulnerabilities.append({
                            'type': 'Insecure Deserialization (Cookie)',
                            'severity': 'critical',
                            'cookie_name': cookie.name,
                            'description': f'쿠키 "{cookie.name}"에 직렬화된 데이터가 포함되어 있습니다.',
                            'recommendation': 'JWT나 서명된 토큰을 사용하고, 직렬화된 객체를 쿠키에 저장하지 마세요.'
                        })

                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Deserialization cookie scan error: {str(e)}")

    def _scan_serialization_functions(self) -> None:
        """직렬화 함수 사용 확인"""
        try:
            found = []

            for pattern, name, severity in self.SERIALIZATION_INDICATORS:
                if re.search(pattern, self.html_content, re.IGNORECASE):
                    found.append({'pattern': pattern, 'name': name, 'severity': severity})

            if found:
                self.vulnerabilities.append({
                    'type': 'Unsafe Deserialization Functions',
                    'severity': found[0]['severity'],
                    'functions': [f['name'] for f in found[:3]],
                    'description': f'{len(found)}개의 안전하지 않은 역직렬화 함수가 발견되었습니다.',
                    'recommendation': '안전한 직렬화 방식(JSON 등)을 사용하고, 신뢰할 수 없는 데이터를 역직렬화하지 마세요.'
                })

        except Exception as e:
            logger.debug(f"Serialization function scan error: {str(e)}")

    def _scan_encoded_data(self) -> None:
        """인코딩된 직렬화 데이터 탐지"""
        try:
            # URL이나 HTML에서 Base64로 인코딩된 것으로 보이는 긴 문자열 찾기
            base64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
            matches = re.findall(base64_pattern, self.html_content)

            suspicious_count = 0
            for match in matches[:10]:  # 최대 10개만 검사
                try:
                    decoded = base64.b64decode(match)
                    # Pickle, Java serialization 등의 magic bytes 확인
                    if decoded.startswith((b'\x80', b'\xac\xed', b'rO0')):
                        suspicious_count += 1
                except Exception:
                    pass

            if suspicious_count > 0:
                self.vulnerabilities.append({
                    'type': 'Serialized Data in Response',
                    'severity': 'high',
                    'count': suspicious_count,
                    'description': f'{suspicious_count}개의 직렬화된 데이터가 응답에서 발견되었습니다.',
                    'recommendation': '직렬화된 객체 대신 JSON을 사용하세요.'
                })

        except Exception as e:
            logger.debug(f"Encoded data scan error: {str(e)}")

    def _build_result(self) -> Dict[str, Any]:
        """스캔 결과 빌드"""
        result = super()._build_result()
        result.update({
            'vulnerabilities': self.vulnerabilities,
            'total': len(self.vulnerabilities),
            'has_deserialization': len(self.vulnerabilities) > 0,
            'scanner_id': self.metadata['id']
        })
        return result


class JWTSecurityScanner(BaseScanner):
    """JWT 보안 취약점 스캐너"""

    metadata = {
        'id': 'jwt_security',
        'name': 'JWT 보안 검사',
        'icon': '🔑',
        'description': 'JSON Web Token 보안 취약점 탐지',
        'weight': 2,
        'field': 'jwt_vulnerabilities'
    }

    def __init__(self, response: requests.Response = None, html_content: str = None, **kwargs):
        """JWTSecurityScanner 초기화"""
        super().__init__(url='', **kwargs)
        self.response = response
        self.html_content = html_content or ''
        self.vulnerabilities = []
        self.tokens: List[Tuple[str, str]] = []

    def _execute_scan(self) -> None:
        """JWT 보안 스캔 실행"""
        try:
            # 1. JWT 토큰 탐지
            self._find_jwt_tokens()

            # 2. 각 토큰 분석
            for token_info in self.tokens[:5]:  # 최대 5개만 분석
                self._analyze_jwt(token_info)

        except Exception as e:
            logger.error(f"JWT security scan error: {str(e)}")

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


class TemplateInjectionScanner(BaseScanner):
    """SSTI (Server-Side Template Injection) 취약점 스캐너"""

    metadata = {
        'id': 'template_injection',
        'name': '템플릿 주입 스캔',
        'icon': '📝',
        'description': 'Server-Side Template Injection 취약점 탐지',
        'weight': 2,
        'field': 'template_injection'
    }

    TEMPLATE_INDICATORS = [
        # Jinja2
        ('{{', '}}', 'Jinja2/Flask', 'high'),
        ('{%', '%}', 'Jinja2/Django', 'high'),

        # Other templates
        ('${', '}', 'Freemarker/Velocity', 'high'),
        ('#{', '}', 'JSF/EL', 'medium'),
        ('<%', '%>', 'JSP/ERB', 'high'),
    ]

    SSTI_PARAMS = [
        'template', 'tmpl', 'view', 'layout', 'page', 'content',
        'text', 'body', 'message', 'name', 'title'
    ]

    def __init__(self, url: str = '', html_content: str = None, **kwargs):
        """TemplateInjectionScanner 초기화"""
        super().__init__(url=url, **kwargs)
        self.html_content = html_content or ''
        self.vulnerabilities = []

    def _execute_scan(self) -> None:
        """SSTI 스캔 실행"""
        try:
            # 1. HTML에서 템플릿 구문 탐지
            if self.html_content:
                self._detect_template_syntax()

            # 2. URL 파라미터에서 SSTI 가능성
            if self.url:
                self._scan_url_parameters()

        except Exception as e:
            logger.error(f"Template injection scan error: {str(e)}")

    def _detect_template_syntax(self) -> None:
        """템플릿 구문 탐지"""
        try:
            for open_tag, close_tag, engine, severity in self.TEMPLATE_INDICATORS:
                pattern = re.escape(open_tag) + r'.*?' + re.escape(close_tag)
                matches = re.findall(pattern, self.html_content, re.DOTALL)

                if matches:
                    self.vulnerabilities.append({
                        'type': 'Template Engine Detected',
                        'severity': severity,
                        'engine': engine,
                        'examples': matches[:3],
                        'description': f'{engine} 템플릿 엔진이 감지되었습니다. SSTI에 취약할 수 있습니다.',
                        'attack_example': f'{open_tag}7*7{close_tag}',
                        'recommendation': '사용자 입력을 템플릿으로 렌더링하지 마세요. 샌드박스를 활성화하세요.'
                    })

        except Exception as e:
            logger.debug(f"Template syntax detection error: {str(e)}")

    def _scan_url_parameters(self) -> None:
        """URL 파라미터에서 SSTI 검사"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param_name in params.keys():
                if param_name.lower() in self.SSTI_PARAMS:
                    self.vulnerabilities.append({
                        'type': 'SSTI (Potential)',
                        'severity': 'critical',
                        'parameter': param_name,
                        'description': f'파라미터 "{param_name}"가 템플릿 주입에 취약할 수 있습니다.',
                        'attack_examples': [
                            '{{7*7}}',
                            '{{config}}',
                            '{{self.__dict__}}',
                            "${7*7}",
                        ],
                        'recommendation': '사용자 입력을 템플릿으로 처리하지 말고, 데이터로만 사용하세요.'
                    })

        except Exception as e:
            logger.debug(f"SSTI URL parameter scan error: {str(e)}")

    def _build_result(self) -> Dict[str, Any]:
        """스캔 결과 빌드"""
        result = super()._build_result()
        result.update({
            'vulnerabilities': self.vulnerabilities,
            'total': len(self.vulnerabilities),
            'has_ssti': len(self.vulnerabilities) > 0,
            'scanner_id': self.metadata['id']
        })
        return result


class NoSQLInjectionScanner(BaseScanner):
    """NoSQL Injection 취약점 스캐너"""

    metadata = {
        'id': 'nosql_injection',
        'name': 'NoSQL Injection 스캔',
        'icon': '🗄️',
        'description': 'NoSQL 데이터베이스 주입 취약점 탐지',
        'weight': 2,
        'field': 'nosql_injection'
    }

    NOSQL_INDICATORS = [
        'mongodb', 'mongo', 'couchdb', 'redis', 'cassandra',
        'dynamodb', 'elasticsearch', 'firebase'
    ]

    NOSQL_PARAMS = [
        'id', '_id', 'user', 'username', 'email', 'search', 'query',
        'filter', 'where', 'find', 'match', 'selector'
    ]

    def __init__(self, url: str = '', response: requests.Response = None,
                 html_content: str = None, **kwargs):
        """NoSQLInjectionScanner 초기화"""
        super().__init__(url=url, **kwargs)
        self.response = response
        self.html_content = html_content or ''
        self.vulnerabilities = []
        self.uses_nosql = False

    def _execute_scan(self) -> None:
        """NoSQL Injection 스캔 실행"""
        try:
            # 1. NoSQL 데이터베이스 사용 탐지
            self._detect_nosql()

            # 2. URL 파라미터 검사
            if self.uses_nosql and self.url:
                self._scan_url_parameters()

            # 3. JSON 입력 검사
            if self.uses_nosql and self.response:
                self._scan_json_inputs()

        except Exception as e:
            logger.error(f"NoSQL injection scan error: {str(e)}")

    def _detect_nosql(self) -> None:
        """NoSQL 데이터베이스 사용 탐지"""
        try:
            # 응답 헤더나 HTML에서 NoSQL 관련 키워드 찾기
            content_lower = self.html_content.lower()
            if self.response:
                content_lower += str(self.response.headers).lower()

            for indicator in self.NOSQL_INDICATORS:
                if indicator in content_lower:
                    self.uses_nosql = True
                    break

        except Exception as e:
            logger.debug(f"NoSQL detection error: {str(e)}")

    def _scan_url_parameters(self) -> None:
        """URL 파라미터에서 NoSQL Injection 검사"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param_name, param_values in params.items():
                if param_name.lower() in self.NOSQL_PARAMS:
                    param_value = param_values[0] if param_values else ''

                    # JSON 형식이면 더 위험
                    is_json = param_value.startswith(('{', '['))

                    self.vulnerabilities.append({
                        'type': 'NoSQL Injection (Potential)',
                        'severity': 'critical' if is_json else 'high',
                        'parameter': param_name,
                        'value_type': 'JSON' if is_json else 'string',
                        'description': f'파라미터 "{param_name}"가 NoSQL Injection에 취약할 수 있습니다.',
                        'attack_examples': [
                            '{"$ne": null}',
                            '{"$gt": ""}',
                            '{"username": {"$regex": "^admin"}}',
                            '[$ne]=1',
                        ],
                        'recommendation': '입력값을 타입 체크하고, $where, $regex 등 위험한 연산자를 차단하세요.'
                    })

        except Exception as e:
            logger.debug(f"NoSQL URL parameter scan error: {str(e)}")

    def _scan_json_inputs(self) -> None:
        """JSON 입력 필드 검사"""
        try:
            # Content-Type이 JSON이면
            content_type = self.response.headers.get('Content-Type', '')

            if 'application/json' in content_type:
                self.vulnerabilities.append({
                    'type': 'NoSQL JSON API',
                    'severity': 'medium',
                    'description': 'API가 JSON을 받습니다. NoSQL Injection에 주의해야 합니다.',
                    'recommendation': '모든 JSON 입력을 검증하고, MongoDB 연산자($ne, $gt 등)를 필터링하세요.'
                })

        except Exception as e:
            logger.debug(f"NoSQL JSON input scan error: {str(e)}")

    def _build_result(self) -> Dict[str, Any]:
        """스캔 결과 빌드"""
        result = super()._build_result()
        result.update({
            'vulnerabilities': self.vulnerabilities,
            'total': len(self.vulnerabilities),
            'has_nosql_injection': len(self.vulnerabilities) > 0,
            'uses_nosql': self.uses_nosql,
            'scanner_id': self.metadata['id']
        })
        return result


class SSLTLSDeepScanner(BaseScanner):
    """SSL/TLS 심층 보안 검사 스캐너"""

    metadata = {
        'id': 'ssl_tls_deep',
        'name': 'SSL/TLS 심층 검사',
        'icon': '🔐',
        'description': 'SSL/TLS 설정 및 인증서 심층 분석',
        'weight': 2,
        'field': 'ssl_tls_vulnerabilities'
    }

    WEAK_CIPHERS = [
        'DES', '3DES', 'RC4', 'MD5', 'NULL', 'anon', 'EXPORT'
    ]

    def __init__(self, url: str, **kwargs):
        """SSLTLSDeepScanner 초기화"""
        super().__init__(url=url, **kwargs)
        self.vulnerabilities = []

    def _execute_scan(self) -> None:
        """SSL/TLS 심층 스캔 실행"""
        try:
            parsed = urlparse(self.url)

            if parsed.scheme != 'https':
                self.vulnerabilities.append({
                    'type': 'No HTTPS',
                    'severity': 'critical',
                    'description': 'HTTPS를 사용하지 않습니다.',
                    'recommendation': 'HTTPS를 활성화하고 HTTP를 HTTPS로 리다이렉트하세요.'
                })
                return

            hostname = parsed.hostname
            port = parsed.port or 443

            # SSL/TLS 연결 정보 가져오기
            self._check_ssl_version(hostname, port)
            self._check_certificate(hostname, port)

        except Exception as e:
            logger.error(f"SSL/TLS scan error: {str(e)}")

    def _check_ssl_version(self, hostname: str, port: int) -> None:
        """SSL/TLS 버전 및 Cipher Suite 검사"""
        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()

                    # TLS 버전 검사
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self.vulnerabilities.append({
                            'type': 'Weak TLS Version',
                            'severity': 'high',
                            'version': version,
                            'description': f'약한 TLS 버전을 사용합니다: {version}',
                            'recommendation': 'TLS 1.2 이상만 사용하도록 설정하세요.'
                        })

                    # Cipher Suite 검사
                    if cipher:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.upper() for weak in self.WEAK_CIPHERS):
                            self.vulnerabilities.append({
                                'type': 'Weak Cipher Suite',
                                'severity': 'high',
                                'cipher': cipher_name,
                                'description': f'약한 암호화 알고리즘을 사용합니다: {cipher_name}',
                                'recommendation': '강력한 cipher suite만 허용하도록 설정하세요.'
                            })

        except Exception as e:
            logger.debug(f"SSL version check error: {str(e)}")

    def _check_certificate(self, hostname: str, port: int) -> None:
        """SSL 인증서 검사"""
        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    if not cert:
                        self.vulnerabilities.append({
                            'type': 'No Certificate',
                            'severity': 'critical',
                            'description': 'SSL 인증서를 가져올 수 없습니다.',
                            'recommendation': '유효한 SSL 인증서를 설치하세요.'
                        })
                        return

                    # 인증서 만료일 검사
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days

                        if days_until_expiry < 0:
                            self.vulnerabilities.append({
                                'type': 'Certificate Expired',
                                'severity': 'critical',
                                'expiry_date': not_after,
                                'description': 'SSL 인증서가 만료되었습니다.',
                                'recommendation': '인증서를 갱신하세요.'
                            })
                        elif days_until_expiry < 30:
                            self.vulnerabilities.append({
                                'type': 'Certificate Expiring Soon',
                                'severity': 'medium',
                                'expiry_date': not_after,
                                'days_remaining': days_until_expiry,
                                'description': f'SSL 인증서가 {days_until_expiry}일 후 만료됩니다.',
                                'recommendation': '인증서를 갱신하세요.'
                            })

        except ssl.SSLError as e:
            self.vulnerabilities.append({
                'type': 'SSL Error',
                'severity': 'high',
                'description': f'SSL 연결 오류: {str(e)}',
                'recommendation': 'SSL 설정을 점검하세요.'
            })
        except Exception as e:
            logger.debug(f"Certificate check error: {str(e)}")

    def _build_result(self) -> Dict[str, Any]:
        """스캔 결과 빌드"""
        result = super()._build_result()
        result.update({
            'vulnerabilities': self.vulnerabilities,
            'total': len(self.vulnerabilities),
            'has_ssl_issues': len(self.vulnerabilities) > 0,
            'scanner_id': self.metadata['id']
        })
        return result