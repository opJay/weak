"""
Batch 6: API 및 인증/인가 보안 스캐너 리팩토링
RESTAPISecurityScanner, GraphQLSecurityScanner, OAuthSecurityScanner,
SessionSecurityScanner, PasswordPolicyScanner, RateLimitingScanner,
LDAPInjectionScanner, AuthorizationScanner
"""

import re
import json
import time
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
import requests
from requests.exceptions import RequestException

from .base import BaseScanner

logger = logging.getLogger('scanner')


class RESTAPISecurityScanner(BaseScanner):
    """REST API 보안 취약점 스캐너 - 리팩토링 버전"""

    metadata = {
        'id': 'rest_api_security',
        'name': 'REST API 보안 검사',
        'icon': '🔌',
        'description': 'REST API 보안 취약점 탐지 (Rate Limit, Mass Assignment, Data Exposure)',
        'weight': 2,
        'field': 'rest_api_vulnerabilities'
    }

    API_INDICATORS = [
        '/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql',
        'application/json', 'application/xml'
    ]

    SENSITIVE_ENDPOINTS = [
        '/api/users', '/api/admin', '/api/config', '/api/settings',
        '/api/internal', '/api/debug', '/api/test'
    ]

    def __init__(self, url: str = None, response: requests.Response = None,
                 html_content: str = None, **kwargs):
        """
        Args:
            url: 스캔 대상 URL
            response: HTTP 응답 객체
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', response=response,
                        html_content=html_content, **kwargs)

    def _execute_scan(self) -> None:
        """REST API 보안 스캔 실행"""
        # API 엔드포인트 탐지
        if not self._detect_api():
            self.vulnerabilities = []
            return

        # 각 보안 검사 수행
        self._check_rate_limiting()
        self._check_excessive_data_exposure()
        self._check_mass_assignment()
        self._check_api_versioning()
        self._check_sensitive_endpoints()

    def _detect_api(self) -> bool:
        """API 사용 여부 탐지"""
        # URL 경로 검사
        if self.url and any(indicator in self.url.lower()
                           for indicator in self.API_INDICATORS[:6]):
            return True

        # Content-Type 검사
        if self.response and hasattr(self.response, 'headers'):
            content_type = self.response.headers.get('Content-Type', '')
            if any(indicator in content_type.lower()
                   for indicator in self.API_INDICATORS[6:]):
                return True

        # HTML에서 API 호출 패턴 찾기
        if self.html_content:
            api_patterns = [
                r'fetch\([\'"`]/api/',
                r'axios\.',
                r'XMLHttpRequest',
                r'ajax\('
            ]
            for pattern in api_patterns:
                if re.search(pattern, self.html_content):
                    return True

        return False

    def _check_rate_limiting(self) -> None:
        """Rate Limiting 검사"""
        if not self.response or not hasattr(self.response, 'headers'):
            return

        headers = self.response.headers
        rate_limit_headers = [
            'X-Rate-Limit-Limit',
            'X-RateLimit-Limit',
            'RateLimit-Limit'
        ]

        has_rate_limit = any(header in headers for header in rate_limit_headers)

        if not has_rate_limit:
            self.vulnerabilities.append({
                'type': 'Missing Rate Limiting',
                'severity': 'high',
                'description': 'API에 Rate Limiting이 설정되지 않았습니다.',
                'recommendation': 'API에 Rate Limiting을 구현하여 과도한 요청을 방지하세요.'
            })

    def _check_excessive_data_exposure(self) -> None:
        """과도한 데이터 노출 검사"""
        if not self.response:
            return

        try:
            # JSON 응답 분석
            if hasattr(self.response, 'text'):
                response_text = self.response.text
                if response_text.startswith('{') or response_text.startswith('['):
                    data = json.loads(response_text)

                    # 민감한 필드 검사
                    sensitive_fields = [
                        'password', 'secret', 'token', 'apikey', 'api_key',
                        'private_key', 'ssn', 'credit_card'
                    ]

                    def check_sensitive(obj, path=''):
                        if isinstance(obj, dict):
                            for key, value in obj.items():
                                lower_key = key.lower()
                                if any(field in lower_key for field in sensitive_fields):
                                    self.vulnerabilities.append({
                                        'type': 'Excessive Data Exposure',
                                        'severity': 'critical',
                                        'field': f'{path}.{key}' if path else key,
                                        'description': f'민감한 필드 "{key}"가 API 응답에 포함되어 있습니다.',
                                        'recommendation': '민감한 정보는 API 응답에서 제외하거나 마스킹 처리하세요.'
                                    })
                                check_sensitive(value, f'{path}.{key}' if path else key)
                        elif isinstance(obj, list):
                            for i, item in enumerate(obj[:3]):  # 처음 3개만 검사
                                check_sensitive(item, f'{path}[{i}]')

                    check_sensitive(data)
        except Exception:
            pass

    def _check_mass_assignment(self) -> None:
        """Mass Assignment 취약점 검사"""
        if not self.html_content:
            return

        # PUT/PATCH 메서드 사용 패턴 찾기
        patterns = [
            r'method\s*[:=]\s*[\'"`]PUT[\'"`]',
            r'method\s*[:=]\s*[\'"`]PATCH[\'"`]',
            r'\.put\(',
            r'\.patch\('
        ]

        for pattern in patterns:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'Potential Mass Assignment',
                    'severity': 'medium',
                    'description': 'PUT/PATCH 메서드 사용이 감지되었습니다. Mass Assignment 취약점 가능성이 있습니다.',
                    'recommendation': 'DTO나 화이트리스트를 사용하여 허용된 필드만 업데이트하도록 제한하세요.'
                })
                break

    def _check_api_versioning(self) -> None:
        """API 버전 관리 검사"""
        if not self.url:
            return

        # 버전 패턴 검사
        version_patterns = [r'/v\d+/', r'/api/v\d+/']
        has_version = any(re.search(pattern, self.url) for pattern in version_patterns)

        if not has_version and '/api/' in self.url:
            self.vulnerabilities.append({
                'type': 'Missing API Versioning',
                'severity': 'low',
                'description': 'API 버전 관리가 구현되지 않았습니다.',
                'recommendation': 'API 버전을 명시하여 하위 호환성을 유지하세요.'
            })

    def _check_sensitive_endpoints(self) -> None:
        """민감한 엔드포인트 검사"""
        if not self.url:
            return

        for endpoint in self.SENSITIVE_ENDPOINTS:
            if endpoint in self.url.lower():
                self.vulnerabilities.append({
                    'type': 'Sensitive Endpoint Exposed',
                    'severity': 'high',
                    'endpoint': endpoint,
                    'description': f'민감한 엔드포인트 "{endpoint}"가 노출되어 있습니다.',
                    'recommendation': '적절한 인증과 권한 검사를 구현하세요.'
                })


class GraphQLSecurityScanner(BaseScanner):
    """GraphQL 보안 취약점 스캐너 - 리팩토링 버전"""

    metadata = {
        'id': 'graphql_security',
        'name': 'GraphQL 보안 검사',
        'icon': '📊',
        'description': 'GraphQL 취약점 탐지 (Introspection, Query Depth, Batch Attack)',
        'weight': 2,
        'field': 'graphql_vulnerabilities'
    }

    def __init__(self, url: str = None, response: requests.Response = None,
                 html_content: str = None, **kwargs):
        """
        Args:
            url: 스캔 대상 URL
            response: HTTP 응답 객체
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', response=response,
                        html_content=html_content, **kwargs)

    def _execute_scan(self) -> None:
        """GraphQL 보안 스캔 실행"""
        # GraphQL 사용 여부 탐지
        if not self._detect_graphql():
            self.vulnerabilities = []
            return

        # 각 보안 검사 수행
        self._check_introspection()
        self._check_query_depth()
        self._check_batch_queries()
        self._check_query_complexity()

    def _detect_graphql(self) -> bool:
        """GraphQL 사용 여부 탐지"""
        # URL에 graphql 포함
        if self.url and 'graphql' in self.url.lower():
            return True

        # HTML에서 GraphQL 패턴 찾기
        if self.html_content:
            graphql_patterns = [
                r'__typename',
                r'query\s+{',
                r'mutation\s+{',
                r'subscription\s+{',
                r'graphql',
                r'apollo'
            ]
            for pattern in graphql_patterns:
                if re.search(pattern, self.html_content, re.IGNORECASE):
                    return True

        return False

    def _check_introspection(self) -> None:
        """Introspection 활성화 검사"""
        if self.html_content and '__schema' in self.html_content:
            self.vulnerabilities.append({
                'type': 'GraphQL Introspection Enabled',
                'severity': 'medium',
                'description': 'GraphQL Introspection이 활성화되어 있어 스키마 정보가 노출됩니다.',
                'recommendation': '프로덕션 환경에서는 Introspection을 비활성화하세요.'
            })

    def _check_query_depth(self) -> None:
        """Query Depth 제한 검사"""
        if self.html_content:
            # 깊은 중첩 쿼리 패턴 찾기
            nested_pattern = r'{\s*\w+\s*{\s*\w+\s*{\s*\w+\s*{'
            if re.search(nested_pattern, self.html_content):
                self.vulnerabilities.append({
                    'type': 'Deep Query Nesting',
                    'severity': 'medium',
                    'description': '깊게 중첩된 GraphQL 쿼리가 감지되었습니다.',
                    'recommendation': 'Query Depth 제한을 구현하여 DoS 공격을 방지하세요.'
                })

    def _check_batch_queries(self) -> None:
        """Batch Query 공격 가능성 검사"""
        if self.html_content:
            # 배열 형태의 쿼리 패턴
            batch_pattern = r'\[\s*{.*?query.*?}\s*,\s*{.*?query.*?}\s*\]'
            if re.search(batch_pattern, self.html_content, re.DOTALL):
                self.vulnerabilities.append({
                    'type': 'Batch Query Attack Possible',
                    'severity': 'medium',
                    'description': 'Batch Query가 허용되어 있어 DoS 공격 위험이 있습니다.',
                    'recommendation': 'Batch Query 크기 제한을 구현하세요.'
                })

    def _check_query_complexity(self) -> None:
        """Query Complexity 제한 검사"""
        if not self.response or not hasattr(self.response, 'headers'):
            return

        # Complexity 관련 헤더 확인
        headers = self.response.headers
        if 'X-Query-Complexity' not in headers:
            self.vulnerabilities.append({
                'type': 'Missing Query Complexity Limits',
                'severity': 'low',
                'description': 'Query Complexity 제한이 설정되지 않았습니다.',
                'recommendation': 'Query Complexity 분석 및 제한을 구현하세요.'
            })


class OAuthSecurityScanner(BaseScanner):
    """OAuth 보안 취약점 스캐너 - 리팩토링 버전"""

    metadata = {
        'id': 'oauth_security',
        'name': 'OAuth 보안 검사',
        'icon': '🔑',
        'description': 'OAuth 인증 취약점 탐지 (CSRF, Open Redirect, Code Reuse)',
        'weight': 2,
        'field': 'oauth_vulnerabilities'
    }

    def __init__(self, url: str = None, response: requests.Response = None,
                 html_content: str = None, **kwargs):
        """
        Args:
            url: 스캔 대상 URL
            response: HTTP 응답 객체
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', response=response,
                        html_content=html_content, **kwargs)

    def _execute_scan(self) -> None:
        """OAuth 보안 스캔 실행"""
        # OAuth 사용 여부 탐지
        if not self._detect_oauth():
            self.vulnerabilities = []
            return

        # 각 보안 검사 수행
        self._check_state_parameter()
        self._check_redirect_uri_validation()
        self._check_token_exposure()
        self._check_implicit_flow()

    def _detect_oauth(self) -> bool:
        """OAuth 사용 여부 탐지"""
        # URL 파라미터 검사
        if self.url:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)
            oauth_params = ['client_id', 'redirect_uri', 'response_type', 'scope', 'state']
            if any(param in params for param in oauth_params):
                return True

        # HTML에서 OAuth 패턴 찾기
        if self.html_content:
            oauth_patterns = [
                r'oauth',
                r'authorization_code',
                r'client_id',
                r'redirect_uri',
                r'/authorize',
                r'/token'
            ]
            for pattern in oauth_patterns:
                if re.search(pattern, self.html_content, re.IGNORECASE):
                    return True

        return False

    def _check_state_parameter(self) -> None:
        """State 파라미터 CSRF 보호 검사"""
        if self.url:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            # OAuth flow에서 state 파라미터 누락
            if 'response_type' in params and 'state' not in params:
                self.vulnerabilities.append({
                    'type': 'Missing OAuth State Parameter',
                    'severity': 'high',
                    'description': 'OAuth state 파라미터가 없어 CSRF 공격에 취약합니다.',
                    'recommendation': '예측 불가능한 state 파라미터를 생성하고 검증하세요.'
                })

    def _check_redirect_uri_validation(self) -> None:
        """Redirect URI 검증 검사"""
        if self.url:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            if 'redirect_uri' in params:
                redirect_uri = params['redirect_uri'][0]

                # Open Redirect 가능성
                if redirect_uri.startswith('//') or redirect_uri.startswith('http'):
                    self.vulnerabilities.append({
                        'type': 'OAuth Open Redirect',
                        'severity': 'medium',
                        'description': 'redirect_uri가 외부 URL을 허용할 수 있습니다.',
                        'recommendation': '화이트리스트 방식으로 redirect_uri를 검증하세요.'
                    })

    def _check_token_exposure(self) -> None:
        """토큰 노출 검사"""
        if self.html_content:
            # URL Fragment에 토큰 노출 패턴
            token_patterns = [
                r'#access_token',
                r'#token',
                r'location\.hash',
                r'access_token'
            ]

            for pattern in token_patterns:
                if re.search(pattern, self.html_content, re.IGNORECASE):
                    self.vulnerabilities.append({
                        'type': 'Token Exposure in URL',
                        'severity': 'high',
                        'description': '액세스 토큰이 URL fragment에 노출될 수 있습니다.',
                        'recommendation': 'Authorization Code flow를 사용하고 토큰은 백엔드에서 처리하세요.'
                    })
                    break

    def _check_implicit_flow(self) -> None:
        """Implicit Flow 사용 검사"""
        if self.url:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            if params.get('response_type') == ['token']:
                self.vulnerabilities.append({
                    'type': 'Implicit Flow Usage',
                    'severity': 'medium',
                    'description': 'Implicit Flow는 보안상 권장되지 않습니다.',
                    'recommendation': 'PKCE를 사용한 Authorization Code flow로 마이그레이션하세요.'
                })


class SessionSecurityScanner(BaseScanner):
    """세션 보안 취약점 스캐너 - 리팩토링 버전"""

    metadata = {
        'id': 'session_security',
        'name': '세션 보안 검사',
        'icon': '🎫',
        'description': '세션 관리 취약점 탐지 (Session Fixation, Hijacking)',
        'weight': 1.5,
        'field': 'session_vulnerabilities'
    }

    def __init__(self, url: str = None, response: requests.Response = None,
                 html_content: str = None, **kwargs):
        """
        Args:
            url: 스캔 대상 URL
            response: HTTP 응답 객체
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', response=response,
                        html_content=html_content, **kwargs)

    def _execute_scan(self) -> None:
        """세션 보안 스캔 실행"""
        self._check_session_cookie_security()
        self._check_session_fixation()
        self._check_session_timeout()
        self._check_concurrent_sessions()

    def _check_session_cookie_security(self) -> None:
        """세션 쿠키 보안 설정 검사"""
        if not self.response or not hasattr(self.response, 'cookies'):
            return

        for cookie_name, cookie in self.response.cookies.items():
            # 세션 쿠키 식별
            if 'session' in cookie_name.lower() or 'sid' in cookie_name.lower():
                # HttpOnly 플래그 검사
                if not cookie.get('httponly'):
                    self.vulnerabilities.append({
                        'type': 'Session Cookie Missing HttpOnly',
                        'severity': 'high',
                        'cookie': cookie_name,
                        'description': f'세션 쿠키 "{cookie_name}"에 HttpOnly 플래그가 없습니다.',
                        'recommendation': 'HttpOnly 플래그를 설정하여 XSS 공격을 방지하세요.'
                    })

                # Secure 플래그 검사 (HTTPS인 경우)
                if self.url and self.url.startswith('https') and not cookie.get('secure'):
                    self.vulnerabilities.append({
                        'type': 'Session Cookie Missing Secure Flag',
                        'severity': 'medium',
                        'cookie': cookie_name,
                        'description': f'세션 쿠키 "{cookie_name}"에 Secure 플래그가 없습니다.',
                        'recommendation': 'Secure 플래그를 설정하여 HTTPS에서만 전송되도록 하세요.'
                    })

    def _check_session_fixation(self) -> None:
        """Session Fixation 취약점 검사"""
        if self.url:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            # URL에 세션 ID 전달
            session_params = ['sessionid', 'sid', 'session', 'phpsessid', 'jsessionid']
            for param in session_params:
                if param in params:
                    self.vulnerabilities.append({
                        'type': 'Session ID in URL',
                        'severity': 'high',
                        'parameter': param,
                        'description': f'세션 ID가 URL 파라미터 "{param}"에 노출되어 있습니다.',
                        'recommendation': '세션 ID는 쿠키를 통해서만 전달하세요.'
                    })

    def _check_session_timeout(self) -> None:
        """세션 타임아웃 설정 검사"""
        if self.html_content:
            # 자동 로그아웃 관련 스크립트 검색
            timeout_patterns = [
                r'setTimeout.*logout',
                r'session.*timeout',
                r'idle.*timeout'
            ]

            has_timeout = any(re.search(pattern, self.html_content, re.IGNORECASE)
                            for pattern in timeout_patterns)

            if not has_timeout:
                self.vulnerabilities.append({
                    'type': 'Missing Session Timeout',
                    'severity': 'low',
                    'description': '세션 타임아웃이 구현되지 않은 것으로 보입니다.',
                    'recommendation': '적절한 세션 타임아웃을 구현하세요.'
                })

    def _check_concurrent_sessions(self) -> None:
        """동시 세션 제한 검사"""
        # HTML에서 동시 세션 제한 관련 패턴 검색
        if self.html_content:
            concurrent_patterns = [
                r'concurrent.*session',
                r'multiple.*login',
                r'already.*logged'
            ]

            has_limit = any(re.search(pattern, self.html_content, re.IGNORECASE)
                          for pattern in concurrent_patterns)

            if not has_limit:
                self.vulnerabilities.append({
                    'type': 'No Concurrent Session Control',
                    'severity': 'low',
                    'description': '동시 세션 제한이 구현되지 않은 것으로 보입니다.',
                    'recommendation': '동시 로그인 세션 수를 제한하세요.'
                })


class PasswordPolicyScanner(BaseScanner):
    """비밀번호 정책 검사 스캐너 - 리팩토링 버전"""

    metadata = {
        'id': 'password_policy',
        'name': '비밀번호 정책 검사',
        'icon': '🔐',
        'description': '비밀번호 정책 검사 (복잡도, Brute Force 방어)',
        'weight': 1,
        'field': 'password_policy'
    }

    def __init__(self, url: str = None, response: requests.Response = None,
                 html_content: str = None, **kwargs):
        """
        Args:
            url: 스캔 대상 URL
            response: HTTP 응답 객체
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', response=response,
                        html_content=html_content, **kwargs)

    def _execute_scan(self) -> None:
        """비밀번호 정책 스캔 실행"""
        self._check_password_fields()
        self._check_password_complexity()
        self._check_brute_force_protection()
        self._check_password_reset()

    def _check_password_fields(self) -> None:
        """비밀번호 입력 필드 검사"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')
        password_fields = soup.find_all('input', {'type': 'password'})

        for field in password_fields:
            # 자동완성 허용 검사
            if field.get('autocomplete') != 'off':
                self.vulnerabilities.append({
                    'type': 'Password Autocomplete Enabled',
                    'severity': 'low',
                    'field': field.get('name', 'unknown'),
                    'description': '비밀번호 필드에 자동완성이 활성화되어 있습니다.',
                    'recommendation': 'autocomplete="off" 속성을 추가하세요.'
                })

            # 최소 길이 검사
            minlength = field.get('minlength')
            if not minlength or int(minlength) < 8:
                self.vulnerabilities.append({
                    'type': 'Weak Password Length',
                    'severity': 'medium',
                    'field': field.get('name', 'unknown'),
                    'description': '비밀번호 최소 길이가 8자 미만입니다.',
                    'recommendation': '최소 8자 이상의 비밀번호를 요구하세요.'
                })

    def _check_password_complexity(self) -> None:
        """비밀번호 복잡도 검사"""
        if not self.html_content:
            return

        # 패스워드 검증 패턴 찾기
        complexity_patterns = [
            r'(?=.*[A-Z])',  # 대문자
            r'(?=.*[0-9])',   # 숫자
            r'(?=.*[!@#$%])', # 특수문자
            r'pattern\s*=\s*["\'].*(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])'
        ]

        # 패스워드 필드가 있는지 확인
        has_password_field = re.search(r'type\s*=\s*["\']password["\']', self.html_content)

        if has_password_field:
            has_complexity = any(re.search(pattern, self.html_content)
                               for pattern in complexity_patterns)

            if not has_complexity:
                self.vulnerabilities.append({
                    'type': 'No Password Complexity Requirements',
                    'severity': 'medium',
                    'description': '비밀번호 복잡도 요구사항이 구현되지 않았습니다.',
                    'recommendation': '대/소문자, 숫자, 특수문자를 포함하도록 요구하세요.'
                })

    def _check_brute_force_protection(self) -> None:
        """Brute Force 방어 메커니즘 검사"""
        if not self.html_content:
            return

        # CAPTCHA 또는 Rate Limiting 패턴 찾기
        protection_patterns = [
            r'captcha',
            r'recaptcha',
            r'rate.*limit',
            r'too.*many.*attempts',
            r'account.*locked'
        ]

        has_protection = any(re.search(pattern, self.html_content, re.IGNORECASE)
                           for pattern in protection_patterns)

        if not has_protection:
            self.vulnerabilities.append({
                'type': 'No Brute Force Protection',
                'severity': 'high',
                'description': 'Brute Force 공격 방어 메커니즘이 감지되지 않았습니다.',
                'recommendation': 'CAPTCHA, 계정 잠금, Rate Limiting을 구현하세요.'
            })

    def _check_password_reset(self) -> None:
        """비밀번호 재설정 보안 검사"""
        if not self.html_content:
            return

        # 비밀번호 재설정 관련 패턴
        reset_patterns = [
            r'forgot.*password',
            r'reset.*password',
            r'password.*recovery'
        ]

        has_reset = any(re.search(pattern, self.html_content, re.IGNORECASE)
                       for pattern in reset_patterns)

        if has_reset:
            # 보안 질문 사용 검사
            if re.search(r'security.*question', self.html_content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'Weak Password Reset',
                    'severity': 'medium',
                    'description': '보안 질문은 약한 비밀번호 재설정 방법입니다.',
                    'recommendation': '이메일 또는 SMS 기반의 안전한 재설정 방법을 사용하세요.'
                })


class RateLimitingScanner(BaseScanner):
    """Rate Limiting 검사 스캐너 - 리팩토링 버전"""

    metadata = {
        'id': 'rate_limiting',
        'name': 'Rate Limiting 검사',
        'icon': '⏱️',
        'description': 'Rate Limiting 검사 (API/로그인 제한)',
        'weight': 1,
        'field': 'rate_limiting'
    }

    def __init__(self, url: str = None, response: requests.Response = None,
                 html_content: str = None, **kwargs):
        """
        Args:
            url: 스캔 대상 URL
            response: HTTP 응답 객체
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', response=response,
                        html_content=html_content, **kwargs)

    def _execute_scan(self) -> None:
        """Rate Limiting 스캔 실행"""
        self._check_rate_limit_headers()
        self._check_retry_after()
        self._check_api_rate_limits()
        self._check_login_rate_limits()

    def _check_rate_limit_headers(self) -> None:
        """Rate Limit 헤더 검사"""
        if not self.response or not hasattr(self.response, 'headers'):
            return

        headers = self.response.headers
        rate_headers = [
            'X-Rate-Limit-Limit',
            'X-RateLimit-Limit',
            'RateLimit-Limit'
        ]

        has_rate_limit = any(header in headers for header in rate_headers)

        if not has_rate_limit:
            self.vulnerabilities.append({
                'type': 'Missing Rate Limit Headers',
                'severity': 'medium',
                'description': 'Rate Limiting 헤더가 설정되지 않았습니다.',
                'recommendation': 'X-Rate-Limit-* 헤더를 구현하여 클라이언트에 제한 정보를 제공하세요.'
            })

    def _check_retry_after(self) -> None:
        """Retry-After 헤더 검사"""
        if not self.response or not hasattr(self.response, 'headers'):
            return

        if self.response.status_code == 429 and 'Retry-After' not in self.response.headers:
            self.vulnerabilities.append({
                'type': 'Missing Retry-After Header',
                'severity': 'low',
                'description': '429 응답에 Retry-After 헤더가 없습니다.',
                'recommendation': 'Rate limit 초과 시 Retry-After 헤더를 제공하세요.'
            })

    def _check_api_rate_limits(self) -> None:
        """API Rate Limiting 검사"""
        if self.url and '/api/' in self.url:
            if not self.response or not hasattr(self.response, 'headers'):
                return

            headers = self.response.headers
            if not any('rate' in h.lower() or 'limit' in h.lower() for h in headers):
                self.vulnerabilities.append({
                    'type': 'API Without Rate Limiting',
                    'severity': 'high',
                    'description': 'API 엔드포인트에 Rate Limiting이 구현되지 않았습니다.',
                    'recommendation': 'API에 적절한 Rate Limiting을 구현하세요.'
                })

    def _check_login_rate_limits(self) -> None:
        """로그인 Rate Limiting 검사"""
        if self.html_content:
            # 로그인 폼 탐지
            login_patterns = [
                r'<form.*login',
                r'<input.*type="password"',
                r'action="/login"'
            ]

            is_login_page = any(re.search(pattern, self.html_content, re.IGNORECASE)
                               for pattern in login_patterns)

            if is_login_page:
                # Rate limiting 관련 메시지 검색
                limit_patterns = [
                    r'too many attempts',
                    r'rate limit',
                    r'try again later'
                ]

                has_limit = any(re.search(pattern, self.html_content, re.IGNORECASE)
                              for pattern in limit_patterns)

                if not has_limit:
                    self.vulnerabilities.append({
                        'type': 'Login Without Rate Limiting',
                        'severity': 'high',
                        'description': '로그인 페이지에 Rate Limiting이 구현되지 않았습니다.',
                        'recommendation': '로그인 시도 횟수를 제한하세요.'
                    })


class LDAPInjectionScanner(BaseScanner):
    """LDAP Injection 취약점 스캐너 - 리팩토링 버전"""

    metadata = {
        'id': 'ldap_injection',
        'name': 'LDAP Injection 검사',
        'icon': '📖',
        'description': 'LDAP Injection 취약점 탐지',
        'weight': 1.5,
        'field': 'ldap_injection'
    }

    LDAP_PARAMS = ['username', 'user', 'uid', 'cn', 'email', 'mail', 'dn']
    LDAP_CHARS = ['(', ')', '*', '\\', '/', '|', '&', '=']

    def __init__(self, url: str = None, response: requests.Response = None,
                 html_content: str = None, **kwargs):
        """
        Args:
            url: 스캔 대상 URL
            response: HTTP 응답 객체
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', response=response,
                        html_content=html_content, **kwargs)

    def _execute_scan(self) -> None:
        """LDAP Injection 스캔 실행"""
        self._check_ldap_params()
        self._check_ldap_filters()
        self._check_ldap_authentication()
        self._check_error_messages()

    def _check_ldap_params(self) -> None:
        """LDAP 관련 파라미터 검사"""
        if not self.url:
            return

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        for param_name in params:
            if param_name.lower() in self.LDAP_PARAMS:
                param_value = params[param_name][0]

                # 위험한 LDAP 문자 검사
                if any(char in param_value for char in self.LDAP_CHARS):
                    self.vulnerabilities.append({
                        'type': 'LDAP Injection Characters',
                        'severity': 'high',
                        'parameter': param_name,
                        'description': f'파라미터 "{param_name}"에 LDAP 특수문자가 포함되어 있습니다.',
                        'recommendation': 'LDAP 쿼리 전에 입력값을 이스케이프 처리하세요.'
                    })

    def _check_ldap_filters(self) -> None:
        """LDAP 필터 패턴 검사"""
        if not self.html_content:
            return

        # LDAP 필터 패턴
        filter_patterns = [
            r'\(uid=.*\)',
            r'\(cn=.*\)',
            r'\(&\(.*\)\)',
            r'\(\|.*\)',
            r'objectClass='
        ]

        for pattern in filter_patterns:
            if re.search(pattern, self.html_content):
                self.vulnerabilities.append({
                    'type': 'LDAP Filter Pattern Detected',
                    'severity': 'medium',
                    'pattern': pattern,
                    'description': 'LDAP 필터 패턴이 HTML에 노출되어 있습니다.',
                    'recommendation': 'LDAP 필터를 클라이언트에 노출하지 마세요.'
                })
                break

    def _check_ldap_authentication(self) -> None:
        """LDAP 인증 관련 검사"""
        if not self.html_content:
            return

        # LDAP 인증 관련 패턴
        auth_patterns = [
            r'ldap.*bind',
            r'ldap.*auth',
            r'ldap.*login',
            r'distinguishedName'
        ]

        for pattern in auth_patterns:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'LDAP Authentication Detected',
                    'severity': 'low',
                    'description': 'LDAP 인증이 사용되고 있습니다.',
                    'recommendation': '안전한 LDAP 바인딩과 입력 검증을 구현하세요.'
                })
                break

    def _check_error_messages(self) -> None:
        """LDAP 에러 메시지 노출 검사"""
        if not self.html_content:
            return

        # LDAP 에러 메시지 패턴
        error_patterns = [
            r'LDAP.*error',
            r'Invalid DN syntax',
            r'No such object',
            r'LDAP bind failed'
        ]

        for pattern in error_patterns:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'LDAP Error Message Disclosure',
                    'severity': 'medium',
                    'pattern': pattern,
                    'description': 'LDAP 에러 메시지가 노출되어 있습니다.',
                    'recommendation': '상세한 에러 메시지를 숨기고 일반적인 메시지를 표시하세요.'
                })


class AuthorizationScanner(BaseScanner):
    """인가(Authorization) 취약점 스캐너 - 리팩토링 버전"""

    metadata = {
        'id': 'authorization',
        'name': '인가 검사',
        'icon': '🚪',
        'description': 'BOLA/IDOR (객체/함수 레벨 인가 오류) 탐지',
        'weight': 2,
        'field': 'authorization'
    }

    def __init__(self, url: str = None, response: requests.Response = None,
                 html_content: str = None, **kwargs):
        """
        Args:
            url: 스캔 대상 URL
            response: HTTP 응답 객체
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', response=response,
                        html_content=html_content, **kwargs)

    def _execute_scan(self) -> None:
        """인가 취약점 스캔 실행"""
        self._check_direct_object_references()
        self._check_predictable_ids()
        self._check_admin_interfaces()
        self._check_function_level_access()

    def _check_direct_object_references(self) -> None:
        """직접 객체 참조(IDOR) 검사"""
        if not self.url:
            return

        # URL에서 ID 패턴 찾기
        id_patterns = [
            r'/user/(\d+)',
            r'/profile/(\d+)',
            r'/document/(\d+)',
            r'/order/(\d+)',
            r'[?&]id=(\d+)',
            r'[?&]uid=(\d+)'
        ]

        for pattern in id_patterns:
            match = re.search(pattern, self.url)
            if match:
                id_value = match.group(1)
                if id_value and id_value.isdigit():
                    self.vulnerabilities.append({
                        'type': 'Direct Object Reference',
                        'severity': 'high',
                        'pattern': pattern,
                        'value': id_value,
                        'description': '직접 객체 참조(IDOR) 패턴이 감지되었습니다.',
                        'recommendation': '적절한 권한 검증을 구현하고 UUID 사용을 고려하세요.'
                    })

    def _check_predictable_ids(self) -> None:
        """예측 가능한 ID 패턴 검사"""
        if not self.html_content:
            return

        # 연속적인 ID 패턴 찾기
        sequential_patterns = [
            r'id["\']?\s*[:=]\s*["\']?\d{1,6}["\']?',
            r'userId["\']?\s*[:=]\s*["\']?\d{1,6}["\']?',
            r'recordId["\']?\s*[:=]\s*["\']?\d{1,6}["\']?'
        ]

        for pattern in sequential_patterns:
            matches = re.findall(pattern, self.html_content)
            if len(matches) > 2:
                self.vulnerabilities.append({
                    'type': 'Predictable Resource IDs',
                    'severity': 'medium',
                    'description': '예측 가능한 연속적인 ID가 사용되고 있습니다.',
                    'recommendation': 'UUID나 랜덤한 식별자를 사용하세요.'
                })
                break

    def _check_admin_interfaces(self) -> None:
        """관리자 인터페이스 접근 제어 검사"""
        admin_patterns = [
            '/admin', '/administrator', '/management',
            '/control-panel', '/dashboard/admin'
        ]

        # URL 검사
        if self.url:
            for pattern in admin_patterns:
                if pattern in self.url.lower():
                    # 인증 관련 헤더 확인
                    if self.response and hasattr(self.response, 'status_code'):
                        if self.response.status_code == 200:
                            self.vulnerabilities.append({
                                'type': 'Admin Interface Exposed',
                                'severity': 'critical',
                                'url': self.url,
                                'description': '관리자 인터페이스가 노출되어 있습니다.',
                                'recommendation': '강력한 인증 및 IP 제한을 구현하세요.'
                            })

    def _check_function_level_access(self) -> None:
        """함수 레벨 접근 제어 검사"""
        if not self.html_content:
            return

        # 민감한 기능 패턴
        sensitive_functions = [
            r'deleteUser',
            r'modifyRole',
            r'updatePermission',
            r'exportData',
            r'resetPassword'
        ]

        for func in sensitive_functions:
            if re.search(func, self.html_content, re.IGNORECASE):
                self.vulnerabilities.append({
                    'type': 'Function Level Access Control',
                    'severity': 'high',
                    'function': func,
                    'description': f'민감한 기능 "{func}"이 클라이언트에 노출되어 있습니다.',
                    'recommendation': '서버 측에서 적절한 권한 검증을 구현하세요.'
                })