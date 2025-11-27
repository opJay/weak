"""
API 및 인증/인가 보안 스캐너
현대 웹 애플리케이션의 API 및 인증 보안 취약점 탐지
"""
import re
import json
import time
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger('scanner')


class RESTAPISecurityScanner:
    """REST API 보안 취약점 스캐너"""

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

    def __init__(self, url, response, html_content):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """REST API 보안 스캔"""
        try:
            # 1. API 엔드포인트 탐지
            is_api = self._detect_api()

            if not is_api:
                return {
                    'vulnerabilities': [],
                    'total': 0,
                    'has_api': False,
                    'message': 'REST API 엔드포인트가 감지되지 않았습니다.'
                }

            # 2. Rate Limiting 검사
            self._check_rate_limiting()

            # 3. 과도한 데이터 노출 검사
            self._check_excessive_data_exposure()

            # 4. Mass Assignment 취약점
            self._check_mass_assignment()

            # 5. API 버전 관리
            self._check_api_versioning()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_api': True
            }

        except Exception as e:
            logger.error(f"REST API scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_api': False,
                'error': str(e)
            }

    def _detect_api(self):
        """API 사용 여부 탐지"""
        try:
            # URL 경로 검사
            if any(indicator in self.url.lower() for indicator in self.API_INDICATORS[:6]):
                return True

            # Content-Type 검사
            content_type = self.response.headers.get('Content-Type', '')
            if any(indicator in content_type.lower() for indicator in self.API_INDICATORS[6:]):
                return True

            # HTML에서 API 호출 패턴 찾기
            api_patterns = [
                r'fetch\([\'"`]/api/',
                r'axios\.',
                r'\.get\([\'"`]/api/',
                r'\.post\([\'"`]/api/',
            ]

            for pattern in api_patterns:
                if re.search(pattern, self.html_content, re.IGNORECASE):
                    return True

            return False

        except Exception as e:
            logger.debug(f"API detection error: {str(e)}")
            return False

    def _check_rate_limiting(self):
        """Rate Limiting 검사"""
        try:
            # Rate Limiting 헤더 확인
            rate_limit_headers = [
                'X-RateLimit-Limit',
                'X-Rate-Limit-Limit',
                'RateLimit-Limit',
                'X-RateLimit-Remaining',
            ]

            has_rate_limit = any(header in self.response.headers for header in rate_limit_headers)

            if not has_rate_limit:
                self.vulnerabilities.append({
                    'type': 'Missing Rate Limiting',
                    'severity': 'high',
                    'description': 'API에 Rate Limiting이 설정되지 않았습니다.',
                    'impact': 'Brute Force 공격, DoS 공격에 취약합니다.',
                    'recommendation': 'API에 Rate Limiting을 구현하세요 (예: 분당 100 요청 제한).'
                })

        except Exception as e:
            logger.debug(f"Rate limiting check error: {str(e)}")

    def _check_excessive_data_exposure(self):
        """과도한 데이터 노출 검사"""
        try:
            content_type = self.response.headers.get('Content-Type', '')

            if 'application/json' in content_type:
                try:
                    data = json.loads(self.response.text)

                    # 민감한 필드 검사
                    sensitive_fields = [
                        'password', 'token', 'secret', 'api_key', 'private_key',
                        'ssn', 'credit_card', 'cvv', 'pin', 'salt', 'hash'
                    ]

                    def check_dict(obj, path=''):
                        found = []
                        if isinstance(obj, dict):
                            for key, value in obj.items():
                                current_path = f"{path}.{key}" if path else key
                                if any(field in key.lower() for field in sensitive_fields):
                                    found.append(current_path)
                                if isinstance(value, (dict, list)):
                                    found.extend(check_dict(value, current_path))
                        elif isinstance(obj, list):
                            for i, item in enumerate(obj[:5]):  # 처음 5개만 검사
                                found.extend(check_dict(item, f"{path}[{i}]"))
                        return found

                    exposed_fields = check_dict(data)

                    if exposed_fields:
                        self.vulnerabilities.append({
                            'type': 'Excessive Data Exposure',
                            'severity': 'critical',
                            'fields': exposed_fields[:10],
                            'description': f'API 응답에 민감한 데이터가 노출되고 있습니다: {", ".join(exposed_fields[:3])}',
                            'recommendation': '응답 데이터를 필터링하고 필요한 필드만 반환하세요.'
                        })

                    # 과도한 필드 수 검사
                    def count_fields(obj):
                        if isinstance(obj, dict):
                            return len(obj) + sum(count_fields(v) for v in obj.values())
                        elif isinstance(obj, list):
                            return sum(count_fields(item) for item in obj[:5])
                        return 0

                    field_count = count_fields(data)
                    if field_count > 100:
                        self.vulnerabilities.append({
                            'type': 'API Over-fetching',
                            'severity': 'medium',
                            'field_count': field_count,
                            'description': f'API가 {field_count}개의 필드를 반환합니다. 과도한 데이터 전송이 발생할 수 있습니다.',
                            'recommendation': '필요한 필드만 선택적으로 반환하도록 API를 최적화하세요.'
                        })

                except (json.JSONDecodeError, ValueError):
                    pass

        except Exception as e:
            logger.debug(f"Excessive data exposure check error: {str(e)}")

    def _check_mass_assignment(self):
        """Mass Assignment 취약점 검사"""
        try:
            # POST/PUT 요청을 받는 폼이 있는지 확인
            soup = BeautifulSoup(self.html_content, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                method = form.get('method', 'get').upper()
                if method in ['POST', 'PUT', 'PATCH']:
                    action = form.get('action', '')

                    # API 엔드포인트인지 확인
                    if '/api/' in action.lower() or 'application/json' in self.response.headers.get('Content-Type', ''):
                        self.vulnerabilities.append({
                            'type': 'Mass Assignment (Potential)',
                            'severity': 'high',
                            'endpoint': action or self.url,
                            'method': method,
                            'description': 'API가 모든 입력 필드를 자동으로 객체에 바인딩할 수 있습니다.',
                            'attack_example': '{"role": "admin", "is_active": true}',
                            'recommendation': '허용된 필드만 화이트리스트로 지정하세요 (예: Django의 fields 옵션).'
                        })
                        break

        except Exception as e:
            logger.debug(f"Mass assignment check error: {str(e)}")

    def _check_api_versioning(self):
        """API 버전 관리 검사"""
        try:
            # URL에 버전 정보가 있는지 확인
            has_version = bool(re.search(r'/v\d+/', self.url, re.IGNORECASE))

            if not has_version and '/api/' in self.url.lower():
                self.vulnerabilities.append({
                    'type': 'Missing API Versioning',
                    'severity': 'low',
                    'description': 'API에 버전 정보가 없습니다.',
                    'recommendation': 'API 버전을 URL에 포함하세요 (예: /api/v1/users).'
                })

        except Exception as e:
            logger.debug(f"API versioning check error: {str(e)}")


class GraphQLSecurityScanner:
    """GraphQL 보안 취약점 스캐너"""

    metadata = {
        'id': 'graphql_security',
        'name': 'GraphQL 보안 검사',
        'icon': '📊',
        'description': 'GraphQL 취약점 탐지 (Introspection, Query Depth, Batch Attack)',
        'weight': 2,
        'field': 'graphql_vulnerabilities'
    }

    GRAPHQL_INDICATORS = [
        '/graphql', '/graphiql', '/api/graphql', '/__graphql'
    ]

    def __init__(self, url, html_content, session=None):
        self.url = url
        self.html_content = html_content
        self.session = session or requests.Session()
        self.vulnerabilities = []

    def scan(self):
        """GraphQL 보안 스캔"""
        try:
            # 1. GraphQL 엔드포인트 탐지
            graphql_endpoint = self._detect_graphql()

            if not graphql_endpoint:
                return {
                    'vulnerabilities': [],
                    'total': 0,
                    'has_graphql': False,
                    'message': 'GraphQL 엔드포인트가 감지되지 않았습니다.'
                }

            # 2. Introspection 활성화 검사
            self._check_introspection(graphql_endpoint)

            # 3. Query Depth Limit 검사
            self._check_query_depth_limit(graphql_endpoint)

            # 4. Batch Attack 가능성
            self._check_batch_attack()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_graphql': True,
                'endpoint': graphql_endpoint
            }

        except Exception as e:
            logger.error(f"GraphQL scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_graphql': False,
                'error': str(e)
            }

    def _detect_graphql(self):
        """GraphQL 엔드포인트 탐지"""
        try:
            # URL 경로에서 GraphQL 찾기
            for indicator in self.GRAPHQL_INDICATORS:
                if indicator in self.url.lower():
                    return self.url

            # HTML에서 GraphQL 엔드포인트 찾기
            patterns = [
                r'["\']https?://[^"\']+/graphql["\']',
                r'["\']\/graphql["\']',
                r'graphqlEndpoint\s*[:=]\s*["\']([^"\']+)["\']',
            ]

            for pattern in patterns:
                match = re.search(pattern, self.html_content, re.IGNORECASE)
                if match:
                    endpoint = match.group(1) if match.groups() else match.group(0).strip('"\'')
                    parsed = urlparse(self.url)
                    if not endpoint.startswith('http'):
                        endpoint = f"{parsed.scheme}://{parsed.netloc}{endpoint}"
                    return endpoint

            return None

        except Exception as e:
            logger.debug(f"GraphQL detection error: {str(e)}")
            return None

    def _check_introspection(self, endpoint):
        """Introspection 쿼리 활성화 검사"""
        try:
            introspection_query = {
                'query': '''
                    {
                        __schema {
                            types {
                                name
                            }
                        }
                    }
                '''
            }

            # Introspection 쿼리 시도 (실제로는 시뮬레이션만)
            # 프로덕션에서는 실제 요청을 보내지 않음
            self.vulnerabilities.append({
                'type': 'GraphQL Introspection Enabled (Potential)',
                'severity': 'medium',
                'endpoint': endpoint,
                'description': 'GraphQL Introspection이 활성화되어 있을 수 있습니다.',
                'impact': '공격자가 전체 스키마 구조를 파악할 수 있습니다.',
                'recommendation': '프로덕션 환경에서는 Introspection을 비활성화하세요.'
            })

        except Exception as e:
            logger.debug(f"Introspection check error: {str(e)}")

    def _check_query_depth_limit(self, endpoint):
        """Query Depth Limit 검사"""
        try:
            # Query Depth Limit이 없으면 DoS 공격 가능
            self.vulnerabilities.append({
                'type': 'Missing Query Depth Limit',
                'severity': 'high',
                'endpoint': endpoint,
                'description': 'GraphQL Query Depth 제한이 설정되지 않았을 수 있습니다.',
                'attack_example': '''
                    query {
                        user {
                            posts {
                                comments {
                                    author {
                                        posts {
                                            ... (무한 반복)
                                        }
                                    }
                                }
                            }
                        }
                    }
                ''',
                'impact': '깊은 중첩 쿼리로 서버 리소스를 고갈시킬 수 있습니다.',
                'recommendation': 'Query Depth를 제한하세요 (예: 최대 7단계).'
            })

        except Exception as e:
            logger.debug(f"Query depth check error: {str(e)}")

    def _check_batch_attack(self):
        """Batch Attack 가능성 검사"""
        try:
            self.vulnerabilities.append({
                'type': 'GraphQL Batch Attack (Potential)',
                'severity': 'medium',
                'description': 'GraphQL이 배치 쿼리를 허용할 수 있습니다.',
                'attack_example': '[{query: "..."}, {query: "..."}, ... x 1000]',
                'impact': '단일 요청으로 수천 개의 쿼리를 실행하여 Rate Limit을 우회할 수 있습니다.',
                'recommendation': '배치 쿼리 개수를 제한하고 Query Complexity를 계산하세요.'
            })

        except Exception as e:
            logger.debug(f"Batch attack check error: {str(e)}")


class OAuthSecurityScanner:
    """OAuth 보안 취약점 스캐너"""

    metadata = {
        'id': 'oauth_security',
        'name': 'OAuth 보안 검사',
        'icon': '🔐',
        'description': 'OAuth 인증 취약점 탐지 (CSRF, Open Redirect, Code Reuse)',
        'weight': 2,
        'field': 'oauth_vulnerabilities'
    }

    OAUTH_INDICATORS = [
        'oauth', 'authorize', 'access_token', 'client_id',
        'redirect_uri', 'grant_type', 'response_type'
    ]

    def __init__(self, url, html_content):
        self.url = url
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """OAuth 보안 스캔"""
        try:
            # 1. OAuth 사용 여부 탐지
            uses_oauth = self._detect_oauth()

            if not uses_oauth:
                return {
                    'vulnerabilities': [],
                    'total': 0,
                    'has_oauth': False,
                    'message': 'OAuth가 감지되지 않았습니다.'
                }

            # 2. State 파라미터 검사 (CSRF 방어)
            self._check_state_parameter()

            # 3. Redirect URI 검증
            self._check_redirect_uri()

            # 4. Authorization Code 재사용
            self._check_code_reuse()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_oauth': True
            }

        except Exception as e:
            logger.error(f"OAuth scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_oauth': False,
                'error': str(e)
            }

    def _detect_oauth(self):
        """OAuth 사용 여부 탐지"""
        try:
            # URL 파라미터 검사
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            if any(indicator in params for indicator in self.OAUTH_INDICATORS):
                return True

            # HTML에서 OAuth 관련 코드 찾기
            oauth_patterns = [
                r'oauth',
                r'authorize\?',
                r'client_id=',
                r'redirect_uri=',
                r'access_token',
            ]

            for pattern in oauth_patterns:
                if re.search(pattern, self.html_content, re.IGNORECASE):
                    return True

            return False

        except Exception as e:
            logger.debug(f"OAuth detection error: {str(e)}")
            return False

    def _check_state_parameter(self):
        """State 파라미터 검사 (CSRF 방어)"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            # OAuth 플로우인데 state 파라미터가 없으면 취약
            is_oauth_flow = any(key in params for key in ['authorize', 'response_type', 'client_id'])

            if is_oauth_flow and 'state' not in params:
                self.vulnerabilities.append({
                    'type': 'Missing OAuth State Parameter',
                    'severity': 'high',
                    'description': 'OAuth 인증 플로우에 state 파라미터가 없습니다.',
                    'impact': 'CSRF 공격으로 사용자의 계정을 공격자의 OAuth 계정과 연결할 수 있습니다.',
                    'recommendation': 'state 파라미터를 사용하여 CSRF 공격을 방지하세요.'
                })

        except Exception as e:
            logger.debug(f"State parameter check error: {str(e)}")

    def _check_redirect_uri(self):
        """Redirect URI 검증"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            redirect_uri = params.get('redirect_uri', [None])[0]

            if redirect_uri:
                # 와일드카드나 오픈 리다이렉트 가능성
                if '*' in redirect_uri or not redirect_uri.startswith(('http://', 'https://')):
                    self.vulnerabilities.append({
                        'type': 'Insecure OAuth Redirect URI',
                        'severity': 'critical',
                        'redirect_uri': redirect_uri,
                        'description': 'OAuth redirect_uri가 안전하지 않게 설정되어 있습니다.',
                        'impact': '공격자가 인증 코드를 탈취할 수 있습니다.',
                        'recommendation': 'redirect_uri를 정확한 URL로 화이트리스트에 등록하세요.'
                    })

        except Exception as e:
            logger.debug(f"Redirect URI check error: {str(e)}")

    def _check_code_reuse(self):
        """Authorization Code 재사용 검사"""
        try:
            # Authorization Code는 한 번만 사용되어야 함
            self.vulnerabilities.append({
                'type': 'OAuth Code Reuse (Potential)',
                'severity': 'medium',
                'description': 'Authorization Code가 재사용 가능할 수 있습니다.',
                'recommendation': 'Authorization Code는 한 번만 사용 가능하도록 구현하고, 재사용 시도 시 경고하세요.'
            })

        except Exception as e:
            logger.debug(f"Code reuse check error: {str(e)}")


class SessionSecurityScanner:
    """세션 관리 보안 스캐너"""

    metadata = {
        'id': 'session_security',
        'name': '세션 보안 검사',
        'icon': '🎫',
        'description': '세션 관리 취약점 탐지 (Session Fixation, Hijacking)',
        'weight': 2,
        'field': 'session_vulnerabilities'
    }

    def __init__(self, response, url):
        self.response = response
        self.url = url
        self.vulnerabilities = []

    def scan(self):
        """세션 보안 스캔"""
        try:
            # 1. 세션 쿠키 검사
            session_cookies = self._get_session_cookies()

            if not session_cookies:
                return {
                    'vulnerabilities': [],
                    'total': 0,
                    'has_session': False,
                    'message': '세션 쿠키가 감지되지 않았습니다.'
                }

            # 2. Session Fixation 취약점
            self._check_session_fixation(session_cookies)

            # 3. 세션 타임아웃
            self._check_session_timeout()

            # 4. 세션 ID 복잡도
            self._check_session_id_complexity(session_cookies)

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_session': True
            }

        except Exception as e:
            logger.error(f"Session security scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_session': False,
                'error': str(e)
            }

    def _get_session_cookies(self):
        """세션 쿠키 찾기"""
        try:
            session_cookie_names = [
                'sessionid', 'session', 'sessid', 'phpsessid',
                'jsessionid', 'aspsessionid', 'sid', 'ssid'
            ]

            found_cookies = []
            for cookie in self.response.cookies:
                if any(name in cookie.name.lower() for name in session_cookie_names):
                    found_cookies.append(cookie)

            return found_cookies

        except Exception as e:
            logger.debug(f"Get session cookies error: {str(e)}")
            return []

    def _check_session_fixation(self, session_cookies):
        """Session Fixation 취약점 검사"""
        try:
            for cookie in session_cookies:
                # 로그인 페이지에서 세션 ID가 변경되지 않으면 취약
                self.vulnerabilities.append({
                    'type': 'Session Fixation (Potential)',
                    'severity': 'high',
                    'cookie_name': cookie.name,
                    'description': f'세션 쿠키 "{cookie.name}"가 로그인 후 재생성되지 않을 수 있습니다.',
                    'impact': '공격자가 사용자의 세션 ID를 미리 설정할 수 있습니다.',
                    'recommendation': '로그인 성공 시 새로운 세션 ID를 생성하세요.'
                })

        except Exception as e:
            logger.debug(f"Session fixation check error: {str(e)}")

    def _check_session_timeout(self):
        """세션 타임아웃 검사"""
        try:
            # 세션 타임아웃 설정 확인 (일반적으로 확인 불가능하므로 경고만)
            self.vulnerabilities.append({
                'type': 'Session Timeout Not Verified',
                'severity': 'low',
                'description': '세션 타임아웃 설정을 확인할 수 없습니다.',
                'recommendation': '적절한 세션 타임아웃을 설정하세요 (예: 30분 비활동 시 로그아웃).'
            })

        except Exception as e:
            logger.debug(f"Session timeout check error: {str(e)}")

    def _check_session_id_complexity(self, session_cookies):
        """세션 ID 복잡도 검사"""
        try:
            for cookie in session_cookies:
                session_id = cookie.value

                # 길이 검사
                if len(session_id) < 32:
                    self.vulnerabilities.append({
                        'type': 'Weak Session ID',
                        'severity': 'medium',
                        'cookie_name': cookie.name,
                        'id_length': len(session_id),
                        'description': f'세션 ID "{cookie.name}"의 길이가 {len(session_id)}자로 짧습니다.',
                        'recommendation': '최소 32자 이상의 무작위 세션 ID를 사용하세요.'
                    })

                # 단순 패턴 검사
                if re.match(r'^[0-9]+$', session_id) or re.match(r'^[a-z]+$', session_id):
                    self.vulnerabilities.append({
                        'type': 'Predictable Session ID',
                        'severity': 'high',
                        'cookie_name': cookie.name,
                        'description': f'세션 ID "{cookie.name}"가 예측 가능한 패턴을 사용합니다.',
                        'recommendation': '암호학적으로 안전한 난수 생성기를 사용하세요.'
                    })

        except Exception as e:
            logger.debug(f"Session ID complexity check error: {str(e)}")


class PasswordPolicyScanner:
    """비밀번호 정책 스캐너"""

    metadata = {
        'id': 'password_policy',
        'name': '비밀번호 정책 검사',
        'icon': '🔑',
        'description': '비밀번호 정책 및 Brute Force 방어 검사',
        'weight': 1.5,
        'field': 'password_policy'
    }

    def __init__(self, html_content, url):
        self.html_content = html_content
        self.url = url
        self.vulnerabilities = []

    def scan(self):
        """비밀번호 정책 스캔"""
        try:
            # 1. 비밀번호 입력 필드 찾기
            password_fields = self._find_password_fields()

            if not password_fields:
                return {
                    'vulnerabilities': [],
                    'total': 0,
                    'has_password_field': False,
                    'message': '비밀번호 입력 필드가 발견되지 않았습니다.'
                }

            # 2. 클라이언트 사이드 비밀번호 정책 검사
            self._check_password_requirements()

            # 3. Brute Force 방어 메커니즘
            self._check_brute_force_protection()

            # 4. 비밀번호 강도 미터
            self._check_password_strength_meter()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_password_field': True,
                'password_fields_count': len(password_fields)
            }

        except Exception as e:
            logger.error(f"Password policy scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_password_field': False,
                'error': str(e)
            }

    def _find_password_fields(self):
        """비밀번호 입력 필드 찾기"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            password_fields = soup.find_all('input', type='password')
            return password_fields

        except Exception as e:
            logger.debug(f"Find password fields error: {str(e)}")
            return []

    def _check_password_requirements(self):
        """비밀번호 요구사항 검사"""
        try:
            # HTML/JS에서 비밀번호 정책 찾기
            requirements_patterns = [
                r'minlength[="\'](\d+)',
                r'pattern[="\']([^"\']+)',
                r'(?:minimum|min).*?(\d+).*?character',
            ]

            found_requirements = False
            for pattern in requirements_patterns:
                if re.search(pattern, self.html_content, re.IGNORECASE):
                    found_requirements = True
                    break

            if not found_requirements:
                self.vulnerabilities.append({
                    'type': 'Weak Password Policy',
                    'severity': 'medium',
                    'description': '비밀번호 복잡도 요구사항이 설정되지 않았습니다.',
                    'recommendation': '''강력한 비밀번호 정책을 구현하세요:
- 최소 8자 이상
- 대문자, 소문자, 숫자, 특수문자 포함
- 일반적인 비밀번호 차단'''
                })

        except Exception as e:
            logger.debug(f"Password requirements check error: {str(e)}")

    def _check_brute_force_protection(self):
        """Brute Force 방어 검사"""
        try:
            # CAPTCHA, Rate Limiting 등의 방어 메커니즘 확인
            protection_indicators = [
                'captcha', 'recaptcha', 'hcaptcha', 'rate-limit',
                'login-attempt', 'account-locked', 'too many attempts'
            ]

            has_protection = any(
                indicator in self.html_content.lower()
                for indicator in protection_indicators
            )

            if not has_protection:
                self.vulnerabilities.append({
                    'type': 'Missing Brute Force Protection',
                    'severity': 'high',
                    'description': 'Brute Force 공격 방어 메커니즘이 감지되지 않았습니다.',
                    'impact': '공격자가 무제한으로 비밀번호를 시도할 수 있습니다.',
                    'recommendation': '''Brute Force 방어를 구현하세요:
- 로그인 시도 횟수 제한 (예: 5회 실패 시 15분 잠금)
- CAPTCHA 추가
- Rate Limiting 적용'''
                })

        except Exception as e:
            logger.debug(f"Brute force protection check error: {str(e)}")

    def _check_password_strength_meter(self):
        """비밀번호 강도 미터 검사"""
        try:
            strength_indicators = [
                'strength', 'strong', 'weak', 'password-meter',
                'password-strength', 'zxcvbn'
            ]

            has_strength_meter = any(
                indicator in self.html_content.lower()
                for indicator in strength_indicators
            )

            if not has_strength_meter:
                self.vulnerabilities.append({
                    'type': 'Missing Password Strength Indicator',
                    'severity': 'low',
                    'description': '비밀번호 강도 표시기가 없습니다.',
                    'recommendation': '사용자가 강력한 비밀번호를 선택하도록 실시간 강도 피드백을 제공하세요.'
                })

        except Exception as e:
            logger.debug(f"Password strength meter check error: {str(e)}")


class RateLimitingScanner:
    """Rate Limiting 검사 스캐너"""

    metadata = {
        'id': 'rate_limiting',
        'name': 'Rate Limiting 검사',
        'icon': '⏱️',
        'description': 'API 및 로그인 Rate Limiting 검사',
        'weight': 1.5,
        'field': 'rate_limiting'
    }

    def __init__(self, response, url):
        self.response = response
        self.url = url
        self.vulnerabilities = []

    def scan(self):
        """Rate Limiting 스캔"""
        try:
            # 1. Rate Limit 헤더 검사
            self._check_rate_limit_headers()

            # 2. 429 상태 코드 지원
            self._check_429_support()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities)
            }

        except Exception as e:
            logger.error(f"Rate limiting scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'error': str(e)
            }

    def _check_rate_limit_headers(self):
        """Rate Limit 헤더 검사"""
        try:
            rate_limit_headers = {
                'X-RateLimit-Limit': 'Rate limit 최대값',
                'X-RateLimit-Remaining': '남은 요청 수',
                'X-RateLimit-Reset': 'Reset 시간',
                'Retry-After': '재시도 대기 시간',
            }

            missing_headers = []
            for header, description in rate_limit_headers.items():
                if header not in self.response.headers:
                    missing_headers.append((header, description))

            if len(missing_headers) == len(rate_limit_headers):
                self.vulnerabilities.append({
                    'type': 'Missing Rate Limiting',
                    'severity': 'high',
                    'description': 'Rate Limiting 헤더가 전혀 설정되지 않았습니다.',
                    'impact': 'API 남용, Brute Force 공격, DoS 공격에 취약합니다.',
                    'recommendation': '''Rate Limiting을 구현하세요:
- X-RateLimit-* 헤더 추가
- 429 Too Many Requests 상태 코드 사용
- IP/사용자별 요청 제한'''
                })

        except Exception as e:
            logger.debug(f"Rate limit headers check error: {str(e)}")

    def _check_429_support(self):
        """429 상태 코드 지원 검사"""
        try:
            # 현재 응답이 429가 아니면 Rate Limiting이 없을 가능성
            if self.response.status_code != 429:
                pass  # 정상적인 요청이므로 확인 불가

        except Exception as e:
            logger.debug(f"429 support check error: {str(e)}")


class LDAPInjectionScanner:
    """LDAP Injection 취약점 스캐너"""

    metadata = {
        'id': 'ldap_injection',
        'name': 'LDAP Injection 검사',
        'icon': '📁',
        'description': 'LDAP 쿼리 주입 취약점 탐지',
        'weight': 1.5,
        'field': 'ldap_injection'
    }

    LDAP_PARAMS = [
        'username', 'user', 'uid', 'cn', 'dn', 'login',
        'email', 'name', 'search', 'query', 'filter'
    ]

    LDAP_INDICATORS = [
        'ldap://', 'ldaps://', 'activedirectory', 'openldap'
    ]

    def __init__(self, url, html_content):
        self.url = url
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """LDAP Injection 스캔"""
        try:
            # 1. LDAP 사용 여부 탐지
            uses_ldap = self._detect_ldap()

            if not uses_ldap:
                return {
                    'vulnerabilities': [],
                    'total': 0,
                    'has_ldap': False,
                    'message': 'LDAP 사용이 감지되지 않았습니다.'
                }

            # 2. URL 파라미터 검사
            self._check_url_parameters()

            # 3. 입력 필드 검사
            self._check_input_fields()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_ldap': True
            }

        except Exception as e:
            logger.error(f"LDAP injection scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_ldap': False,
                'error': str(e)
            }

    def _detect_ldap(self):
        """LDAP 사용 여부 탐지"""
        try:
            return any(
                indicator in self.html_content.lower() or indicator in self.url.lower()
                for indicator in self.LDAP_INDICATORS
            )

        except Exception as e:
            logger.debug(f"LDAP detection error: {str(e)}")
            return False

    def _check_url_parameters(self):
        """URL 파라미터에서 LDAP Injection 검사"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param_name in params.keys():
                if param_name.lower() in self.LDAP_PARAMS:
                    self.vulnerabilities.append({
                        'type': 'LDAP Injection (Potential)',
                        'severity': 'high',
                        'parameter': param_name,
                        'description': f'파라미터 "{param_name}"가 LDAP Injection에 취약할 수 있습니다.',
                        'attack_examples': [
                            '*)(uid=*',
                            'admin)(&(password=*',
                            '*))%00',
                        ],
                        'recommendation': '입력값을 이스케이프 처리하고 LDAP 쿼리를 파라미터화하세요.'
                    })

        except Exception as e:
            logger.debug(f"LDAP URL parameter check error: {str(e)}")

    def _check_input_fields(self):
        """입력 필드에서 LDAP Injection 검사"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            inputs = soup.find_all('input')

            for input_field in inputs:
                name = input_field.get('name', '').lower()
                if name in self.LDAP_PARAMS:
                    self.vulnerabilities.append({
                        'type': 'LDAP Injection (Input Field)',
                        'severity': 'high',
                        'input_name': name,
                        'description': f'입력 필드 "{name}"이 LDAP Injection에 취약할 수 있습니다.',
                        'recommendation': 'LDAP 특수문자를 이스케이프하세요: * ( ) \\ / NUL'
                    })

        except Exception as e:
            logger.debug(f"LDAP input field check error: {str(e)}")


class AuthorizationScanner:
    """인가 취약점 스캐너 (BOLA/IDOR)"""

    metadata = {
        'id': 'authorization',
        'name': '인가 취약점 검사',
        'icon': '🚫',
        'description': 'BOLA/IDOR 취약점 탐지 (객체/함수 레벨 인가 오류)',
        'weight': 2,
        'field': 'authorization_vulnerabilities'
    }

    SENSITIVE_RESOURCES = [
        '/user/', '/profile/', '/account/', '/admin/', '/api/users/',
        '/api/orders/', '/api/invoices/', '/api/documents/'
    ]

    ID_PATTERNS = [
        r'/\d+/?$',  # /users/123
        r'[?&]id=\d+',  # ?id=123
        r'[?&]user_id=\d+',
        r'[?&]account_id=\d+',
    ]

    def __init__(self, url):
        self.url = url
        self.vulnerabilities = []

    def scan(self):
        """인가 취약점 스캔"""
        try:
            # 1. IDOR (Insecure Direct Object Reference) 검사
            self._check_idor()

            # 2. BOLA (Broken Object Level Authorization) 검사
            self._check_bola()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities)
            }

        except Exception as e:
            logger.error(f"Authorization scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'error': str(e)
            }

    def _check_idor(self):
        """IDOR 취약점 검사"""
        try:
            # 민감한 리소스에 직접 ID로 접근하는 패턴 찾기
            for resource in self.SENSITIVE_RESOURCES:
                if resource in self.url.lower():
                    for pattern in self.ID_PATTERNS:
                        if re.search(pattern, self.url):
                            self.vulnerabilities.append({
                                'type': 'IDOR (Insecure Direct Object Reference)',
                                'severity': 'critical',
                                'url': self.url,
                                'resource': resource,
                                'description': f'민감한 리소스 "{resource}"에 숫자 ID로 직접 접근할 수 있습니다.',
                                'attack_example': 'ID를 변경하여 다른 사용자의 데이터에 접근 (예: /users/123 → /users/124)',
                                'recommendation': '''인가 검증을 구현하세요:
- 현재 사용자가 해당 리소스에 접근 권한이 있는지 확인
- UUID 같은 예측 불가능한 ID 사용
- 간접 참조 맵 사용'''
                            })
                            return  # 한 번만 보고

        except Exception as e:
            logger.debug(f"IDOR check error: {str(e)}")

    def _check_bola(self):
        """BOLA 취약점 검사"""
        try:
            # API 엔드포인트에서 객체 레벨 인가 검사
            if '/api/' in self.url.lower():
                for pattern in self.ID_PATTERNS:
                    if re.search(pattern, self.url):
                        self.vulnerabilities.append({
                            'type': 'BOLA (Broken Object Level Authorization)',
                            'severity': 'critical',
                            'url': self.url,
                            'description': 'API가 객체 레벨 인가를 검증하지 않을 수 있습니다.',
                            'impact': '다른 사용자의 객체를 조회/수정/삭제할 수 있습니다.',
                            'recommendation': '''모든 API 엔드포인트에서 인가를 검증하세요:
- 요청한 사용자가 해당 객체의 소유자인지 확인
- 역할 기반 접근 제어 (RBAC) 구현
- 자동화된 인가 테스트 추가'''
                        })
                        return

        except Exception as e:
            logger.debug(f"BOLA check error: {str(e)}")
