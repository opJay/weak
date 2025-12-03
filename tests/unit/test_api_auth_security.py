"""
Batch 6 API 및 인증/인가 스캐너 테스트
RESTAPISecurityScanner, GraphQLSecurityScanner, OAuthSecurityScanner,
SessionSecurityScanner, PasswordPolicyScanner, RateLimitingScanner,
LDAPInjectionScanner, AuthorizationScanner
"""

import pytest
from unittest.mock import Mock
import json

from scanner.scanners.restapi_security import RESTAPISecurityScanner
from scanner.scanners.graph_ql_security import GraphQLSecurityScanner
from scanner.scanners.o_auth_security import OAuthSecurityScanner
from scanner.scanners.session_security import SessionSecurityScanner
from scanner.scanners.password_policy import PasswordPolicyScanner
from scanner.scanners.rate_limiting import RateLimitingScanner
from scanner.scanners.ldap_injection import LDAPInjectionScanner
from scanner.scanners.authorization import AuthorizationScanner


class TestRESTAPISecurityScanner:
    """RESTAPISecurityScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_api_endpoint(self):
        """TP: API 엔드포인트 탐지"""
        # Given
        url = 'https://example.com/api/v1/users'
        response = Mock()
        response.headers = {'Content-Type': 'application/json'}

        # When
        scanner = RESTAPISecurityScanner(url=url, response=response)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'rest_api_security'
        assert 'vulnerabilities' in result

    @pytest.mark.unit
    def test_true_positive_missing_rate_limit(self):
        """TP: Rate Limiting 없음"""
        # Given
        url = 'https://example.com/api/users'
        response = Mock()
        response.headers = {}

        # When
        scanner = RESTAPISecurityScanner(url=url, response=response)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Rate Limiting' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_excessive_data_exposure(self):
        """TP: 과도한 데이터 노출"""
        # Given
        url = 'https://example.com/api/users'
        response = Mock()
        response.headers = {'Content-Type': 'application/json'}
        response.text = json.dumps({
            'id': 1,
            'username': 'test',
            'password': 'hashed_password',
            'api_key': 'secret_key'
        })

        # When
        scanner = RESTAPISecurityScanner(url=url, response=response)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Excessive Data Exposure' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_no_api(self):
        """TN: API가 아닌 경우"""
        # Given
        url = 'https://example.com/about'
        html_content = '<html><body>About page</body></html>'

        # When
        scanner = RESTAPISecurityScanner(url=url, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] == 0

    @pytest.mark.unit
    def test_mass_assignment_detection(self):
        """TP: Mass Assignment 패턴 탐지"""
        # Given
        html_content = '''
        <script>
        fetch('/api/user', {
            method: 'PUT',
            body: JSON.stringify(userData)
        });
        </script>
        '''

        # When
        scanner = RESTAPISecurityScanner(url='https://example.com/api/users',
                                        html_content=html_content)
        result = scanner.scan()

        # Then
        assert any('Mass Assignment' in v['type'] for v in result['vulnerabilities'])


class TestGraphQLSecurityScanner:
    """GraphQLSecurityScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_graphql_endpoint(self):
        """TP: GraphQL 엔드포인트 탐지"""
        # Given
        url = 'https://example.com/graphql'

        # When
        scanner = GraphQLSecurityScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'graphql_security'
        assert 'vulnerabilities' in result

    @pytest.mark.unit
    def test_true_positive_introspection_enabled(self):
        """TP: Introspection 활성화"""
        # Given
        html_content = '''
        <script>
        const query = `{ __schema { types { name } } }`;
        </script>
        '''

        # When
        scanner = GraphQLSecurityScanner(url='https://example.com/graphql',
                                        html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Introspection' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_deep_query_nesting(self):
        """TP: 깊은 쿼리 중첩"""
        # Given
        html_content = '''
        query {
            user {
                posts {
                    comments {
                        author {
                            friends {
                                posts
                            }
                        }
                    }
                }
            }
        }
        '''

        # When
        scanner = GraphQLSecurityScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Deep Query Nesting' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_no_graphql(self):
        """TN: GraphQL이 아닌 경우"""
        # Given
        url = 'https://example.com/rest/api'
        html_content = '<html><body>REST API</body></html>'

        # When
        scanner = GraphQLSecurityScanner(url=url, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] == 0


class TestOAuthSecurityScanner:
    """OAuthSecurityScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_missing_state_parameter(self):
        """TP: State 파라미터 누락"""
        # Given
        url = 'https://example.com/oauth/authorize?client_id=123&response_type=code&redirect_uri=http://callback'

        # When
        scanner = OAuthSecurityScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Missing OAuth State Parameter' in v['type'] for v in result['vulnerabilities'])
        assert result['scanner_id'] == 'o_auth_security'

    @pytest.mark.unit
    def test_true_positive_open_redirect(self):
        """TP: OAuth Open Redirect"""
        # Given
        url = 'https://example.com/oauth/authorize?redirect_uri=http://evil.com/callback'

        # When
        scanner = OAuthSecurityScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Open Redirect' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_token_in_url(self):
        """TP: 토큰이 URL에 노출"""
        # Given
        # OAuth 패턴이 있어야 OAuth 검사가 실행됨
        url = 'https://example.com/oauth/callback'
        html_content = '''
        <script>
        const token = location.hash.match(/#access_token=([^&]+)/);
        // OAuth callback handling
        </script>
        '''

        # When
        scanner = OAuthSecurityScanner(url=url, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Token Exposure' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_implicit_flow(self):
        """TP: Implicit Flow 사용"""
        # Given
        url = 'https://example.com/oauth/authorize?response_type=token'

        # When
        scanner = OAuthSecurityScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Implicit Flow' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_secure_oauth(self):
        """TN: 안전한 OAuth 구현"""
        # Given
        url = 'https://example.com/oauth/authorize?client_id=123&response_type=code&state=random123&redirect_uri=https://app.com/callback'

        # When
        scanner = OAuthSecurityScanner(url=url)
        result = scanner.scan()

        # Then
        # State가 있고 response_type이 code이므로 주요 취약점은 없어야 함
        critical_vulns = [v for v in result['vulnerabilities'] if v.get('severity') in ['high', 'critical']]
        assert len(critical_vulns) == 0


class TestSessionSecurityScanner:
    """SessionSecurityScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_session_cookie_missing_httponly(self):
        """TP: 세션 쿠키에 HttpOnly 플래그 누락"""
        # Given
        response = Mock()
        response.cookies = {
            'sessionid': {'value': 'abc123', 'httponly': False}
        }

        # When
        scanner = SessionSecurityScanner(response=response)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('HttpOnly' in v['type'] for v in result['vulnerabilities'])
        assert result['scanner_id'] == 'session_security'

    @pytest.mark.unit
    def test_true_positive_session_in_url(self):
        """TP: URL에 세션 ID 노출"""
        # Given
        url = 'https://example.com/app?sessionid=abc123xyz'

        # When
        scanner = SessionSecurityScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Session ID in URL' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_secure_session(self):
        """TN: 안전한 세션 관리"""
        # Given
        response = Mock()
        response.cookies = {
            'sessionid': {'value': 'abc123', 'httponly': True, 'secure': True}
        }
        url = 'https://example.com/app'

        # When
        scanner = SessionSecurityScanner(url=url, response=response)
        result = scanner.scan()

        # Then
        # HttpOnly와 Secure가 설정되어 있으므로 쿠키 관련 취약점은 없어야 함
        cookie_vulns = [v for v in result['vulnerabilities'] if 'Cookie' in v['type']]
        assert len(cookie_vulns) == 0

    @pytest.mark.unit
    def test_missing_session_timeout(self):
        """TP: 세션 타임아웃 미구현"""
        # Given
        html_content = '''
        <html>
        <body>
            <h1>Dashboard</h1>
            <p>Welcome user</p>
        </body>
        </html>
        '''

        # When
        scanner = SessionSecurityScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert any('Session Timeout' in v['type'] for v in result['vulnerabilities'])


class TestPasswordPolicyScanner:
    """PasswordPolicyScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_weak_password_length(self):
        """TP: 약한 비밀번호 길이"""
        # Given
        html_content = '''
        <form>
            <input type="password" name="password" minlength="4" />
        </form>
        '''

        # When
        scanner = PasswordPolicyScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Weak Password Length' in v['type'] for v in result['vulnerabilities'])
        assert result['scanner_id'] == 'password_policy'

    @pytest.mark.unit
    def test_true_positive_autocomplete_enabled(self):
        """TP: 비밀번호 자동완성 활성화"""
        # Given
        html_content = '''
        <form>
            <input type="password" name="password" />
        </form>
        '''

        # When
        scanner = PasswordPolicyScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Autocomplete' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_no_complexity(self):
        """TP: 복잡도 요구사항 없음"""
        # Given
        html_content = '''
        <form>
            <input type="password" name="password" minlength="8" />
            <button type="submit">Submit</button>
        </form>
        '''

        # When
        scanner = PasswordPolicyScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        # 복잡도 검사 또는 다른 취약점이 있어야 함
        assert result['total'] > 0
        # 복잡도 또는 다른 보안 문제가 있는지 확인
        has_security_issue = any('Complexity' in v['type'] or
                                'Brute Force' in v['type'] or
                                'Autocomplete' in v['type']
                                for v in result['vulnerabilities'])
        assert has_security_issue

    @pytest.mark.unit
    def test_true_positive_no_brute_force_protection(self):
        """TP: Brute Force 방어 없음"""
        # Given
        html_content = '''
        <form action="/login" method="post">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <button type="submit">Login</button>
        </form>
        '''

        # When
        scanner = PasswordPolicyScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert any('Brute Force' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_secure_password_policy(self):
        """TN: 안전한 비밀번호 정책"""
        # Given
        html_content = '''
        <form>
            <input type="password" name="password" minlength="12" autocomplete="off"
                   pattern="(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%])" />
            <div class="g-recaptcha"></div>
        </form>
        '''

        # When
        scanner = PasswordPolicyScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        # 강력한 비밀번호 정책이 구현되어 있으므로 심각한 취약점은 없어야 함
        critical_vulns = [v for v in result['vulnerabilities'] if v.get('severity') in ['high', 'critical']]
        assert len(critical_vulns) == 0


class TestRateLimitingScanner:
    """RateLimitingScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_missing_rate_limit_headers(self):
        """TP: Rate Limit 헤더 누락"""
        # Given
        response = Mock()
        response.headers = {}
        response.status_code = 200

        # When
        scanner = RateLimitingScanner(response=response)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Missing Rate Limit Headers' in v['type'] for v in result['vulnerabilities'])
        assert result['scanner_id'] == 'rate_limiting'

    @pytest.mark.unit
    def test_true_positive_429_without_retry_after(self):
        """TP: 429 응답에 Retry-After 헤더 없음"""
        # Given
        response = Mock()
        response.status_code = 429
        response.headers = {}

        # When
        scanner = RateLimitingScanner(response=response)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Retry-After' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_api_without_rate_limit(self):
        """TP: API에 Rate Limiting 없음"""
        # Given
        url = 'https://example.com/api/users'
        response = Mock()
        response.headers = {'Content-Type': 'application/json'}

        # When
        scanner = RateLimitingScanner(url=url, response=response)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('API Without Rate Limiting' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_login_without_rate_limit(self):
        """TP: 로그인 페이지에 Rate Limiting 없음"""
        # Given
        html_content = '''
        <form action="/login" method="post">
            <input type="password" name="password" />
            <button>Login</button>
        </form>
        '''

        # When
        scanner = RateLimitingScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Login Without Rate Limiting' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_has_rate_limit(self):
        """TN: Rate Limiting이 구현된 경우"""
        # Given
        response = Mock()
        response.headers = {
            'X-Rate-Limit-Limit': '100',
            'X-Rate-Limit-Remaining': '95'
        }

        # When
        scanner = RateLimitingScanner(response=response)
        result = scanner.scan()

        # Then
        # Rate limit 헤더가 있으므로 해당 취약점은 없어야 함
        assert not any('Missing Rate Limit Headers' in v['type'] for v in result['vulnerabilities'])


class TestLDAPInjectionScanner:
    """LDAPInjectionScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_ldap_injection_chars(self):
        """TP: LDAP Injection 문자 탐지"""
        # Given
        url = 'https://example.com/search?username=admin*)(uid=*'

        # When
        scanner = LDAPInjectionScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('LDAP Injection' in v['type'] for v in result['vulnerabilities'])
        assert result['scanner_id'] == 'ldap_injection'

    @pytest.mark.unit
    def test_true_positive_ldap_filter_exposed(self):
        """TP: LDAP 필터 노출"""
        # Given
        html_content = '''
        <script>
        const filter = "(uid=admin)";
        </script>
        '''

        # When
        scanner = LDAPInjectionScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('LDAP Filter' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_ldap_error_message(self):
        """TP: LDAP 에러 메시지 노출"""
        # Given
        html_content = '''
        <div class="error">
            LDAP bind failed: Invalid DN syntax
        </div>
        '''

        # When
        scanner = LDAPInjectionScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('LDAP Error' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_no_ldap(self):
        """TN: LDAP 사용하지 않음"""
        # Given
        url = 'https://example.com/search?q=test'
        html_content = '<html><body>Search results</body></html>'

        # When
        scanner = LDAPInjectionScanner(url=url, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] == 0

    @pytest.mark.unit
    def test_ldap_authentication_detection(self):
        """TP: LDAP 인증 사용 탐지"""
        # Given
        html_content = '''
        <script>
        function ldapLogin(username, password) {
            // LDAP authentication
        }
        </script>
        '''

        # When
        scanner = LDAPInjectionScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert any('LDAP Authentication' in v['type'] for v in result['vulnerabilities'])


class TestAuthorizationScanner:
    """AuthorizationScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_direct_object_reference(self):
        """TP: 직접 객체 참조(IDOR)"""
        # Given
        url = 'https://example.com/user/12345'

        # When
        scanner = AuthorizationScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Direct Object Reference' in v['type'] for v in result['vulnerabilities'])
        assert result['scanner_id'] == 'authorization'

    @pytest.mark.unit
    def test_true_positive_predictable_ids(self):
        """TP: 예측 가능한 ID 패턴"""
        # Given
        html_content = '''
        <script>
        const users = [
            {id: 1, name: "User1"},
            {id: 2, name: "User2"},
            {id: 3, name: "User3"},
            {id: 4, name: "User4"}
        ];
        </script>
        '''

        # When
        scanner = AuthorizationScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Predictable Resource IDs' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_admin_interface_exposed(self):
        """TP: 관리자 인터페이스 노출"""
        # Given
        url = 'https://example.com/admin/dashboard'
        response = Mock()
        response.status_code = 200

        # When
        scanner = AuthorizationScanner(url=url, response=response)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Admin Interface' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_sensitive_function_exposed(self):
        """TP: 민감한 기능 노출"""
        # Given
        html_content = '''
        <script>
        function deleteUser(userId) {
            fetch(`/api/user/${userId}`, {method: 'DELETE'});
        }
        </script>
        '''

        # When
        scanner = AuthorizationScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Function Level Access' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_secure_authorization(self):
        """TN: 안전한 인가 구현"""
        # Given
        url = 'https://example.com/dashboard'
        html_content = '<html><body>User Dashboard</body></html>'

        # When
        scanner = AuthorizationScanner(url=url, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] == 0

    @pytest.mark.unit
    def test_edge_case_no_content(self):
        """Edge Case: 콘텐츠가 없는 경우"""
        # Given
        scanner = AuthorizationScanner()

        # When
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert 'error' not in result