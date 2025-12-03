"""
Batch 5 고급 스캐너 테스트
Deserialization, JWT, Template Injection, NoSQL Injection, SSL/TLS Deep 스캐너
"""

import pytest
from unittest.mock import Mock, patch
import base64
import json

from scanner.scanners.deserialization import DeserializationScanner
from scanner.scanners.jwt_security import JWTSecurityScanner
from scanner.scanners.template_injection import TemplateInjectionScanner
from scanner.scanners.no_sql_injection import NoSQLInjectionScanner
from scanner.scanners.ssltls_deep import SSLTLSDeepScanner


class TestDeserializationScanner:
    """DeserializationScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_pickle_cookie(self):
        """TP: 쿠키에서 Pickle 데이터 발견"""
        # Given
        mock_response = Mock()
        mock_cookie = Mock()
        mock_cookie.name = 'session'
        # Pickle magic bytes (Python 2)
        mock_cookie.value = base64.b64encode(b'\x80\x02}q\x00X\x04\x00\x00\x00userq\x01X\x05\x00\x00\x00adminq\x02s.').decode()
        mock_response.cookies = [mock_cookie]

        # When
        scanner = DeserializationScanner(response=mock_response)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'deserialization'
        assert result['total'] > 0
        assert result['has_deserialization'] is True
        assert any('Cookie' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_serialization_functions(self):
        """TP: HTML에서 직렬화 함수 발견"""
        # Given
        html_content = '''
        <script>
        function loadData() {
            var data = pickle.loads(userData);
            ObjectInputStream ois = new ObjectInputStream(input);
            unserialize($data);
        }
        </script>
        '''

        # When
        scanner = DeserializationScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Unsafe Deserialization Functions' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_encoded_data(self):
        """TP: Base64로 인코딩된 직렬화 데이터"""
        # Given
        # Java serialization magic bytes: 0xac 0xed - 더 긴 패턴 필요 (최소 40자)
        java_bytes = b'\xac\xed\x00\x05' + b'x' * 40  # 40자 이상으로 만듦
        serialized_java = base64.b64encode(java_bytes).decode()
        html_content = f'<input type="hidden" value="{serialized_java}" />'

        # When
        scanner = DeserializationScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Serialized Data' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_no_serialization(self):
        """TN: 직렬화 데이터가 없는 경우"""
        # Given
        html_content = '<div>Regular content without serialization</div>'
        mock_response = Mock()
        mock_response.cookies = []

        # When
        scanner = DeserializationScanner(response=mock_response, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_deserialization'] is False

    @pytest.mark.unit
    def test_edge_case_no_content(self):
        """Edge Case: 콘텐츠가 없는 경우"""
        # Given
        scanner = DeserializationScanner()

        # When
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert 'error' not in result


class TestJWTSecurityScanner:
    """JWTSecurityScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_algorithm_none(self):
        """TP: JWT with alg:none 취약점"""
        # Given
        header = {"alg": "none", "typ": "JWT"}
        payload = {"user": "admin", "iat": 1234567890}
        # 더 긴 signature 부분 생성 (최소 10자 이상)
        fake_signature = base64.urlsafe_b64encode(b'fake_signature_data').decode().rstrip('=')
        token = f"{base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')}." \
                f"{base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')}." \
                f"{fake_signature}"

        html_content = f'<script>var token = "{token}";</script>'

        # When
        scanner = JWTSecurityScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'jwt_security'
        assert result['has_jwt'] is True
        assert result['total'] > 0
        assert any('Algorithm None' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_no_expiration(self):
        """TP: JWT without expiration"""
        # Given
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "admin"}  # No 'exp' claim
        token = f"{base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')}." \
                f"{base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')}." \
                f"signature"

        mock_response = Mock()
        mock_response.headers = {'Authorization': f'Bearer {token}'}
        mock_response.cookies = []

        # When
        scanner = JWTSecurityScanner(response=mock_response)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('No Expiration' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_sensitive_data(self):
        """TP: JWT with sensitive data"""
        # Given
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "admin", "password": "secret123", "credit_card": "1234-5678"}
        token = f"{base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')}." \
                f"{base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')}." \
                f"signature"

        mock_cookie = Mock()
        mock_cookie.name = 'auth'
        mock_cookie.value = token

        mock_response = Mock()
        mock_response.headers = {}
        mock_response.cookies = [mock_cookie]

        # When
        scanner = JWTSecurityScanner(response=mock_response)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Sensitive Data' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_no_jwt(self):
        """TN: JWT가 없는 경우"""
        # Given
        html_content = '<html><body>No JWT tokens here</body></html>'
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.cookies = []

        # When
        scanner = JWTSecurityScanner(response=mock_response, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_jwt'] is False
        assert 'message' in result

    @pytest.mark.unit
    def test_weak_algorithm_hs256(self):
        """TP: Weak algorithm (HS256)"""
        # Given
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"user": "admin", "exp": 9999999999}
        # 더 긴 signature 부분 생성 (최소 10자 이상)
        fake_signature = base64.urlsafe_b64encode(b'fake_signature_data').decode().rstrip('=')
        token = f"{base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')}." \
                f"{base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')}." \
                f"{fake_signature}"

        html_content = f'<input type="hidden" name="jwt" value="{token}" />'

        # When
        scanner = JWTSecurityScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Weak Algorithm' in v['type'] for v in result['vulnerabilities'])


class TestTemplateInjectionScanner:
    """TemplateInjectionScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_jinja2_syntax(self):
        """TP: Jinja2 템플릿 구문 발견"""
        # Given
        html_content = '''
        <html>
            <body>
                <h1>Welcome {{user.name}}</h1>
                <p>{%if admin%}Admin Panel{%endif%}</p>
            </body>
        </html>
        '''
        url = 'https://example.com/page'

        # When
        scanner = TemplateInjectionScanner(url=url, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'template_injection'
        assert result['total'] > 0
        assert result['has_ssti'] is True
        assert any('Jinja2' in v.get('engine', '') for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_ssti_parameters(self):
        """TP: SSTI 위험 파라미터"""
        # Given
        url = 'https://example.com/render?template=user_template&content=data'
        html_content = '<div>Template rendered</div>'

        # When
        scanner = TemplateInjectionScanner(url=url, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('SSTI (Potential)' in v['type'] for v in result['vulnerabilities'])
        assert any('template' in v.get('parameter', '') for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_multiple_template_engines(self):
        """TP: 여러 템플릿 엔진 구문"""
        # Given
        html_content = '''
        {{variable}}
        ${expression}
        <%=value%>
        '''

        # When
        scanner = TemplateInjectionScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] >= 3  # 최소 3개의 다른 엔진 탐지

    @pytest.mark.unit
    def test_true_negative_no_template(self):
        """TN: 템플릿 구문이 없는 경우"""
        # Given
        url = 'https://example.com/page?id=123'
        html_content = '<html><body>Regular HTML content</body></html>'

        # When
        scanner = TemplateInjectionScanner(url=url, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_ssti'] is False

    @pytest.mark.unit
    def test_edge_case_empty_url(self):
        """Edge Case: URL이 없는 경우"""
        # Given
        html_content = '{{test}}'

        # When
        scanner = TemplateInjectionScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0  # HTML에서는 템플릿 탐지
        assert 'error' not in result


class TestNoSQLInjectionScanner:
    """NoSQLInjectionScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_nosql_with_params(self):
        """TP: NoSQL 데이터베이스 사용 + 위험 파라미터"""
        # Given
        url = 'https://example.com/api/users?username=admin&filter={"active":true}'
        html_content = '<div>MongoDB powered application</div>'
        mock_response = Mock()
        mock_response.headers = {'X-Powered-By': 'Express/MongoDB'}

        # When
        scanner = NoSQLInjectionScanner(url=url, response=mock_response, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'nosql_injection'
        assert result['uses_nosql'] is True
        assert result['total'] > 0
        assert result['has_nosql_injection'] is True
        assert any('NoSQL Injection' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_json_api(self):
        """TP: JSON API with NoSQL"""
        # Given
        html_content = 'elasticsearch cluster status'
        mock_response = Mock()
        mock_response.headers = {'Content-Type': 'application/json'}

        # When
        scanner = NoSQLInjectionScanner(response=mock_response, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['uses_nosql'] is True
        assert result['total'] > 0
        assert any('JSON API' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_no_nosql(self):
        """TN: NoSQL을 사용하지 않는 경우"""
        # Given
        url = 'https://example.com/page?id=123'
        html_content = '<html><body>MySQL database</body></html>'
        mock_response = Mock()
        mock_response.headers = {}

        # When
        scanner = NoSQLInjectionScanner(url=url, response=mock_response, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['uses_nosql'] is False
        assert result['total'] == 0
        assert result['has_nosql_injection'] is False

    @pytest.mark.unit
    def test_json_parameter_detection(self):
        """TP: JSON 형식 파라미터 탐지"""
        # Given
        url = 'https://example.com/api?query={"$ne":null}'
        html_content = 'redis cache enabled'

        # When
        scanner = NoSQLInjectionScanner(url=url, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['uses_nosql'] is True
        assert result['total'] > 0
        assert any(v.get('value_type') == 'JSON' for v in result['vulnerabilities'])
        assert any(v.get('severity') == 'critical' for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_edge_case_no_content(self):
        """Edge Case: 콘텐츠가 없는 경우"""
        # Given
        scanner = NoSQLInjectionScanner()

        # When
        result = scanner.scan()

        # Then
        assert result['uses_nosql'] is False
        assert result['total'] == 0
        assert 'error' not in result


class TestSSLTLSDeepScanner:
    """SSLTLSDeepScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_no_https(self):
        """TP: HTTP만 사용하는 경우"""
        # Given
        url = 'http://example.com'

        # When
        scanner = SSLTLSDeepScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'ssl_tls_deep'
        assert result['total'] == 1
        assert result['has_ssl_issues'] is True
        assert result['vulnerabilities'][0]['type'] == 'No HTTPS'
        assert result['vulnerabilities'][0]['severity'] == 'critical'

    @pytest.mark.unit
    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_true_positive_weak_tls_version(self, mock_ssl_context, mock_socket):
        """TP: 약한 TLS 버전 사용"""
        # Given
        url = 'https://example.com'

        # Mock SSL socket
        mock_ssock = Mock()
        mock_ssock.version.return_value = 'TLSv1'  # Weak version
        mock_ssock.cipher.return_value = ('AES256-SHA', 'TLSv1', 256)
        mock_ssock.getpeercert.return_value = {
            'notAfter': 'Dec 31 23:59:59 2025 GMT'
        }

        # Configure context manager for wrap_socket
        mock_wrap_socket_cm = Mock()
        mock_wrap_socket_cm.__enter__ = Mock(return_value=mock_ssock)
        mock_wrap_socket_cm.__exit__ = Mock(return_value=False)

        mock_context = Mock()
        mock_context.wrap_socket.return_value = mock_wrap_socket_cm
        mock_ssl_context.return_value = mock_context

        # Configure context manager for socket
        mock_sock_cm = Mock()
        mock_sock_cm.__enter__ = Mock(return_value=Mock())
        mock_sock_cm.__exit__ = Mock(return_value=False)
        mock_socket.return_value = mock_sock_cm

        # When
        scanner = SSLTLSDeepScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Weak TLS Version' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_true_positive_weak_cipher(self, mock_ssl_context, mock_socket):
        """TP: 약한 암호화 알고리즘 사용"""
        # Given
        url = 'https://example.com'

        # Mock SSL socket with weak cipher
        mock_ssock = Mock()
        mock_ssock.version.return_value = 'TLSv1.2'
        mock_ssock.cipher.return_value = ('RC4-SHA', 'TLSv1.2', 128)  # Weak cipher
        mock_ssock.getpeercert.return_value = {
            'notAfter': 'Dec 31 23:59:59 2025 GMT'
        }

        # Configure context manager for wrap_socket
        mock_wrap_socket_cm = Mock()
        mock_wrap_socket_cm.__enter__ = Mock(return_value=mock_ssock)
        mock_wrap_socket_cm.__exit__ = Mock(return_value=False)

        mock_context = Mock()
        mock_context.wrap_socket.return_value = mock_wrap_socket_cm
        mock_ssl_context.return_value = mock_context

        # Configure context manager for socket
        mock_sock_cm = Mock()
        mock_sock_cm.__enter__ = Mock(return_value=Mock())
        mock_sock_cm.__exit__ = Mock(return_value=False)
        mock_socket.return_value = mock_sock_cm

        # When
        scanner = SSLTLSDeepScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Weak Cipher Suite' in v['type'] for v in result['vulnerabilities'])
        assert any('RC4' in v.get('cipher', '') for v in result['vulnerabilities'])

    @pytest.mark.unit
    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_true_positive_expired_certificate(self, mock_ssl_context, mock_socket):
        """TP: 만료된 인증서"""
        # Given
        url = 'https://example.com'

        # Mock SSL socket with expired certificate
        mock_ssock = Mock()
        mock_ssock.version.return_value = 'TLSv1.3'
        mock_ssock.cipher.return_value = ('AES256-GCM-SHA384', 'TLSv1.3', 256)
        mock_ssock.getpeercert.return_value = {
            'notAfter': 'Jan 01 00:00:00 2020 GMT'  # Expired
        }

        # Configure context manager for wrap_socket
        mock_wrap_socket_cm = Mock()
        mock_wrap_socket_cm.__enter__ = Mock(return_value=mock_ssock)
        mock_wrap_socket_cm.__exit__ = Mock(return_value=False)

        mock_context = Mock()
        mock_context.wrap_socket.return_value = mock_wrap_socket_cm
        mock_ssl_context.return_value = mock_context

        # Configure context manager for socket
        mock_sock_cm = Mock()
        mock_sock_cm.__enter__ = Mock(return_value=Mock())
        mock_sock_cm.__exit__ = Mock(return_value=False)
        mock_socket.return_value = mock_sock_cm

        # When
        scanner = SSLTLSDeepScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Certificate Expired' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_true_negative_secure_ssl(self, mock_ssl_context, mock_socket):
        """TN: 안전한 SSL/TLS 설정"""
        # Given
        url = 'https://example.com'

        # Mock secure SSL socket
        mock_ssock = Mock()
        mock_ssock.version.return_value = 'TLSv1.3'
        mock_ssock.cipher.return_value = ('AES256-GCM-SHA384', 'TLSv1.3', 256)
        mock_ssock.getpeercert.return_value = {
            'notAfter': 'Dec 31 23:59:59 2030 GMT'  # Valid for years
        }

        # Configure context manager for wrap_socket
        mock_wrap_socket_cm = Mock()
        mock_wrap_socket_cm.__enter__ = Mock(return_value=mock_ssock)
        mock_wrap_socket_cm.__exit__ = Mock(return_value=False)

        mock_context = Mock()
        mock_context.wrap_socket.return_value = mock_wrap_socket_cm
        mock_ssl_context.return_value = mock_context

        # Configure context manager for socket
        mock_sock_cm = Mock()
        mock_sock_cm.__enter__ = Mock(return_value=Mock())
        mock_sock_cm.__exit__ = Mock(return_value=False)
        mock_socket.return_value = mock_sock_cm

        # When
        scanner = SSLTLSDeepScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_ssl_issues'] is False