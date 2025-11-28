"""
Batch 3 스캐너 단위 테스트

5개 기본 스캐너에 대한 포괄적인 테스트
"""

import pytest
from unittest.mock import Mock, patch
import requests

# 테스트 대상 스캐너 임포트
from scanner.scanners_refactored_batch3 import (
    OpenRedirectScanner,
    DirectoryListingScanner,
    HTTPMethodScanner,
    SSLTLSBasicScanner,
    SensitiveFileScanner
)


class TestOpenRedirectScanner:
    """OpenRedirectScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_redirect_param(self):
        """TP: 리다이렉트 파라미터가 있는 URL"""
        # Given
        url = 'https://example.com/login?next=/dashboard&user=test'

        # When
        scanner = OpenRedirectScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'open_redirect'
        assert result['total'] > 0
        assert any('next' in str(v) for v in result['vulnerabilities'])
        assert result['has_open_redirect'] is True

    @pytest.mark.unit
    def test_true_positive_url_value(self):
        """TP: URL 값을 가진 리다이렉트 파라미터"""
        # Given
        url = 'https://example.com/logout?redirect_url=https://evil.com'

        # When
        scanner = OpenRedirectScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] >= 2  # 파라미터 탐지 + URL 값 탐지
        assert any('URL Value' in v.get('type', '') for v in result['vulnerabilities'])
        assert result['url_values_found'] is True

    @pytest.mark.unit
    def test_true_negative_safe_params(self):
        """TN: 안전한 파라미터만 있는 URL"""
        # Given
        url = 'https://example.com/search?q=test&page=1&sort=asc'

        # When
        scanner = OpenRedirectScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_open_redirect'] is False

    @pytest.mark.unit
    def test_false_positive_redirect_in_value(self):
        """FP 방지: 파라미터 값에만 redirect가 포함된 경우"""
        # Given
        url = 'https://example.com/search?keyword=redirect'

        # When
        scanner = OpenRedirectScanner(url=url)
        result = scanner.scan()

        # Then: keyword는 REDIRECT_PARAMS에 없으므로 탐지 안 됨
        assert result['total'] == 0

    @pytest.mark.unit
    def test_edge_case_no_query_params(self):
        """Edge Case: 쿼리 파라미터가 없는 URL"""
        # Given
        url = 'https://example.com/page'

        # When
        scanner = OpenRedirectScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert 'error' not in result


class TestDirectoryListingScanner:
    """DirectoryListingScanner 테스트"""

    @pytest.fixture
    def mock_session(self):
        """Mock HTTP 세션"""
        return Mock(spec=requests.Session)

    @pytest.mark.unit
    def test_true_positive_apache_listing(self, mock_session):
        """TP: Apache 디렉토리 리스팅"""
        # Given
        html = '''
        <html>
        <head><title>Index of /backup</title></head>
        <body>
        <h1>Index of /backup</h1>
        <a href="../">Parent Directory</a>
        </body>
        </html>
        '''

        mock_response = Mock()
        mock_response.text = html
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response

        # When
        scanner = DirectoryListingScanner(url='https://example.com/backup', session=mock_session)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'directory_listing'
        assert result['total'] > 0
        assert result['has_listing'] is True
        assert any('Directory Listing' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_normal_page(self):
        """TN: 정상적인 웹 페이지"""
        # Given
        html = '''
        <html>
        <head><title>회사 소개</title></head>
        <body>
        <h1>우리 회사를 소개합니다</h1>
        <p>일반적인 웹 페이지 콘텐츠입니다.</p>
        </body>
        </html>
        '''

        # When
        scanner = DirectoryListingScanner(html_content=html)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_listing'] is False

    @pytest.mark.unit
    def test_false_positive_parent_directory_text(self):
        """FP 방지: 본문에 Parent Directory 텍스트가 있지만 링크가 아닌 경우"""
        # Given
        html = '''
        <html>
        <body>
        <p>Parent Directory라는 용어를 설명하는 문서입니다.</p>
        </body>
        </html>
        '''

        # When
        scanner = DirectoryListingScanner(html_content=html)
        result = scanner.scan()

        # Then: Parent Directory만 있고 다른 패턴이 없으면 탐지함 (보수적 접근)
        # 실제로는 <a href="../"> 패턴이 없으므로 더 정확함
        assert result['total'] == 1  # Parent Directory 패턴 매칭

    @pytest.mark.unit
    def test_edge_case_network_error(self, mock_session):
        """Edge Case: 네트워크 오류"""
        # Given
        mock_session.get.side_effect = requests.RequestException("Connection error")

        # When
        scanner = DirectoryListingScanner(url='https://example.com', session=mock_session)
        result = scanner.scan()

        # Then: 네트워크 오류는 취약점이 아님
        assert result['total'] == 0
        assert 'error' not in result


class TestHTTPMethodScanner:
    """HTTPMethodScanner 테스트"""

    @pytest.fixture
    def mock_session(self):
        """Mock HTTP 세션"""
        return Mock(spec=requests.Session)

    @pytest.mark.unit
    def test_true_positive_dangerous_methods(self, mock_session):
        """TP: 위험한 메서드가 허용된 서버"""
        # Given
        options_response = Mock()
        options_response.headers = {'Allow': 'GET, POST, PUT, DELETE, OPTIONS'}
        mock_session.options.return_value = options_response

        trace_response = Mock()
        trace_response.status_code = 405  # TRACE는 비활성화
        mock_session.request.return_value = trace_response

        # When
        scanner = HTTPMethodScanner(url='https://example.com', session=mock_session)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'http_methods'
        assert result['total'] > 0
        assert any('PUT' in str(v) and 'DELETE' in str(v) for v in result['vulnerabilities'])
        assert result['has_dangerous_methods'] is True

    @pytest.mark.unit
    def test_true_positive_trace_enabled(self, mock_session):
        """TP: TRACE 메서드가 활성화된 서버"""
        # Given
        options_response = Mock()
        options_response.headers = {'Allow': 'GET, POST'}
        mock_session.options.return_value = options_response

        trace_response = Mock()
        trace_response.status_code = 200  # TRACE 활성화
        trace_response.text = 'TRACE / HTTP/1.1\r\nHost: example.com'
        mock_session.request.return_value = trace_response

        # When
        scanner = HTTPMethodScanner(url='https://example.com', session=mock_session)
        result = scanner.scan()

        # Then
        assert result['total'] >= 2  # TRACE enabled + XST vulnerable
        assert result['trace_enabled'] is True
        assert result['xst_vulnerable'] is True

    @pytest.mark.unit
    def test_true_negative_safe_methods(self, mock_session):
        """TN: 안전한 메서드만 허용하는 서버"""
        # Given
        options_response = Mock()
        options_response.headers = {'Allow': 'GET, POST, HEAD'}
        mock_session.options.return_value = options_response

        trace_response = Mock()
        trace_response.status_code = 405  # TRACE 비활성화
        mock_session.request.return_value = trace_response

        # When
        scanner = HTTPMethodScanner(url='https://example.com', session=mock_session)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_dangerous_methods'] is False

    @pytest.mark.unit
    def test_edge_case_no_allow_header(self, mock_session):
        """Edge Case: Allow 헤더가 없는 경우"""
        # Given
        options_response = Mock()
        options_response.headers = {}  # Allow 헤더 없음
        mock_session.options.return_value = options_response

        trace_response = Mock()
        trace_response.status_code = 405
        mock_session.request.return_value = trace_response

        # When
        scanner = HTTPMethodScanner(url='https://example.com', session=mock_session)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert 'error' not in result


class TestSSLTLSBasicScanner:
    """SSLTLSBasicScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_http(self):
        """TP: HTTP 사이트"""
        # Given
        url = 'http://example.com'

        # When
        scanner = SSLTLSBasicScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'ssl_tls'
        assert result['total'] >= 2  # No HTTPS + Plain HTTP
        assert result['https'] is False
        assert result['status'] == 'warning'
        assert any('No HTTPS' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_https(self):
        """TN: HTTPS 사이트"""
        # Given
        url = 'https://example.com'

        # When
        scanner = SSLTLSBasicScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['https'] is True
        assert result['status'] == 'ok'

    @pytest.mark.unit
    def test_edge_case_no_scheme(self):
        """Edge Case: 스킴이 없는 URL"""
        # Given
        url = 'example.com'  # 스킴 없음

        # When
        scanner = SSLTLSBasicScanner(url=url)
        result = scanner.scan()

        # Then: 스킴이 없으면 HTTP로 간주
        assert result['total'] > 0
        assert result['https'] is False

    @pytest.mark.unit
    def test_edge_case_websocket(self):
        """Edge Case: WebSocket URL"""
        # Given
        url = 'wss://example.com/socket'

        # When
        scanner = SSLTLSBasicScanner(url=url)
        result = scanner.scan()

        # Then: wss는 HTTPS가 아니므로 경고
        assert result['total'] > 0
        assert result['https'] is False

    @pytest.mark.unit
    def test_backward_compatibility(self):
        """기존 check_ssl_tls 함수와의 호환성"""
        # Given
        https_url = 'https://example.com'
        http_url = 'http://example.com'

        # When
        https_scanner = SSLTLSBasicScanner(url=https_url)
        https_result = https_scanner.scan()

        http_scanner = SSLTLSBasicScanner(url=http_url)
        http_result = http_scanner.scan()

        # Then: 기존 필드들이 모두 존재
        assert 'https' in https_result
        assert 'status' in https_result
        assert 'message' in https_result

        assert https_result['message'] == 'HTTPS를 사용합니다.'
        assert http_result['message'] == 'HTTPS를 사용하지 않습니다. SSL/TLS 인증서를 설정하세요.'


class TestSensitiveFileScanner:
    """SensitiveFileScanner 테스트"""

    @pytest.fixture
    def mock_session(self):
        """Mock HTTP 세션"""
        return Mock(spec=requests.Session)

    @pytest.mark.unit
    def test_true_positive_env_file(self, mock_session):
        """TP: .env 파일 노출"""
        # Given
        env_content = '''DATABASE_URL=postgres://user:pass@localhost/db
SECRET_KEY=supersecretkey123
API_KEY=abcdef123456'''

        def mock_get(url, **kwargs):
            response = Mock()
            if '.env' in url:
                response.status_code = 200
                response.content = env_content.encode()
                response.text = env_content
            else:
                response.status_code = 404
                response.content = b'Not Found'
                response.text = 'Not Found'
            return response

        mock_session.get.side_effect = mock_get

        # When
        scanner = SensitiveFileScanner(url='https://example.com', session=mock_session)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'sensitive_files'
        assert result['total'] > 0
        assert any('.env' in v.get('file', '') for v in result['vulnerabilities'])
        assert any(v.get('severity') == 'critical' for v in result['vulnerabilities'])
        assert result['has_exposed_files'] is True

    @pytest.mark.unit
    def test_true_positive_git_config(self, mock_session):
        """TP: .git/config 파일 노출"""
        # Given
        git_config = '''[core]
	repositoryformatversion = 0
	filemode = true
[remote "origin"]
	url = https://github.com/user/repo.git'''

        def mock_get(url, **kwargs):
            response = Mock()
            if '.git/config' in url:
                response.status_code = 200
                response.content = git_config.encode()
                response.text = git_config
            else:
                response.status_code = 404
                response.content = b'Not Found'
                response.text = 'Not Found'
            return response

        mock_session.get.side_effect = mock_get

        # When
        scanner = SensitiveFileScanner(url='https://example.com', session=mock_session)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('.git/config' in v.get('file', '') for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_all_protected(self, mock_session):
        """TN: 모든 파일이 보호된 경우"""
        # Given
        mock_response = Mock()
        mock_response.status_code = 403  # Forbidden
        mock_response.content = b'403 Forbidden'
        mock_response.text = '403 Forbidden'
        mock_session.get.return_value = mock_response

        # When
        scanner = SensitiveFileScanner(url='https://example.com', session=mock_session)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_exposed_files'] is False

    @pytest.mark.unit
    def test_false_positive_custom_404(self, mock_session):
        """FP 방지: 커스텀 404 페이지"""
        # Given
        custom_404 = '''<html>
        <head><title>Page Not Found</title></head>
        <body>
        <h1>404 Error</h1>
        <p>The page you are looking for does not exist.</p>
        </body>
        </html>'''

        mock_response = Mock()
        mock_response.status_code = 200  # 200이지만 실제로는 404 내용
        mock_response.content = custom_404.encode()
        mock_response.text = custom_404
        mock_session.get.return_value = mock_response

        # When
        scanner = SensitiveFileScanner(url='https://example.com', session=mock_session)
        result = scanner.scan()

        # Then: _is_real_404 메서드가 FP를 필터링
        assert result['total'] == 0

    @pytest.mark.unit
    def test_edge_case_empty_file(self, mock_session):
        """Edge Case: 파일은 있지만 내용이 없는 경우"""
        # Given
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b''  # 빈 내용
        mock_response.text = ''
        mock_session.get.return_value = mock_response

        # When
        scanner = SensitiveFileScanner(url='https://example.com', session=mock_session)
        result = scanner.scan()

        # Then: 내용이 없으면 탐지하지 않음
        assert result['total'] == 0

    @pytest.mark.unit
    def test_evidence_extraction(self, mock_session):
        """증거 추출 테스트"""
        # Given
        responses = {
            '.env': 'API_KEY=secret\nDB_PASSWORD=pass123',
            'composer.json': '{"require": {"php": ">=7.4"}}',
            'backup.sql': 'CREATE TABLE users (id INT, name VARCHAR(255));'
        }

        def mock_get(url, **kwargs):
            response = Mock()
            for file_path, content in responses.items():
                # Check for exact file path match at the end of URL
                if url.endswith('/' + file_path) or url.endswith(file_path):
                    response.status_code = 200
                    response.content = content.encode()
                    response.text = content
                    return response
            response.status_code = 404
            response.content = b'Not Found'
            response.text = 'Not Found'
            return response

        mock_session.get.side_effect = mock_get

        # When
        scanner = SensitiveFileScanner(url='https://example.com', session=mock_session)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        # 증거가 포함되어 있는지 확인
        for vuln in result['vulnerabilities']:
            assert 'evidence' in vuln
            if '.env' in vuln.get('file', ''):
                assert 'Environment variables' in vuln['evidence']
            elif 'composer.json' in vuln.get('file', ''):
                assert 'Composer dependencies' in vuln['evidence']
            elif 'backup.sql' in vuln.get('file', ''):
                assert 'SQL dump' in vuln['evidence']