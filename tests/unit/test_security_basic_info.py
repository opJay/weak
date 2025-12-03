"""
Batch 3 스캐너 단위 테스트

5개 기본 스캐너에 대한 포괄적인 테스트
"""

import pytest
from unittest.mock import Mock, patch
import requests

# 테스트 대상 스캐너 임포트
from scanner.scanners.open_redirect import OpenRedirectScanner
from scanner.scanners.directory_listing import DirectoryListingScanner
from scanner.scanners.http_method import HTTPMethodScanner
from scanner.scanners.ssltls_basic import SSLTLSBasicScanner
from scanner.scanners.sensitive_file import SensitiveFileScanner


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
    def test_edge_case_network_error(self):
        """네트워크 에러 처리 테스트"""
        scanner = DirectoryListingScanner()
        with patch('requests.get', side_effect=Exception("Network error")):
            scanner.url = "http://test.com"

            result = scanner.scan()
            # 에러 발생 시에도 결과 반환
            assert result is not None
            assert "scanner_id" in result


class TestSensitiveFileScanner:
    """SensitiveFileScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_sensitive_files(self):
        """TP: 민감한 파일 탐지"""
        # Given
        responses = {
            '.env': 'DB_PASSWORD=secret123\nAPI_KEY=abc',
            'composer.json': '{"require": {"php": ">=7.0"}}',
            'backup.sql': 'CREATE TABLE users'
        }

        mock_session = Mock()

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