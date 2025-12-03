"""
Batch 4 고급 스캐너 테스트
SSRF, XXE, Command Injection, Path Traversal, File Upload 스캐너
"""

import pytest
from unittest.mock import Mock
import requests

from scanner.scanners.ssrf import SSRFScanner
from scanner.scanners.xxe import XXEScanner
from scanner.scanners.command_injection import CommandInjectionScanner
from scanner.scanners.path_traversal import PathTraversalScanner
from scanner.scanners.file_upload import FileUploadScanner


class TestSSRFScanner:
    """SSRFScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_url_param(self):
        """TP: URL 파라미터에 SSRF 취약점"""
        # Given
        url = 'https://example.com/fetch?url=http://169.254.169.254/latest/meta-data'

        # When
        scanner = SSRFScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'ssrf'
        assert result['total'] > 0
        assert any('SSRF' in v['type'] for v in result['vulnerabilities'])
        assert result['has_ssrf'] is True

    @pytest.mark.unit
    def test_true_positive_internal_ip(self):
        """TP: 내부 IP 접근 가능"""
        # Given
        url = 'https://example.com/proxy?dest=http://localhost:8080/admin'

        # When
        scanner = SSRFScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('localhost' in str(v) for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_no_url_params(self):
        """TN: URL 파라미터가 없는 경우"""
        # Given
        url = 'https://example.com/page'

        # When
        scanner = SSRFScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_ssrf'] is False

    @pytest.mark.unit
    def test_form_with_url_input(self):
        """TP: URL 입력 폼 필드"""
        # Given
        html_content = '''
        <form action="/submit">
            <input type="url" name="callback" />
            <input type="text" name="proxy" />
        </form>
        '''

        # When
        scanner = SSRFScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Form Input' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_edge_case_no_content(self):
        """Edge Case: 콘텐츠가 없는 경우"""
        # Given
        scanner = SSRFScanner()

        # When
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert 'error' not in result


class TestXXEScanner:
    """XXEScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_xml_content_type(self):
        """TP: XML Content-Type 헤더"""
        # Given
        response = Mock()
        response.headers = {'Content-Type': 'application/xml'}

        # When
        scanner = XXEScanner(response=response)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'xxe'
        assert result['total'] > 0
        assert any('XML Processing' in v['type'] for v in result['vulnerabilities'])
        assert result['has_xxe'] is True

    @pytest.mark.unit
    def test_true_positive_xml_file_upload(self):
        """TP: XML 파일 업로드 허용"""
        # Given
        html_content = '''
        <form>
            <input type="file" name="upload" accept=".xml,application/xml" />
        </form>
        '''

        # When
        scanner = XXEScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('XML File Upload' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_xml_doctype(self):
        """TP: XML DOCTYPE 선언"""
        # Given
        html_content = '''<?xml version="1.0"?>
        <!DOCTYPE root>
        <root>data</root>
        '''

        # When
        scanner = XXEScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('DOCTYPE' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_no_xml(self):
        """TN: XML이 없는 경우"""
        # Given
        response = Mock()
        response.headers = {'Content-Type': 'text/html'}
        html_content = '<html><body>No XML here</body></html>'

        # When
        scanner = XXEScanner(response=response, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_xxe'] is False

    @pytest.mark.unit
    def test_file_upload_without_accept(self):
        """TP: accept 속성이 없는 파일 업로드 (모든 파일 허용)"""
        # Given
        html_content = '''
        <form>
            <input type="file" name="document" />
        </form>
        '''

        # When
        scanner = XXEScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('all files' in str(v) for v in result['vulnerabilities'])


class TestCommandInjectionScanner:
    """CommandInjectionScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_cmd_param(self):
        """TP: 명령어 관련 파라미터"""
        # Given
        url = 'https://example.com/run?cmd=ls%20-la'

        # When
        scanner = CommandInjectionScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'command_injection'
        assert result['total'] > 0
        assert any('Command Injection' in v['type'] for v in result['vulnerabilities'])
        assert result['has_command_injection'] is True

    @pytest.mark.unit
    def test_true_positive_dangerous_chars(self):
        """TP: 위험한 문자가 포함된 파라미터 값"""
        # Given
        url = 'https://example.com/ping?host=8.8.8.8;whoami'

        # When
        scanner = CommandInjectionScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any(v.get('severity') == 'critical' for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_exec_pattern(self):
        """TP: 명령 실행 패턴 발견"""
        # Given
        html_content = '''
        <script>
        function runCommand() {
            exec(userInput);
        }
        </script>
        '''

        # When
        scanner = CommandInjectionScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Pattern Detected' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_safe_params(self):
        """TN: 안전한 파라미터"""
        # Given
        url = 'https://example.com/search?q=test&page=1'
        html_content = '<html><body>Safe content</body></html>'

        # When
        scanner = CommandInjectionScanner(url=url, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_command_injection'] is False

    @pytest.mark.unit
    def test_form_with_command_input(self):
        """TP: 명령어 관련 폼 입력"""
        # Given
        html_content = '''
        <form action="/execute">
            <input name="cmd" type="text" />
            <textarea name="script"></textarea>
        </form>
        '''

        # When
        scanner = CommandInjectionScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Form Input' in v['type'] for v in result['vulnerabilities'])


class TestPathTraversalScanner:
    """PathTraversalScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_traversal_pattern(self):
        """TP: 경로 순회 패턴"""
        # Given
        url = 'https://example.com/download?file=../../../etc/passwd'

        # When
        scanner = PathTraversalScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'path_traversal'
        assert result['total'] > 0
        assert any(v.get('severity') == 'critical' for v in result['vulnerabilities'])
        assert result['has_path_traversal'] is True

    @pytest.mark.unit
    def test_true_positive_encoded_traversal(self):
        """TP: 인코딩된 경로 순회"""
        # Given
        url = 'https://example.com/read?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd'

        # When
        scanner = PathTraversalScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Path Traversal' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_path_param(self):
        """TP: 경로 관련 파라미터"""
        # Given
        url = 'https://example.com/view?document=report.pdf'

        # When
        scanner = PathTraversalScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert result['has_path_traversal'] is True

    @pytest.mark.unit
    def test_true_negative_no_path_params(self):
        """TN: 경로 관련 파라미터가 없는 경우"""
        # Given
        url = 'https://example.com/search?q=test&sort=asc'

        # When
        scanner = PathTraversalScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_path_traversal'] is False

    @pytest.mark.unit
    def test_url_path_detection(self):
        """TP: URL 경로에서 파일 접근 패턴"""
        # Given
        url = 'https://example.com/files/document/report'  # 'document'는 PATH_PARAMS에 포함

        # When
        scanner = PathTraversalScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('URL Path' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_edge_case_no_url(self):
        """Edge Case: URL이 제공되지 않은 경우"""
        # Given
        scanner = PathTraversalScanner()

        # When
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert 'error' not in result


class TestFileUploadScanner:
    """FileUploadScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_unrestricted_upload(self):
        """TP: 제한 없는 파일 업로드"""
        # Given
        html_content = '''
        <form>
            <input type="file" name="upload" />
        </form>
        '''

        # When
        scanner = FileUploadScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['scanner_id'] == 'file_upload'
        assert result['total'] > 0
        assert any('Unrestricted' in v['type'] for v in result['vulnerabilities'])
        assert any(v.get('severity') == 'critical' for v in result['vulnerabilities'])
        assert result['has_file_upload'] is True

    @pytest.mark.unit
    def test_true_positive_dangerous_extensions(self):
        """TP: 위험한 확장자 허용"""
        # Given
        html_content = '''
        <form>
            <input type="file" name="script" accept=".php,.asp,.jsp" />
        </form>
        '''

        # When
        scanner = FileUploadScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Dangerous' in v['type'] for v in result['vulnerabilities'])
        assert any('php' in str(v) for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_wildcard_accept(self):
        """TP: 와일드카드 accept 속성"""
        # Given
        html_content = '''
        <form>
            <input type="file" name="any" accept="*/*" />
        </form>
        '''

        # When
        scanner = FileUploadScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any(v.get('severity') == 'critical' for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_client_side_validation(self):
        """TP: 클라이언트 사이드 검증만 있는 경우"""
        # Given
        html_content = '''
        <form>
            <input type="file" name="image" accept="image/*" />
        </form>
        '''

        # When
        scanner = FileUploadScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Server Validation' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_no_file_input(self):
        """TN: 파일 업로드가 없는 경우"""
        # Given
        html_content = '''
        <form>
            <input type="text" name="username" />
            <input type="password" name="password" />
        </form>
        '''

        # When
        scanner = FileUploadScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_file_upload'] is False

    @pytest.mark.unit
    def test_edge_case_no_content(self):
        """Edge Case: HTML 콘텐츠가 없는 경우"""
        # Given
        scanner = FileUploadScanner()

        # When
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert 'error' not in result