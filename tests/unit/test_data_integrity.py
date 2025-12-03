"""
Batch 9 Data Integrity Security Scanners 단위 테스트
"""

import unittest
from unittest.mock import Mock, MagicMock, patch
import json
import base64

from scanner.scanners.jwt_advanced_scanner import JWTAdvancedScanner
from scanner.scanners.serialization_integrity_scanner import SerializationIntegrityScanner
from scanner.scanners.api_integrity_scanner import APIIntegrityScanner
from scanner.scanners.checksum_validation_scanner import ChecksumValidationScanner


class TestJWTAdvancedScanner(unittest.TestCase):
    """JWTAdvancedScanner 테스트"""

    def setUp(self):
        self.scanner = JWTAdvancedScanner(
            url='https://example.com',
            html_content='<html></html>'
        )

    def test_no_algorithm_jwt(self):
        """알고리즘이 none인 JWT 탐지"""
        # none 알고리즘 JWT
        header = base64.urlsafe_b64encode(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()).decode().rstrip('=')
        payload = base64.urlsafe_b64encode(json.dumps({'sub': '1234'}).encode()).decode().rstrip('=')
        jwt_token = f"{header}.{payload}."

        html = f'<script>const token = "{jwt_token}";</script>'
        scanner = JWTAdvancedScanner(url='https://example.com', html_content=html)

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('No Algorithm' in v.get('type', '') for v in vulns))

    def test_weak_secret_detection(self):
        """약한 시크릿 탐지"""
        # HS256 with weak secret
        header = base64.urlsafe_b64encode(json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode()).decode().rstrip('=')
        payload = base64.urlsafe_b64encode(json.dumps({'sub': '1234'}).encode()).decode().rstrip('=')

        # 실제로 'secret'으로 서명된 토큰 생성 (간단한 시뮬레이션)
        import hmac
        import hashlib
        message = f"{header}.{payload}"
        signature = base64.urlsafe_b64encode(
            hmac.new(b'secret', message.encode(), hashlib.sha256).digest()
        ).decode().rstrip('=')

        jwt_token = f"{message}.{signature}"

        html = f'<script>const token = "{jwt_token}";</script>'
        scanner = JWTAdvancedScanner(url='https://example.com', html_content=html)

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Weak Secret' in v.get('type', '') for v in vulns))

    def test_kid_injection_vulnerability(self):
        """Kid 인젝션 취약점 탐지"""
        header = base64.urlsafe_b64encode(
            json.dumps({'alg': 'RS256', 'kid': '../../../etc/passwd'}).encode()
        ).decode().rstrip('=')
        payload = base64.urlsafe_b64encode(json.dumps({'sub': '1234'}).encode()).decode().rstrip('=')
        jwt_token = f"{header}.{payload}.signature"

        html = f'<script>const token = "{jwt_token}";</script>'
        scanner = JWTAdvancedScanner(url='https://example.com', html_content=html)

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Kid Injection' in v.get('type', '') for v in vulns))

    def test_missing_jwt_claims(self):
        """필수 JWT claims 누락 탐지"""
        header = base64.urlsafe_b64encode(json.dumps({'alg': 'HS256'}).encode()).decode().rstrip('=')
        # exp, iss, aud가 없는 payload
        payload = base64.urlsafe_b64encode(json.dumps({'sub': '1234'}).encode()).decode().rstrip('=')
        jwt_token = f"{header}.{payload}.signature"

        html = f'<script>const token = "{jwt_token}";</script>'
        scanner = JWTAdvancedScanner(url='https://example.com', html_content=html)

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']

        # exp, iss, aud 누락 확인
        vuln_types = [v.get('type', '') for v in vulns]
        self.assertTrue(any('No Expiration' in t for t in vuln_types))
        self.assertTrue(any('No Issuer' in t for t in vuln_types))
        self.assertTrue(any('No Audience' in t for t in vuln_types))

    def test_jwk_exposure(self):
        """JWK 노출 탐지"""
        html = '''
        <script>
        const jwk = {
            "kty": "RSA",
            "kid": "key-1",
            "use": "sig",
            "n": "xGOr-H0A-6_BOXI7an...",
            "e": "AQAB"
        };
        </script>
        '''

        scanner = JWTAdvancedScanner(url='https://example.com', html_content=html)

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('JWK Exposure' in v.get('type', '') for v in vulns))

    def test_clean_jwt(self):
        """정상적인 JWT"""
        # RS256 with proper claims
        header = base64.urlsafe_b64encode(json.dumps({'alg': 'RS256', 'typ': 'JWT'}).encode()).decode().rstrip('=')
        import time
        payload = base64.urlsafe_b64encode(json.dumps({
            'sub': '1234',
            'exp': int(time.time()) + 3600,
            'iss': 'example.com',
            'aud': 'api.example.com'
        }).encode()).decode().rstrip('=')
        jwt_token = f"{header}.{payload}.signature"

        html = f'<script>const token = "{jwt_token}";</script>'
        scanner = JWTAdvancedScanner(url='https://example.com', html_content=html)

        result = scanner.scan()
        self.assertTrue(len(result.get('vulnerabilities', [])) == 0)


class TestSerializationIntegrityScanner(unittest.TestCase):
    """SerializationIntegrityScanner 테스트"""

    def setUp(self):
        self.scanner = SerializationIntegrityScanner(
            url='https://example.com',
            html_content='<html></html>'
        )

    def test_unsigned_session_cookie(self):
        """서명되지 않은 세션 쿠키 탐지"""
        response = Mock()
        response.headers = {
            'Set-Cookie': 'sessionid=abcd1234; HttpOnly'
        }

        scanner = SerializationIntegrityScanner(
            url='https://example.com',
            response=response
        )

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Unsigned Session Cookie' in v.get('type', '') for v in vulns))

    def test_python_pickle_detection(self):
        """Python Pickle 직렬화 탐지"""
        # Base64 encoded pickle
        pickle_data = base64.b64encode(b'\x80\x03}q\x00.').decode()
        html = f'<input type="hidden" name="state" value="{pickle_data}">'

        scanner = SerializationIntegrityScanner(
            url='https://example.com',
            html_content=html
        )

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Pickle' in v.get('type', '') for v in vulns))

    def test_php_serialization_detection(self):
        """PHP 직렬화 탐지"""
        html = '''
        <input type="hidden" name="data" value='a:2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}'>
        '''

        scanner = SerializationIntegrityScanner(
            url='https://example.com',
            html_content=html
        )

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('PHP Serialization' in v.get('type', '') for v in vulns))

    def test_unsafe_json_parsing(self):
        """안전하지 않은 JSON 파싱 탐지"""
        html = '''
        <script>
        var data = eval('(' + jsonString + ')');
        </script>
        '''

        scanner = SerializationIntegrityScanner(
            url='https://example.com',
            html_content=html
        )

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Unsafe JSON Parsing' in v.get('type', '') for v in vulns))

    def test_signed_cookie(self):
        """서명된 쿠키 (안전)"""
        response = Mock()
        response.headers = {
            'Set-Cookie': 'session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.signature; HttpOnly'
        }

        scanner = SerializationIntegrityScanner(
            url='https://example.com',
            response=response
        )

        result = scanner.scan()
        self.assertTrue(len(result.get('vulnerabilities', [])) == 0)


class TestAPIIntegrityScanner(unittest.TestCase):
    """APIIntegrityScanner 테스트"""

    def setUp(self):
        self.scanner = APIIntegrityScanner(
            url='https://example.com/api',
            html_content='<html></html>'
        )

    def test_missing_api_signature(self):
        """API 응답 서명 누락"""
        response = Mock()
        response.headers = {
            'Content-Type': 'application/json'
        }

        scanner = APIIntegrityScanner(
            url='https://example.com/api',
            response=response
        )

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('No API Response Signature' in v.get('type', '') for v in vulns))

    def test_weak_digest_algorithm(self):
        """약한 다이제스트 알고리즘"""
        response = Mock()
        response.headers = {
            'Content-Type': 'application/json',
            'Digest': 'MD5=1234567890abcdef'
        }

        scanner = APIIntegrityScanner(
            url='https://example.com/api',
            response=response
        )

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Weak Digest Algorithm' in v.get('type', '') for v in vulns))

    def test_weak_etag(self):
        """Weak ETag 탐지"""
        response = Mock()
        response.headers = {
            'Content-Type': 'application/json',
            'ETag': 'W/"123"'
        }

        scanner = APIIntegrityScanner(
            url='https://example.com/api',
            response=response
        )

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Weak ETag' in v.get('type', '') for v in vulns))

    def test_deprecated_content_md5(self):
        """Deprecated Content-MD5 헤더"""
        response = Mock()
        response.headers = {
            'Content-Type': 'application/json',
            'Content-MD5': '1234567890abcdef'
        }

        scanner = APIIntegrityScanner(
            url='https://example.com/api',
            response=response
        )

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Deprecated Content-MD5' in v.get('type', '') for v in vulns))

    def test_no_api_versioning(self):
        """API 버전 관리 없음"""
        scanner = APIIntegrityScanner(
            url='https://example.com/api/users'
        )

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('No API Versioning' in v.get('type', '') for v in vulns))

    def test_secure_api(self):
        """안전한 API 응답"""
        response = Mock()
        response.headers = {
            'Content-Type': 'application/json',
            'X-Signature': 'sha256=abcdef...',
            'ETag': '"a1b2c3d4e5f6789012345678901234567890"',
            'API-Version': 'v1'
        }

        scanner = APIIntegrityScanner(
            url='https://example.com/api/v1/users',
            response=response
        )

        result = scanner.scan()
        self.assertTrue(len(result.get('vulnerabilities', [])) == 0)


class TestChecksumValidationScanner(unittest.TestCase):
    """ChecksumValidationScanner 테스트"""

    def setUp(self):
        self.scanner = ChecksumValidationScanner(
            url='https://example.com',
            html_content='<html></html>'
        )
        self.mock_http = Mock()
        self.scanner.http_client = self.mock_http

    def test_no_download_checksums(self):
        """다운로드 파일 체크섬 없음"""
        html = '''
        <html>
        <a href="/download/software.zip">Download Software</a>
        </html>
        '''

        scanner = ChecksumValidationScanner(
            url='https://example.com',
            html_content=html
        )

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('No Download Checksums' in v.get('type', '') for v in vulns))

    def test_weak_checksum_algorithm(self):
        """약한 체크섬 알고리즘"""
        html = '''
        <html>
        <a href="/download/software.zip">Download Software</a>
        <p>MD5: 1234567890abcdef1234567890abcdef</p>
        </html>
        '''

        scanner = ChecksumValidationScanner(
            url='https://example.com',
            html_content=html
        )

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Weak Checksum Algorithm' in v.get('type', '') for v in vulns))

    def test_md5_checksum_file(self):
        """MD5 체크섬 파일 탐지"""
        self.mock_http.get.return_value = Mock(
            status_code=200,
            text='1234567890abcdef1234567890abcdef  file.tar.gz'
        )

        result = self.scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('MD5 Checksum File' in v.get('type', '') for v in vulns))

    def test_unsigned_checksum_file(self):
        """서명되지 않은 체크섬 파일"""
        self.mock_http.get.side_effect = [
            Mock(  # SHA256SUMS
                status_code=200,
                text='abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890  file.tar.gz'
            ),
            Mock(status_code=404)  # SHA512SUMS
        ]

        result = self.scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('Unsigned Checksum File' in v.get('type', '') for v in vulns))

    def test_no_upload_checksum_validation(self):
        """파일 업로드 체크섬 검증 없음"""
        html = '''
        <html>
        <form>
            <input type="file" name="upload">
            <button type="submit">Upload</button>
        </form>
        </html>
        '''

        scanner = ChecksumValidationScanner(
            url='https://example.com',
            html_content=html
        )

        result = scanner.scan()
        self.assertFalse(len(result.get('vulnerabilities', [])) == 0)
        vulns = result['vulnerabilities']
        self.assertTrue(any('No Upload Checksum Validation' in v.get('type', '') for v in vulns))

    def test_secure_checksums(self):
        """안전한 체크섬 구현"""
        html = '''
        <html>
        <a href="/download/software.zip">Download Software</a>
        <p>SHA256: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890</p>
        </html>
        '''

        scanner = ChecksumValidationScanner(
            url='https://example.com',
            html_content=html
        )
        scanner.http_client = Mock()
        scanner.http_client.get.return_value = Mock(status_code=404)

        result = scanner.scan()
        self.assertTrue(len(result.get('vulnerabilities', [])) == 0)


class TestScannerIntegration(unittest.TestCase):
    """Batch 9 스캐너 통합 테스트"""

    def test_all_scanners_have_metadata(self):
        """모든 스캐너가 올바른 메타데이터를 가지고 있는지 확인"""
        scanners = [
            JWTAdvancedScanner,
            SerializationIntegrityScanner,
            APIIntegrityScanner,
            ChecksumValidationScanner
        ]

        for scanner_class in scanners:
            scanner = scanner_class()
            metadata = scanner.get_metadata()

            # 필수 메타데이터 필드 확인
            self.assertIn('id', metadata)
            self.assertIn('name', metadata)
            self.assertIn('category', metadata)
            self.assertIn('severity', metadata)
            self.assertIn('description', metadata)
            self.assertIn('owasp', metadata)

            # OWASP 카테고리가 리스트인지 확인
            self.assertIsInstance(metadata['owasp'], list)
            self.assertTrue(len(metadata['owasp']) > 0)

    def test_all_scanners_return_consistent_results(self):
        """모든 스캐너가 일관된 결과 형식을 반환하는지 확인"""
        scanners = [
            JWTAdvancedScanner(),
            SerializationIntegrityScanner(),
            APIIntegrityScanner(),
            ChecksumValidationScanner()
        ]

        for scanner in scanners:
            result = scanner.scan()

            # 필수 결과 필드 확인
            self.assertIn('passed', result)
            self.assertIn('vulnerabilities', result)
            self.assertIn('severity', result)
            self.assertIn('message', result)

            # 데이터 타입 확인
            self.assertIsInstance(len(result.get('vulnerabilities', [])) == 0, bool)
            self.assertIsInstance(result['vulnerabilities'], list)
            self.assertIn(result['severity'], ['low', 'medium', 'high', 'critical'])
            self.assertIsInstance(result['message'], str)


if __name__ == '__main__':
    unittest.main()