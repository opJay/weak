"""
Batch 8 Supply Chain Security Scanners 단위 테스트
"""

import unittest
from unittest.mock import Mock, MagicMock
import json

from scanner.scanners_refactored_batch8 import (
    SoftwareSupplyChainScanner,
    PackageIntegrityScanner,
    TyposquattingScanner,
    OutdatedDependencyScanner,
    LicenseComplianceScanner
)


class TestSoftwareSupplyChainScanner(unittest.TestCase):
    """SoftwareSupplyChainScanner 테스트"""

    def setUp(self):
        self.scanner = SoftwareSupplyChainScanner(
            url='https://example.com',
            html_content='<html></html>'
        )
        self.mock_http = Mock()
        self.scanner.http_client = self.mock_http

    def test_exposed_dependencies_with_secrets(self):
        """종속성 파일에서 민감한 정보 탐지"""
        # package.json with API key
        self.mock_http.get.return_value = Mock(
            status_code=200,
            text='{"dependencies": {}, "api_key": "sk-1234567890abcdef"}'
        )

        result = self.scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        # 민감한 정보 노출과 파일 노출 둘 다 탐지
        self.assertEqual(len(vulns), 2)
        self.assertTrue(any(v['type'] == 'sensitive_info_in_dependencies' for v in vulns))
        self.assertTrue(any(v['type'] == 'exposed_dependency_file' for v in vulns))

    def test_missing_sri_on_cdn_scripts(self):
        """CDN 스크립트의 SRI 누락 탐지"""
        html = '''
        <html>
        <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/axios/0.21.1/axios.min.js"></script>
        </html>
        '''

        scanner = SoftwareSupplyChainScanner(
            url='https://example.com',
            html_content=html
        )

        result = scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        sri_vulns = [v for v in vulns if v['type'] == 'missing_sri']
        self.assertEqual(len(sri_vulns), 2)

    def test_vulnerable_library_detection(self):
        """취약한 라이브러리 버전 탐지"""
        html = '''
        <html>
        <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
        <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.2.32/angular.min.js"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
        </html>
        '''

        scanner = SoftwareSupplyChainScanner(
            url='https://example.com',
            html_content=html
        )

        result = scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        lib_vulns = [v for v in vulns if v['type'] == 'vulnerable_library']
        self.assertGreaterEqual(len(lib_vulns), 3)

    def test_clean_site(self):
        """깨끗한 사이트 테스트"""
        html = '''
        <html>
        <script src="/js/app.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js"
                integrity="sha384-hmo9q6p..."></script>
        </html>
        '''

        scanner = SoftwareSupplyChainScanner(
            url='https://example.com',
            html_content=html
        )
        self.mock_http.get.return_value = Mock(status_code=404)
        scanner.http_client = self.mock_http

        result = scanner.scan()
        self.assertTrue(result['passed'])


class TestPackageIntegrityScanner(unittest.TestCase):
    """PackageIntegrityScanner 테스트"""

    def setUp(self):
        self.scanner = PackageIntegrityScanner(
            url='https://example.com',
            html_content='<html></html>'
        )
        self.mock_http = Mock()
        self.scanner.http_client = self.mock_http

    def test_weak_hash_in_lockfile(self):
        """Lockfile에서 약한 해시 알고리즘 탐지"""
        # package-lock.json with SHA-1 hashes
        lockfile_content = '''
        {
          "packages": {
            "axios": {
              "version": "0.21.1",
              "integrity": "sha1-IlY0gZY/qRbVz..."
            },
            "lodash": {
              "version": "4.17.21",
              "integrity": "sha512-v2kDEe57l..."
            }
          }
        }
        '''

        self.mock_http.get.return_value = Mock(
            status_code=200,
            text=lockfile_content
        )

        result = self.scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        weak_hash_vulns = [v for v in vulns if v['type'] == 'weak_hash_algorithm']
        self.assertEqual(len(weak_hash_vulns), 1)
        self.assertEqual(weak_hash_vulns[0]['algorithm'], 'SHA-1')

    def test_missing_integrity_in_lockfile(self):
        """Lockfile에서 무결성 해시 누락 탐지"""
        lockfile_content = '''
        {
          "packages": {
            "axios": {
              "version": "0.21.1"
            }
          }
        }
        '''

        self.mock_http.get.return_value = Mock(
            status_code=200,
            text=lockfile_content
        )

        result = self.scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        missing_integrity = [v for v in vulns if v['type'] == 'missing_integrity']
        self.assertEqual(len(missing_integrity), 1)

    def test_weak_sri_algorithm(self):
        """약한 SRI 알고리즘 탐지"""
        html = '''
        <html>
        <script src="https://cdn.example.com/lib.js"
                integrity="sha1-abc123..."></script>
        </html>
        '''

        scanner = PackageIntegrityScanner(
            url='https://example.com',
            html_content=html
        )

        result = scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        weak_sri = [v for v in vulns if v['type'] == 'weak_sri_algorithm']
        self.assertEqual(len(weak_sri), 1)

    def test_md5_checksum_detection(self):
        """MD5 체크섬 파일 탐지"""
        self.mock_http.get.side_effect = [
            Mock(status_code=404),  # package-lock.json
            Mock(status_code=404),  # yarn.lock
            Mock(status_code=404),  # Pipfile.lock
            Mock(status_code=404),  # poetry.lock
            Mock(status_code=404),  # composer.lock
            Mock(status_code=404),  # Gemfile.lock
            Mock(status_code=404),  # go.sum
            Mock(status_code=404),  # SHA256SUMS
            Mock(status_code=404),  # SHA512SUMS
            Mock(status_code=200, text='a1b2c3d4e5f6789012345678  file.tar.gz'),  # MD5SUMS
        ]

        result = self.scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        weak_checksum = [v for v in vulns if v['type'] == 'weak_checksum_algorithm']
        self.assertEqual(len(weak_checksum), 1)
        self.assertEqual(weak_checksum[0]['algorithm'], 'MD5')


class TestTyposquattingScanner(unittest.TestCase):
    """TyposquattingScanner 테스트"""

    def setUp(self):
        self.scanner = TyposquattingScanner(
            url='https://example.com',
            html_content='<html></html>'
        )
        self.mock_http = Mock()
        self.scanner.http_client = self.mock_http

    def test_typosquatting_in_package_json(self):
        """package.json에서 타이포스쿼팅 탐지"""
        package_json = '''
        {
          "dependencies": {
            "reakt": "^17.0.0",
            "expresss": "^4.17.0",
            "lodahs": "^4.17.0"
          }
        }
        '''

        self.mock_http.get.return_value = Mock(
            status_code=200,
            text=package_json
        )

        result = self.scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        typo_vulns = [v for v in vulns if v['type'] == 'typosquatting']
        self.assertGreaterEqual(len(typo_vulns), 2)  # reakt와 expresss 최소 탐지

    def test_suspicious_package_names(self):
        """의심스러운 패키지명 패턴 탐지"""
        package_json = '''
        {
          "dependencies": {
            "test-package": "1.0.0",
            "my-app-temp": "2.0.0",
            "demo-lib": "0.1.0"
          }
        }
        '''

        self.mock_http.get.return_value = Mock(
            status_code=200,
            text=package_json
        )

        result = self.scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        suspicious = [v for v in vulns if v['type'] == 'suspicious_package_name']
        self.assertGreaterEqual(len(suspicious), 2)

    def test_cdn_typosquatting(self):
        """CDN URL에서 타이포스쿼팅 탐지"""
        html = '''
        <html>
        <script src="https://unpkg.com/reakt@17.0.0/index.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/expresss@4.17.0"></script>
        </html>
        '''

        scanner = TyposquattingScanner(
            url='https://example.com',
            html_content=html
        )

        result = scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        cdn_typo = [v for v in vulns if v['type'] == 'cdn_typosquatting']
        self.assertEqual(len(cdn_typo), 2)

    def test_clean_dependencies(self):
        """정상적인 종속성"""
        package_json = '''
        {
          "dependencies": {
            "react": "^17.0.0",
            "express": "^4.17.0",
            "lodash": "^4.17.0"
          }
        }
        '''

        self.mock_http.get.return_value = Mock(
            status_code=200,
            text=package_json
        )

        result = self.scanner.scan()
        self.assertTrue(result['passed'])


class TestOutdatedDependencyScanner(unittest.TestCase):
    """OutdatedDependencyScanner 테스트"""

    def setUp(self):
        self.scanner = OutdatedDependencyScanner(
            url='https://example.com',
            html_content='<html></html>'
        )
        self.mock_http = Mock()
        self.scanner.http_client = self.mock_http

    def test_vulnerable_dependency_versions(self):
        """알려진 취약한 버전 탐지"""
        package_json = '''
        {
          "dependencies": {
            "lodash": "3.10.1",
            "minimist": "0.2.1",
            "axios": "0.18.0"
          }
        }
        '''

        self.mock_http.get.side_effect = [
            Mock(status_code=200, text=package_json),  # package.json
            Mock(status_code=404)  # requirements.txt
        ]

        result = self.scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        vuln_deps = [v for v in vulns if v['type'] == 'vulnerable_dependency']
        self.assertGreaterEqual(len(vuln_deps), 3)

        # CVE 정보 확인
        self.assertTrue(any('CVE-' in v.get('cve', '') for v in vuln_deps))

    def test_pre_release_versions(self):
        """프리릴리즈 버전 탐지"""
        package_json = '''
        {
          "dependencies": {
            "my-lib": "^0.1.0",
            "another-lib": "^0.9.5"
          }
        }
        '''

        self.mock_http.get.side_effect = [
            Mock(status_code=200, text=package_json),  # package.json
            Mock(status_code=404)  # requirements.txt
        ]

        result = self.scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        pre_release = [v for v in vulns if v['type'] == 'pre_release_version']
        self.assertEqual(len(pre_release), 2)

    def test_eol_cdn_libraries(self):
        """EOL CDN 라이브러리 탐지"""
        html = '''
        <html>
        <script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
        <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.5.8/angular.min.js"></script>
        <script src="https://unpkg.com/react@15.6.2/dist/react.js"></script>
        </html>
        '''

        scanner = OutdatedDependencyScanner(
            url='https://example.com',
            html_content=html
        )
        self.mock_http.get.return_value = Mock(status_code=404)
        scanner.http_client = self.mock_http

        result = scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        eol_libs = [v for v in vulns if v['type'] == 'eol_cdn_library']
        self.assertGreaterEqual(len(eol_libs), 3)

    def test_eol_runtime_versions(self):
        """EOL 런타임 버전 탐지"""
        self.mock_http.get.side_effect = [
            Mock(status_code=404),  # package.json
            Mock(status_code=404),  # requirements.txt
            Mock(status_code=200, text='14.17.0'),  # .nvmrc - EOL Node.js
            Mock(status_code=200, text='3.6.0')  # .python-version - EOL Python
        ]

        result = self.scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        eol_runtime = [v for v in vulns if v['type'] == 'eol_runtime']
        self.assertEqual(len(eol_runtime), 2)

    def test_up_to_date_dependencies(self):
        """최신 종속성"""
        package_json = '''
        {
          "dependencies": {
            "react": "^18.2.0",
            "lodash": "^4.17.21",
            "axios": "^1.3.0"
          }
        }
        '''

        self.mock_http.get.side_effect = [
            Mock(status_code=200, text=package_json),
            Mock(status_code=404),  # requirements.txt
            Mock(status_code=404),  # .nvmrc
            Mock(status_code=404)   # .python-version
        ]

        result = self.scanner.scan()
        self.assertTrue(result['passed'])


class TestLicenseComplianceScanner(unittest.TestCase):
    """LicenseComplianceScanner 테스트"""

    def setUp(self):
        self.scanner = LicenseComplianceScanner(
            url='https://example.com',
            html_content='<html></html>'
        )
        self.mock_http = Mock()
        self.scanner.http_client = self.mock_http

    def test_copyleft_license_detection(self):
        """Copyleft 라이선스 탐지"""
        license_content = '''
        GNU GENERAL PUBLIC LICENSE
        Version 3, 29 June 2007
        '''

        self.mock_http.get.side_effect = [
            Mock(status_code=200, text=license_content),  # LICENSE
        ]

        result = self.scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        copyleft = [v for v in vulns if v['type'] == 'copyleft_license']
        self.assertEqual(len(copyleft), 1)
        self.assertIn('GPL', copyleft[0]['license'])

    def test_commercial_restriction(self):
        """상업적 사용 제한 라이선스 탐지"""
        license_content = '''
        This work is licensed under CC-BY-NC-SA 4.0
        NonCommercial use only
        '''

        self.mock_http.get.side_effect = [
            Mock(status_code=200, text=license_content),  # LICENSE
        ]

        result = self.scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        commercial = [v for v in vulns if v['type'] == 'commercial_restriction']
        self.assertEqual(len(commercial), 1)

    def test_missing_license(self):
        """라이선스 파일 누락"""
        self.mock_http.get.return_value = Mock(status_code=404)

        result = self.scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        missing = [v for v in vulns if v['type'] == 'missing_license']
        self.assertEqual(len(missing), 1)

    def test_copyleft_dependencies(self):
        """Copyleft 종속성 탐지"""
        package_json = '{"dependencies": {}}'
        package_lock = '''
        {
          "packages": {
            "some-gpl-lib": {
              "version": "1.0.0",
              "license": "GPL-3.0"
            },
            "another-lib": {
              "version": "2.0.0",
              "license": "AGPL-3.0"
            }
          }
        }
        '''

        self.mock_http.get.side_effect = [
            Mock(status_code=404),  # LICENSE files
            Mock(status_code=404),
            Mock(status_code=404),
            Mock(status_code=404),
            Mock(status_code=200, text=package_json),  # package.json
            Mock(status_code=200, text=package_lock),  # package-lock.json
            Mock(status_code=200, text=package_json),  # package.json (compatibility check)
            Mock(status_code=200, text=package_lock)   # package-lock.json (compatibility check)
        ]

        result = self.scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        copyleft_deps = [v for v in vulns if v['type'] == 'copyleft_dependencies']
        self.assertEqual(len(copyleft_deps), 1)
        self.assertEqual(copyleft_deps[0]['count'], 2)

    def test_license_compatibility(self):
        """라이선스 호환성 문제 탐지"""
        package_json = '{"license": "MIT"}'
        package_lock = '''
        {
          "packages": {
            "gpl-lib": {
              "version": "1.0.0",
              "license": "GPL-3.0"
            }
          }
        }
        '''

        self.mock_http.get.side_effect = [
            Mock(status_code=404),  # LICENSE files
            Mock(status_code=404),
            Mock(status_code=404),
            Mock(status_code=404),
            Mock(status_code=200, text=package_json),  # package.json
            Mock(status_code=200, text=package_lock),  # package-lock.json
            Mock(status_code=200, text=package_json),  # package.json (compatibility)
            Mock(status_code=200, text=package_lock.upper())   # package-lock.json (GPL check)
        ]

        result = self.scanner.scan()
        self.assertFalse(result['passed'])
        vulns = result['vulnerabilities']

        incompatibility = [v for v in vulns if v['type'] == 'license_incompatibility']
        self.assertGreaterEqual(len(incompatibility), 1)

    def test_permissive_license(self):
        """허용적 라이선스 (문제 없음)"""
        license_content = '''
        MIT License
        Copyright (c) 2024
        '''

        self.mock_http.get.side_effect = [
            Mock(status_code=200, text=license_content),  # LICENSE
        ]

        result = self.scanner.scan()
        self.assertTrue(result['passed'])


class TestScannerIntegration(unittest.TestCase):
    """Batch 8 스캐너 통합 테스트"""

    def test_all_scanners_have_metadata(self):
        """모든 스캐너가 올바른 메타데이터를 가지고 있는지 확인"""
        scanners = [
            SoftwareSupplyChainScanner,
            PackageIntegrityScanner,
            TyposquattingScanner,
            OutdatedDependencyScanner,
            LicenseComplianceScanner
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
            SoftwareSupplyChainScanner(),
            PackageIntegrityScanner(),
            TyposquattingScanner(),
            OutdatedDependencyScanner(),
            LicenseComplianceScanner()
        ]

        for scanner in scanners:
            result = scanner.scan()

            # 필수 결과 필드 확인
            self.assertIn('passed', result)
            self.assertIn('vulnerabilities', result)
            self.assertIn('severity', result)
            self.assertIn('message', result)

            # 데이터 타입 확인
            self.assertIsInstance(result['passed'], bool)
            self.assertIsInstance(result['vulnerabilities'], list)
            self.assertIn(result['severity'], ['low', 'medium', 'high', 'critical'])
            self.assertIsInstance(result['message'], str)


if __name__ == '__main__':
    unittest.main()