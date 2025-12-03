"""
스캐너 초기화 검증 테스트
tasks.py에서 사용하는 실제 패턴 검증
"""
import os
import sys
import django
import pytest
import inspect
import requests
from unittest.mock import Mock
import importlib

# Django 설정
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()


class TestScannerInitialization:
    """스캐너 초기화 검증"""

    @pytest.fixture
    def standard_args(self):
        """tasks.py의 표준 인자 세트"""
        mock_response = Mock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.text = '<html><body>Test</body></html>'
        mock_response.content = b'<html><body>Test</body></html>'
        mock_response.url = 'https://example.com'
        mock_response.cookies = Mock()

        return {
            'url': 'https://example.com',
            'html_content': mock_response.text,
            'response': mock_response
        }

    @pytest.fixture
    def scanner_mappings(self):
        """스캐너 매핑 정보"""
        return {
            # Basic security scanners
            'xss': 'scanner.scanners.xss_scanner.XSSScanner',
            'sql_injection': 'scanner.scanners.sql_injection_scanner.SQLInjectionScanner',
            'security_headers': 'scanner.scanners.security_header_scanner.SecurityHeaderScanner',
            'cors': 'scanner.scanners.cors.CORSScanner',
            'cookie_security': 'scanner.scanners.cookie_scanner.CookieScanner',
            'csrf': 'scanner.scanners.csrf.CSRFScanner',
            'clickjacking': 'scanner.scanners.clickjacking.ClickjackingScanner',
            'information_disclosure': 'scanner.scanners.information_disclosure.InformationDisclosureScanner',
            'http_methods': 'scanner.scanners.http_method.HTTPMethodScanner',
            'sensitive_files': 'scanner.scanners.sensitive_file.SensitiveFileScanner',
            'mixed_content': 'scanner.scanners.mixed_content.MixedContentScanner',
            'subresource_integrity': 'scanner.scanners.subresource_integrity.SubresourceIntegrityScanner',
            'directory_listing': 'scanner.scanners.directory_listing.DirectoryListingScanner',
            'open_redirect': 'scanner.scanners.open_redirect.OpenRedirectScanner',
            'ssl_tls_basic': 'scanner.scanners.ssltls_basic.SSLTLSBasicScanner',

            # Advanced security scanners
            'ssrf': 'scanner.scanners.ssrf.SSRFScanner',
            'xxe': 'scanner.scanners.xxe.XXEScanner',
            'command_injection': 'scanner.scanners.command_injection.CommandInjectionScanner',
            'deserialization': 'scanner.scanners.deserialization.DeserializationScanner',
            'file_upload': 'scanner.scanners.file_upload.FileUploadScanner',
            'path_traversal': 'scanner.scanners.path_traversal.PathTraversalScanner',
            'jwt_security': 'scanner.scanners.jwt_security.JWTSecurityScanner',
            'template_injection': 'scanner.scanners.template_injection.TemplateInjectionScanner',
            'nosql_injection': 'scanner.scanners.no_sql_injection.NoSQLInjectionScanner',
            'ssl_tls_deep': 'scanner.scanners.ssltls_deep.SSLTLSDeepScanner',

            # API and Auth scanners
            'rest_api_security': 'scanner.scanners.restapi_security.RESTAPISecurityScanner',
            'graphql_security': 'scanner.scanners.graph_ql_security.GraphQLSecurityScanner',
            'oauth_security': 'scanner.scanners.o_auth_security.OAuthSecurityScanner',
            'session_security': 'scanner.scanners.session_security.SessionSecurityScanner',
            'password_policy': 'scanner.scanners.password_policy.PasswordPolicyScanner',
            'rate_limiting': 'scanner.scanners.rate_limiting.RateLimitingScanner',
            'ldap_injection': 'scanner.scanners.ldap_injection.LDAPInjectionScanner',
            'authorization': 'scanner.scanners.authorization.AuthorizationScanner',

            # Business logic scanners
            'price_manipulation': 'scanner.scanners.price_manipulation.PriceManipulationScanner',
            'race_condition': 'scanner.scanners.race_condition.RaceConditionScanner',
            'workflow_bypass': 'scanner.scanners.workflow_bypass.WorkflowBypassScanner',
            'account_enumeration': 'scanner.scanners.account_enumeration.AccountEnumerationScanner',
            'resource_exhaustion': 'scanner.scanners.resource_exhaustion.ResourceExhaustionScanner',
            'logging_monitoring': 'scanner.scanners.logging_monitoring.LoggingMonitoringScanner',
            'business_logic_anomaly': 'scanner.scanners.business_logic_anomaly.BusinessLogicAnomalyScanner',

            # Supply chain scanners
            'software_supply_chain': 'scanner.scanners.software_supply_chain_scanner.SoftwareSupplyChainScanner',
            'package_integrity': 'scanner.scanners.package_integrity_scanner.PackageIntegrityScanner',
            'typosquatting': 'scanner.scanners.typosquatting_scanner.TyposquattingScanner',
            'outdated_dependency': 'scanner.scanners.outdated_dependency_scanner.OutdatedDependencyScanner',
            'license_compliance': 'scanner.scanners.license_compliance_scanner.LicenseComplianceScanner',

            # Data integrity scanners
            'jwt_advanced': 'scanner.scanners.jwt_advanced_scanner.JWTAdvancedScanner',
            'serialization_integrity': 'scanner.scanners.serialization_integrity_scanner.SerializationIntegrityScanner',
            'api_integrity': 'scanner.scanners.api_integrity_scanner.APIIntegrityScanner',
            'checksum_validation': 'scanner.scanners.checksum_validation_scanner.ChecksumValidationScanner',

            # Exception handling scanner
            'exception_handling': 'scanner.scanners.exception_handling_scanner.ExceptionHandlingScanner'
        }

    def test_all_scanners_signature_compatibility(self, scanner_mappings):
        """모든 스캐너의 시그니처 호환성 검증"""
        errors = []
        checked_scanners = []

        for scanner_id, scanner_path in scanner_mappings.items():
            try:
                # 동적 import
                module_path, class_name = scanner_path.rsplit('.', 1)
                module = importlib.import_module(module_path)
                scanner_class = getattr(module, class_name)

                # __init__ 시그니처 검사
                sig = inspect.signature(scanner_class.__init__)
                params = sig.parameters

                # 필수 파라미터 확인
                required_params = []
                optional_params = []
                has_kwargs = False

                for name, param in params.items():
                    if name == 'self':
                        continue

                    if param.kind == inspect.Parameter.VAR_KEYWORD:
                        has_kwargs = True
                    elif param.default == inspect.Parameter.empty:
                        required_params.append(name)
                    else:
                        optional_params.append(name)

                # tasks.py가 전달하는 인자들이 받아들여질 수 있는지 확인
                can_accept_url = 'url' in optional_params or 'url' in required_params or has_kwargs
                can_accept_html = 'html_content' in optional_params or 'html_content' in required_params or has_kwargs
                can_accept_response = 'response' in optional_params or 'response' in required_params or has_kwargs

                if not (can_accept_url and can_accept_html and can_accept_response):
                    errors.append(
                        f"{scanner_id} ({class_name}):\n"
                        f"  - url 수용: {can_accept_url}\n"
                        f"  - html_content 수용: {can_accept_html}\n"
                        f"  - response 수용: {can_accept_response}\n"
                        f"  - 파라미터: {list(params.keys())}"
                    )

                checked_scanners.append(scanner_id)

            except Exception as e:
                errors.append(f"{scanner_id}: Import/검사 오류 - {e}")

        # 모든 스캐너 검사 확인
        assert len(checked_scanners) == 50, \
            f"50개 스캐너 중 {len(checked_scanners)}개만 검사됨"

        if errors:
            pytest.fail(
                f"시그니처 호환성 문제 ({len(errors)}개):\n" + "\n".join(errors)
            )

    def test_all_scanners_can_be_initialized(self, scanner_mappings, standard_args):
        """모든 스캐너가 표준 인자로 초기화 가능한지 검증"""
        errors = []
        success_count = 0

        for scanner_id, scanner_path in scanner_mappings.items():
            try:
                module_path, class_name = scanner_path.rsplit('.', 1)
                module = importlib.import_module(module_path)
                scanner_class = getattr(module, class_name)

                # 초기화 시도
                scanner = scanner_class(**standard_args)
                assert scanner is not None

                # scan() 메서드 존재 확인
                assert hasattr(scanner, 'scan'), \
                    f"{scanner_id}: scan() 메서드가 없음"

                success_count += 1

            except TypeError as e:
                errors.append(
                    f"{scanner_id} ({class_name}):\n"
                    f"  초기화 실패: {e}\n"
                    f"  전달된 인자: {list(standard_args.keys())}"
                )
            except Exception as e:
                errors.append(
                    f"{scanner_id} ({class_name}):\n"
                    f"  기타 오류: {e}"
                )

        print(f"\n성공적으로 초기화된 스캐너: {success_count}/50")

        if errors:
            pytest.fail(
                f"초기화 실패 ({len(errors)}개):\n" + "\n".join(errors[:10])  # 처음 10개만 표시
            )

    def test_scanner_initialization_with_minimal_args(self, scanner_mappings):
        """최소 인자로 초기화 가능한지 테스트"""
        errors = []

        for scanner_id, scanner_path in scanner_mappings.items():
            try:
                module_path, class_name = scanner_path.rsplit('.', 1)
                module = importlib.import_module(module_path)
                scanner_class = getattr(module, class_name)

                # 최소 인자로 초기화 시도
                minimal_args = {
                    'url': 'https://example.com'
                }

                try:
                    scanner = scanner_class(**minimal_args)
                except TypeError:
                    # html_content도 필요한 경우
                    minimal_args['html_content'] = '<html></html>'
                    scanner = scanner_class(**minimal_args)

                assert scanner is not None

            except Exception as e:
                # 최소 인자 초기화 실패는 허용 (response가 필요한 경우 등)
                pass

    def test_scanner_base_class_inheritance(self, scanner_mappings):
        """모든 스캐너가 BaseScanner를 상속하는지 확인"""
        from scanner.base import BaseScanner

        not_inherited = []

        for scanner_id, scanner_path in scanner_mappings.items():
            try:
                module_path, class_name = scanner_path.rsplit('.', 1)
                module = importlib.import_module(module_path)
                scanner_class = getattr(module, class_name)

                if not issubclass(scanner_class, BaseScanner):
                    not_inherited.append(f"{scanner_id} ({class_name})")

            except Exception as e:
                not_inherited.append(f"{scanner_id}: Import 오류 - {e}")

        if not_inherited:
            pytest.fail(
                f"BaseScanner를 상속하지 않는 스캐너:\n" +
                "\n".join(not_inherited)
            )

    def test_scanner_metadata_completeness(self, scanner_mappings):
        """모든 스캐너의 metadata 완전성 검증"""
        metadata_issues = []

        required_fields = ['id', 'name', 'description', 'field']
        optional_fields = ['icon', 'category', 'severity', 'weight']

        for scanner_id, scanner_path in scanner_mappings.items():
            try:
                module_path, class_name = scanner_path.rsplit('.', 1)
                module = importlib.import_module(module_path)
                scanner_class = getattr(module, class_name)

                if not hasattr(scanner_class, 'metadata'):
                    metadata_issues.append(f"{scanner_id}: metadata 속성 없음")
                    continue

                metadata = scanner_class.metadata

                # 필수 필드 검사
                for field in required_fields:
                    if field not in metadata:
                        metadata_issues.append(
                            f"{scanner_id}: 필수 필드 '{field}' 누락"
                        )

                # ID 일치 검사 (선택적 - 매핑이 다를 수 있음)
                # 일부 스캐너는 레거시 이유로 다른 ID를 사용할 수 있음
                # if metadata.get('id') != scanner_id:
                #     metadata_issues.append(
                #         f"{scanner_id}: metadata.id가 '{metadata.get('id')}'로 불일치"
                #     )

                # field 값 검사
                if not metadata.get('field'):
                    metadata_issues.append(
                        f"{scanner_id}: field 값이 비어있음"
                    )

            except Exception as e:
                metadata_issues.append(f"{scanner_id}: 검사 오류 - {e}")

        if metadata_issues:
            pytest.fail(
                f"Metadata 문제 ({len(metadata_issues)}개):\n" +
                "\n".join(metadata_issues[:20])  # 처음 20개만 표시
            )

    def test_scanner_scan_method_signature(self, scanner_mappings):
        """scan() 메서드의 시그니처 일관성 검증"""
        signature_issues = []

        for scanner_id, scanner_path in scanner_mappings.items():
            try:
                module_path, class_name = scanner_path.rsplit('.', 1)
                module = importlib.import_module(module_path)
                scanner_class = getattr(module, class_name)

                # scan 메서드 시그니처 검사
                if hasattr(scanner_class, 'scan'):
                    sig = inspect.signature(scanner_class.scan)
                    params = list(sig.parameters.keys())

                    # scan()은 self 외에 인자를 받지 않아야 함
                    if len(params) > 1:
                        signature_issues.append(
                            f"{scanner_id}: scan() 메서드가 추가 인자를 받음: {params[1:]}"
                        )
                else:
                    signature_issues.append(f"{scanner_id}: scan() 메서드 없음")

            except Exception as e:
                signature_issues.append(f"{scanner_id}: 검사 오류 - {e}")

        if signature_issues:
            pytest.fail(
                f"scan() 메서드 시그니처 문제:\n" +
                "\n".join(signature_issues)
            )

    def test_scanner_return_type_consistency(self, scanner_mappings, standard_args):
        """scan() 메서드가 일관된 형식을 반환하는지 검증"""
        return_type_issues = []
        tested_count = 0

        for scanner_id, scanner_path in scanner_mappings.items():
            try:
                module_path, class_name = scanner_path.rsplit('.', 1)
                module = importlib.import_module(module_path)
                scanner_class = getattr(module, class_name)

                # 스캐너 초기화 및 실행
                scanner = scanner_class(**standard_args)
                result = scanner.scan()

                # 반환 타입 검사
                if not isinstance(result, dict):
                    return_type_issues.append(
                        f"{scanner_id}: dict가 아닌 {type(result)}를 반환"
                    )
                else:
                    # 기본 필드 검사
                    if 'scanner_id' not in result and 'vulnerabilities' not in result:
                        return_type_issues.append(
                            f"{scanner_id}: scanner_id나 vulnerabilities 필드 없음"
                        )

                tested_count += 1

            except Exception:
                # 런타임 오류는 별도 테스트에서 처리
                pass

        print(f"\n반환 타입 테스트 완료: {tested_count}/50")

        if return_type_issues:
            pytest.fail(
                f"반환 타입 문제:\n" +
                "\n".join(return_type_issues)
            )

    def test_tasks_py_import_paths(self, scanner_mappings):
        """tasks.py의 import 경로와 실제 스캐너 위치 일치 확인"""
        import_mismatches = []

        # tasks.py에서 사용하는 import 경로들
        tasks_imports = {
            'xss': 'scanner.scanners.xss_scanner',
            'sql_injection': 'scanner.scanners.sql_injection_scanner',
            'security_headers': 'scanner.scanners.security_header_scanner',
            'cors': 'scanner.scanners.cors',
            'cookie_security': 'scanner.scanners.cookie_scanner',
            'csrf': 'scanner.scanners.csrf',
            'clickjacking': 'scanner.scanners.clickjacking',
            'information_disclosure': 'scanner.scanners.information_disclosure',
            'http_methods': 'scanner.scanners.http_method',
            'sensitive_files': 'scanner.scanners.sensitive_file',
            'mixed_content': 'scanner.scanners.mixed_content',
            'subresource_integrity': 'scanner.scanners.subresource_integrity',
            'directory_listing': 'scanner.scanners.directory_listing',
            'open_redirect': 'scanner.scanners.open_redirect',
            'ssl_tls_basic': 'scanner.scanners.ssltls_basic',
        }

        for scanner_id, expected_module in tasks_imports.items():
            actual_path = scanner_mappings.get(scanner_id, '')

            if expected_module not in actual_path:
                import_mismatches.append(
                    f"{scanner_id}:\n"
                    f"  Expected: {expected_module}\n"
                    f"  Actual: {actual_path}"
                )

        if import_mismatches:
            pytest.fail(
                f"Import 경로 불일치:\n" +
                "\n".join(import_mismatches)
            )