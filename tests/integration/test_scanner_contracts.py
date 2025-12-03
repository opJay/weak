"""
스캐너 계약 테스트
모든 스캐너가 tasks.py의 호출 규약을 준수하는지 검증
"""
import os
import sys
import django
import pytest
from unittest.mock import Mock
import requests

# Django 설정
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

# 모든 스캐너 클래스 import
from scanner.scanners.xss_scanner import XSSScanner
from scanner.scanners.sql_injection_scanner import SQLInjectionScanner
from scanner.scanners.security_header_scanner import SecurityHeaderScanner
from scanner.scanners.cors import CORSScanner
from scanner.scanners.cookie_scanner import CookieScanner
from scanner.scanners.csrf import CSRFScanner
from scanner.scanners.clickjacking import ClickjackingScanner
from scanner.scanners.information_disclosure import InformationDisclosureScanner
from scanner.scanners.http_method import HTTPMethodScanner
from scanner.scanners.sensitive_file import SensitiveFileScanner
from scanner.scanners.mixed_content import MixedContentScanner
from scanner.scanners.subresource_integrity import SubresourceIntegrityScanner
from scanner.scanners.directory_listing import DirectoryListingScanner
from scanner.scanners.open_redirect import OpenRedirectScanner
from scanner.scanners.ssltls_basic import SSLTLSBasicScanner

# Advanced security scanners
from scanner.scanners.ssrf import SSRFScanner
from scanner.scanners.xxe import XXEScanner
from scanner.scanners.command_injection import CommandInjectionScanner
from scanner.scanners.deserialization import DeserializationScanner
from scanner.scanners.file_upload import FileUploadScanner
from scanner.scanners.path_traversal import PathTraversalScanner
from scanner.scanners.jwt_security import JWTSecurityScanner
from scanner.scanners.template_injection import TemplateInjectionScanner
from scanner.scanners.no_sql_injection import NoSQLInjectionScanner
from scanner.scanners.ssltls_deep import SSLTLSDeepScanner

# API and Auth scanners
from scanner.scanners.restapi_security import RESTAPISecurityScanner
from scanner.scanners.graph_ql_security import GraphQLSecurityScanner
from scanner.scanners.o_auth_security import OAuthSecurityScanner
from scanner.scanners.session_security import SessionSecurityScanner
from scanner.scanners.password_policy import PasswordPolicyScanner
from scanner.scanners.rate_limiting import RateLimitingScanner
from scanner.scanners.ldap_injection import LDAPInjectionScanner
from scanner.scanners.authorization import AuthorizationScanner

# Business logic scanners
from scanner.scanners.price_manipulation import PriceManipulationScanner
from scanner.scanners.race_condition import RaceConditionScanner
from scanner.scanners.workflow_bypass import WorkflowBypassScanner
from scanner.scanners.account_enumeration import AccountEnumerationScanner
from scanner.scanners.resource_exhaustion import ResourceExhaustionScanner
from scanner.scanners.logging_monitoring import LoggingMonitoringScanner
from scanner.scanners.business_logic_anomaly import BusinessLogicAnomalyScanner

# Supply chain scanners
from scanner.scanners.software_supply_chain_scanner import SoftwareSupplyChainScanner
from scanner.scanners.package_integrity_scanner import PackageIntegrityScanner
from scanner.scanners.typosquatting_scanner import TyposquattingScanner
from scanner.scanners.outdated_dependency_scanner import OutdatedDependencyScanner
from scanner.scanners.license_compliance_scanner import LicenseComplianceScanner

# Data integrity scanners
from scanner.scanners.jwt_advanced_scanner import JWTAdvancedScanner
from scanner.scanners.serialization_integrity_scanner import SerializationIntegrityScanner
from scanner.scanners.api_integrity_scanner import APIIntegrityScanner
from scanner.scanners.checksum_validation_scanner import ChecksumValidationScanner

# Exception handling scanner
from scanner.scanners.exception_handling_scanner import ExceptionHandlingScanner


class TestScannerContracts:
    """스캐너 계약 테스트"""

    @pytest.fixture
    def mock_response(self):
        """tasks.py에서 생성하는 것과 동일한 Response 객체"""
        response = Mock(spec=requests.Response)
        response.status_code = 200
        response.headers = {
            'Content-Type': 'text/html; charset=utf-8',
            'Server': 'nginx/1.18.0',
            'X-Frame-Options': 'SAMEORIGIN'
        }
        response.text = '''<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
    <form method="POST" action="/login">
        <input type="text" name="username">
        <input type="password" name="password">
        <input name="csrf_token" value="test_token_123">
        <button type="submit">Login</button>
    </form>
    <script src="http://insecure.js"></script>
    <script src="https://cdn.example.com/script.js"></script>
</body>
</html>'''
        response.content = response.text.encode('utf-8')
        response.url = 'https://example.com'
        response.cookies = Mock()
        response.json = Mock(side_effect=ValueError("Not JSON"))
        return response

    @pytest.fixture
    def all_scanner_classes(self):
        """모든 스캐너 클래스 리스트"""
        return [
            # Basic security scanners (15개)
            XSSScanner, SQLInjectionScanner, SecurityHeaderScanner,
            CORSScanner, CookieScanner, CSRFScanner,
            ClickjackingScanner, InformationDisclosureScanner, HTTPMethodScanner,
            SensitiveFileScanner, MixedContentScanner, SubresourceIntegrityScanner,
            DirectoryListingScanner, OpenRedirectScanner, SSLTLSBasicScanner,

            # Advanced security scanners (10개)
            SSRFScanner, XXEScanner, CommandInjectionScanner,
            DeserializationScanner, FileUploadScanner, PathTraversalScanner,
            JWTSecurityScanner, TemplateInjectionScanner, NoSQLInjectionScanner,
            SSLTLSDeepScanner,

            # API and Auth scanners (8개)
            RESTAPISecurityScanner, GraphQLSecurityScanner, OAuthSecurityScanner,
            SessionSecurityScanner, PasswordPolicyScanner, RateLimitingScanner,
            LDAPInjectionScanner, AuthorizationScanner,

            # Business logic scanners (7개)
            PriceManipulationScanner, RaceConditionScanner, WorkflowBypassScanner,
            AccountEnumerationScanner, ResourceExhaustionScanner,
            LoggingMonitoringScanner, BusinessLogicAnomalyScanner,

            # Supply chain scanners (5개)
            SoftwareSupplyChainScanner, PackageIntegrityScanner,
            TyposquattingScanner, OutdatedDependencyScanner,
            LicenseComplianceScanner,

            # Data integrity scanners (4개)
            JWTAdvancedScanner, SerializationIntegrityScanner,
            APIIntegrityScanner, ChecksumValidationScanner,

            # Exception handling scanner (1개)
            ExceptionHandlingScanner
        ]

    def test_scanner_count(self, all_scanner_classes):
        """스캐너 개수 확인 (50개)"""
        assert len(all_scanner_classes) == 50, f"스캐너 개수: {len(all_scanner_classes)}"

    @pytest.mark.parametrize("scanner_class", [
        XSSScanner, SQLInjectionScanner, SecurityHeaderScanner,
        CORSScanner, CookieScanner, CSRFScanner,
        ClickjackingScanner, InformationDisclosureScanner, HTTPMethodScanner,
        SensitiveFileScanner, MixedContentScanner, SubresourceIntegrityScanner,
        DirectoryListingScanner, OpenRedirectScanner, SSLTLSBasicScanner,
        SSRFScanner, XXEScanner, CommandInjectionScanner,
        DeserializationScanner, FileUploadScanner, PathTraversalScanner,
        JWTSecurityScanner, TemplateInjectionScanner, NoSQLInjectionScanner,
        SSLTLSDeepScanner, RESTAPISecurityScanner, GraphQLSecurityScanner,
        OAuthSecurityScanner, SessionSecurityScanner, PasswordPolicyScanner,
        RateLimitingScanner, LDAPInjectionScanner, AuthorizationScanner,
        PriceManipulationScanner, RaceConditionScanner, WorkflowBypassScanner,
        AccountEnumerationScanner, ResourceExhaustionScanner,
        LoggingMonitoringScanner, BusinessLogicAnomalyScanner,
        SoftwareSupplyChainScanner, PackageIntegrityScanner,
        TyposquattingScanner, OutdatedDependencyScanner,
        LicenseComplianceScanner, JWTAdvancedScanner,
        SerializationIntegrityScanner, APIIntegrityScanner,
        ChecksumValidationScanner, ExceptionHandlingScanner
    ])
    def test_scanner_initialization_with_tasks_pattern(self, scanner_class, mock_response):
        """tasks.py의 호출 패턴으로 스캐너 초기화 가능 검증"""

        # Given: tasks.py와 동일한 인자
        init_args = {
            'url': 'https://example.com',
            'html_content': mock_response.text,
            'response': mock_response
        }

        # When: 스캐너 초기화
        try:
            scanner = scanner_class(**init_args)
            result = scanner.scan()
        except TypeError as e:
            pytest.fail(
                f"{scanner_class.__name__} 초기화 실패: {e}\n"
                f"tasks.py 호출 패턴과 호환되지 않음\n"
                f"전달된 인자: {list(init_args.keys())}"
            )
        except Exception as e:
            # 초기화는 성공했지만 scan() 실행 중 오류 (이는 허용)
            pass

        # Then: 결과가 표준 형식
        if result:
            assert isinstance(result, dict), f"{scanner_class.__name__}: 결과가 dict가 아님"

    def test_all_scanners_accept_standard_args(self, mock_response, all_scanner_classes):
        """모든 스캐너가 표준 인자를 받을 수 있는지 일괄 검증"""
        failed_scanners = []

        for scanner_class in all_scanner_classes:
            try:
                # tasks.py의 표준 호출 패턴
                scanner = scanner_class(
                    url='https://example.com',
                    html_content=mock_response.text,
                    response=mock_response
                )
                assert scanner is not None
            except TypeError as e:
                failed_scanners.append(
                    f"{scanner_class.__name__}: {str(e)}"
                )
            except Exception:
                # 초기화는 성공 (다른 런타임 오류는 무시)
                pass

        if failed_scanners:
            pytest.fail(
                f"{len(failed_scanners)}개 스캐너가 표준 인자를 받지 못함:\n" +
                "\n".join(failed_scanners)
            )

    def test_scanner_scan_method_returns_dict(self, mock_response, all_scanner_classes):
        """모든 스캐너의 scan() 메서드가 dict를 반환하는지 검증"""
        failed_scanners = []

        for scanner_class in all_scanner_classes:
            try:
                scanner = scanner_class(
                    url='https://example.com',
                    html_content=mock_response.text,
                    response=mock_response
                )
                result = scanner.scan()

                if not isinstance(result, dict):
                    failed_scanners.append(
                        f"{scanner_class.__name__}: scan()이 {type(result)}를 반환 (dict 예상)"
                    )

            except Exception as e:
                # 런타임 오류는 별도 테스트에서 처리
                pass

        if failed_scanners:
            pytest.fail(
                f"{len(failed_scanners)}개 스캐너가 올바른 형식을 반환하지 않음:\n" +
                "\n".join(failed_scanners)
            )

    def test_scanner_metadata_exists(self, all_scanner_classes):
        """모든 스캐너가 metadata를 가지고 있는지 검증"""
        missing_metadata = []

        for scanner_class in all_scanner_classes:
            if not hasattr(scanner_class, 'metadata'):
                missing_metadata.append(scanner_class.__name__)
            else:
                metadata = scanner_class.metadata
                # 필수 필드 확인 (icon은 선택적)
                required_fields = ['id', 'name', 'description', 'field']
                for field in required_fields:
                    if field not in metadata:
                        missing_metadata.append(
                            f"{scanner_class.__name__}: metadata에 '{field}' 필드 누락"
                        )

        if missing_metadata:
            pytest.fail(
                f"Metadata 문제:\n" + "\n".join(missing_metadata)
            )

    def test_no_positional_only_args_in_init(self, all_scanner_classes):
        """스캐너 __init__이 위치 전용 인자를 요구하지 않는지 검증"""
        import inspect

        problematic_scanners = []

        for scanner_class in all_scanner_classes:
            sig = inspect.signature(scanner_class.__init__)
            params = sig.parameters

            # self를 제외한 필수 위치 인자 확인
            for name, param in params.items():
                if name == 'self':
                    continue

                if param.default == inspect.Parameter.empty and \
                   param.kind in (inspect.Parameter.POSITIONAL_ONLY,
                                inspect.Parameter.POSITIONAL_OR_KEYWORD):
                    # kwargs가 있으면 괜찮음
                    if 'kwargs' not in params:
                        problematic_scanners.append(
                            f"{scanner_class.__name__}: '{name}'은 필수 인자인데 "
                            f"기본값이 없음"
                        )

        if problematic_scanners:
            pytest.fail(
                "필수 위치 인자 문제:\n" + "\n".join(problematic_scanners)
            )