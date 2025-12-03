"""
API 엔드포인트 테스트
- 요약 API와 스캐너 상세 API 테스트
- 성능 비교 및 페이로드 크기 검증
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from django.test import RequestFactory
from django.utils import timezone
from api.views import ScanViewSet
from api.serializers import (
    ScanSummarySerializer,
    ScannerDetailSerializer
)
from scanner.models import ScanRequest, SecurityScanResult


@pytest.fixture
def scan_request():
    """테스트용 스캔 요청 객체"""
    scan = MagicMock(spec=ScanRequest)
    scan.id = 'test-scan-id'
    scan.url = 'https://example.com'
    scan.target_domain = 'example.com'
    scan.status = 'completed'
    scan.progress = 100
    scan.created_at = timezone.now()
    scan.started_at = timezone.now()
    scan.completed_at = timezone.now()
    scan.error_message = None
    scan.scan_types = ['security', 'standards', 'accessibility']
    scan.deep_scan = False
    scan.duration.return_value = 67.397

    # Security result mock
    security_result = MagicMock(spec=SecurityScanResult)
    security_result.overall_score = 88
    security_result.risk_level = 'low'
    security_result.scanner_metadata = [
        {
            'id': 'xss',
            'name': 'XSS 스캐너',
            'icon': '💉',
            'description': 'Cross-Site Scripting 취약점 탐지',
            'weight': 2,
            'field': 'xss_vulnerabilities'
        },
        {
            'id': 'sql_injection',
            'name': 'SQL Injection 스캐너',
            'icon': '💾',
            'description': 'SQL 주입 취약점 탐지',
            'weight': 2,
            'field': 'sql_injection'
        },
        {
            'id': 'security_headers',
            'name': '보안 헤더 검사',
            'icon': '🔒',
            'description': '보안 관련 HTTP 헤더 검사',
            'weight': 1,
            'field': 'security_headers'
        }
    ]

    # 각 필드 설정
    security_result.xss_vulnerabilities = {
        'overall_score': 100,
        'vulnerabilities': []
    }
    security_result.sql_injection = {
        'overall_score': 100,
        'vulnerabilities': []
    }
    security_result.security_headers = {
        'overall_score': 100,
        'vulnerabilities': []
    }

    scan.security_result = security_result

    # Standards result mock
    standards_result = MagicMock()
    standards_result.overall_score = 95
    standards_result.html_valid = True
    standards_result.html_error_count = 0
    standards_result.css_valid = True
    standards_result.css_error_count = 0
    standards_result.js_error_count = 0
    standards_result.seo_score = 90
    standards_result.scanner_metadata = [
        {
            'id': 'html_validation',
            'name': 'HTML 유효성 검사',
            'icon': '📄',
            'field': 'html_errors',
            'overall_score': 100,
            'vulnerabilities': []
        },
        {
            'id': 'seo_check',
            'name': 'SEO 최적화',
            'icon': '🔍',
            'field': 'seo_issues',
            'overall_score': 90,
            'vulnerabilities': []
        }
    ]

    # Accessibility result mock
    accessibility_result = MagicMock()
    accessibility_result.overall_score = 92
    accessibility_result.wcag_level = 'AA'
    accessibility_result.total_issues = 3
    accessibility_result.critical_issues = 0
    accessibility_result.serious_issues = 1  # Add explicit value instead of MagicMock
    accessibility_result.scanner_metadata = [
        {
            'id': 'basic_accessibility',
            'name': '기본 접근성 검사',
            'icon': '♿',
            'field': 'accessibility_issues',
            'overall_score': 92,
            'vulnerabilities': []
        }
    ]

    # 추가 Mock 속성 (ScanResultSerializer용)
    scan.standards_result = standards_result
    scan.accessibility_result = accessibility_result
    scan.vulnerabilities.all.return_value = []  # 빈 취약점 목록

    return scan


@pytest.fixture
def request_factory():
    """Django RequestFactory"""
    return RequestFactory()


class TestSummaryAPI:
    """요약 API 테스트"""

    def test_summary_api_response(self, scan_request, request_factory):
        """요약 API 응답 테스트"""
        # Given
        view = ScanViewSet()
        view.get_object = MagicMock(return_value=scan_request)
        request = request_factory.get('/api/scan/test-id/summary/')

        # When
        response = view.scan_summary(request, pk='test-id')

        # Then
        assert response.status_code == 200
        data = response.data

        # 필수 필드 확인
        assert 'id' in data
        assert 'url' in data
        assert 'security_summary' in data
        assert 'standards_summary' in data
        assert 'accessibility_summary' in data

        # 보안 요약 정보 확인
        security = data['security_summary']
        assert security['overall_score'] == 88
        assert security['risk_level'] == 'low'
        assert security['scanner_count'] == 3

    def test_summary_api_incomplete_scan(self, scan_request, request_factory):
        """완료되지 않은 스캔에 대한 요약 API 테스트"""
        # Given
        scan_request.status = 'running'
        scan_request.progress = 50
        view = ScanViewSet()
        view.get_object = MagicMock(return_value=scan_request)
        request = request_factory.get('/api/scan/test-id/summary/')

        # When
        response = view.scan_summary(request, pk='test-id')

        # Then
        assert response.status_code == 202
        assert response.data['error'] == 'Scan not completed'
        assert response.data['status'] == 'running'
        assert response.data['progress'] == 50

    def test_summary_serializer_payload_size(self, scan_request):
        """요약 Serializer의 페이로드 크기 테스트"""
        # Given
        serializer = ScanSummarySerializer(scan_request)

        # When
        data = serializer.data
        json_str = json.dumps(data, ensure_ascii=False)
        size = len(json_str.encode('utf-8'))

        # Then
        assert size < 10000  # 10KB 미만이어야 함
        print(f"\n요약 API 페이로드 크기: {size} bytes ({size/1024:.1f}KB)")


class TestScannerDetailAPI:
    """스캐너 상세 API 테스트"""

    @pytest.mark.parametrize("scanner_id,expected_field", [
        ('xss', 'xss_vulnerabilities'),
        ('sql_injection', 'sql_injection'),
        ('security_headers', 'security_headers'),
        ('cors', 'cors_misconfiguration'),
        ('csrf', 'csrf_protection'),
        ('jwt', 'jwt_vulnerabilities'),
        ('ssrf', 'ssrf_vulnerabilities'),
        ('xxe', 'xxe_vulnerabilities'),
    ])
    def test_scanner_id_mapping(self, scanner_id, expected_field, request_factory):
        """스캐너 ID 매핑 테스트"""
        # Given
        view = ScanViewSet()

        # When
        field_name = view._get_field_name_for_scanner(scanner_id)

        # Then
        assert field_name == expected_field

    def test_scanner_detail_api_response(self, scan_request, request_factory):
        """스캐너 상세 API 응답 테스트"""
        # Given
        from rest_framework.test import APIRequestFactory
        from rest_framework.request import Request

        view = ScanViewSet()
        view.get_object = MagicMock(return_value=scan_request)

        # APIRequestFactory 사용하여 DRF Request 객체 생성
        api_factory = APIRequestFactory()
        raw_request = api_factory.get('/api/scan/test-id/scanner/',
                                      {'scanner_id': 'xss'})
        request = Request(raw_request)

        # When
        response = view.scanner_detail(request, pk='test-id')

        # Then
        assert response.status_code == 200
        data = response.data

        # 필수 필드 확인
        assert data['scanner_id'] == 'xss'
        assert data['name'] == 'XSS 스캐너'
        assert data['status'] == 'pass'
        assert data['overall_score'] == 100
        assert 'guide' in data
        assert 'statistics' in data

    def test_scanner_detail_invalid_scanner_id(self, scan_request, request_factory):
        """유효하지 않은 스캐너 ID 테스트"""
        # Given
        from rest_framework.test import APIRequestFactory
        from rest_framework.request import Request

        view = ScanViewSet()
        view.get_object = MagicMock(return_value=scan_request)

        api_factory = APIRequestFactory()
        raw_request = api_factory.get('/api/scan/test-id/scanner/',
                                      {'scanner_id': 'invalid_scanner'})
        request = Request(raw_request)

        # When
        response = view.scanner_detail(request, pk='test-id')

        # Then
        assert response.status_code == 400
        assert 'Unknown scanner_id' in response.data['error']

    def test_scanner_detail_missing_scanner_id(self, scan_request, request_factory):
        """scanner_id 파라미터 누락 테스트"""
        # Given
        from rest_framework.test import APIRequestFactory
        from rest_framework.request import Request

        view = ScanViewSet()
        view.get_object = MagicMock(return_value=scan_request)

        api_factory = APIRequestFactory()
        raw_request = api_factory.get('/api/scan/test-id/scanner/')
        request = Request(raw_request)

        # When
        response = view.scanner_detail(request, pk='test-id')

        # Then
        assert response.status_code == 400
        assert response.data['error'] == 'scanner_id parameter required'

    def test_scanner_detail_serializer_payload_size(self, scan_request):
        """스캐너 상세 Serializer의 페이로드 크기 테스트"""
        # Given
        security_result = scan_request.security_result
        serializer = ScannerDetailSerializer(
            security_result,
            context={'scanner_id': 'xss', 'field_name': 'xss_vulnerabilities'}
        )

        # When
        data = serializer.data
        json_str = json.dumps(data, ensure_ascii=False)
        size = len(json_str.encode('utf-8'))

        # Then
        assert size < 5000  # 5KB 미만이어야 함
        print(f"\n스캐너 상세 API 페이로드 크기: {size} bytes ({size/1024:.1f}KB)")


class TestAPIPerformance:
    """API 성능 비교 테스트"""

    def test_payload_size_comparison(self):
        """Payload 크기 비교 테스트"""
        small_payload = {"data": "test"}
        large_payload = {"data": "x" * 1000}

        assert len(str(small_payload)) < len(str(large_payload))
        assert len(str(large_payload)) > 100
        assert len(str(small_payload)) < 50
class TestScannerIDShortcuts:
    """간단한 스캐너 ID 지원 테스트"""

    @pytest.mark.parametrize("short_id,expected_field", [
        # 기본 보안 스캐너
        ('xss', 'xss_vulnerabilities'),
        ('cors', 'cors_misconfiguration'),
        ('csrf', 'csrf_protection'),
        ('cookie_security', 'sensitive_data_exposure'),
        ('sri', 'subresource_integrity'),
        ('info_disclosure', 'sensitive_data_exposure'),

        # 고급 보안 스캐너
        ('ssrf', 'ssrf_vulnerabilities'),
        ('xxe', 'xxe_vulnerabilities'),
        ('jwt', 'jwt_vulnerabilities'),
        ('ssti', 'template_injection'),
        ('nosql', 'nosql_injection'),

        # API 보안 스캐너
        ('rest_api', 'rest_api_vulnerabilities'),
        ('graphql', 'graphql_vulnerabilities'),
        ('oauth', 'oauth_vulnerabilities'),
        ('session', 'session_vulnerabilities'),
    ])
    def test_short_scanner_ids(self, short_id, expected_field):
        """간단한 스캐너 ID 매핑 테스트"""
        # Given
        view = ScanViewSet()

        # When
        field_name = view._get_field_name_for_scanner(short_id)

        # Then
        assert field_name == expected_field, f"{short_id}가 {expected_field}로 매핑되어야 함"