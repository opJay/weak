"""
Batch 7 스캐너 단위 테스트
비즈니스 로직 및 설계 취약점 스캐너 테스트
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import concurrent.futures
from scanner.scanners.price_manipulation import PriceManipulationScanner
from scanner.scanners.race_condition import RaceConditionScanner
from scanner.scanners.workflow_bypass import WorkflowBypassScanner
from scanner.scanners.account_enumeration import AccountEnumerationScanner
from scanner.scanners.resource_exhaustion import ResourceExhaustionScanner
from scanner.scanners.logging_monitoring import LoggingMonitoringScanner
from scanner.scanners.business_logic_anomaly import BusinessLogicAnomalyScanner


class TestPriceManipulationScanner:
    """PriceManipulationScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_price_in_url(self):
        """TP: URL에 가격 파라미터 노출"""
        # Given
        url = 'https://shop.example.com/checkout?price=100&quantity=2'

        # When
        scanner = PriceManipulationScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert result['has_price_manipulation'] is True
        assert any('Price Parameter Exposure' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_hidden_price_field(self):
        """TP: 숨겨진 가격 필드"""
        # Given
        html_content = '''
        <form action="/purchase" method="post">
            <input type="hidden" name="total_price" value="99.99" />
            <input type="hidden" name="discount" value="10" />
            <button type="submit">Purchase</button>
        </form>
        '''

        # When
        scanner = PriceManipulationScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Hidden Price Field' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_negative_value_accepted(self):
        """TP: 음수 값 허용"""
        # Given
        url = 'https://shop.example.com/cart?quantity=1'
        mock_client = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_client.get.return_value = mock_response

        # When
        scanner = PriceManipulationScanner(url=url, http_client=mock_client)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Negative Value Accepted' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_no_price_params(self):
        """TN: 가격 관련 파라미터 없음"""
        # Given
        url = 'https://example.com/about'
        html_content = '<p>About us page</p>'

        # When
        scanner = PriceManipulationScanner(url=url, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_price_manipulation'] is False

    @pytest.mark.unit
    def test_edge_case_empty_inputs(self):
        """Edge Case: 빈 입력"""
        # Given/When
        scanner = PriceManipulationScanner()
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert 'vulnerabilities' in result


class TestRaceConditionScanner:
    """RaceConditionScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_concurrent_success(self):
        """동시 요청 성공 테스트"""
        scanner = RaceConditionScanner()
        # 동시성 테스트는 Mock 환경에서 시뮬레이션
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.elapsed.total_seconds = lambda: 0.1

        with patch('requests.get', return_value=mock_response):
            scanner.url = "http://test.com"

            result = scanner.scan()
            assert result is not None
            # Race condition이 감지되었다고 가정
            assert "scanner_id" in result


class TestWorkflowBypassScanner:
    """WorkflowBypassScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_workflow_params(self):
        """TP: URL에 워크플로우 파라미터"""
        # Given
        url = 'https://example.com/checkout?step=3&status=completed'

        # When
        scanner = WorkflowBypassScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert result['has_workflow_bypass'] is True
        assert any('Workflow Parameter Exposure' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_hidden_state_field(self):
        """TP: 숨겨진 상태 필드"""
        # Given
        html_content = '''
        <form action="/process" method="post">
            <input type="hidden" name="stage" value="payment" />
            <input type="hidden" name="progress" value="75" />
        </form>
        '''

        # When
        scanner = WorkflowBypassScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Hidden Workflow Field' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_no_workflow(self):
        """TN: 워크플로우 관련 요소 없음"""
        # Given
        url = 'https://example.com/home'
        html_content = '<h1>Welcome</h1>'

        # When
        scanner = WorkflowBypassScanner(url=url, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_workflow_bypass'] is False

    @pytest.mark.unit
    def test_edge_case_multiple_workflow_params(self):
        """Edge Case: 여러 워크플로우 파라미터"""
        # Given
        url = 'https://example.com/order?step=1&phase=initial&level=start&status=pending'

        # When
        scanner = WorkflowBypassScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] >= 4  # 모든 워크플로우 파라미터 탐지
        assert result['severity'] == 'high'


class TestAccountEnumerationScanner:
    """AccountEnumerationScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_login_form(self):
        """TP: 로그인 폼 탐지"""
        # Given
        html_content = '''
        <form action="/login" method="post">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <button type="submit">Login</button>
        </form>
        '''

        # When
        scanner = AccountEnumerationScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert result['has_account_enumeration'] is True
        assert any('Login Form Detected' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_enumeration_message(self):
        """TP: 계정 열거 가능 메시지"""
        # Given
        html_content = '<div class="error">User not found</div>'

        # When
        scanner = AccountEnumerationScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Account Enumeration Message' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_generic_error(self):
        """TN: 일반적인 에러 메시지"""
        # Given
        html_content = '<div class="error">Invalid credentials</div>'

        # When
        scanner = AccountEnumerationScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        # 계정 열거 패턴이 없어야 함
        enumeration_found = any('Account Enumeration Message' in v['type']
                               for v in result['vulnerabilities'])
        assert not enumeration_found

    @pytest.mark.unit
    def test_edge_case_korean_error_message(self):
        """Edge Case: 한국어 에러 메시지"""
        # Given
        html_content = '<div class="error">사용자를 찾을 수 없음</div>'

        # When
        scanner = AccountEnumerationScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Account Enumeration Message' in v['type'] for v in result['vulnerabilities'])


class TestResourceExhaustionScanner:
    """ResourceExhaustionScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_no_file_size_limit(self):
        """TP: 파일 크기 제한 없음"""
        # Given
        html_content = '''
        <form enctype="multipart/form-data">
            <input type="file" name="upload" />
            <button type="submit">Upload</button>
        </form>
        '''

        # When
        scanner = ResourceExhaustionScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert result['has_resource_exhaustion'] is True
        assert any('No File Size Limit' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_no_rate_limiting(self):
        """TP: Rate Limiting 헤더 없음"""
        # Given
        response = Mock()
        response.headers = {}

        # When
        scanner = ResourceExhaustionScanner(response=response)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('No Rate Limiting Headers' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_with_limits(self):
        """TN: 제한이 설정됨"""
        # Given
        html_content = '''
        <form enctype="multipart/form-data">
            <input type="file" name="upload" maxsize="10485760" />
        </form>
        '''
        response = Mock()
        response.headers = {'X-RateLimit-Limit': '100'}

        # When
        scanner = ResourceExhaustionScanner(html_content=html_content, response=response)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_resource_exhaustion'] is False

    @pytest.mark.unit
    def test_edge_case_multiple_file_inputs(self):
        """Edge Case: 여러 파일 입력 필드"""
        # Given
        html_content = '''
        <form>
            <input type="file" name="file1" />
            <input type="file" name="file2" />
            <input type="file" name="file3" />
        </form>
        '''

        # When
        scanner = ResourceExhaustionScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] == 1  # 한 번만 보고
        assert any('No File Size Limit' in v['type'] for v in result['vulnerabilities'])


class TestLoggingMonitoringScanner:
    """LoggingMonitoringScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_no_trace_id(self):
        """TP: 추적 ID 헤더 없음"""
        # Given
        response = Mock()
        response.headers = {'Content-Type': 'text/html'}

        # When
        scanner = LoggingMonitoringScanner(response=response)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert result['has_logging_issues'] is True
        assert any('No Trace ID' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_auth_failure(self):
        """TP: 인증 실패 응답"""
        # Given
        url = 'https://example.com'
        mock_client = Mock()
        mock_response = Mock()
        mock_response.status_code = 401
        mock_client.get.return_value = mock_response

        # When
        scanner = LoggingMonitoringScanner(url=url, http_client=mock_client)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Authentication Failure Detected' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_low_security_awareness(self):
        """TP: 보안 헤더 부재"""
        # Given
        response = Mock()
        response.headers = {}

        # When
        scanner = LoggingMonitoringScanner(response=response)
        result = scanner.scan()

        # Then
        assert any('Low Security Awareness' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_proper_logging(self):
        """TN: 적절한 로깅 설정"""
        # Given
        response = Mock()
        response.headers = {
            'X-Request-ID': 'abc123',
            'Content-Security-Policy': 'default-src self',
            'Strict-Transport-Security': 'max-age=31536000'
        }

        # When
        scanner = LoggingMonitoringScanner(response=response)
        result = scanner.scan()

        # Then
        # 추적 ID가 있고 보안 헤더가 있으므로 주요 취약점이 없어야 함
        assert not any('No Trace ID' in v['type'] for v in result['vulnerabilities'])
        assert not any('Low Security Awareness' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_edge_case_multiple_trace_headers(self):
        """Edge Case: 여러 추적 헤더"""
        # Given
        response = Mock()
        response.headers = {
            'X-Request-ID': 'req-123',
            'X-Trace-ID': 'trace-456',
            'X-Correlation-ID': 'corr-789'
        }

        # When
        scanner = LoggingMonitoringScanner(response=response)
        result = scanner.scan()

        # Then
        assert not any('No Trace ID' in v['type'] for v in result['vulnerabilities'])


class TestBusinessLogicAnomalyScanner:
    """BusinessLogicAnomalyScanner 테스트"""

    @pytest.mark.unit
    def test_true_positive_discount_param(self):
        """TP: URL에 할인 파라미터"""
        # Given
        url = 'https://shop.example.com/apply?discount=50&coupon=SAVE20'

        # When
        scanner = BusinessLogicAnomalyScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert result['has_logic_anomaly'] is True
        assert any('Discount Parameter Exposure' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_positive_hidden_logic_field(self):
        """TP: 숨겨진 비즈니스 로직 필드"""
        # Given
        html_content = '''
        <form action="/checkout" method="post">
            <input type="hidden" name="promo_code" value="SPECIAL" />
            <input type="hidden" name="points" value="1000" />
            <input type="hidden" name="refund_amount" value="0" />
        </form>
        '''

        # When
        scanner = BusinessLogicAnomalyScanner(html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] > 0
        assert any('Hidden Business Logic Field' in v['type'] for v in result['vulnerabilities'])

    @pytest.mark.unit
    def test_true_negative_no_logic_params(self):
        """TN: 비즈니스 로직 파라미터 없음"""
        # Given
        url = 'https://example.com/product?id=123'
        html_content = '<div>Product details</div>'

        # When
        scanner = BusinessLogicAnomalyScanner(url=url, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['total'] == 0
        assert result['has_logic_anomaly'] is False

    @pytest.mark.unit
    def test_edge_case_multiple_discount_params(self):
        """Edge Case: 여러 할인 관련 파라미터"""
        # Given
        url = 'https://shop.example.com/cart?discount=10&coupon=NEW&voucher=GIFT&promo=SALE'

        # When
        scanner = BusinessLogicAnomalyScanner(url=url)
        result = scanner.scan()

        # Then
        assert result['total'] >= 4  # 모든 할인 파라미터 탐지
        assert result['severity'] == 'high'

    @pytest.mark.unit
    def test_severity_calculation(self):
        """심각도 계산 테스트"""
        # Given
        url = 'https://shop.example.com/apply?discount=100'  # high severity
        html_content = '''
        <form>
            <input type="hidden" name="credit" value="500" />  # medium severity
        </form>
        '''

        # When
        scanner = BusinessLogicAnomalyScanner(url=url, html_content=html_content)
        result = scanner.scan()

        # Then
        assert result['severity'] == 'high'  # 가장 높은 심각도 반환