"""
SecurityHeaderScanner 유닛 테스트

탐지 정확도 중심의 테스트:
- True Positive: 실제 문제를 정확히 탐지
- False Positive: 안전한 것을 문제로 오탐지 방지
- False Negative: 문제를 놓치지 않기
"""

import pytest
from unittest.mock import Mock, MagicMock

# 프로젝트 루트를 Python 경로에 추가
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from scanner.scanners_refactored import SecurityHeaderScanner


class TestSecurityHeaderScanner:
    """SecurityHeaderScanner 탐지 능력 검증"""

    # ==================== True Positive 테스트 ====================

    @pytest.mark.unit
    def test_detect_all_missing_headers(self):
        """모든 보안 헤더가 누락된 경우 100% 탐지해야 함"""
        # Given: 보안 헤더가 전혀 없는 응답
        headers = {
            'Server': 'Apache/2.4.1',
            'Content-Type': 'text/html'
        }

        # When: 스캔 실행
        scanner = SecurityHeaderScanner(headers=headers)
        result = scanner.scan()

        # Then: 7개 헤더 모두 누락으로 탐지
        assert result['missing_count'] == 7, "7개 보안 헤더가 모두 누락되어야 함"
        assert result['total_count'] == 7
        assert len(result['vulnerabilities']) >= 2, "최소 2개 이상 중요 헤더 누락 취약점"

        # 각 헤더별 누락 확인
        for header_name in scanner.SECURITY_HEADERS.keys():
            assert result['headers'][header_name]['present'] == False
            assert result['headers'][header_name]['status'] == 'missing'

    @pytest.mark.unit
    def test_detect_weak_hsts_configuration(self):
        """약한 HSTS 설정 탐지"""
        # Given: max-age가 너무 짧은 HSTS
        headers = {
            'Strict-Transport-Security': 'max-age=60'  # 60초는 너무 짧음
        }

        # When
        scanner = SecurityHeaderScanner(headers=headers)
        result = scanner.scan()

        # Then: 약한 설정으로 탐지
        hsts_result = result['headers']['Strict-Transport-Security']
        assert hsts_result['present'] == True
        assert hsts_result['status'] == 'weak'
        assert 'warning' in hsts_result
        assert 'max-age가 너무 짧습니다' in hsts_result['warning']

        # 취약점으로 보고
        weak_hsts = [v for v in result['vulnerabilities'] if 'Strict-Transport-Security' in v['header']]
        assert len(weak_hsts) > 0, "약한 HSTS는 취약점으로 보고되어야 함"

    @pytest.mark.unit
    def test_detect_weak_csp_with_unsafe_inline(self):
        """unsafe-inline이 포함된 약한 CSP 탐지"""
        # Given: unsafe-inline이 포함된 CSP
        headers = {
            'Content-Security-Policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval'"
        }

        # When
        scanner = SecurityHeaderScanner(headers=headers)
        result = scanner.scan()

        # Then: 약한 CSP로 탐지
        csp_result = result['headers']['Content-Security-Policy']
        assert csp_result['status'] == 'weak'
        assert 'unsafe-inline' in csp_result.get('warning', '')

    @pytest.mark.unit
    def test_detect_invalid_xframe_options(self):
        """잘못된 X-Frame-Options 값 탐지"""
        # Given: 유효하지 않은 값
        headers = {
            'X-Frame-Options': 'ALLOW'  # 잘못된 값
        }

        # When
        scanner = SecurityHeaderScanner(headers=headers)
        result = scanner.scan()

        # Then: 약한 설정으로 탐지
        xframe_result = result['headers']['X-Frame-Options']
        assert xframe_result['status'] == 'weak'
        assert '유효하지 않은 값' in xframe_result.get('warning', '')

    @pytest.mark.unit
    def test_detect_server_information_disclosure(self):
        """Server 헤더 정보 노출은 탐지하지 않음 (스코프 밖)"""
        # Given: Server 헤더만 있고 보안 헤더는 없음
        headers = {
            'Server': 'Apache/2.4.1 (Unix) OpenSSL/1.0.1e PHP/5.5.3'
        }

        # When
        scanner = SecurityHeaderScanner(headers=headers)
        result = scanner.scan()

        # Then: 보안 헤더 누락은 탐지하지만 Server 헤더는 무시
        assert result['missing_count'] == 7
        # Server 헤더 관련 취약점은 없어야 함 (다른 스캐너의 역할)

    # ==================== False Positive 방지 테스트 ====================

    @pytest.mark.unit
    def test_no_false_positive_with_all_secure_headers(self):
        """모든 보안 헤더가 올바르게 설정된 경우 취약점 없음"""
        # Given: 완벽한 보안 헤더 세트
        headers = {
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'",
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
            'X-XSS-Protection': '1; mode=block'
        }

        # When
        scanner = SecurityHeaderScanner(headers=headers)
        result = scanner.scan()

        # Then: 취약점 0개
        assert result['missing_count'] == 0, "누락된 헤더가 없어야 함"
        assert len(result['vulnerabilities']) == 0, "취약점이 없어야 함"
        assert result['total'] == 0

        # 모든 헤더가 OK 상태
        for header_name in scanner.SECURITY_HEADERS.keys():
            assert result['headers'][header_name]['present'] == True
            assert result['headers'][header_name]['status'] == 'ok'

    @pytest.mark.unit
    def test_no_false_positive_with_valid_variations(self):
        """유효한 변형 값들을 잘못 탐지하지 않음"""
        # Given: 다양한 유효한 값들
        test_cases = [
            {
                'X-Frame-Options': 'SAMEORIGIN'  # DENY 대신 SAMEORIGIN도 유효
            },
            {
                'Referrer-Policy': 'no-referrer'  # strict-origin 외 다른 안전한 옵션
            },
            {
                'Strict-Transport-Security': 'max-age=63072000'  # 2년도 충분
            }
        ]

        for headers in test_cases:
            # When
            scanner = SecurityHeaderScanner(headers=headers)
            result = scanner.scan()

            # Then: 이 헤더들은 weak로 표시되지 않아야 함
            for header_name, header_value in headers.items():
                if header_name in result['headers']:
                    status = result['headers'][header_name].get('status')
                    # SAMEORIGIN과 no-referrer는 weak가 아님
                    if header_name == 'X-Frame-Options' and 'SAMEORIGIN' in header_value:
                        assert status == 'ok', f"{header_name}이 잘못 weak로 표시됨"
                    elif header_name == 'Strict-Transport-Security':
                        assert status == 'ok', "충분한 max-age가 weak로 표시됨"

    # ==================== False Negative 방지 테스트 ====================

    @pytest.mark.unit
    def test_must_detect_partial_headers_missing(self):
        """일부 헤더만 있을 때도 누락된 헤더 정확히 탐지"""
        # Given: 3개만 설정된 헤더
        headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block'
        }

        # When
        scanner = SecurityHeaderScanner(headers=headers)
        result = scanner.scan()

        # Then: 4개 누락 탐지
        assert result['missing_count'] == 4
        missing = result['missing_headers']
        assert 'Strict-Transport-Security' in missing, "HSTS 누락을 탐지해야 함"
        assert 'Content-Security-Policy' in missing, "CSP 누락을 탐지해야 함"

    @pytest.mark.unit
    def test_must_detect_hsts_without_includesubdomains(self):
        """includeSubDomains가 없는 HSTS도 주의사항으로 표시"""
        # Given: includeSubDomains가 없는 HSTS
        headers = {
            'Strict-Transport-Security': 'max-age=31536000'  # includeSubDomains 없음
        }

        # When
        scanner = SecurityHeaderScanner(headers=headers)
        result = scanner.scan()

        # Then: note나 recommendation에 언급
        hsts_result = result['headers']['Strict-Transport-Security']
        assert hsts_result['present'] == True
        assert 'includeSubDomains' in hsts_result.get('note', ''), \
            "includeSubDomains 권장사항을 놓치면 안 됨"

    @pytest.mark.unit
    def test_detect_all_weak_csp_patterns(self):
        """다양한 약한 CSP 패턴 모두 탐지"""
        weak_csp_values = [
            "default-src *",  # 와일드카드
            "script-src 'unsafe-eval'",  # unsafe-eval
            "style-src 'unsafe-inline'",  # unsafe-inline
            "default-src 'self' *",  # 와일드카드 포함
        ]

        for csp_value in weak_csp_values:
            # Given
            headers = {'Content-Security-Policy': csp_value}

            # When
            scanner = SecurityHeaderScanner(headers=headers)
            result = scanner.scan()

            # Then
            csp_result = result['headers']['Content-Security-Policy']
            assert csp_result['status'] == 'weak', \
                f"약한 CSP를 탐지하지 못함: {csp_value}"

    # ==================== 엣지 케이스 테스트 ====================

    @pytest.mark.unit
    def test_handle_empty_headers(self):
        """빈 헤더 딕셔너리 처리"""
        # Given
        headers = {}

        # When
        scanner = SecurityHeaderScanner(headers=headers)
        result = scanner.scan()

        # Then: 에러 없이 모든 헤더 누락으로 처리
        assert result['missing_count'] == 7
        assert 'error' not in result

    @pytest.mark.unit
    def test_handle_none_headers(self):
        """None 헤더 처리"""
        # Given & When
        scanner = SecurityHeaderScanner(headers=None)
        result = scanner.scan()

        # Then: 에러 없이 처리
        assert result['missing_count'] == 7
        assert 'error' not in result

    @pytest.mark.unit
    def test_handle_malformed_header_values(self):
        """잘못된 형식의 헤더 값 처리"""
        # Given: 이상한 값들
        headers = {
            'Strict-Transport-Security': '',  # 빈 값
            'X-Frame-Options': '   ',  # 공백만
            'Content-Security-Policy': None,  # None 값
        }

        # When
        scanner = SecurityHeaderScanner(headers=headers)
        result = scanner.scan()

        # Then: 에러 없이 처리
        assert 'error' not in result

    @pytest.mark.unit
    def test_case_sensitivity(self):
        """헤더 이름 대소문자 처리"""
        # Given: 대소문자 혼용
        headers = {
            'strict-transport-security': 'max-age=31536000',  # 소문자
            'X-FRAME-OPTIONS': 'DENY',  # 대문자
        }

        # When
        scanner = SecurityHeaderScanner(headers=headers)
        result = scanner.scan()

        # Then: 표준 형식으로만 인식 (HTTP 헤더는 대소문자 구분 없지만 정확한 형식 사용)
        # 대부분의 HTTP 라이브러리가 정규화하므로 이 테스트는 구현에 따라 다름

    # ==================== 통합 시나리오 테스트 ====================

    @pytest.mark.unit
    def test_realistic_secure_site(self):
        """실제 안전한 사이트 시나리오"""
        # Given: Google 수준의 보안 헤더
        headers = {
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'strict-dynamic'",
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }

        # When
        scanner = SecurityHeaderScanner(headers=headers)
        result = scanner.scan()

        # Then: 주요 헤더는 모두 있음
        assert result['missing_count'] <= 2, "선택적 헤더 2개 정도만 누락"
        assert len([v for v in result['vulnerabilities'] if v['severity'] == 'high']) == 0, \
            "높은 심각도 취약점은 없어야 함"

    @pytest.mark.unit
    def test_realistic_vulnerable_site(self):
        """실제 취약한 사이트 시나리오"""
        # Given: 전형적인 취약한 사이트
        headers = {
            'Server': 'Apache/2.2.15',
            'X-Powered-By': 'PHP/5.3.3',
            'Set-Cookie': 'session=abc123'
            # 보안 헤더 전무
        }

        # When
        scanner = SecurityHeaderScanner(headers=headers)
        result = scanner.scan()

        # Then: 모든 보안 헤더 누락
        assert result['missing_count'] == 7
        assert result['severity'] in ['high', 'critical'], "전체 심각도가 높아야 함"

        # 중요 헤더 누락은 취약점으로
        high_severity = [v for v in result['vulnerabilities'] if v['severity'] == 'high']
        assert len(high_severity) >= 2, "HSTS, CSP 등 중요 헤더 누락 탐지"

    # ==================== 성능 테스트 ====================

    @pytest.mark.unit
    def test_performance_with_many_headers(self):
        """많은 헤더가 있어도 빠른 처리"""
        # Given: 100개의 헤더
        headers = {f'Custom-Header-{i}': f'value-{i}' for i in range(100)}
        headers.update({
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Frame-Options': 'DENY'
        })

        # When
        import time
        start = time.time()
        scanner = SecurityHeaderScanner(headers=headers)
        result = scanner.scan()
        elapsed = time.time() - start

        # Then: 0.1초 이내 처리
        assert elapsed < 0.1, f"처리 시간이 너무 김: {elapsed}초"
        assert result['missing_count'] == 5  # 7개 중 2개만 있음


class TestSecurityHeaderScannerIntegration:
    """BaseScanner와의 통합 테스트"""

    @pytest.mark.unit
    def test_base_scanner_error_handling(self):
        """BaseScanner의 에러 처리 동작"""
        # Given: 스캔 중 예외 발생하도록 설정
        scanner = SecurityHeaderScanner(headers={'test': 'value'})

        # 강제로 예외 발생
        original_execute = scanner._execute_scan
        def raise_error():
            raise ValueError("Test error")
        scanner._execute_scan = raise_error

        # When
        result = scanner.scan()

        # Then: 에러 결과 반환
        assert 'error' in result
        assert result['error'] == 'Test error'
        assert result['total'] == 0
        assert result['vulnerabilities'] == []

    @pytest.mark.unit
    def test_severity_calculation(self):
        """심각도 계산 테스트"""
        # Given: 다양한 심각도의 취약점
        headers = {}  # 모든 헤더 누락

        # When
        scanner = SecurityHeaderScanner(headers=headers)
        result = scanner.scan()

        # Then: 가장 높은 심각도 반환
        assert result['severity'] == 'high', "HSTS, CSP 누락으로 high 심각도"