"""
API Serializers
스캔 요청 및 결과를 JSON으로 변환
"""
from rest_framework import serializers
from scanner.models import (
    ScanRequest,
    SecurityScanResult,
    WebStandardsResult,
    AccessibilityResult,
    Vulnerability
)


class ScanRequestSerializer(serializers.ModelSerializer):
    """스캔 요청 Serializer"""

    duration = serializers.SerializerMethodField()

    class Meta:
        model = ScanRequest
        fields = [
            'id', 'url', 'target_domain', 'scan_types', 'deep_scan',
            'status', 'progress', 'created_at', 'started_at', 'completed_at',
            'error_message', 'duration'
        ]
        read_only_fields = [
            'id', 'target_domain', 'status', 'progress', 'created_at',
            'started_at', 'completed_at', 'error_message'
        ]

    def get_duration(self, obj):
        """스캔 소요 시간"""
        return obj.duration()


class ScanRequestCreateSerializer(serializers.Serializer):
    """스캔 요청 생성 Serializer"""

    url = serializers.URLField(
        max_length=2048,
        required=True,
        help_text='스캔할 URL (예: https://example.com)'
    )
    scan_types = serializers.ListField(
        child=serializers.ChoiceField(choices=['security', 'standards', 'accessibility']),
        required=False,
        default=['security', 'standards', 'accessibility'],
        help_text='스캔 유형 목록'
    )
    deep_scan = serializers.BooleanField(
        required=False,
        default=False,
        help_text='심층 스캔 여부'
    )

    def validate_url(self, value):
        """URL 검증"""
        from urllib.parse import urlparse
        from django.conf import settings
        import ipaddress

        # URL 파싱
        parsed = urlparse(value)

        # 스킴 검증
        if parsed.scheme not in ['http', 'https']:
            raise serializers.ValidationError('HTTP 또는 HTTPS URL만 지원됩니다.')

        # 호스트 검증
        if not parsed.netloc:
            raise serializers.ValidationError('유효한 URL이 아닙니다.')

        # 내부 IP 차단 (SSRF 방지)
        try:
            # 호스트 추출
            host = parsed.netloc.split(':')[0]

            # IP 주소인 경우 검증
            try:
                ip = ipaddress.ip_address(host)

                # 차단된 IP 범위 확인
                blocked_ranges = settings.BLOCKED_IP_RANGES
                for blocked_range in blocked_ranges:
                    network = ipaddress.ip_network(blocked_range)
                    if ip in network:
                        raise serializers.ValidationError(
                            '내부 네트워크 또는 로컬호스트는 스캔할 수 없습니다.'
                        )
            except ValueError:
                # 도메인인 경우 localhost 등 차단
                if host.lower() in ['localhost', '127.0.0.1', '0.0.0.0']:
                    raise serializers.ValidationError(
                        '로컬호스트는 스캔할 수 없습니다.'
                    )
        except Exception as e:
            raise serializers.ValidationError(f'URL 검증 실패: {str(e)}')

        return value

    def validate_scan_types(self, value):
        """스캔 유형 검증"""
        if not value:
            raise serializers.ValidationError('최소 하나의 스캔 유형을 선택해야 합니다.')

        # 중복 제거
        return list(set(value))


class VulnerabilitySerializer(serializers.ModelSerializer):
    """취약점 Serializer"""

    class Meta:
        model = Vulnerability
        fields = [
            'id', 'category', 'vulnerability_type', 'severity',
            'title', 'description', 'affected_url', 'affected_element',
            'evidence', 'recommendation', 'cve_id', 'cwe_id',
            'owasp_category', 'created_at'
        ]


class SecurityScanResultSerializer(serializers.ModelSerializer):
    """보안 스캔 결과 Serializer"""

    class Meta:
        model = SecurityScanResult
        fields = [
            'overall_score', 'risk_level',
            'sql_injection', 'xss_vulnerabilities', 'csrf_protection',
            'insecure_deserialization', 'xml_external_entities',
            'broken_access_control', 'security_misconfiguration',
            'sensitive_data_exposure', 'insufficient_logging',
            'vulnerable_components', 'security_headers', 'ssl_tls_result',
            'clickjacking', 'cors_misconfiguration', 'open_redirects',
            'scanner_metadata', 'created_at', 'updated_at'
        ]


class WebStandardsResultSerializer(serializers.ModelSerializer):
    """웹 표준 결과 Serializer"""

    class Meta:
        model = WebStandardsResult
        fields = [
            'overall_score', 'html_valid', 'html_errors', 'html_warnings',
            'html_error_count', 'css_valid', 'css_errors', 'css_warnings',
            'css_error_count', 'js_errors', 'js_console_logs', 'js_error_count',
            'seo_score', 'seo_issues', 'meta_tags', 'page_load_time',
            'page_size', 'scanner_metadata', 'created_at', 'updated_at'
        ]


class AccessibilityResultSerializer(serializers.ModelSerializer):
    """접근성 결과 Serializer"""

    class Meta:
        model = AccessibilityResult
        fields = [
            'overall_score', 'wcag_level', 'perceivable_issues',
            'operable_issues', 'understandable_issues', 'robust_issues',
            'aria_errors', 'aria_warnings', 'keyboard_navigation',
            'color_contrast', 'screen_reader_issues', 'alt_text_missing',
            'heading_structure', 'form_labels', 'total_issues',
            'critical_issues', 'serious_issues', 'moderate_issues',
            'minor_issues', 'scanner_metadata', 'created_at', 'updated_at'
        ]


class ScanResultSerializer(serializers.ModelSerializer):
    """전체 스캔 결과 Serializer"""

    security_result = SecurityScanResultSerializer(read_only=True)
    standards_result = WebStandardsResultSerializer(read_only=True)
    accessibility_result = AccessibilityResultSerializer(read_only=True)
    vulnerabilities = VulnerabilitySerializer(many=True, read_only=True)
    duration = serializers.SerializerMethodField()

    class Meta:
        model = ScanRequest
        fields = [
            'id', 'url', 'target_domain', 'scan_types', 'deep_scan',
            'status', 'progress', 'created_at', 'started_at', 'completed_at',
            'error_message', 'duration', 'security_result', 'standards_result',
            'accessibility_result', 'vulnerabilities'
        ]

    def get_duration(self, obj):
        """스캔 소요 시간"""
        return obj.duration()
