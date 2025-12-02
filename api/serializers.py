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


class ScanSummarySerializer(serializers.ModelSerializer):
    """스캔 결과 요약 (경량 버전)"""

    security_summary = serializers.SerializerMethodField()
    standards_summary = serializers.SerializerMethodField()
    accessibility_summary = serializers.SerializerMethodField()
    duration = serializers.SerializerMethodField()

    class Meta:
        model = ScanRequest
        fields = [
            'id', 'url', 'target_domain', 'status', 'duration', 'created_at',
            'security_summary', 'standards_summary', 'accessibility_summary'
        ]

    def get_duration(self, obj):
        """스캔 소요 시간"""
        return obj.duration()

    def get_security_summary(self, obj):
        """보안 결과 요약"""
        try:
            result = obj.security_result

            # scanner_metadata에서 스캐너 목록 가져오기
            scanner_list = []
            if result.scanner_metadata:
                for meta in result.scanner_metadata:
                    scanner_item = {
                        'id': meta.get('id'),
                        'name': meta.get('name'),
                        'icon': meta.get('icon'),
                        'status': 'pass',  # 기본값
                        'severity': 'low',  # 기본값
                        'count': 0
                    }

                    # 실제 결과 필드에서 상태 확인
                    field_name = meta.get('field')
                    if field_name:
                        field_value = getattr(result, field_name, {})
                        if isinstance(field_value, dict):
                            # 취약점이 있는지 확인
                            vulnerabilities = field_value.get('vulnerabilities', [])
                            if vulnerabilities:
                                scanner_item['status'] = 'fail'
                                scanner_item['count'] = len(vulnerabilities)
                                # 가장 높은 심각도 찾기
                                severities = [v.get('severity', 'low') for v in vulnerabilities]
                                severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
                                max_severity = max(severities, key=lambda x: severity_order.get(x, 0))
                                scanner_item['severity'] = max_severity
                            else:
                                scanner_item['status'] = 'pass'

                    scanner_list.append(scanner_item)

            # 심각도별 개수 계산
            critical_count = sum(1 for s in scanner_list if s['severity'] == 'critical' and s['status'] == 'fail')
            high_count = sum(1 for s in scanner_list if s['severity'] == 'high' and s['status'] == 'fail')
            medium_count = sum(1 for s in scanner_list if s['severity'] == 'medium' and s['status'] == 'fail')
            low_count = sum(1 for s in scanner_list if s['severity'] == 'low' and s['status'] == 'fail')

            return {
                'overall_score': result.overall_score,
                'risk_level': result.risk_level,
                'scanner_count': len(scanner_list),
                'critical_count': critical_count,
                'high_count': high_count,
                'medium_count': medium_count,
                'low_count': low_count,
                'scanners': scanner_list
            }
        except SecurityScanResult.DoesNotExist:
            return None

    def get_standards_summary(self, obj):
        """웹 표준 결과 요약"""
        try:
            result = obj.standards_result

            # scanner_metadata에서 스캐너 목록 가져오기
            scanner_list = []
            if result.scanner_metadata:
                for meta in result.scanner_metadata:
                    scanner_item = {
                        'id': meta.get('id'),
                        'name': meta.get('name'),
                        'icon': meta.get('icon'),
                        'status': 'pass',  # 기본값
                        'severity': 'info',  # 웹 표준은 대부분 info 레벨
                        'count': 0
                    }

                    # 실제 결과 필드에서 상태 확인
                    field_name = meta.get('field')
                    if field_name:
                        field_value = getattr(result, field_name, {})
                        if isinstance(field_value, dict):
                            # 취약점/이슈가 있는지 확인
                            vulnerabilities = field_value.get('vulnerabilities', field_value.get('issues', []))
                            if vulnerabilities:
                                scanner_item['status'] = 'fail'
                                scanner_item['count'] = len(vulnerabilities)
                                # 심각도 설정 (웹 표준은 주로 info/low)
                                if field_name in ['html_errors', 'css_errors', 'js_errors']:
                                    scanner_item['severity'] = 'medium'
                                elif field_name == 'seo_issues':
                                    scanner_item['severity'] = 'low'
                            else:
                                scanner_item['status'] = 'pass'

                    scanner_list.append(scanner_item)

            return {
                'overall_score': result.overall_score,
                'html_valid': result.html_valid,
                'html_error_count': result.html_error_count,
                'css_valid': result.css_valid,
                'css_error_count': result.css_error_count,
                'js_error_count': result.js_error_count,
                'seo_score': result.seo_score,
                'scanner_count': len(scanner_list),
                'scanners': scanner_list
            }
        except WebStandardsResult.DoesNotExist:
            return None

    def get_accessibility_summary(self, obj):
        """접근성 결과 요약"""
        try:
            result = obj.accessibility_result

            # scanner_metadata에서 스캐너 목록 가져오기
            scanner_list = []
            if result.scanner_metadata:
                for meta in result.scanner_metadata:
                    scanner_item = {
                        'id': meta.get('id'),
                        'name': meta.get('name'),
                        'icon': meta.get('icon'),
                        'status': 'pass',  # 기본값
                        'severity': 'low',  # 접근성은 대부분 low/medium
                        'count': 0
                    }

                    # 실제 결과 필드에서 상태 확인
                    field_name = meta.get('field')
                    if field_name:
                        field_value = getattr(result, field_name, {})
                        if isinstance(field_value, dict):
                            # 취약점/이슈가 있는지 확인
                            vulnerabilities = field_value.get('vulnerabilities', field_value.get('issues', []))
                            if vulnerabilities:
                                scanner_item['status'] = 'fail'
                                scanner_item['count'] = len(vulnerabilities)
                                # 심각도 설정 (접근성 이슈별로 다름)
                                severities = [v.get('severity', 'low') for v in vulnerabilities if isinstance(v, dict)]
                                if severities:
                                    severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
                                    max_severity = max(severities, key=lambda x: severity_order.get(x, 0))
                                    scanner_item['severity'] = max_severity
                            else:
                                scanner_item['status'] = 'pass'

                    scanner_list.append(scanner_item)

            return {
                'overall_score': result.overall_score,
                'wcag_level': result.wcag_level,
                'total_issues': result.total_issues,
                'critical_issues': result.critical_issues,
                'serious_issues': result.serious_issues,
                'scanner_count': len(scanner_list),
                'scanners': scanner_list
            }
        except AccessibilityResult.DoesNotExist:
            return None


class ScannerDetailSerializer(serializers.Serializer):
    """개별 스캐너 상세 정보"""

    scanner_id = serializers.SerializerMethodField()
    name = serializers.SerializerMethodField()
    icon = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    severity = serializers.SerializerMethodField()
    overall_score = serializers.SerializerMethodField()
    description = serializers.SerializerMethodField()
    vulnerabilities = serializers.SerializerMethodField()
    metadata = serializers.SerializerMethodField()
    guide = serializers.SerializerMethodField()
    statistics = serializers.SerializerMethodField()

    def get_scanner_id(self, obj):
        """스캐너 ID"""
        return self.context.get('scanner_id')

    def get_name(self, obj):
        """스캐너 이름"""
        scanner_id = self.context.get('scanner_id')
        # scanner_metadata에서 이름 찾기
        if obj.scanner_metadata:
            for meta in obj.scanner_metadata:
                if meta.get('id') == scanner_id:
                    return meta.get('name')
        return scanner_id

    def get_icon(self, obj):
        """스캐너 아이콘"""
        scanner_id = self.context.get('scanner_id')
        if obj.scanner_metadata:
            for meta in obj.scanner_metadata:
                if meta.get('id') == scanner_id:
                    return meta.get('icon')
        return '🔍'

    def get_status(self, obj):
        """스캐너 상태"""
        field_name = self.context.get('field_name')
        field_value = getattr(obj, field_name, {})
        if isinstance(field_value, dict):
            vulnerabilities = field_value.get('vulnerabilities', [])
            return 'fail' if vulnerabilities else 'pass'
        return 'unknown'

    def get_severity(self, obj):
        """최고 심각도"""
        field_name = self.context.get('field_name')
        field_value = getattr(obj, field_name, {})
        if isinstance(field_value, dict):
            vulnerabilities = field_value.get('vulnerabilities', [])
            if vulnerabilities:
                severities = [v.get('severity', 'low') for v in vulnerabilities]
                severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
                return max(severities, key=lambda x: severity_order.get(x, 0))
        return 'info'

    def get_overall_score(self, obj):
        """스캐너 점수"""
        field_name = self.context.get('field_name')
        field_value = getattr(obj, field_name, {})
        if isinstance(field_value, dict):
            return field_value.get('overall_score', 100)
        return 100

    def get_description(self, obj):
        """스캐너 설명"""
        scanner_id = self.context.get('scanner_id')
        if obj.scanner_metadata:
            for meta in obj.scanner_metadata:
                if meta.get('id') == scanner_id:
                    return meta.get('description')
        return ''

    def get_vulnerabilities(self, obj):
        """취약점 상세 목록"""
        field_name = self.context.get('field_name')
        field_value = getattr(obj, field_name, {})
        if isinstance(field_value, dict):
            return field_value.get('vulnerabilities', [])
        return []

    def get_metadata(self, obj):
        """스캐너 메타데이터"""
        scanner_id = self.context.get('scanner_id')
        if obj.scanner_metadata:
            for meta in obj.scanner_metadata:
                if meta.get('id') == scanner_id:
                    return {
                        'name': meta.get('name'),
                        'icon': meta.get('icon'),
                        'description': meta.get('description'),
                        'weight': meta.get('weight', 1),
                        'field': meta.get('field')
                    }
        return {}

    def get_guide(self, obj):
        """해결 가이드 정보"""
        scanner_id = self.context.get('scanner_id')

        # 가이드 정보 가져오기 (guides.py 파일이 있다면)
        try:
            from scanner.guides import SCANNER_GUIDES
            return SCANNER_GUIDES.get(scanner_id, {})
        except ImportError:
            # guides.py가 아직 없으면 기본 가이드 반환
            return {
                'description': f'{self.get_name(obj)} 검사 결과입니다.',
                'recommendation': '보안 모범 사례를 따라 구현하세요.',
                'references': []
            }

    def get_statistics(self, obj):
        """통계 정보"""
        field_name = self.context.get('field_name')
        field_value = getattr(obj, field_name, {})

        if isinstance(field_value, dict):
            vulnerabilities = field_value.get('vulnerabilities', [])

            # 심각도별 개수 계산
            severity_counts = {}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'info')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            return {
                'total_vulnerabilities': len(vulnerabilities),
                'critical_count': severity_counts.get('critical', 0),
                'high_count': severity_counts.get('high', 0),
                'medium_count': severity_counts.get('medium', 0),
                'low_count': severity_counts.get('low', 0),
                'info_count': severity_counts.get('info', 0),
                'passed': len(vulnerabilities) == 0
            }

        return {
            'total_vulnerabilities': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'info_count': 0,
            'passed': True
        }
