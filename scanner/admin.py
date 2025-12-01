"""
Scanner 앱 Admin 설정
"""
from django.contrib import admin
from django.utils.html import format_html
from django.contrib import messages
from .models import (
    ScanRequest,
    SecurityScanResult,
    WebStandardsResult,
    AccessibilityResult,
    Vulnerability,
    ScannerConfiguration,
    ScannerPreset
)


@admin.register(ScanRequest)
class ScanRequestAdmin(admin.ModelAdmin):
    """스캔 요청 Admin"""

    list_display = [
        'id', 'target_domain', 'status_badge', 'progress',
        'created_at', 'duration_display'
    ]
    list_filter = ['status', 'scan_types', 'created_at']
    search_fields = ['url', 'target_domain', 'ip_address']
    readonly_fields = ['id', 'created_at', 'started_at', 'completed_at', 'task_id']

    fieldsets = (
        ('기본 정보', {
            'fields': ('id', 'url', 'target_domain', 'scan_types', 'deep_scan')
        }),
        ('상태', {
            'fields': ('status', 'progress', 'task_id')
        }),
        ('시간 정보', {
            'fields': ('created_at', 'started_at', 'completed_at')
        }),
        ('요청자 정보', {
            'fields': ('ip_address', 'user_agent')
        }),
        ('에러', {
            'fields': ('error_message',),
            'classes': ('collapse',)
        }),
    )

    def status_badge(self, obj):
        """상태 뱃지"""
        colors = {
            'pending': '#6c757d',
            'running': '#007bff',
            'completed': '#28a745',
            'failed': '#dc3545',
        }
        color = colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = '상태'

    def duration_display(self, obj):
        """소요 시간 표시"""
        duration = obj.duration()
        if duration:
            return f"{duration:.2f}초"
        return '-'
    duration_display.short_description = '소요 시간'


@admin.register(SecurityScanResult)
class SecurityScanResultAdmin(admin.ModelAdmin):
    """보안 스캔 결과 Admin"""

    list_display = [
        'scan_request', 'overall_score', 'risk_level_badge', 'created_at'
    ]
    list_filter = ['risk_level', 'created_at']
    search_fields = ['scan_request__target_domain']
    readonly_fields = ['created_at', 'updated_at']

    def risk_level_badge(self, obj):
        """위험 수준 뱃지"""
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#17a2b8',
            'info': '#6c757d',
        }
        color = colors.get(obj.risk_level, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_risk_level_display()
        )
    risk_level_badge.short_description = '위험 수준'


@admin.register(WebStandardsResult)
class WebStandardsResultAdmin(admin.ModelAdmin):
    """웹 표준 결과 Admin"""

    list_display = [
        'scan_request', 'overall_score', 'html_valid', 'css_valid',
        'html_error_count', 'css_error_count', 'js_error_count', 'created_at'
    ]
    list_filter = ['html_valid', 'css_valid', 'created_at']
    search_fields = ['scan_request__target_domain']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(AccessibilityResult)
class AccessibilityResultAdmin(admin.ModelAdmin):
    """접근성 결과 Admin"""

    list_display = [
        'scan_request', 'overall_score', 'wcag_level_badge',
        'total_issues', 'critical_issues', 'created_at'
    ]
    list_filter = ['wcag_level', 'created_at']
    search_fields = ['scan_request__target_domain']
    readonly_fields = ['created_at', 'updated_at']

    def wcag_level_badge(self, obj):
        """WCAG 등급 뱃지"""
        colors = {
            'AAA': '#28a745',
            'AA': '#17a2b8',
            'A': '#ffc107',
            'None': '#dc3545',
        }
        color = colors.get(obj.wcag_level, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_wcag_level_display()
        )
    wcag_level_badge.short_description = 'WCAG 등급'


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    """취약점 Admin"""

    list_display = [
        'title', 'severity_badge', 'category', 'vulnerability_type',
        'affected_url_short', 'created_at'
    ]
    list_filter = ['severity', 'category', 'vulnerability_type', 'created_at']
    search_fields = ['title', 'description', 'affected_url']
    readonly_fields = ['created_at']

    fieldsets = (
        ('분류', {
            'fields': ('category', 'vulnerability_type', 'severity')
        }),
        ('상세 정보', {
            'fields': ('title', 'description', 'affected_url', 'affected_element', 'evidence')
        }),
        ('권장 사항', {
            'fields': ('recommendation',)
        }),
        ('참조 정보', {
            'fields': ('cve_id', 'cwe_id', 'owasp_category'),
            'classes': ('collapse',)
        }),
        ('메타', {
            'fields': ('scan_request', 'created_at'),
            'classes': ('collapse',)
        }),
    )

    def severity_badge(self, obj):
        """심각도 뱃지"""
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#17a2b8',
            'info': '#6c757d',
        }
        color = colors.get(obj.severity, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; '
            'border-radius: 3px;">{}</span>',
            color, obj.get_severity_display()
        )
    severity_badge.short_description = '심각도'

    def affected_url_short(self, obj):
        """URL 축약 표시"""
        url = obj.affected_url
        if len(url) > 50:
            return url[:50] + '...'
        return url
    affected_url_short.short_description = '영향받는 URL'


@admin.register(ScannerConfiguration)
class ScannerConfigurationAdmin(admin.ModelAdmin):
    """스캐너 설정 Admin"""

    list_display = [
        'enabled_status', 'display_status', 'scanner_id', 'name',
        'category', 'timeout', 'weight', 'display_order',
        'total_runs', 'success_rate_display', 'avg_duration_display'
    ]
    list_filter = [
        'category', 'enabled', 'show_in_results',
        'show_if_passed', 'show_if_failed'
    ]
    search_fields = ['scanner_id', 'name', 'description']
    list_editable = [
        'enabled', 'show_in_results', 'display_order',
        'timeout', 'weight'
    ]
    list_per_page = 50  # 50개 스캐너를 한 페이지에 표시

    fieldsets = (
        ('기본 정보', {
            'fields': ('scanner_id', 'name', 'category', 'icon', 'description'),
            'description': '스캐너의 기본 정보입니다.'
        }),
        ('실행 제어', {
            'fields': ('enabled', 'timeout', 'weight'),
            'description': '스캔 실행 시 이 스캐너를 어떻게 처리할지 설정합니다.'
        }),
        ('결과 표시 제어', {
            'fields': (
                'show_in_results', 'show_details',
                'show_if_passed', 'show_if_failed',
                'display_order'
            ),
            'description': '스캔 결과 페이지에서 이 스캐너 결과를 어떻게 표시할지 설정합니다.'
        }),
        ('커스텀 메시지 (선택사항)', {
            'fields': ('custom_pass_message', 'custom_fail_message'),
            'classes': ('collapse',),
            'description': '기본 메시지 대신 표시할 커스텀 메시지를 설정할 수 있습니다.'
        }),
        ('통계', {
            'fields': (
                'total_runs', 'total_failures',
                'avg_duration', 'last_run_at'
            ),
            'classes': ('collapse',),
            'description': '스캐너 실행 통계입니다. (자동 업데이트됨)'
        }),
        ('메타정보', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )

    readonly_fields = [
        'total_runs', 'total_failures', 'avg_duration',
        'last_run_at', 'created_at', 'updated_at'
    ]

    def enabled_status(self, obj):
        """활성화 상태 뱃지"""
        if obj.enabled:
            color = '#28a745'
            text = '✅ 활성'
        else:
            color = '#dc3545'
            text = '❌ 비활성'
        return format_html(
            '<span style="background-color: {}; color: white; '
            'padding: 3px 10px; border-radius: 3px; font-size: 12px;">{}</span>',
            color, text
        )
    enabled_status.short_description = '실행'
    enabled_status.admin_order_field = 'enabled'

    def display_status(self, obj):
        """표시 상태 뱃지"""
        if obj.show_in_results:
            color = '#17a2b8'
            text = '👁️ 표시'
        else:
            color = '#6c757d'
            text = '🚫 숨김'
        return format_html(
            '<span style="background-color: {}; color: white; '
            'padding: 3px 10px; border-radius: 3px; font-size: 12px;">{}</span>',
            color, text
        )
    display_status.short_description = '결과'
    display_status.admin_order_field = 'show_in_results'

    def success_rate_display(self, obj):
        """성공률 표시"""
        if obj.total_runs == 0:
            return '-'
        rate = obj.success_rate()
        color = '#28a745' if rate >= 80 else '#ffc107' if rate >= 50 else '#dc3545'
        return format_html(
            '<span style="color: {}; font-weight: bold;">{:.1f}%</span>',
            color, rate
        )
    success_rate_display.short_description = '성공률'

    def avg_duration_display(self, obj):
        """평균 실행 시간 표시"""
        if obj.avg_duration == 0:
            return '-'
        return f'{obj.avg_duration:.2f}초'
    avg_duration_display.short_description = '평균 시간'

    actions = [
        'enable_scanners', 'disable_scanners',
        'show_in_results_action', 'hide_from_results_action',
        'reset_display_order', 'reset_statistics'
    ]

    def enable_scanners(self, request, queryset):
        """선택한 스캐너 활성화"""
        updated = queryset.update(enabled=True)
        self.message_user(
            request,
            f'{updated}개 스캐너가 활성화되었습니다.',
            messages.SUCCESS
        )
    enable_scanners.short_description = '선택한 스캐너 활성화'

    def disable_scanners(self, request, queryset):
        """선택한 스캐너 비활성화"""
        updated = queryset.update(enabled=False)
        self.message_user(
            request,
            f'{updated}개 스캐너가 비활성화되었습니다.',
            messages.WARNING
        )
    disable_scanners.short_description = '선택한 스캐너 비활성화'

    def show_in_results_action(self, request, queryset):
        """결과 페이지에 표시"""
        updated = queryset.update(show_in_results=True)
        self.message_user(
            request,
            f'{updated}개 스캐너가 결과 페이지에 표시됩니다.',
            messages.SUCCESS
        )
    show_in_results_action.short_description = '결과 페이지에 표시'

    def hide_from_results_action(self, request, queryset):
        """결과 페이지에서 숨김"""
        updated = queryset.update(show_in_results=False)
        self.message_user(
            request,
            f'{updated}개 스캐너가 결과 페이지에서 숨겨집니다.',
            messages.WARNING
        )
    hide_from_results_action.short_description = '결과 페이지에서 숨김'

    def reset_display_order(self, request, queryset):
        """표시 순서 초기화"""
        for i, config in enumerate(queryset.order_by('category', 'scanner_id')):
            config.display_order = i * 10  # 10 단위로 설정
            config.save()
        self.message_user(
            request,
            f'{queryset.count()}개 스캐너의 표시 순서가 초기화되었습니다.',
            messages.INFO
        )
    reset_display_order.short_description = '표시 순서 초기화'

    def reset_statistics(self, request, queryset):
        """통계 초기화"""
        updated = queryset.update(
            total_runs=0,
            total_failures=0,
            avg_duration=0.0,
            last_run_at=None
        )
        self.message_user(
            request,
            f'{updated}개 스캐너의 통계가 초기화되었습니다.',
            messages.INFO
        )
    reset_statistics.short_description = '통계 초기화'

    def get_queryset(self, request):
        """쿼리셋 최적화"""
        qs = super().get_queryset(request)
        return qs.select_related().order_by('category', 'display_order', 'scanner_id')

    # list_display에서 직접 필드를 참조하도록 수정
    list_display = [
        'enabled_status', 'display_status', 'scanner_id', 'name',
        'category', 'timeout', 'weight', 'display_order',
        'total_runs', 'success_rate_display', 'avg_duration_display'
    ]

    # list_editable에서 enabled와 show_in_results 필드 추가
    # (list_display에서 메서드로 표시하더라도 실제 필드는 편집 가능)
    list_editable = [
        'display_order', 'timeout', 'weight'
    ]


@admin.register(ScannerPreset)
class ScannerPresetAdmin(admin.ModelAdmin):
    """스캐너 프리셋 Admin"""

    list_display = ['active_status', 'name', 'description', 'created_at']
    search_fields = ['name', 'description']
    readonly_fields = ['created_at', 'updated_at']

    fieldsets = (
        ('프리셋 정보', {
            'fields': ('name', 'description', 'is_active'),
        }),
        ('설정', {
            'fields': ('configurations',),
            'description': 'JSON 형식으로 scanner_id별 설정을 입력하세요.',
            'classes': ('wide',)
        }),
        ('메타정보', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',),
        }),
    )

    def active_status(self, obj):
        """활성 상태 표시"""
        if obj.is_active:
            return format_html(
                '<span style="color: #28a745; font-weight: bold;">✓ 활성</span>'
            )
        return '-'
    active_status.short_description = '상태'

    actions = ['apply_preset', 'create_current_as_preset']

    def apply_preset(self, request, queryset):
        """선택한 프리셋 적용"""
        if queryset.count() > 1:
            self.message_user(
                request,
                '한 번에 하나의 프리셋만 적용할 수 있습니다.',
                messages.ERROR
            )
            return

        preset = queryset.first()
        if preset:
            preset.apply()
            self.message_user(
                request,
                f'"{preset.name}" 프리셋이 적용되었습니다.',
                messages.SUCCESS
            )
    apply_preset.short_description = '선택한 프리셋 적용'

    def create_current_as_preset(self, request, queryset):
        """현재 설정을 새 프리셋으로 저장"""
        # 현재 모든 스캐너 설정 가져오기
        configs = ScannerConfiguration.objects.all()
        preset_config = {}

        for config in configs:
            preset_config[config.scanner_id] = {
                'enabled': config.enabled,
                'show_in_results': config.show_in_results,
                'show_details': config.show_details,
                'show_if_passed': config.show_if_passed,
                'show_if_failed': config.show_if_failed,
                'timeout': config.timeout,
                'weight': config.weight,
                'display_order': config.display_order,
            }

        # 새 프리셋 생성
        from django.utils import timezone
        new_preset = ScannerPreset.objects.create(
            name=f'스냅샷_{timezone.now().strftime("%Y%m%d_%H%M%S")}',
            description='현재 설정의 스냅샷',
            configurations=preset_config,
            is_active=False
        )

        self.message_user(
            request,
            f'현재 설정이 "{new_preset.name}" 프리셋으로 저장되었습니다.',
            messages.SUCCESS
        )
    create_current_as_preset.short_description = '현재 설정을 프리셋으로 저장'
