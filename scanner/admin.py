"""
Scanner 앱 Admin 설정
"""
from django.contrib import admin
from django.utils.html import format_html
from .models import (
    ScanRequest,
    SecurityScanResult,
    WebStandardsResult,
    AccessibilityResult,
    Vulnerability
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
