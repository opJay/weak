"""
스캔 관련 모델 정의
URL 스캔 요청 및 결과를 저장하는 모델들
"""
from django.db import models
from django.utils import timezone
import uuid


class ScanRequest(models.Model):
    """스캔 요청 메인 모델"""

    STATUS_CHOICES = [
        ('pending', '대기 중'),
        ('running', '실행 중'),
        ('completed', '완료'),
        ('failed', '실패'),
    ]

    # 기본 정보
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    url = models.URLField(max_length=2048, verbose_name='스캔 URL')
    target_domain = models.CharField(max_length=255, verbose_name='대상 도메인')

    # 스캔 설정
    scan_types = models.JSONField(
        default=list,
        verbose_name='스캔 유형',
        help_text='["security", "standards", "accessibility"]'
    )
    deep_scan = models.BooleanField(default=False, verbose_name='심층 스캔')

    # 상태 관리
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending',
        verbose_name='상태'
    )
    progress = models.IntegerField(default=0, verbose_name='진행률 (%)')

    # 시간 정보
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='생성 시간')
    started_at = models.DateTimeField(null=True, blank=True, verbose_name='시작 시간')
    completed_at = models.DateTimeField(null=True, blank=True, verbose_name='완료 시간')

    # 에러 정보
    error_message = models.TextField(blank=True, verbose_name='에러 메시지')

    # 요청자 정보
    ip_address = models.GenericIPAddressField(verbose_name='IP 주소')
    user_agent = models.CharField(max_length=500, verbose_name='User Agent')

    # Celery 작업 ID
    task_id = models.CharField(max_length=255, blank=True, verbose_name='작업 ID')

    class Meta:
        verbose_name = '스캔 요청'
        verbose_name_plural = '스캔 요청 목록'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['status']),
            models.Index(fields=['target_domain']),
        ]

    def __str__(self):
        return f"{self.target_domain} - {self.get_status_display()}"

    def duration(self):
        """스캔 소요 시간 계산"""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class SecurityScanResult(models.Model):
    """보안 스캔 결과"""

    RISK_LEVEL_CHOICES = [
        ('critical', '치명적'),
        ('high', '높음'),
        ('medium', '중간'),
        ('low', '낮음'),
        ('info', '정보'),
    ]

    scan_request = models.OneToOneField(
        ScanRequest,
        on_delete=models.CASCADE,
        related_name='security_result',
        verbose_name='스캔 요청'
    )

    # 전체 점수 및 위험도
    overall_score = models.IntegerField(default=0, verbose_name='전체 점수 (0-100)')
    risk_level = models.CharField(
        max_length=20,
        choices=RISK_LEVEL_CHOICES,
        default='info',
        verbose_name='위험 수준'
    )

    # OWASP Top 10 검사 결과 (각각 JSON 형식으로 저장)
    sql_injection = models.JSONField(default=dict, verbose_name='SQL Injection')
    xss_vulnerabilities = models.JSONField(default=dict, verbose_name='XSS 취약점')
    csrf_protection = models.JSONField(default=dict, verbose_name='CSRF 보호')
    insecure_deserialization = models.JSONField(default=dict, verbose_name='안전하지 않은 역직렬화')
    xml_external_entities = models.JSONField(default=dict, verbose_name='XXE')
    broken_access_control = models.JSONField(default=dict, verbose_name='접근 제어 오류')
    security_misconfiguration = models.JSONField(default=dict, verbose_name='보안 설정 오류')
    sensitive_data_exposure = models.JSONField(default=dict, verbose_name='민감 데이터 노출')
    insufficient_logging = models.JSONField(default=dict, verbose_name='불충분한 로깅')
    vulnerable_components = models.JSONField(default=dict, verbose_name='취약한 컴포넌트')

    # 보안 헤더 검사
    security_headers = models.JSONField(default=dict, verbose_name='보안 헤더')

    # SSL/TLS 검사
    ssl_tls_result = models.JSONField(default=dict, verbose_name='SSL/TLS 결과')

    # 기타 취약점
    clickjacking = models.JSONField(default=dict, verbose_name='클릭재킹')
    cors_misconfiguration = models.JSONField(default=dict, verbose_name='CORS 설정 오류')
    open_redirects = models.JSONField(default=dict, verbose_name='오픈 리다이렉트')

    # 고급 보안 취약점 (scanners_advanced.py)
    ssrf_vulnerabilities = models.JSONField(default=dict, verbose_name='SSRF 취약점')
    xxe_vulnerabilities = models.JSONField(default=dict, verbose_name='XXE 취약점')
    command_injection = models.JSONField(default=dict, verbose_name='Command Injection')
    deserialization = models.JSONField(default=dict, verbose_name='Deserialization 취약점')
    file_upload = models.JSONField(default=dict, verbose_name='파일 업로드 취약점')
    path_traversal = models.JSONField(default=dict, verbose_name='경로 순회 공격')
    jwt_vulnerabilities = models.JSONField(default=dict, verbose_name='JWT 취약점')
    template_injection = models.JSONField(default=dict, verbose_name='템플릿 주입')
    nosql_injection = models.JSONField(default=dict, verbose_name='NoSQL Injection')
    ssl_tls_vulnerabilities = models.JSONField(default=dict, verbose_name='SSL/TLS 취약점')

    # API 및 인증/인가 취약점 (scanners_api.py)
    rest_api_vulnerabilities = models.JSONField(default=dict, verbose_name='REST API 취약점')
    graphql_vulnerabilities = models.JSONField(default=dict, verbose_name='GraphQL 취약점')
    oauth_vulnerabilities = models.JSONField(default=dict, verbose_name='OAuth 취약점')
    session_vulnerabilities = models.JSONField(default=dict, verbose_name='Session 취약점')
    password_policy = models.JSONField(default=dict, verbose_name='비밀번호 정책')
    rate_limiting = models.JSONField(default=dict, verbose_name='Rate Limiting')
    ldap_injection = models.JSONField(default=dict, verbose_name='LDAP Injection')
    authorization_vulnerabilities = models.JSONField(default=dict, verbose_name='Authorization 취약점')

    # OWASP 2025 신규 대응 스캐너 (scanners_supply_chain.py, scanners_exception.py)
    supply_chain_vulnerabilities = models.JSONField(default=dict, verbose_name='Supply Chain 취약점')
    exception_handling_vulnerabilities = models.JSONField(default=dict, verbose_name='Exception Handling 취약점')

    # 비즈니스 로직 및 설계 취약점 (scanners_business_logic.py)
    price_manipulation_vulnerabilities = models.JSONField(default=dict, verbose_name='가격 조작 취약점')
    race_condition_vulnerabilities = models.JSONField(default=dict, verbose_name='레이스 컨디션 취약점')
    workflow_bypass_vulnerabilities = models.JSONField(default=dict, verbose_name='워크플로우 우회 취약점')
    account_enumeration_vulnerabilities = models.JSONField(default=dict, verbose_name='계정 열거 취약점')
    resource_exhaustion_vulnerabilities = models.JSONField(default=dict, verbose_name='리소스 소진 취약점')
    logging_monitoring_vulnerabilities = models.JSONField(default=dict, verbose_name='로깅/모니터링 취약점')
    business_logic_anomaly_vulnerabilities = models.JSONField(default=dict, verbose_name='비즈니스 로직 이상')

    # 공급망 보안 강화 (scanners_supply_chain_advanced.py)
    package_integrity_vulnerabilities = models.JSONField(default=dict, verbose_name='패키지 무결성 취약점')
    typosquatting_vulnerabilities = models.JSONField(default=dict, verbose_name='타이포스쿼팅 취약점')
    outdated_dependency_vulnerabilities = models.JSONField(default=dict, verbose_name='오래된 종속성 취약점')
    license_compliance_vulnerabilities = models.JSONField(default=dict, verbose_name='라이선스 준수 취약점')

    # 데이터 무결성 강화 (scanners_integrity_advanced.py)
    jwt_advanced_vulnerabilities = models.JSONField(default=dict, verbose_name='JWT 고급 취약점')
    serialization_integrity_vulnerabilities = models.JSONField(default=dict, verbose_name='직렬화 무결성 취약점')
    api_integrity_vulnerabilities = models.JSONField(default=dict, verbose_name='API 무결성 취약점')
    checksum_validation_vulnerabilities = models.JSONField(default=dict, verbose_name='체크섬 검증 취약점')

    # 스캐너 메타데이터
    scanner_metadata = models.JSONField(default=list, verbose_name='스캐너 메타데이터')

    # 메타 정보
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='생성 시간')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='수정 시간')

    class Meta:
        verbose_name = '보안 스캔 결과'
        verbose_name_plural = '보안 스캔 결과 목록'

    def __str__(self):
        return f"{self.scan_request.target_domain} - 보안 ({self.overall_score}점)"


class WebStandardsResult(models.Model):
    """웹 표준 검사 결과"""

    scan_request = models.OneToOneField(
        ScanRequest,
        on_delete=models.CASCADE,
        related_name='standards_result',
        verbose_name='스캔 요청'
    )

    # 전체 점수
    overall_score = models.IntegerField(default=0, verbose_name='전체 점수 (0-100)')

    # HTML Validation
    html_valid = models.BooleanField(default=False, verbose_name='HTML 유효성')
    html_errors = models.JSONField(default=list, verbose_name='HTML 에러')
    html_warnings = models.JSONField(default=list, verbose_name='HTML 경고')
    html_error_count = models.IntegerField(default=0, verbose_name='HTML 에러 수')

    # CSS Validation
    css_valid = models.BooleanField(default=False, verbose_name='CSS 유효성')
    css_errors = models.JSONField(default=list, verbose_name='CSS 에러')
    css_warnings = models.JSONField(default=list, verbose_name='CSS 경고')
    css_error_count = models.IntegerField(default=0, verbose_name='CSS 에러 수')

    # JavaScript Errors
    js_errors = models.JSONField(default=list, verbose_name='JavaScript 에러')
    js_console_logs = models.JSONField(default=list, verbose_name='콘솔 로그')
    js_error_count = models.IntegerField(default=0, verbose_name='JS 에러 수')

    # SEO
    seo_score = models.IntegerField(default=0, verbose_name='SEO 점수')
    seo_issues = models.JSONField(default=list, verbose_name='SEO 이슈')
    meta_tags = models.JSONField(default=dict, verbose_name='메타 태그')

    # 성능
    page_load_time = models.FloatField(null=True, blank=True, verbose_name='페이지 로드 시간 (초)')
    page_size = models.IntegerField(null=True, blank=True, verbose_name='페이지 크기 (bytes)')

    # 스캐너 메타데이터
    scanner_metadata = models.JSONField(default=list, verbose_name='스캐너 메타데이터')

    # 메타 정보
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='생성 시간')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='수정 시간')

    class Meta:
        verbose_name = '웹 표준 결과'
        verbose_name_plural = '웹 표준 결과 목록'

    def __str__(self):
        return f"{self.scan_request.target_domain} - 웹 표준 ({self.overall_score}점)"


class AccessibilityResult(models.Model):
    """웹 접근성 검사 결과"""

    WCAG_LEVEL_CHOICES = [
        ('AAA', 'WCAG AAA'),
        ('AA', 'WCAG AA'),
        ('A', 'WCAG A'),
        ('None', '미달'),
    ]

    scan_request = models.OneToOneField(
        ScanRequest,
        on_delete=models.CASCADE,
        related_name='accessibility_result',
        verbose_name='스캔 요청'
    )

    # 전체 점수 및 등급
    overall_score = models.IntegerField(default=0, verbose_name='전체 점수 (0-100)')
    wcag_level = models.CharField(
        max_length=10,
        choices=WCAG_LEVEL_CHOICES,
        default='None',
        verbose_name='WCAG 등급'
    )

    # WCAG 2.1 4가지 원칙별 이슈
    perceivable_issues = models.JSONField(default=list, verbose_name='인식 가능성 이슈')
    operable_issues = models.JSONField(default=list, verbose_name='운용 가능성 이슈')
    understandable_issues = models.JSONField(default=list, verbose_name='이해 가능성 이슈')
    robust_issues = models.JSONField(default=list, verbose_name='견고성 이슈')

    # 세부 검사 항목
    aria_errors = models.JSONField(default=list, verbose_name='ARIA 에러')
    aria_warnings = models.JSONField(default=list, verbose_name='ARIA 경고')
    keyboard_navigation = models.JSONField(default=dict, verbose_name='키보드 네비게이션')
    color_contrast = models.JSONField(default=list, verbose_name='색상 대비')
    screen_reader_issues = models.JSONField(default=list, verbose_name='스크린 리더 이슈')
    alt_text_missing = models.JSONField(default=list, verbose_name='대체 텍스트 누락')
    heading_structure = models.JSONField(default=dict, verbose_name='제목 구조')
    form_labels = models.JSONField(default=list, verbose_name='폼 레이블')

    # 통계
    total_issues = models.IntegerField(default=0, verbose_name='전체 이슈 수')
    critical_issues = models.IntegerField(default=0, verbose_name='치명적 이슈 수')
    serious_issues = models.IntegerField(default=0, verbose_name='심각한 이슈 수')
    moderate_issues = models.IntegerField(default=0, verbose_name='보통 이슈 수')
    minor_issues = models.IntegerField(default=0, verbose_name='경미한 이슈 수')

    # 스캐너 메타데이터
    scanner_metadata = models.JSONField(default=list, verbose_name='스캐너 메타데이터')

    # 메타 정보
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='생성 시간')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='수정 시간')

    class Meta:
        verbose_name = '접근성 결과'
        verbose_name_plural = '접근성 결과 목록'

    def __str__(self):
        return f"{self.scan_request.target_domain} - 접근성 ({self.wcag_level})"


class Vulnerability(models.Model):
    """개별 취약점 상세 정보"""

    SEVERITY_CHOICES = [
        ('critical', '치명적'),
        ('high', '높음'),
        ('medium', '중간'),
        ('low', '낮음'),
        ('info', '정보'),
    ]

    CATEGORY_CHOICES = [
        ('security', '보안'),
        ('standards', '웹 표준'),
        ('accessibility', '접근성'),
    ]

    scan_request = models.ForeignKey(
        ScanRequest,
        on_delete=models.CASCADE,
        related_name='vulnerabilities',
        verbose_name='스캔 요청'
    )

    # 분류
    category = models.CharField(
        max_length=100,
        choices=CATEGORY_CHOICES,
        verbose_name='카테고리'
    )
    vulnerability_type = models.CharField(max_length=100, verbose_name='취약점 유형')
    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        verbose_name='심각도'
    )

    # 상세 정보
    title = models.CharField(max_length=500, verbose_name='제목')
    description = models.TextField(verbose_name='설명')
    affected_url = models.URLField(max_length=2048, verbose_name='영향받는 URL')
    affected_element = models.CharField(
        max_length=500,
        blank=True,
        verbose_name='영향받는 요소'
    )
    evidence = models.TextField(blank=True, verbose_name='증거')
    recommendation = models.TextField(verbose_name='권장 사항')

    # 참조 정보
    cve_id = models.CharField(max_length=50, blank=True, verbose_name='CVE ID')
    cwe_id = models.CharField(max_length=50, blank=True, verbose_name='CWE ID')
    owasp_category = models.CharField(max_length=100, blank=True, verbose_name='OWASP 카테고리')

    # 메타 정보
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='생성 시간')

    class Meta:
        verbose_name = '취약점'
        verbose_name_plural = '취약점 목록'
        ordering = ['-severity', '-created_at']
        indexes = [
            models.Index(fields=['scan_request', 'severity']),
            models.Index(fields=['category']),
        ]

    def __str__(self):
        return f"[{self.get_severity_display()}] {self.title}"
