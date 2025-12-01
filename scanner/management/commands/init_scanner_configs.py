"""
초기 스캐너 설정 데이터 생성 Command
ProgressManager에서 스캐너 정보를 가져와 ScannerConfiguration 모델에 저장
"""

from django.core.management.base import BaseCommand
from django.db import transaction
from scanner.models import ScannerConfiguration, ScannerPreset
from scanner.progress_manager import ProgressManager
import re


class Command(BaseCommand):
    help = '스캐너 설정 초기 데이터 생성 (50개 스캐너)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='기존 데이터를 모두 삭제하고 다시 생성',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='실제로 데이터를 생성하지 않고 시뮬레이션만 수행',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING('=' * 60))
        self.stdout.write(self.style.WARNING('스캐너 설정 초기화 시작'))
        self.stdout.write(self.style.WARNING('=' * 60))

        reset = options.get('reset', False)
        dry_run = options.get('dry_run', False)

        if reset and not dry_run:
            # 기존 데이터 삭제
            deleted_count = ScannerConfiguration.objects.all().delete()[0]
            self.stdout.write(
                self.style.WARNING(f'기존 설정 {deleted_count}개 삭제됨')
            )

        # ProgressManager에서 스캐너 정보 가져오기
        pm = ProgressManager()

        created_count = 0
        updated_count = 0

        # 스캐너 ID 매핑 (스캐너 이름 -> 실제 스캐너 ID)
        scanner_id_mapping = {
            # 기본 보안 스캐너 (15개)
            '보안 헤더 검사': 'security_headers',
            'SSL/TLS 검사': 'ssl_tls',
            'XSS 취약점 스캔': 'xss_vulnerabilities',
            'SQL Injection 스캔': 'sql_injection',
            'CORS 설정 검사': 'cors_misconfiguration',
            '쿠키 보안 검사': 'cookie_security',
            'CSRF 보호 검사': 'csrf_protection',
            '클릭재킹 방어 검사': 'clickjacking',
            '정보 노출 검사': 'information_disclosure',
            'HTTP 메서드 검사': 'http_methods',
            '민감한 파일 노출 검사': 'sensitive_files',
            'Mixed Content 검사': 'mixed_content',
            'SRI 검사': 'subresource_integrity',
            '디렉토리 리스팅 검사': 'directory_listing',
            'Open Redirect 검사': 'open_redirect',

            # 고급 보안 스캐너 (10개)
            'SSRF 취약점 검사': 'ssrf_vulnerabilities',
            'XXE 취약점 검사': 'xxe_vulnerabilities',
            'Command Injection 검사': 'command_injection',
            'Deserialization 취약점 검사': 'deserialization',
            '파일 업로드 취약점 검사': 'file_upload',
            '경로 순회 공격 검사': 'path_traversal',
            'JWT 보안 검사': 'jwt_vulnerabilities',
            '템플릿 주입 검사': 'template_injection',
            'NoSQL Injection 검사': 'nosql_injection',
            'SSL/TLS 심층 검사': 'ssl_tls_deep',

            # API 및 인증/인가 스캐너 (8개)
            'REST API 보안 검사': 'rest_api_security',
            'GraphQL 보안 검사': 'graphql_security',
            'OAuth 보안 검사': 'oauth_security',
            'Session 보안 검사': 'session_security',
            'Password Policy 검사': 'password_policy',
            'Rate Limiting 검사': 'rate_limiting',
            'LDAP Injection 검사': 'ldap_injection',
            'Authorization 검사': 'authorization',

            # OWASP 2025 신규 대응 스캐너 (2개)
            'Software Supply Chain 검사': 'supply_chain',
            'Exception Handling 검사': 'exception_handling',

            # 비즈니스 로직 및 설계 취약점 스캐너 (7개)
            '가격 조작 탐지': 'price_manipulation',
            '레이스 컨디션 탐지': 'race_condition',
            '워크플로우 우회 탐지': 'workflow_bypass',
            '계정 열거 탐지': 'account_enumeration',
            '리소스 소진 탐지': 'resource_exhaustion',
            '로깅/모니터링 검사': 'logging_monitoring',
            '비즈니스 로직 이상 탐지': 'business_logic_anomaly',

            # 공급망 보안 강화 (4개)
            '패키지 무결성 검증': 'package_integrity',
            '타이포스쿼팅 탐지': 'typosquatting',
            '오래된 종속성 검사': 'outdated_dependencies',
            '라이선스 준수 검사': 'license_compliance',

            # 데이터 무결성 강화 (4개)
            'JWT 고급 보안 검증': 'jwt_advanced',
            '직렬화 무결성 검증': 'serialization_integrity',
            'API 응답 무결성 검사': 'api_integrity',
            '체크섬 검증': 'checksum_validation',

            # 웹 표준 스캐너 (4개)
            'SEO 검사': 'seo_check',
            'HTML 구조 검증': 'html_validation',
            'CSS 분석': 'css_analysis',
            'JavaScript 검사': 'js_check',

            # 접근성 스캐너 (1개)
            '기본 접근성 검사': 'basic_accessibility'
        }

        # 아이콘 매핑
        icon_mapping = {
            'security': '🔒',
            'standards': '📏',
            'accessibility': '♿'
        }

        with transaction.atomic():
            display_order = 0

            for category, scanners in pm.SCANNERS.items():
                self.stdout.write(f'\n{category.upper()} 카테고리 처리 중...')

                for scanner_name, weight in scanners:
                    # scanner_id 가져오기
                    scanner_id = scanner_id_mapping.get(scanner_name)

                    if not scanner_id:
                        # 매핑이 없으면 자동 생성 (fallback)
                        scanner_id = self._generate_scanner_id(scanner_name)
                        self.stdout.write(
                            self.style.WARNING(
                                f'  ⚠️  매핑 없음: {scanner_name} -> {scanner_id} (자동 생성)'
                            )
                        )

                    icon = icon_mapping.get(category, '🔍')

                    # 설명 생성
                    description = self._generate_description(scanner_name, category)

                    if dry_run:
                        self.stdout.write(
                            f'  [DRY-RUN] {scanner_name} ({scanner_id})'
                        )
                        continue

                    # ScannerConfiguration 생성 또는 업데이트
                    config, created = ScannerConfiguration.objects.update_or_create(
                        scanner_id=scanner_id,
                        defaults={
                            'name': scanner_name,
                            'category': category,
                            'icon': icon,
                            'description': description,
                            'enabled': True,
                            'timeout': 30,  # 기본 30초
                            'weight': weight,
                            'show_in_results': True,
                            'show_details': True,
                            'show_if_passed': True,
                            'show_if_failed': True,
                            'display_order': display_order,
                        }
                    )

                    display_order += 10  # 10씩 증가하여 중간에 삽입 여지 남김

                    if created:
                        created_count += 1
                        self.stdout.write(
                            self.style.SUCCESS(f'  ✅ 생성: {scanner_name} ({scanner_id})')
                        )
                    else:
                        updated_count += 1
                        self.stdout.write(
                            self.style.INFO(f'  🔄 업데이트: {scanner_name} ({scanner_id})')
                        )

        # 기본 프리셋 생성
        if not dry_run:
            self._create_default_presets()

        # 결과 출력
        self.stdout.write('\n' + '=' * 60)
        self.stdout.write(self.style.SUCCESS('✅ 스캐너 설정 초기화 완료'))
        self.stdout.write(f'  - 신규 생성: {created_count}개')
        self.stdout.write(f'  - 업데이트: {updated_count}개')
        self.stdout.write(f'  - 총 스캐너: {created_count + updated_count}개')

        # 카테고리별 통계
        if not dry_run:
            for category in ['security', 'standards', 'accessibility']:
                count = ScannerConfiguration.objects.filter(category=category).count()
                self.stdout.write(f'  - {category}: {count}개')

        self.stdout.write('=' * 60)

    def _generate_scanner_id(self, scanner_name):
        """스캐너 이름을 snake_case ID로 변환"""
        # 한글 제거, 특수문자를 언더스코어로
        scanner_id = re.sub(r'[^a-zA-Z0-9\s]', '', scanner_name)
        # 공백을 언더스코어로
        scanner_id = scanner_id.lower().strip().replace(' ', '_')
        # 중복 언더스코어 제거
        scanner_id = re.sub(r'_+', '_', scanner_id)
        return scanner_id

    def _generate_description(self, scanner_name, category):
        """스캐너 설명 생성"""
        descriptions = {
            # 보안 스캐너
            'security_headers': '웹 애플리케이션의 보안 헤더 설정을 검사합니다.',
            'ssl_tls': 'SSL/TLS 인증서 및 설정의 보안성을 검증합니다.',
            'xss_vulnerabilities': 'Cross-Site Scripting (XSS) 취약점을 탐지합니다.',
            'sql_injection': 'SQL Injection 취약점을 탐지합니다.',
            'cors_misconfiguration': 'CORS (Cross-Origin Resource Sharing) 설정 오류를 검사합니다.',
            'cookie_security': '쿠키의 보안 속성 설정을 검증합니다.',
            'csrf_protection': 'CSRF (Cross-Site Request Forgery) 방어 메커니즘을 검사합니다.',
            'clickjacking': 'Clickjacking 공격 방어 설정을 검증합니다.',
            'information_disclosure': '민감한 정보 노출 여부를 검사합니다.',
            'http_methods': '위험한 HTTP 메서드 활성화 여부를 검사합니다.',
            'sensitive_files': '민감한 파일의 외부 노출 여부를 검사합니다.',
            'mixed_content': 'HTTPS 페이지의 HTTP 리소스 포함 여부를 검사합니다.',
            'subresource_integrity': 'Subresource Integrity (SRI) 설정을 검증합니다.',
            'directory_listing': '디렉토리 리스팅 활성화 여부를 검사합니다.',
            'open_redirect': 'Open Redirect 취약점을 탐지합니다.',

            # 고급 보안
            'ssrf_vulnerabilities': 'Server-Side Request Forgery (SSRF) 취약점을 탐지합니다.',
            'xxe_vulnerabilities': 'XML External Entity (XXE) 취약점을 탐지합니다.',
            'command_injection': 'OS Command Injection 취약점을 탐지합니다.',
            'deserialization': '안전하지 않은 역직렬화 취약점을 탐지합니다.',
            'file_upload': '파일 업로드 관련 보안 취약점을 검사합니다.',
            'path_traversal': '경로 순회 (Path Traversal) 공격 취약점을 탐지합니다.',
            'jwt_vulnerabilities': 'JWT 토큰 관련 보안 취약점을 검사합니다.',
            'template_injection': '템플릿 인젝션 취약점을 탐지합니다.',
            'nosql_injection': 'NoSQL Injection 취약점을 탐지합니다.',
            'ssl_tls_deep': 'SSL/TLS 설정의 심층 보안 분석을 수행합니다.',

            # API 및 인증
            'rest_api_security': 'REST API의 보안 설정 및 취약점을 검사합니다.',
            'graphql_security': 'GraphQL API의 보안 취약점을 검사합니다.',
            'oauth_security': 'OAuth 인증 구현의 보안성을 검증합니다.',
            'session_security': '세션 관리의 보안성을 검사합니다.',
            'password_policy': '비밀번호 정책 및 강도를 검증합니다.',
            'rate_limiting': 'Rate Limiting 설정을 검사합니다.',
            'ldap_injection': 'LDAP Injection 취약점을 탐지합니다.',
            'authorization': '인가 (Authorization) 취약점을 검사합니다.',

            # 비즈니스 로직
            'price_manipulation': '가격 조작 관련 비즈니스 로직 취약점을 탐지합니다.',
            'race_condition': '레이스 컨디션 취약점을 탐지합니다.',
            'workflow_bypass': '워크플로우 우회 취약점을 탐지합니다.',
            'account_enumeration': '계정 열거 공격 취약점을 탐지합니다.',
            'resource_exhaustion': '리소스 소진 공격 취약점을 검사합니다.',
            'logging_monitoring': '로깅 및 모니터링 설정을 검증합니다.',
            'business_logic_anomaly': '비즈니스 로직 이상 패턴을 탐지합니다.',

            # 공급망 보안
            'package_integrity': '패키지 무결성을 검증합니다.',
            'typosquatting': '타이포스쿼팅 공격을 탐지합니다.',
            'outdated_dependencies': '오래된 종속성 및 취약한 컴포넌트를 검사합니다.',
            'license_compliance': '라이선스 준수 여부를 검사합니다.',

            # 데이터 무결성
            'jwt_advanced': 'JWT 토큰의 고급 보안 검증을 수행합니다.',
            'serialization_integrity': '직렬화 데이터의 무결성을 검증합니다.',
            'api_integrity': 'API 응답의 무결성을 검사합니다.',
            'checksum_validation': '체크섬 검증 메커니즘을 검사합니다.',

            # 웹 표준
            'seo_check': 'SEO (검색 엔진 최적화) 설정을 검사합니다.',
            'html_validation': 'HTML 문서의 유효성을 검증합니다.',
            'css_analysis': 'CSS 코드를 분석하고 최적화 여부를 검사합니다.',
            'js_check': 'JavaScript 코드의 오류 및 보안 이슈를 검사합니다.',

            # 접근성
            'basic_accessibility': 'WCAG 기준에 따른 웹 접근성을 검사합니다.'
        }

        # scanner_name을 scanner_id로 변환
        scanner_id = self._generate_scanner_id(scanner_name)

        # 매핑된 설명이 있으면 사용, 없으면 기본 설명 생성
        if scanner_id in descriptions:
            return descriptions[scanner_id]

        # 기본 설명 생성
        if category == 'security':
            return f'{scanner_name}를 수행하여 보안 취약점을 탐지합니다.'
        elif category == 'standards':
            return f'{scanner_name}를 수행하여 웹 표준 준수 여부를 검증합니다.'
        elif category == 'accessibility':
            return f'{scanner_name}를 수행하여 웹 접근성을 검증합니다.'
        else:
            return f'{scanner_name}를 수행합니다.'

    def _create_default_presets(self):
        """기본 프리셋 생성"""
        self.stdout.write('\n기본 프리셋 생성 중...')

        # 1. 전체 활성화 프리셋
        all_configs = ScannerConfiguration.objects.all()
        full_preset_config = {}
        for config in all_configs:
            full_preset_config[config.scanner_id] = {
                'enabled': True,
                'show_in_results': True,
                'show_details': True,
                'show_if_passed': True,
                'show_if_failed': True,
            }

        preset_full, created = ScannerPreset.objects.update_or_create(
            name='전체 스캔',
            defaults={
                'description': '모든 스캐너를 활성화하여 완전한 보안 검사를 수행합니다.',
                'configurations': full_preset_config,
                'is_active': True,
            }
        )

        if created:
            self.stdout.write(self.style.SUCCESS('  ✅ "전체 스캔" 프리셋 생성됨'))

        # 2. 빠른 스캔 프리셋 (주요 스캐너만)
        quick_scanner_ids = [
            'security_headers', 'ssl_tls', 'xss_vulnerabilities',
            'sql_injection', 'csrf_protection', 'clickjacking',
            'cookie_security', 'cors_misconfiguration'
        ]

        quick_preset_config = {}
        for config in all_configs:
            quick_preset_config[config.scanner_id] = {
                'enabled': config.scanner_id in quick_scanner_ids,
                'show_in_results': True,
                'show_details': False,  # 빠른 스캔은 요약만
                'show_if_passed': False,  # 통과한 테스트는 숨김
                'show_if_failed': True,
            }

        preset_quick, created = ScannerPreset.objects.update_or_create(
            name='빠른 스캔',
            defaults={
                'description': '주요 보안 스캐너만 실행하여 빠르게 검사합니다.',
                'configurations': quick_preset_config,
                'is_active': False,
            }
        )

        if created:
            self.stdout.write(self.style.SUCCESS('  ✅ "빠른 스캔" 프리셋 생성됨'))

        # 3. 개발 모드 프리셋
        dev_preset_config = {}
        for config in all_configs:
            # 개발 모드에서는 치명적인 취약점만 검사
            is_critical = config.scanner_id in [
                'sql_injection', 'xss_vulnerabilities', 'command_injection',
                'path_traversal', 'file_upload'
            ]
            dev_preset_config[config.scanner_id] = {
                'enabled': is_critical,
                'show_in_results': True,
                'show_details': True,
                'show_if_passed': False,
                'show_if_failed': True,
            }

        preset_dev, created = ScannerPreset.objects.update_or_create(
            name='개발 모드',
            defaults={
                'description': '개발 중 치명적인 보안 취약점만 검사합니다.',
                'configurations': dev_preset_config,
                'is_active': False,
            }
        )

        if created:
            self.stdout.write(self.style.SUCCESS('  ✅ "개발 모드" 프리셋 생성됨'))