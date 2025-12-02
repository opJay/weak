"""
Celery Tasks
비동기 스캔 작업 처리
"""
from celery import shared_task, group, chord
from django.utils import timezone
from django.conf import settings
import logging
import requests
from bs4 import BeautifulSoup
import time
import json

from .models import (
    ScanRequest,
    SecurityScanResult,
    WebStandardsResult,
    AccessibilityResult,
    Vulnerability,
    ScannerConfiguration
)
from .standards_checker import (
    check_seo_advanced,
    check_html_structure,
    check_css_resources,
    check_javascript,
    calculate_standards_score_advanced
)

logger = logging.getLogger('scanner')


def remove_from_running_scans(scan_request_id):
    """
    Redis에서 실행 중인 스캔 목록에서 제거 (동시성 제어용)

    Note: MAX_CONCURRENT_SCANS 값과 무관하게 항상 제거 시도
    (추가는 조건부, 제거는 무조건 - 일관성 유지)
    """
    try:
        import redis
        redis_client = redis.Redis.from_url(settings.CELERY_BROKER_URL)
        running_scans_key = 'weak:running_scans'
        removed = redis_client.srem(running_scans_key, str(scan_request_id))
        if removed:
            logger.info(f'Removed scan {scan_request_id} from running scans set')
    except Exception as redis_error:
        logger.warning(f'Failed to remove scan from Redis: {str(redis_error)}')


def scan_website_sync(scan_request_id):
    """
    동기 스캔 작업 (Celery 우회)
    백그라운드 스레드에서 직접 실행용
    """
    try:
        scan_request = ScanRequest.objects.get(id=scan_request_id)
        scan_request.status = 'running'
        scan_request.started_at = timezone.now()
        scan_request.progress = 0
        scan_request.save()

        logger.info(f'Starting sync scan for {scan_request.url}')

        # 선택된 스캔 타입 수 계산
        selected_types = []
        if 'security' in scan_request.scan_types:
            selected_types.append('security')
        if 'standards' in scan_request.scan_types:
            selected_types.append('standards')
        if 'accessibility' in scan_request.scan_types:
            selected_types.append('accessibility')

        total_types = len(selected_types)
        completed_types = 0

        # 각 스캔 유형 동기 실행
        if 'security' in scan_request.scan_types:
            logger.info(f'Starting security scan for {scan_request_id}')
            scan_security(scan_request_id)
            completed_types += 1
            # 전체 진행률 업데이트 (security 완료)
            scan_request.refresh_from_db()
            if total_types > 1:
                scan_request.progress = int((completed_types / total_types) * 100)
                scan_request.save()

        if 'standards' in scan_request.scan_types:
            logger.info(f'Starting standards scan for {scan_request_id}')
            scan_standards(scan_request_id)
            completed_types += 1
            # 전체 진행률 업데이트 (standards 완료)
            scan_request.refresh_from_db()
            if total_types > 1 and completed_types < total_types:
                scan_request.progress = int((completed_types / total_types) * 100)
                scan_request.save()

        if 'accessibility' in scan_request.scan_types:
            logger.info(f'Starting accessibility scan for {scan_request_id}')
            scan_accessibility(scan_request_id)
            completed_types += 1

        # 완료 처리
        scan_request.refresh_from_db()
        scan_request.status = 'completed'
        scan_request.completed_at = timezone.now()
        scan_request.progress = 100
        scan_request.save()

        # Redis에서 실행 중인 스캔 목록에서 제거
        remove_from_running_scans(scan_request_id)

        logger.info(f'Sync scan completed for {scan_request.url}')

        return {
            'scan_id': str(scan_request.id),
            'status': 'completed',
            'duration': scan_request.duration()
        }

    except ScanRequest.DoesNotExist:
        logger.error(f'Scan request {scan_request_id} not found')
        raise

    except Exception as e:
        logger.error(f'Sync scan failed for {scan_request_id}: {str(e)}')

        # 실패 상태 업데이트
        try:
            scan_request = ScanRequest.objects.get(id=scan_request_id)
            scan_request.status = 'failed'
            scan_request.completed_at = timezone.now()
            scan_request.error_message = str(e)
            scan_request.save()

            # Redis에서 실행 중인 스캔 목록에서 제거
            remove_from_running_scans(scan_request_id)
        except:
            pass

        raise


@shared_task(bind=True, max_retries=3)
def scan_website(self, scan_request_id):
    """
    메인 스캔 작업
    여러 스캔 유형을 병렬로 실행 (Chord 사용) 또는 동기 실행
    """
    try:
        scan_request = ScanRequest.objects.get(id=scan_request_id)
        scan_request.status = 'running'
        scan_request.started_at = timezone.now()
        scan_request.progress = 0
        scan_request.save()

        logger.info(f'Starting scan for {scan_request.url}')

        # 스캔 유형에 따라 작업 실행
        # Celery 사용 가능하면 비동기 (Chord), 아니면 동기
        try:
            # Celery 비동기 실행 시도 (Chord 사용)
            tasks = []
            if 'security' in scan_request.scan_types:
                tasks.append(scan_security.s(scan_request_id))
            if 'standards' in scan_request.scan_types:
                tasks.append(scan_standards.s(scan_request_id))
            if 'accessibility' in scan_request.scan_types:
                tasks.append(scan_accessibility.s(scan_request_id))

            if tasks:
                # Chord: 모든 태스크 완료 후 complete_scan 콜백 호출
                job = chord(tasks)(complete_scan.s(str(scan_request_id)))
                logger.info(f'Scan started with Celery chord for {scan_request.url}')

                # 비동기 실행이므로 바로 반환 (완료는 complete_scan에서 처리)
                return {
                    'scan_id': str(scan_request.id),
                    'status': 'running'
                }

        except Exception as celery_error:
            # Celery 사용 불가 시 동기 실행
            logger.warning(f'Celery unavailable, running sync: {str(celery_error)}')

            if 'security' in scan_request.scan_types:
                scan_security(scan_request_id)

            if 'standards' in scan_request.scan_types:
                scan_standards(scan_request_id)

            if 'accessibility' in scan_request.scan_types:
                scan_accessibility(scan_request_id)

            # 동기 실행 시 직접 완료 처리
            scan_request.refresh_from_db()
            scan_request.status = 'completed'
            scan_request.completed_at = timezone.now()
            scan_request.progress = 100
            scan_request.save()

            # Redis에서 실행 중인 스캔 목록에서 제거
            remove_from_running_scans(scan_request_id)

            logger.info(f'Scan completed (sync) for {scan_request.url}')

            return {
                'scan_id': str(scan_request.id),
                'status': 'completed',
                'duration': scan_request.duration()
            }

    except ScanRequest.DoesNotExist:
        logger.error(f'Scan request {scan_request_id} not found')
        raise

    except Exception as e:
        logger.error(f'Scan failed for {scan_request_id}: {str(e)}')

        # 실패 상태 업데이트
        try:
            scan_request = ScanRequest.objects.get(id=scan_request_id)
            scan_request.status = 'failed'
            scan_request.error_message = str(e)
            scan_request.completed_at = timezone.now()
            scan_request.save()

            # Redis에서 실행 중인 스캔 목록에서 제거
            remove_from_running_scans(scan_request_id)
        except:
            pass

        # 비동기일 때만 재시도
        if hasattr(self, 'retry'):
            raise self.retry(exc=e, countdown=60)
        else:
            raise


@shared_task
def complete_scan(results, scan_request_id):
    """
    모든 스캔 완료 후 호출되는 Callback (Chord의 마지막 단계)
    Args:
        results: 각 스캔 태스크의 결과 리스트
        scan_request_id: 스캔 요청 ID
    """
    try:
        scan_request = ScanRequest.objects.get(id=scan_request_id)
        scan_request.status = 'completed'
        scan_request.completed_at = timezone.now()
        scan_request.progress = 100
        scan_request.save()

        # Redis에서 실행 중인 스캔 목록에서 제거
        remove_from_running_scans(scan_request_id)

        logger.info(f'All scans completed for {scan_request.url}')

        return {
            'scan_id': str(scan_request.id),
            'status': 'completed',
            'duration': scan_request.duration()
        }
    except Exception as e:
        logger.error(f'Failed to complete scan {scan_request_id}: {str(e)}')
        raise


def collect_scanner_metadata(scanner_class_or_func, results):
    """스캐너의 메타데이터와 결과를 결합하여 반환"""
    if hasattr(scanner_class_or_func, 'metadata'):
        metadata = scanner_class_or_func.metadata.copy()
        metadata['results'] = results
        return metadata
    return None


@shared_task
def scan_security(scan_request_id):
    """
    보안 스캔 작업 (강화 버전)
    """
    logger.info(f'Starting security scan for {scan_request_id}')

    try:
        scan_request = ScanRequest.objects.get(id=scan_request_id)

        # 활성화된 스캐너 설정 로드
        scanner_configs = {
            config.scanner_id: config
            for config in ScannerConfiguration.objects.filter(
                category='security',
                enabled=True
            )
        }
        logger.info(f'Loaded {len(scanner_configs)} active security scanners')

        # ProgressManager 초기화
        from .progress_manager import ProgressManager
        pm = ProgressManager(['security'])  # security만 실행하므로 0-100% 전체 사용

        # 기본 HTTP 요청
        try:
            response = requests.get(
                scan_request.url,
                timeout=settings.SCAN_TIMEOUT,
                headers={'User-Agent': settings.USER_AGENT},
                verify=True
            )
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error(f'Failed to fetch URL {scan_request.url}: {str(e)}')
            raise

        # 보안 스캔 결과 생성
        security_result = SecurityScanResult.objects.create(
            scan_request=scan_request
        )

        # 스캐너 메타데이터를 수집할 리스트
        scanner_metadata = []

        # 1. 보안 헤더 검사 (강화)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()

        # 스캐너 활성화 확인
        if 'security_headers' in scanner_configs:
            from .scanners_compat import SecurityHeaderScanner
            header_scanner = SecurityHeaderScanner(response.headers)
            header_results = header_scanner.scan()
            security_result.security_headers = header_results['headers']

            # 메타데이터 수집
            if meta := collect_scanner_metadata(SecurityHeaderScanner, header_results):
                scanner_metadata.append(meta)
        else:
            logger.info('SecurityHeaderScanner is disabled, skipping...')
            security_result.security_headers = {'skipped': True, 'reason': 'Scanner disabled'}

        # 2. SSL/TLS 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()

        # 스캐너 활성화 확인
        if 'ssl_tls' in scanner_configs:
            ssl_result = check_ssl_tls(scan_request.url)
            security_result.ssl_tls_result = ssl_result

            # 메타데이터 수집
            if meta := collect_scanner_metadata(check_ssl_tls, ssl_result):
                scanner_metadata.append(meta)
        else:
            logger.info('SSL/TLS Scanner is disabled, skipping...')
            security_result.ssl_tls_result = {'skipped': True, 'reason': 'Scanner disabled'}

        # 3. XSS 취약점 스캔
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()

        # 스캐너 활성화 확인
        if 'xss_vulnerabilities' in scanner_configs:
            from .scanners_compat import XSSScanner
            xss_scanner = XSSScanner(scan_request.url)
            xss_results = xss_scanner.scan()
            security_result.xss_vulnerabilities = {
                'total': xss_results['total'],
                'has_xss': xss_results['has_xss'],
                'vulnerabilities': xss_results['vulnerabilities']
            }

            # 메타데이터 수집
            if meta := collect_scanner_metadata(XSSScanner, xss_results):
                scanner_metadata.append(meta)

            # XSS 취약점을 Vulnerability 모델에 저장
            for vuln in xss_results['vulnerabilities'][:5]:  # 최대 5개
                Vulnerability.objects.create(
                    scan_request=scan_request,
                    category='xss',
                    vulnerability_type='cross_site_scripting',
                    severity=vuln.get('severity', 'medium'),
                    title=vuln.get('type', 'XSS Vulnerability'),
                    description=vuln.get('description', ''),
                    recommendation=vuln.get('recommendation', ''),
                    evidence=str(vuln)
                )
        else:
            logger.info('XSS Scanner is disabled, skipping...')
            security_result.xss_vulnerabilities = {'skipped': True, 'reason': 'Scanner disabled'}

        # 4. SQL Injection 스캔
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()

        # 스캐너 활성화 확인
        if 'sql_injection' in scanner_configs:
            from .scanners_compat import SQLInjectionScanner
            sqli_scanner = SQLInjectionScanner(scan_request.url)
            sqli_results = sqli_scanner.scan()
            security_result.sql_injection = {
                'total': sqli_results['total'],
                'has_sqli': sqli_results['has_sqli'],
                'vulnerabilities': sqli_results['vulnerabilities']
            }
            if meta := collect_scanner_metadata(SQLInjectionScanner, sqli_results):
                scanner_metadata.append(meta)

            # SQL Injection 취약점을 Vulnerability 모델에 저장
            for vuln in sqli_results['vulnerabilities'][:5]:  # 최대 5개
                Vulnerability.objects.create(
                    scan_request=scan_request,
                    category='injection',
                    vulnerability_type='sql_injection',
                severity=vuln.get('severity', 'critical'),
                title=vuln.get('type', 'SQL Injection'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)
            )
        else:
            logger.info('SQL Injection Scanner is disabled, skipping...')
            security_result.sql_injection = {'skipped': True, 'reason': 'Scanner disabled'}

        # 5. CORS 설정 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_compat import CORSScanner
        cors_scanner = CORSScanner(scan_request.url, response.headers)
        cors_results = cors_scanner.scan()
        security_result.cors_misconfiguration = cors_results
        if meta := collect_scanner_metadata(CORSScanner, cors_results):
            scanner_metadata.append(meta)

        # CORS 이슈를 Vulnerability 모델에 저장
        for issue in cors_results['issues']:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='security_misconfiguration',
                vulnerability_type='cors_misconfiguration',
                severity=issue.get('severity', 'medium'),
                title=issue.get('type', 'CORS Issue'),
                description=issue.get('description', ''),
                recommendation=issue.get('recommendation', '')
            )

        # 6. 쿠키 보안 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_compat import CookieScanner
        cookie_scanner = CookieScanner(response)
        cookie_results = cookie_scanner.scan()
        security_result.sensitive_data_exposure = cookie_results
        if meta := collect_scanner_metadata(CookieScanner, cookie_results):
            scanner_metadata.append(meta)

        # 쿠키 이슈를 Vulnerability 모델에 저장
        for issue in cookie_results['issues'][:3]:  # 최대 3개
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='sensitive_data_exposure',
                vulnerability_type='insecure_cookie',
                severity=issue.get('severity', 'medium'),
                title=issue.get('type', 'Insecure Cookie'),
                description=issue.get('description', ''),
                recommendation=issue.get('recommendation', ''),
                evidence=str(issue.get('issues', []))
            )

        # 7. CSRF 보호 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_compat import CSRFScanner
        csrf_scanner = CSRFScanner(scan_request.url)
        csrf_results = csrf_scanner.scan()
        security_result.csrf_protection = csrf_results
        if meta := collect_scanner_metadata(CSRFScanner, csrf_results):
            scanner_metadata.append(meta)

        for issue in csrf_results['issues'][:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='broken_access_control',
                vulnerability_type='csrf',
                severity=issue.get('severity', 'high'),
                title=issue.get('type', 'CSRF Vulnerability'),
                description=issue.get('description', ''),
                recommendation=issue.get('recommendation', '')
            )

        # 8. 클릭재킹 방어 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_compat import ClickjackingScanner
        clickjacking_scanner = ClickjackingScanner(response.headers, response.text)
        clickjacking_results = clickjacking_scanner.scan()
        security_result.clickjacking = clickjacking_results
        if meta := collect_scanner_metadata(ClickjackingScanner, clickjacking_results):
            scanner_metadata.append(meta)

        for issue in clickjacking_results['issues']:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='security_misconfiguration',
                vulnerability_type='clickjacking',
                severity=issue.get('severity', 'medium'),
                title=issue.get('type', 'Clickjacking'),
                description=issue.get('description', ''),
                recommendation=issue.get('recommendation', '')
            )

        # 9. 정보 노출 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_compat import InformationDisclosureScanner
        info_scanner = InformationDisclosureScanner(response)
        info_results = info_scanner.scan()
        security_result.insufficient_logging = info_results
        if meta := collect_scanner_metadata(InformationDisclosureScanner, info_results):
            scanner_metadata.append(meta)  # 적절한 필드 사용

        for issue in info_results['issues'][:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='sensitive_data_exposure',
                vulnerability_type='information_disclosure',
                severity=issue.get('severity', 'low'),
                title=issue.get('type', 'Information Disclosure'),
                description=issue.get('description', ''),
                recommendation=issue.get('recommendation', ''),
                evidence=str(issue.get('evidence', []))[:500]
            )

        # 10. HTTP 메서드 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_compat import HTTPMethodScanner
        method_scanner = HTTPMethodScanner(scan_request.url)
        method_results = method_scanner.scan()
        if meta := collect_scanner_metadata(HTTPMethodScanner, method_results):
            scanner_metadata.append(meta)

        for issue in method_results['issues']:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='security_misconfiguration',
                vulnerability_type='dangerous_http_methods',
                severity=issue.get('severity', 'medium'),
                title=issue.get('type', 'HTTP Method'),
                description=issue.get('description', ''),
                recommendation=issue.get('recommendation', '')
            )

        # 11. 민감한 파일 노출 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_compat import SensitiveFileScanner
        file_scanner = SensitiveFileScanner(scan_request.url)
        file_results = file_scanner.scan()
        if meta := collect_scanner_metadata(SensitiveFileScanner, file_results):
            scanner_metadata.append(meta)

        for issue in file_results['issues'][:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='sensitive_data_exposure',
                vulnerability_type='sensitive_file_exposed',
                severity=issue.get('severity', 'high'),
                title=issue.get('type', 'Sensitive File'),
                description=issue.get('description', ''),
                recommendation=issue.get('recommendation', ''),
                evidence=issue.get('url', '')
            )

        # 12. Mixed Content 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_compat import MixedContentScanner
        mixed_scanner = MixedContentScanner(scan_request.url, response.text)
        mixed_results = mixed_scanner.scan()
        if meta := collect_scanner_metadata(MixedContentScanner, mixed_results):
            scanner_metadata.append(meta)

        for issue in mixed_results['issues']:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='security_misconfiguration',
                vulnerability_type='mixed_content',
                severity=issue.get('severity', 'medium'),
                title=issue.get('type', 'Mixed Content'),
                description=issue.get('description', ''),
                recommendation=issue.get('recommendation', '')
            )

        # 13. SRI (Subresource Integrity) 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_compat import SubresourceIntegrityScanner
        sri_scanner = SubresourceIntegrityScanner(response.text)
        sri_results = sri_scanner.scan()
        if meta := collect_scanner_metadata(SubresourceIntegrityScanner, sri_results):
            scanner_metadata.append(meta)

        for issue in sri_results['issues']:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='security_misconfiguration',
                vulnerability_type='missing_sri',
                severity=issue.get('severity', 'medium'),
                title=issue.get('type', 'Missing SRI'),
                description=issue.get('description', ''),
                recommendation=issue.get('recommendation', '')
            )

        # 14. 디렉토리 리스팅 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_compat import DirectoryListingScanner
        listing_scanner = DirectoryListingScanner(scan_request.url)
        listing_results = listing_scanner.scan()
        if meta := collect_scanner_metadata(DirectoryListingScanner, listing_results):
            scanner_metadata.append(meta)

        for issue in listing_results['issues']:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='security_misconfiguration',
                vulnerability_type='directory_listing',
                severity=issue.get('severity', 'medium'),
                title=issue.get('type', 'Directory Listing'),
                description=issue.get('description', ''),
                recommendation=issue.get('recommendation', '')
            )

        # 15. Open Redirect 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_compat import OpenRedirectScanner
        redirect_scanner = OpenRedirectScanner(scan_request.url)
        redirect_results = redirect_scanner.scan()
        security_result.open_redirects = redirect_results
        if meta := collect_scanner_metadata(OpenRedirectScanner, redirect_results):
            scanner_metadata.append(meta)

        for issue in redirect_results['issues']:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='broken_access_control',
                vulnerability_type='open_redirect',
                severity=issue.get('severity', 'medium'),
                title=issue.get('type', 'Open Redirect'),
                description=issue.get('description', ''),
                recommendation=issue.get('recommendation', '')
            )

        # === 고급 보안 스캐너 (scanners_advanced.py) ===

        # 16. SSRF 취약점 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_advanced import SSRFScanner
        ssrf_scanner = SSRFScanner(scan_request.url, response.text)
        ssrf_results = ssrf_scanner.scan()
        security_result.ssrf_vulnerabilities = ssrf_results
        if meta := collect_scanner_metadata(SSRFScanner, ssrf_results):
            scanner_metadata.append(meta)

        for vuln in ssrf_results['vulnerabilities'][:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='injection',
                vulnerability_type='ssrf',
                severity=vuln.get('severity', 'critical'),
                title=vuln.get('type', 'SSRF'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 17. XXE 취약점 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_advanced import XXEScanner
        xxe_scanner = XXEScanner(scan_request.url, response, response.text)
        xxe_results = xxe_scanner.scan()
        security_result.xxe_vulnerabilities = xxe_results
        if meta := collect_scanner_metadata(XXEScanner, xxe_results):
            scanner_metadata.append(meta)

        for vuln in xxe_results['vulnerabilities'][:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='injection',
                vulnerability_type='xxe',
                severity=vuln.get('severity', 'high'),
                title=vuln.get('type', 'XXE'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 18. Command Injection 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_advanced import CommandInjectionScanner
        cmdi_scanner = CommandInjectionScanner(scan_request.url, response.text)
        cmdi_results = cmdi_scanner.scan()
        security_result.command_injection = cmdi_results
        if meta := collect_scanner_metadata(CommandInjectionScanner, cmdi_results):
            scanner_metadata.append(meta)

        for vuln in cmdi_results['vulnerabilities'][:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='injection',
                vulnerability_type='command_injection',
                severity=vuln.get('severity', 'critical'),
                title=vuln.get('type', 'Command Injection'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 19. Deserialization 취약점 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_advanced import DeserializationScanner
        deser_scanner = DeserializationScanner(response, response.text)
        deser_results = deser_scanner.scan()
        security_result.deserialization = deser_results
        if meta := collect_scanner_metadata(DeserializationScanner, deser_results):
            scanner_metadata.append(meta)

        for vuln in deser_results['vulnerabilities'][:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='injection',
                vulnerability_type='deserialization',
                severity=vuln.get('severity', 'critical'),
                title=vuln.get('type', 'Insecure Deserialization'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 20. File Upload 취약점 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_advanced import FileUploadScanner
        upload_scanner = FileUploadScanner(response.text)
        upload_results = upload_scanner.scan()
        security_result.file_upload = upload_results
        if meta := collect_scanner_metadata(FileUploadScanner, upload_results):
            scanner_metadata.append(meta)

        for vuln in upload_results['vulnerabilities'][:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='broken_access_control',
                vulnerability_type='file_upload',
                severity=vuln.get('severity', 'critical'),
                title=vuln.get('type', 'File Upload'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 21. Path Traversal 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_advanced import PathTraversalScanner
        path_scanner = PathTraversalScanner(scan_request.url)
        path_results = path_scanner.scan()
        security_result.path_traversal = path_results
        if meta := collect_scanner_metadata(PathTraversalScanner, path_results):
            scanner_metadata.append(meta)

        for vuln in path_results['vulnerabilities'][:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='broken_access_control',
                vulnerability_type='path_traversal',
                severity=vuln.get('severity', 'high'),
                title=vuln.get('type', 'Path Traversal'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 22. JWT 보안 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_advanced import JWTSecurityScanner
        jwt_scanner = JWTSecurityScanner(response, response.text)
        jwt_results = jwt_scanner.scan()
        security_result.jwt_vulnerabilities = jwt_results
        if meta := collect_scanner_metadata(JWTSecurityScanner, jwt_results):
            scanner_metadata.append(meta)

        for vuln in jwt_results['vulnerabilities'][:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='broken_authentication',
                vulnerability_type='jwt_security',
                severity=vuln.get('severity', 'high'),
                title=vuln.get('type', 'JWT Vulnerability'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 23. Template Injection (SSTI) 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_advanced import TemplateInjectionScanner
        ssti_scanner = TemplateInjectionScanner(scan_request.url, response.text)
        ssti_results = ssti_scanner.scan()
        security_result.template_injection = ssti_results
        if meta := collect_scanner_metadata(TemplateInjectionScanner, ssti_results):
            scanner_metadata.append(meta)

        for vuln in ssti_results['vulnerabilities'][:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='injection',
                vulnerability_type='template_injection',
                severity=vuln.get('severity', 'critical'),
                title=vuln.get('type', 'Template Injection'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 24. NoSQL Injection 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_advanced import NoSQLInjectionScanner
        nosql_scanner = NoSQLInjectionScanner(scan_request.url, response, response.text)
        nosql_results = nosql_scanner.scan()
        security_result.nosql_injection = nosql_results
        if meta := collect_scanner_metadata(NoSQLInjectionScanner, nosql_results):
            scanner_metadata.append(meta)

        for vuln in nosql_results['vulnerabilities'][:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='injection',
                vulnerability_type='nosql_injection',
                severity=vuln.get('severity', 'critical'),
                title=vuln.get('type', 'NoSQL Injection'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 25. SSL/TLS 심층 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_advanced import SSLTLSDeepScanner
        ssl_deep_scanner = SSLTLSDeepScanner(scan_request.url)
        ssl_deep_results = ssl_deep_scanner.scan()
        security_result.ssl_tls_vulnerabilities = ssl_deep_results
        if meta := collect_scanner_metadata(SSLTLSDeepScanner, ssl_deep_results):
            scanner_metadata.append(meta)

        for vuln in ssl_deep_results['vulnerabilities'][:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='security_misconfiguration',
                vulnerability_type='ssl_tls',
                severity=vuln.get('severity', 'high'),
                title=vuln.get('type', 'SSL/TLS Issue'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # === API 및 인증/인가 보안 스캐너 (scanners_api.py) ===

        # 26. REST API 보안 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_api import RESTAPISecurityScanner
        rest_api_scanner = RESTAPISecurityScanner(scan_request.url, response, response.text)
        rest_api_results = rest_api_scanner.scan()
        security_result.rest_api_vulnerabilities = rest_api_results
        if meta := collect_scanner_metadata(RESTAPISecurityScanner, rest_api_results):
            scanner_metadata.append(meta)

        for vuln in rest_api_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='api_security',
                vulnerability_type='rest_api',
                severity=vuln.get('severity', 'high'),
                title=vuln.get('type', 'REST API Security'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 27. GraphQL 보안 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_api import GraphQLSecurityScanner
        graphql_scanner = GraphQLSecurityScanner(scan_request.url, response.text)
        graphql_results = graphql_scanner.scan()
        security_result.graphql_vulnerabilities = graphql_results
        if meta := collect_scanner_metadata(GraphQLSecurityScanner, graphql_results):
            scanner_metadata.append(meta)

        for vuln in graphql_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='api_security',
                vulnerability_type='graphql',
                severity=vuln.get('severity', 'high'),
                title=vuln.get('type', 'GraphQL Security'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 28. OAuth 보안 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_api import OAuthSecurityScanner
        oauth_scanner = OAuthSecurityScanner(scan_request.url, response.text)
        oauth_results = oauth_scanner.scan()
        security_result.oauth_vulnerabilities = oauth_results
        if meta := collect_scanner_metadata(OAuthSecurityScanner, oauth_results):
            scanner_metadata.append(meta)

        for vuln in oauth_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='broken_authentication',
                vulnerability_type='oauth',
                severity=vuln.get('severity', 'high'),
                title=vuln.get('type', 'OAuth Security'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 29. Session 보안 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_api import SessionSecurityScanner
        session_scanner = SessionSecurityScanner(response, scan_request.url)
        session_results = session_scanner.scan()
        security_result.session_vulnerabilities = session_results
        if meta := collect_scanner_metadata(SessionSecurityScanner, session_results):
            scanner_metadata.append(meta)

        for vuln in session_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='broken_authentication',
                vulnerability_type='session',
                severity=vuln.get('severity', 'high'),
                title=vuln.get('type', 'Session Security'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 30. Password Policy 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_api import PasswordPolicyScanner
        password_scanner = PasswordPolicyScanner(response.text, scan_request.url)
        password_results = password_scanner.scan()
        security_result.password_policy = password_results
        if meta := collect_scanner_metadata(PasswordPolicyScanner, password_results):
            scanner_metadata.append(meta)

        for vuln in password_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='broken_authentication',
                vulnerability_type='password_policy',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('type', 'Password Policy'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 31. Rate Limiting 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_api import RateLimitingScanner
        rate_limit_scanner = RateLimitingScanner(response, scan_request.url)
        rate_limit_results = rate_limit_scanner.scan()
        security_result.rate_limiting = rate_limit_results
        if meta := collect_scanner_metadata(RateLimitingScanner, rate_limit_results):
            scanner_metadata.append(meta)

        for vuln in rate_limit_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='security_misconfiguration',
                vulnerability_type='rate_limiting',
                severity=vuln.get('severity', 'high'),
                title=vuln.get('type', 'Rate Limiting'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 32. LDAP Injection 검사
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_api import LDAPInjectionScanner
        ldap_scanner = LDAPInjectionScanner(scan_request.url, response.text)
        ldap_results = ldap_scanner.scan()
        security_result.ldap_injection = ldap_results
        if meta := collect_scanner_metadata(LDAPInjectionScanner, ldap_results):
            scanner_metadata.append(meta)

        for vuln in ldap_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='injection',
                vulnerability_type='ldap_injection',
                severity=vuln.get('severity', 'high'),
                title=vuln.get('type', 'LDAP Injection'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 33. Authorization 검사 (BOLA/IDOR)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_api import AuthorizationScanner
        authz_scanner = AuthorizationScanner(scan_request.url)
        authz_results = authz_scanner.scan()
        security_result.authorization_vulnerabilities = authz_results
        if meta := collect_scanner_metadata(AuthorizationScanner, authz_results):
            scanner_metadata.append(meta)

        for vuln in authz_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='broken_access_control',
                vulnerability_type='authorization',
                severity=vuln.get('severity', 'critical'),
                title=vuln.get('type', 'Authorization'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 34. Software Supply Chain 검사 (OWASP 2025 A03)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_supply_chain import SoftwareSupplyChainScanner
        supply_chain_scanner = SoftwareSupplyChainScanner(scan_request.url, response, response.text)
        supply_chain_results = supply_chain_scanner.scan()
        security_result.supply_chain_vulnerabilities = supply_chain_results
        if meta := collect_scanner_metadata(SoftwareSupplyChainScanner, supply_chain_results):
            scanner_metadata.append(meta)

        for vuln in supply_chain_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='software_supply_chain',
                vulnerability_type='supply_chain',
                severity=vuln.get('severity', 'high'),
                title=vuln.get('title', 'Supply Chain'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 35. Exception Handling 검사 (OWASP 2025 A10)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_exception import ExceptionHandlingScanner
        exception_scanner = ExceptionHandlingScanner(scan_request.url, response, response.text)
        exception_results = exception_scanner.scan()
        security_result.exception_handling_vulnerabilities = exception_results
        if meta := collect_scanner_metadata(ExceptionHandlingScanner, exception_results):
            scanner_metadata.append(meta)

        for vuln in exception_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='exception_handling',
                vulnerability_type='error_exposure',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'Exception Handling'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 36. Price Manipulation 검사 (OWASP 2025 A06)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_business_logic import PriceManipulationScanner
        price_scanner = PriceManipulationScanner(scan_request.url, response, response.text)
        price_results = price_scanner.scan()
        security_result.price_manipulation_vulnerabilities = price_results
        if meta := collect_scanner_metadata(PriceManipulationScanner, price_results):
            scanner_metadata.append(meta)

        for vuln in price_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='business_logic',
                vulnerability_type='price_manipulation',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'Price Manipulation'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 37. Race Condition 검사 (OWASP 2025 A06)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_business_logic import RaceConditionScanner
        race_scanner = RaceConditionScanner(scan_request.url, response, response.text)
        race_results = race_scanner.scan()
        security_result.race_condition_vulnerabilities = race_results
        if meta := collect_scanner_metadata(RaceConditionScanner, race_results):
            scanner_metadata.append(meta)

        for vuln in race_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='business_logic',
                vulnerability_type='race_condition',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'Race Condition'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 38. Workflow Bypass 검사 (OWASP 2025 A06)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_business_logic import WorkflowBypassScanner
        workflow_scanner = WorkflowBypassScanner(scan_request.url, response, response.text)
        workflow_results = workflow_scanner.scan()
        security_result.workflow_bypass_vulnerabilities = workflow_results
        if meta := collect_scanner_metadata(WorkflowBypassScanner, workflow_results):
            scanner_metadata.append(meta)

        for vuln in workflow_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='business_logic',
                vulnerability_type='workflow_bypass',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'Workflow Bypass'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 39. Account Enumeration 검사 (OWASP 2025 A06+A07)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_business_logic import AccountEnumerationScanner
        account_scanner = AccountEnumerationScanner(scan_request.url, response, response.text)
        account_results = account_scanner.scan()
        security_result.account_enumeration_vulnerabilities = account_results
        if meta := collect_scanner_metadata(AccountEnumerationScanner, account_results):
            scanner_metadata.append(meta)

        for vuln in account_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='business_logic',
                vulnerability_type='account_enumeration',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'Account Enumeration'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 40. Resource Exhaustion 검사 (OWASP 2025 A06)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_business_logic import ResourceExhaustionScanner
        resource_scanner = ResourceExhaustionScanner(scan_request.url, response, response.text)
        resource_results = resource_scanner.scan()
        security_result.resource_exhaustion_vulnerabilities = resource_results
        if meta := collect_scanner_metadata(ResourceExhaustionScanner, resource_results):
            scanner_metadata.append(meta)

        for vuln in resource_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='business_logic',
                vulnerability_type='resource_exhaustion',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'Resource Exhaustion'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 41. Logging & Monitoring 검사 (OWASP 2025 A09)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_business_logic import LoggingMonitoringScanner
        logging_scanner = LoggingMonitoringScanner(scan_request.url, response, response.text)
        logging_results = logging_scanner.scan()
        security_result.logging_monitoring_vulnerabilities = logging_results
        if meta := collect_scanner_metadata(LoggingMonitoringScanner, logging_results):
            scanner_metadata.append(meta)

        for vuln in logging_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='logging',
                vulnerability_type='logging_monitoring',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'Logging & Monitoring'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 42. Business Logic Anomaly 검사 (OWASP 2025 A06)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_business_logic import BusinessLogicAnomalyScanner
        anomaly_scanner = BusinessLogicAnomalyScanner(scan_request.url, response, response.text)
        anomaly_results = anomaly_scanner.scan()
        security_result.business_logic_anomaly_vulnerabilities = anomaly_results
        if meta := collect_scanner_metadata(BusinessLogicAnomalyScanner, anomaly_results):
            scanner_metadata.append(meta)

        for vuln in anomaly_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='business_logic',
                vulnerability_type='business_logic_anomaly',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'Business Logic Anomaly'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 43. Package Integrity 검사 (A03 강화)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_supply_chain_advanced import PackageIntegrityScanner
        pkg_integrity_scanner = PackageIntegrityScanner(scan_request.url, response, response.text)
        pkg_integrity_results = pkg_integrity_scanner.scan()
        security_result.package_integrity_vulnerabilities = pkg_integrity_results
        if meta := collect_scanner_metadata(PackageIntegrityScanner, pkg_integrity_results):
            scanner_metadata.append(meta)

        for vuln in pkg_integrity_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='supply_chain',
                vulnerability_type='package_integrity',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'Package Integrity'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 44. Typosquatting 탐지 (A03 강화)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_supply_chain_advanced import TyposquattingScanner
        typo_scanner = TyposquattingScanner(scan_request.url, response, response.text)
        typo_results = typo_scanner.scan()
        security_result.typosquatting_vulnerabilities = typo_results
        if meta := collect_scanner_metadata(TyposquattingScanner, typo_results):
            scanner_metadata.append(meta)

        for vuln in typo_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='supply_chain',
                vulnerability_type='typosquatting',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'Typosquatting'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 45. Outdated Dependency 검사 (A03 강화)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_supply_chain_advanced import OutdatedDependencyScanner
        outdated_scanner = OutdatedDependencyScanner(scan_request.url, response, response.text)
        outdated_results = outdated_scanner.scan()
        security_result.outdated_dependency_vulnerabilities = outdated_results
        if meta := collect_scanner_metadata(OutdatedDependencyScanner, outdated_results):
            scanner_metadata.append(meta)

        for vuln in outdated_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='supply_chain',
                vulnerability_type='outdated_dependency',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'Outdated Dependency'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 46. License Compliance 검사 (A03 강화)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_supply_chain_advanced import LicenseComplianceScanner
        license_scanner = LicenseComplianceScanner(scan_request.url, response, response.text)
        license_results = license_scanner.scan()
        security_result.license_compliance_vulnerabilities = license_results
        if meta := collect_scanner_metadata(LicenseComplianceScanner, license_results):
            scanner_metadata.append(meta)

        for vuln in license_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='supply_chain',
                vulnerability_type='license_compliance',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'License Compliance'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 47. JWT Advanced 검사 (A08 강화)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_integrity_advanced import JWTAdvancedScanner
        jwt_adv_scanner = JWTAdvancedScanner(scan_request.url, response, response.text)
        jwt_adv_results = jwt_adv_scanner.scan()
        security_result.jwt_advanced_vulnerabilities = jwt_adv_results
        if meta := collect_scanner_metadata(JWTAdvancedScanner, jwt_adv_results):
            scanner_metadata.append(meta)

        for vuln in jwt_adv_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='data_integrity',
                vulnerability_type='jwt_advanced',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'JWT Advanced'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 48. Serialization Integrity 검사 (A08 강화)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_integrity_advanced import SerializationIntegrityScanner
        serialization_scanner = SerializationIntegrityScanner(scan_request.url, response, response.text)
        serialization_results = serialization_scanner.scan()
        security_result.serialization_integrity_vulnerabilities = serialization_results
        if meta := collect_scanner_metadata(SerializationIntegrityScanner, serialization_results):
            scanner_metadata.append(meta)

        for vuln in serialization_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='data_integrity',
                vulnerability_type='serialization_integrity',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'Serialization Integrity'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 49. API Integrity 검사 (A08 강화)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_integrity_advanced import APIIntegrityScanner
        api_integrity_scanner = APIIntegrityScanner(scan_request.url, response, response.text)
        api_integrity_results = api_integrity_scanner.scan()
        security_result.api_integrity_vulnerabilities = api_integrity_results
        if meta := collect_scanner_metadata(APIIntegrityScanner, api_integrity_results):
            scanner_metadata.append(meta)

        for vuln in api_integrity_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='data_integrity',
                vulnerability_type='api_integrity',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'API Integrity'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 50. Checksum Validation 검사 (A08 강화)
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        from .scanners_integrity_advanced import ChecksumValidationScanner
        checksum_scanner = ChecksumValidationScanner(scan_request.url, response, response.text)
        checksum_results = checksum_scanner.scan()
        security_result.checksum_validation_vulnerabilities = checksum_results
        if meta := collect_scanner_metadata(ChecksumValidationScanner, checksum_results):
            scanner_metadata.append(meta)

        for vuln in checksum_results.get('vulnerabilities', [])[:5]:
            Vulnerability.objects.create(
                scan_request=scan_request,
                category='data_integrity',
                vulnerability_type='checksum_validation',
                severity=vuln.get('severity', 'medium'),
                title=vuln.get('title', 'Checksum Validation'),
                description=vuln.get('description', ''),
                recommendation=vuln.get('recommendation', ''),
                evidence=str(vuln)[:500]
            )

        # 점수 계산 (강화)
        security_result.overall_score = calculate_security_score_ultra_advanced(
            security_result,
            header_results,
            xss_results,
            sqli_results,
            cors_results,
            cookie_results,
            csrf_results,
            clickjacking_results,
            info_results,
            method_results,
            file_results,
            mixed_results,
            sri_results,
            listing_results,
            redirect_results
        )
        security_result.risk_level = determine_risk_level(security_result.overall_score)

        # 스캐너 메타데이터 저장
        security_result.scanner_metadata = scanner_metadata
        security_result.save()

        # 보안 스캔 완료 - 최종 진행률 설정
        scan_request.progress = pm.get_scan_end_progress('security')
        scan_request.save()

        logger.info(f'Security scan completed for {scan_request_id}')

        return {'status': 'completed', 'type': 'security'}

    except Exception as e:
        logger.error(f'Security scan failed: {str(e)}')
        raise


@shared_task
def scan_standards(scan_request_id):
    """
    웹 표준 검사 작업 (강화 버전)
    """
    from scanner.progress_manager import ProgressManager
    logger.info(f'Starting standards scan for {scan_request_id}')

    try:
        scan_request = ScanRequest.objects.get(id=scan_request_id)

        # ProgressManager 초기화 (standards만 실행하므로 0-100% 전체 사용)
        pm = ProgressManager(['standards'])

        # 기본 HTTP 요청
        try:
            start_time = time.time()
            response = requests.get(
                scan_request.url,
                timeout=settings.SCAN_TIMEOUT,
                headers={'User-Agent': settings.USER_AGENT}
            )
            load_time = time.time() - start_time
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error(f'Failed to fetch URL {scan_request.url}: {str(e)}')
            raise

        # 웹 표준 결과 생성
        standards_result = WebStandardsResult.objects.create(
            scan_request=scan_request,
            page_load_time=load_time,
            page_size=len(response.content)
        )

        # 스캐너 메타데이터를 수집할 리스트
        scanner_metadata = []

        # HTML 파싱
        soup = BeautifulSoup(response.content, 'html.parser')

        # 1. 기본 SEO 검사
        progress, name = pm.next_progress('standards')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        seo_data = check_seo_advanced(soup, scan_request.url, response)
        standards_result.seo_score = seo_data['overall_score']
        standards_result.seo_issues = seo_data['vulnerabilities']
        standards_result.meta_tags = seo_data.get('meta_tags', {})

        # 메타데이터 수집
        if meta := collect_scanner_metadata(check_seo_advanced, seo_data):
            scanner_metadata.append(meta)

        # 2. HTML 구조 검증
        progress, name = pm.next_progress('standards')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        html_validation = check_html_structure(soup, response.text)
        standards_result.html_valid = html_validation['overall_score'] >= 70
        standards_result.html_errors = html_validation['vulnerabilities']
        standards_result.html_warnings = []  # 이제 vulnerabilities로 통합됨
        standards_result.html_error_count = len(html_validation['vulnerabilities'])

        # 메타데이터 수집
        if meta := collect_scanner_metadata(check_html_structure, html_validation):
            scanner_metadata.append(meta)

        # 3. CSS 분석
        progress, name = pm.next_progress('standards')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        css_data = check_css_resources(soup, scan_request.url)
        standards_result.css_valid = css_data['overall_score'] >= 70
        standards_result.css_errors = css_data['vulnerabilities']
        standards_result.css_warnings = []  # 이제 vulnerabilities로 통합됨
        standards_result.css_error_count = len(css_data['vulnerabilities'])

        # 메타데이터 수집
        if meta := collect_scanner_metadata(check_css_resources, css_data):
            scanner_metadata.append(meta)

        # 4. JavaScript 검사
        progress, name = pm.next_progress('standards')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        js_data = check_javascript(soup, scan_request.url)
        standards_result.js_errors = js_data['vulnerabilities']
        standards_result.js_console_logs = []  # 이제 vulnerabilities로 통합됨
        standards_result.js_error_count = len(js_data['vulnerabilities'])

        # 메타데이터 수집
        if meta := collect_scanner_metadata(check_javascript, js_data):
            scanner_metadata.append(meta)

        # 5. 점수 계산 (향상된 버전)
        standards_result.overall_score = calculate_standards_score_advanced(
            standards_result,
            seo_data,
            html_validation,
            css_data,
            js_data
        )

        # 스캐너 메타데이터 저장
        standards_result.scanner_metadata = scanner_metadata
        standards_result.save()

        # 웹 표준 스캔 완료 - 최종 진행률 설정
        scan_request.progress = pm.get_scan_end_progress('standards')
        scan_request.save()

        logger.info(f'Standards scan completed for {scan_request_id}')

        return {'status': 'completed', 'type': 'standards'}

    except Exception as e:
        logger.error(f'Standards scan failed: {str(e)}')
        raise


@shared_task
def scan_accessibility(scan_request_id):
    """
    접근성 검사 작업
    """
    from scanner.progress_manager import ProgressManager
    logger.info(f'Starting accessibility scan for {scan_request_id}')

    try:
        scan_request = ScanRequest.objects.get(id=scan_request_id)

        # ProgressManager 초기화 (accessibility만 실행하므로 0-100% 전체 사용)
        pm = ProgressManager(['accessibility'])

        # 기본 HTTP 요청
        try:
            response = requests.get(
                scan_request.url,
                timeout=settings.SCAN_TIMEOUT,
                headers={'User-Agent': settings.USER_AGENT}
            )
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error(f'Failed to fetch URL {scan_request.url}: {str(e)}')
            raise

        # 접근성 결과 생성
        accessibility_result = AccessibilityResult.objects.create(
            scan_request=scan_request
        )

        # 스캐너 메타데이터를 수집할 리스트
        scanner_metadata = []

        # HTML 파싱
        soup = BeautifulSoup(response.content, 'html.parser')

        # 기본 접근성 검사
        progress, name = pm.next_progress('accessibility')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()
        accessibility_data = check_basic_accessibility(soup, scan_request.url)

        # 메타데이터 수집
        if meta := collect_scanner_metadata(check_basic_accessibility, accessibility_data):
            scanner_metadata.append(meta)

        # 데이터 저장 (이전 형식과 호환)
        alt_text_issues = [v for v in accessibility_data['vulnerabilities'] if v.get('element') == 'img']
        form_label_issues = [v for v in accessibility_data['vulnerabilities'] if v.get('element') == 'input']

        accessibility_result.alt_text_missing = alt_text_issues
        accessibility_result.form_labels = form_label_issues
        accessibility_result.heading_structure = accessibility_data['statistics'].get('heading_structure', {})

        # 통계
        accessibility_result.total_issues = len(accessibility_data['vulnerabilities'])
        accessibility_result.critical_issues = len([i for i in accessibility_data['vulnerabilities'] if i.get('severity') == 'critical'])

        # 점수 및 등급 계산 (새 데이터 형식 사용)
        accessibility_result.overall_score = accessibility_data['overall_score']
        accessibility_result.wcag_level = determine_wcag_level(accessibility_data['overall_score'])

        # 스캐너 메타데이터 저장
        accessibility_result.scanner_metadata = scanner_metadata
        accessibility_result.save()

        # 접근성 스캔 완료 - 최종 진행률 설정
        scan_request.progress = pm.get_scan_end_progress('accessibility')
        scan_request.save()

        logger.info(f'Accessibility scan completed for {scan_request_id}')

        return {'status': 'completed', 'type': 'accessibility'}

    except Exception as e:
        logger.error(f'Accessibility scan failed: {str(e)}')
        raise


# ============================================================================
# Helper Functions
# ============================================================================

def check_security_headers(headers):
    """보안 헤더 검사"""
    security_headers_check = {}

    # 중요 보안 헤더 목록
    required_headers = {
        'Strict-Transport-Security': 'missing',
        'Content-Security-Policy': 'missing',
        'X-Frame-Options': 'missing',
        'X-Content-Type-Options': 'missing',
        'Referrer-Policy': 'missing',
        'Permissions-Policy': 'missing',
    }

    for header, default in required_headers.items():
        if header in headers:
            security_headers_check[header] = {
                'present': True,
                'value': headers[header],
                'status': 'ok'
            }
        else:
            security_headers_check[header] = {
                'present': False,
                'status': 'missing',
                'recommendation': f'{header} 헤더를 추가하세요.'
            }

    return security_headers_check


def check_ssl_tls(url):
    """SSL/TLS 검사 (간단한 버전)"""
    import urllib.parse

    parsed = urllib.parse.urlparse(url)

    if parsed.scheme == 'https':
        return {
            'https': True,
            'status': 'ok',
            'message': 'HTTPS를 사용합니다.'
        }
    else:
        return {
            'https': False,
            'status': 'warning',
            'message': 'HTTPS를 사용하지 않습니다. SSL/TLS 인증서를 설정하세요.'
        }

# SSL/TLS 스캐너 메타데이터
check_ssl_tls.metadata = {
    'id': 'ssl_tls',
    'name': 'SSL/TLS 검사',
    'icon': '🔐',
    'description': 'HTTPS 및 인증서 검증',
    'weight': 1,
    'field': 'ssl_tls_result'
}


def check_seo(soup, url):
    """SEO 검사"""
    issues = []
    meta_tags = {}
    score = 100

    # Title 태그
    title = soup.find('title')
    if not title:
        issues.append({'type': 'title', 'severity': 'high', 'message': 'Title 태그가 없습니다.'})
        score -= 20
    else:
        meta_tags['title'] = title.string
        if len(title.string) > 60:
            issues.append({'type': 'title', 'severity': 'medium', 'message': 'Title이 너무 깁니다 (60자 이하 권장).'})
            score -= 5

    # Meta description
    meta_desc = soup.find('meta', attrs={'name': 'description'})
    if not meta_desc:
        issues.append({'type': 'meta_description', 'severity': 'high', 'message': 'Meta description이 없습니다.'})
        score -= 20
    else:
        meta_tags['description'] = meta_desc.get('content', '')

    # H1 태그
    h1_tags = soup.find_all('h1')
    if not h1_tags:
        issues.append({'type': 'h1', 'severity': 'medium', 'message': 'H1 태그가 없습니다.'})
        score -= 10
    elif len(h1_tags) > 1:
        issues.append({'type': 'h1', 'severity': 'low', 'message': 'H1 태그가 여러 개입니다 (1개 권장).'})
        score -= 5

    # 이미지 alt 속성
    images = soup.find_all('img')
    images_without_alt = [img for img in images if not img.get('alt')]
    if images_without_alt:
        issues.append({
            'type': 'img_alt',
            'severity': 'medium',
            'message': f'{len(images_without_alt)}개의 이미지에 alt 속성이 없습니다.',
            'count': len(images_without_alt)
        })
        score -= min(15, len(images_without_alt) * 2)

    return {
        'score': max(0, score),
        'issues': issues,
        'meta_tags': meta_tags
    }


def check_basic_accessibility(soup, url):
    """기본 접근성 검사"""
    vulnerabilities = []
    score = 100
    statistics = {}

    # 이미지 alt 속성
    images = soup.find_all('img')
    images_without_alt = 0
    for idx, img in enumerate(images):
        if not img.get('alt'):
            images_without_alt += 1
            vulnerabilities.append({
                'element': 'img',
                'src': img.get('src', 'unknown'),
                'position': idx + 1,
                'severity': 'medium',
                'message': 'Alt 속성이 없습니다.'
            })
            score -= 2  # 이미지당 2점 감점

    # 폼 레이블
    inputs = soup.find_all('input', type=['text', 'email', 'password', 'number'])
    inputs_without_label = 0
    for idx, input_elem in enumerate(inputs):
        input_id = input_elem.get('id')
        if input_id:
            label = soup.find('label', attrs={'for': input_id})
            if not label:
                inputs_without_label += 1
                vulnerabilities.append({
                    'element': 'input',
                    'type': input_elem.get('type'),
                    'id': input_id,
                    'severity': 'high',
                    'message': '연결된 label이 없습니다.'
                })
                score -= 5  # 폼 입력당 5점 감점

    # 제목 구조
    headings = soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])
    h1_count = len(soup.find_all('h1'))

    if h1_count == 0:
        vulnerabilities.append({
            'element': 'heading',
            'severity': 'high',
            'message': 'H1 제목이 없습니다. 페이지 구조에 H1이 필요합니다.'
        })
        score -= 10
    elif h1_count > 1:
        vulnerabilities.append({
            'element': 'heading',
            'severity': 'low',
            'message': f'H1 제목이 {h1_count}개 있습니다. 페이지당 1개 권장.'
        })
        score -= 5

    # 통계 정보
    statistics = {
        'total_images': len(images),
        'images_without_alt': images_without_alt,
        'total_inputs': len(inputs),
        'inputs_without_label': inputs_without_label,
        'heading_structure': {
            'total': len(headings),
            'h1_count': h1_count,
            'h2_count': len(soup.find_all('h2')),
            'h3_count': len(soup.find_all('h3')),
        }
    }

    return {
        'overall_score': max(0, score),
        'vulnerabilities': vulnerabilities,
        'statistics': statistics
    }

# 기본 접근성 스캐너 메타데이터
check_basic_accessibility.metadata = {
    'id': 'basic_accessibility',
    'name': '기본 접근성 검사',
    'icon': '♿',
    'description': 'Alt 텍스트, 폼 레이블, 제목 구조 검증',
    'weight': 1,
    'field': 'accessibility_issues'
}


def calculate_security_score(security_result):
    """보안 점수 계산 (임시)"""
    score = 100

    # 보안 헤더 점수
    headers = security_result.security_headers
    missing_headers = sum(1 for h in headers.values() if not h.get('present'))
    score -= missing_headers * 10

    # SSL/TLS 점수
    if not security_result.ssl_tls_result.get('https'):
        score -= 30

    return max(0, min(100, score))


def determine_risk_level(score):
    """위험 수준 결정"""
    if score >= 80:
        return 'low'
    elif score >= 60:
        return 'medium'
    elif score >= 40:
        return 'high'
    else:
        return 'critical'


def calculate_standards_score(standards_result):
    """웹 표준 점수 계산 (임시)"""
    score = 100

    # SEO 점수 반영
    score = (score + standards_result.seo_score) // 2

    # HTML/CSS 유효성
    if not standards_result.html_valid:
        score -= 20
    if not standards_result.css_valid:
        score -= 20

    return max(0, min(100, score))


def calculate_accessibility_score(accessibility_result):
    """접근성 점수 계산 (임시)"""
    score = 100

    # 이슈 수에 따라 점수 감점
    score -= min(50, accessibility_result.total_issues * 5)
    score -= min(30, accessibility_result.critical_issues * 10)

    return max(0, min(100, score))


def determine_wcag_level(score):
    """WCAG 등급 결정"""
    if score >= 90:
        return 'AAA'
    elif score >= 75:
        return 'AA'
    elif score >= 50:
        return 'A'
    else:
        return 'None'


def calculate_security_score_advanced(security_result, header_results, xss_results, sqli_results, cors_results, cookie_results):
    """보안 점수 계산 (강화 버전)"""
    score = 100

    # 1. 보안 헤더 점수 (30점)
    missing_headers = header_results.get('missing_count', 0)
    total_headers = header_results.get('total_count', 7)
    header_score = max(0, 30 - (missing_headers * 5))
    score -= (30 - header_score)

    # 2. SSL/TLS 점수 (20점)
    if not security_result.ssl_tls_result.get('https'):
        score -= 20

    # 3. XSS 취약점 (20점)
    xss_count = xss_results.get('total', 0)
    if xss_count > 0:
        score -= min(20, xss_count * 5)

    # 4. SQL Injection 취약점 (20점)
    sqli_count = sqli_results.get('total', 0)
    if sqli_count > 0:
        score -= min(20, sqli_count * 10)  # SQL Injection이 더 심각

    # 5. CORS 설정 (5점)
    if cors_results.get('misconfigured'):
        score -= 5

    # 6. 쿠키 보안 (5점)
    insecure_cookies = cookie_results.get('insecure_cookies', 0)
    if insecure_cookies > 0:
        score -= min(5, insecure_cookies * 2)

    return max(0, min(100, score))


def calculate_security_score_ultra_advanced(
    security_result, header_results, xss_results, sqli_results, cors_results, cookie_results,
    csrf_results, clickjacking_results, info_results, method_results, file_results,
    mixed_results, sri_results, listing_results, redirect_results
):
    """보안 점수 계산 (초강화 버전 - 15개 검사 항목)"""
    score = 100

    # 1. 보안 헤더 점수 (20점)
    missing_headers = header_results.get('missing_count', 0)
    score -= min(20, missing_headers * 3)

    # 2. SSL/TLS 점수 (15점)
    if not security_result.ssl_tls_result.get('https'):
        score -= 15

    # 3. XSS 취약점 (15점) - 치명적
    xss_count = xss_results.get('total', 0)
    if xss_count > 0:
        score -= min(15, xss_count * 5)

    # 4. SQL Injection 취약점 (15점) - 치명적
    sqli_count = sqli_results.get('total', 0)
    if sqli_count > 0:
        score -= min(15, sqli_count * 8)

    # 5. CORS 설정 (5점)
    if cors_results.get('misconfigured'):
        score -= 5

    # 6. 쿠키 보안 (5점)
    insecure_cookies = cookie_results.get('insecure_cookies', 0)
    if insecure_cookies > 0:
        score -= min(5, insecure_cookies * 2)

    # 7. CSRF 보호 (10점) - 중요
    csrf_vulnerable = csrf_results.get('vulnerable_forms', 0)
    if csrf_vulnerable > 0:
        score -= min(10, csrf_vulnerable * 3)

    # 8. 클릭재킹 방어 (5점)
    if not clickjacking_results.get('protected', True):
        score -= 5

    # 9. 정보 노출 (5점)
    info_issues = info_results.get('total', 0)
    if info_issues > 0:
        score -= min(5, info_issues * 1)

    # 10. 위험한 HTTP 메서드 (3점)
    if method_results.get('has_dangerous_methods', False):
        score -= 3

    # 11. 민감한 파일 노출 (10점) - 중요
    file_issues = file_results.get('total', 0)
    if file_issues > 0:
        score -= min(10, file_issues * 3)

    # 12. Mixed Content (3점)
    if mixed_results.get('has_mixed_content', False):
        score -= 3

    # 13. SRI 누락 (2점)
    if sri_results.get('missing_sri', False):
        score -= 2

    # 14. 디렉토리 리스팅 (3점)
    if listing_results.get('has_listing', False):
        score -= 3

    # 15. Open Redirect (5점)
    if redirect_results.get('has_open_redirect', False):
        score -= 5

    return max(0, min(100, score))
