"""
보안 스캔 리팩토링 버전 - ProgressManager를 활용한 깔끔한 구조
"""

def scan_security_refactored(scan_request_id):
    """리팩토링된 보안 스캔 함수 예시"""

    from scanner.progress_manager import ProgressManager
    from scanner.models import ScanRequest, SecurityScanResult, Vulnerability
    import logging

    logger = logging.getLogger('scanner')

    scan_request = ScanRequest.objects.get(id=scan_request_id)
    pm = ProgressManager(['security'])

    # 스캐너 리스트 정의 (순서대로 실행)
    scanners = [
        # (스캐너 함수, 결과 처리 함수)
        ('security_headers', scan_security_headers),
        ('ssl_tls', scan_ssl_tls),
        ('xss', scan_xss),
        ('sql_injection', scan_sql_injection),
        ('cors', scan_cors),
        ('cookies', scan_cookies),
        ('csrf', scan_csrf),
        ('clickjacking', scan_clickjacking),
        ('info_disclosure', scan_info_disclosure),
        ('http_methods', scan_http_methods),
        ('sensitive_files', scan_sensitive_files),
        ('mixed_content', scan_mixed_content),
        ('sri', scan_sri),
        ('directory_listing', scan_directory_listing),
        ('open_redirect', scan_open_redirect),
    ]

    # 각 스캐너 실행
    for scanner_name, scanner_func in scanners:
        # Progress 업데이트
        progress, name = pm.next_progress('security')
        logger.info(f'{name}: {progress:.1f}%')
        scan_request.progress = progress
        scan_request.save()

        # 스캐너 실행
        try:
            result = scanner_func(scan_request, response)
            # 결과 처리...
        except Exception as e:
            logger.error(f'Scanner {scanner_name} failed: {e}')
            continue

    # 완료
    scan_request.progress = 100
    scan_request.save()