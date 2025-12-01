"""
API Views
스캔 요청 및 결과 조회 API
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.shortcuts import get_object_or_404
from django.utils import timezone
from urllib.parse import urlparse
import logging
from django.conf import settings
from django.db.models import Q

from scanner.models import (
    ScanRequest,
    SecurityScanResult,
    WebStandardsResult,
    AccessibilityResult,
    Vulnerability
)
from .serializers import (
    ScanRequestSerializer,
    ScanRequestCreateSerializer,
    ScanResultSerializer,
    SecurityScanResultSerializer,
    WebStandardsResultSerializer,
    AccessibilityResultSerializer,
    VulnerabilitySerializer
)

logger = logging.getLogger('scanner')


def get_client_ip(request):
    """클라이언트 IP 주소 추출"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


class ScanViewSet(viewsets.ReadOnlyModelViewSet):
    """스캔 ViewSet"""

    queryset = ScanRequest.objects.all()
    serializer_class = ScanRequestSerializer
    permission_classes = [AllowAny]

    def _get_field_name_for_scanner(self, scanner_id):
        """
        scanner_id를 SecurityScanResult의 필드명으로 매핑

        Args:
            scanner_id: 스캐너 설정의 ID

        Returns:
            데이터베이스 필드명 또는 None
        """
        # scanner_id와 DB 필드명 매핑
        field_mapping = {
            'security_headers': 'security_headers',
            'ssl_tls': 'ssl_tls_result',
            'xss_vulnerabilities': 'xss_vulnerabilities',
            'sql_injection': 'sql_injection',
            'cors_misconfiguration': 'cors_misconfiguration',
            'cookie_security': 'cookie_security',
            'csrf_protection': 'csrf_protection',
            'clickjacking': 'clickjacking',
            'information_disclosure': 'sensitive_data_exposure',
            'http_methods': 'http_methods',
            'sensitive_files': 'sensitive_files',
            'mixed_content': 'mixed_content',
            'subresource_integrity': 'subresource_integrity',
            'directory_listing': 'directory_listing',
            'open_redirect': 'open_redirects',
            'ssrf_vulnerabilities': 'ssrf_vulnerabilities',
            'xxe_vulnerabilities': 'xxe_vulnerabilities',
            'command_injection': 'command_injection',
            'deserialization': 'deserialization',
            'file_upload': 'file_upload',
            'path_traversal': 'path_traversal',
            'jwt_vulnerabilities': 'jwt_vulnerabilities',
            'template_injection': 'template_injection',
            'nosql_injection': 'nosql_injection',
            'ssl_tls_deep': 'ssl_tls_vulnerabilities',
            'rest_api_security': 'rest_api_vulnerabilities',
            'graphql_security': 'graphql_vulnerabilities',
            'oauth_security': 'oauth_vulnerabilities',
            'session_security': 'session_vulnerabilities',
            'password_policy': 'password_policy',
            'rate_limiting': 'rate_limiting',
            'ldap_injection': 'ldap_injection',
            'authorization': 'authorization_vulnerabilities',
            'supply_chain': 'supply_chain_vulnerabilities',
            'exception_handling': 'exception_handling_vulnerabilities',
            'price_manipulation': 'price_manipulation_vulnerabilities',
            'race_condition': 'race_condition_vulnerabilities',
            'workflow_bypass': 'workflow_bypass_vulnerabilities',
            'account_enumeration': 'account_enumeration_vulnerabilities',
            'resource_exhaustion': 'resource_exhaustion_vulnerabilities',
            'logging_monitoring': 'logging_monitoring_vulnerabilities',
            'business_logic_anomaly': 'business_logic_anomaly_vulnerabilities',
            'package_integrity': 'package_integrity_vulnerabilities',
            'typosquatting': 'typosquatting_vulnerabilities',
            'outdated_dependencies': 'outdated_dependency_vulnerabilities',
            'license_compliance': 'license_compliance_vulnerabilities',
            'jwt_advanced': 'jwt_advanced_vulnerabilities',
            'serialization_integrity': 'serialization_integrity_vulnerabilities',
            'api_integrity': 'api_integrity_vulnerabilities',
            'checksum_validation': 'checksum_validation_vulnerabilities'
        }

        return field_mapping.get(scanner_id)

    @action(detail=False, methods=['post'], url_path='start')
    def start_scan(self, request):
        """
        스캔 시작
        POST /api/scan/start/
        """
        serializer = ScanRequestCreateSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid request', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 검증된 데이터 추출
        validated_data = serializer.validated_data
        url = validated_data['url']
        scan_types = validated_data.get('scan_types', ['security', 'standards', 'accessibility'])
        deep_scan = validated_data.get('deep_scan', False)

        # 도메인 추출
        parsed_url = urlparse(url)
        target_domain = parsed_url.netloc

        # 클라이언트 정보
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]

        try:
            # 동시 스캔 제한 확인
            if settings.MAX_CONCURRENT_SCANS > 0:
                try:
                    # Redis를 사용한 동시성 제어 (분산 환경 지원)
                    import redis
                    redis_client = redis.Redis.from_url(settings.CELERY_BROKER_URL)
                    redis_client.ping()  # Redis 연결 확인

                    running_scans_key = 'weak:running_scans'
                    current_running = redis_client.scard(running_scans_key)

                    if current_running >= settings.MAX_CONCURRENT_SCANS:
                        logger.warning(f'Concurrent scan limit reached: {current_running}/{settings.MAX_CONCURRENT_SCANS}')
                        return Response({
                            'error': '동시 스캔 제한을 초과했습니다',
                            'message': f'현재 {current_running}개의 스캔이 실행 중입니다. 잠시 후 다시 시도해주세요.',
                            'current_scans': current_running,
                            'max_allowed': settings.MAX_CONCURRENT_SCANS
                        }, status=status.HTTP_429_TOO_MANY_REQUESTS)

                    logger.info(f'Concurrent scans: {current_running}/{settings.MAX_CONCURRENT_SCANS}')

                except Exception as redis_error:
                    # Redis 사용 불가 시 DB 쿼리로 Fallback
                    logger.warning(f'Redis unavailable for concurrency check, using DB: {str(redis_error)}')

                    running_count = ScanRequest.objects.filter(
                        Q(status='pending') | Q(status='running')
                    ).count()

                    if running_count >= settings.MAX_CONCURRENT_SCANS:
                        logger.warning(f'Concurrent scan limit reached (DB): {running_count}/{settings.MAX_CONCURRENT_SCANS}')
                        return Response({
                            'error': '동시 스캔 제한을 초과했습니다',
                            'message': f'현재 {running_count}개의 스캔이 실행 중입니다. 잠시 후 다시 시도해주세요.',
                            'current_scans': running_count,
                            'max_allowed': settings.MAX_CONCURRENT_SCANS
                        }, status=status.HTTP_429_TOO_MANY_REQUESTS)

                    logger.info(f'Concurrent scans (DB): {running_count}/{settings.MAX_CONCURRENT_SCANS}')

            # 스캔 요청 생성
            scan_request = ScanRequest.objects.create(
                url=url,
                target_domain=target_domain,
                scan_types=scan_types,
                deep_scan=deep_scan,
                ip_address=ip_address,
                user_agent=user_agent,
                status='pending'
            )

            logger.info(f'Scan request created: {scan_request.id} for {url}')

            # Celery 태스크 호출 (Redis 있을 경우)
            # Redis 없으면 동기 실행으로 폴백
            try:
                from scanner.tasks import scan_website
                task = scan_website.delay(str(scan_request.id))
                scan_request.task_id = task.id
                scan_request.save()

                # Redis에 실행 중인 스캔 추가 (동시성 제어용)
                if settings.MAX_CONCURRENT_SCANS > 0:
                    try:
                        import redis
                        redis_client = redis.Redis.from_url(settings.CELERY_BROKER_URL)
                        running_scans_key = 'weak:running_scans'
                        redis_client.sadd(running_scans_key, str(scan_request.id))
                        redis_client.expire(running_scans_key, 7200)  # 2시간 자동 만료
                        logger.info(f'Added scan {scan_request.id} to running scans set')
                    except Exception as redis_add_error:
                        logger.warning(f'Failed to add scan to Redis: {str(redis_add_error)}')

                logger.info(f'Async scan started with Celery: {scan_request.id}')
                message = 'Scan started (async)'

            except Exception as celery_error:
                # Redis/Celery 연결 실패 시 백그라운드 스레드로 실행
                logger.warning(f'Celery unavailable, running in background thread: {str(celery_error)}')

                # 백그라운드 스레드에서 실행
                import threading
                from scanner.tasks import scan_website_sync

                def run_scan_in_background(scan_id):
                    try:
                        # 동기 버전 직접 호출 (Celery 우회)
                        scan_website_sync(scan_id)
                    except Exception as scan_error:
                        logger.error(f'Background scan failed: {str(scan_error)}')
                        # 실패 시 DB 업데이트
                        try:
                            scan_obj = ScanRequest.objects.get(id=scan_id)
                            scan_obj.status = 'failed'
                            scan_obj.error_message = str(scan_error)
                            scan_obj.save()
                        except:
                            pass

                # 스레드 시작
                thread = threading.Thread(target=run_scan_in_background, args=(str(scan_request.id),))
                thread.daemon = True
                thread.start()

                # Redis에 실행 중인 스캔 추가 (동시성 제어용) - DB fallback 시에도 추가
                if settings.MAX_CONCURRENT_SCANS > 0:
                    try:
                        import redis
                        redis_client = redis.Redis.from_url(settings.CELERY_BROKER_URL)
                        running_scans_key = 'weak:running_scans'
                        redis_client.sadd(running_scans_key, str(scan_request.id))
                        redis_client.expire(running_scans_key, 7200)  # 2시간 자동 만료
                        logger.info(f'Added scan {scan_request.id} to running scans set (background mode)')
                    except Exception as redis_add_error:
                        # Redis 없으면 DB 상태로만 관리
                        logger.warning(f'Failed to add scan to Redis (background mode): {str(redis_add_error)}')

                # 상태를 running으로 변경
                scan_request.status = 'running'
                scan_request.save()

                message = 'Scan started (background thread)'

            # 응답 반환
            return Response({
                'scan_id': scan_request.id,
                'status': scan_request.status,
                'url': scan_request.url,
                'message': message
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f'Failed to create scan request: {str(e)}')
            return Response(
                {'error': 'Failed to create scan request', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['get'], url_path='status')
    def scan_status(self, request, pk=None):
        """
        스캔 상태 조회
        GET /api/scan/{scan_id}/status/
        """
        scan_request = self.get_object()

        return Response({
            'scan_id': scan_request.id,
            'status': scan_request.status,
            'progress': scan_request.progress,
            'created_at': scan_request.created_at,
            'started_at': scan_request.started_at,
            'completed_at': scan_request.completed_at,
            'error_message': scan_request.error_message,
            'duration': scan_request.duration()
        })

    @action(detail=True, methods=['get'], url_path='results')
    def scan_results(self, request, pk=None):
        """
        전체 스캔 결과 조회
        GET /api/scan/{scan_id}/results/
        """
        scan_request = self.get_object()

        if scan_request.status not in ['completed', 'failed']:
            return Response({
                'error': 'Scan not completed',
                'status': scan_request.status,
                'progress': scan_request.progress
            }, status=status.HTTP_202_ACCEPTED)

        serializer = ScanResultSerializer(scan_request)
        return Response(serializer.data)

    @action(detail=True, methods=['get'], url_path='security')
    def security_results(self, request, pk=None):
        """
        보안 스캔 결과 조회
        GET /api/scan/{scan_id}/security/
        """
        scan_request = self.get_object()

        if scan_request.status != 'completed':
            return Response({
                'error': 'Scan not completed'
            }, status=status.HTTP_202_ACCEPTED)

        try:
            security_result = scan_request.security_result
            serializer = SecurityScanResultSerializer(security_result)
            data = serializer.data

            # ScannerConfiguration에 따른 결과 필터링
            from scanner.models import ScannerConfiguration
            display_configs = ScannerConfiguration.objects.filter(
                category='security'
            ).order_by('display_order', 'scanner_id')

            filtered_data = data.copy()

            # 각 스캐너별로 표시 설정 적용
            for config in display_configs:
                field_name = self._get_field_name_for_scanner(config.scanner_id)

                if field_name and field_name in data:
                    # 결과 표시 여부 확인
                    if not config.show_in_results:
                        # 숨김 처리
                        filtered_data.pop(field_name, None)
                    elif field_name in filtered_data:
                        result = filtered_data[field_name]

                        # 결과가 dict이고 status가 있는 경우
                        if isinstance(result, dict) and 'status' in result:
                            # 통과/실패별 표시 설정 적용
                            if result['status'] == 'pass' and not config.show_if_passed:
                                filtered_data.pop(field_name, None)
                            elif result['status'] == 'fail' and not config.show_if_failed:
                                filtered_data.pop(field_name, None)
                            elif not config.show_details and field_name in filtered_data:
                                # 상세 정보 숨기기
                                filtered_data[field_name] = {
                                    'status': result.get('status'),
                                    'message': config.custom_pass_message if result.get('status') == 'pass' else config.custom_fail_message
                                }

            return Response(filtered_data)
        except SecurityScanResult.DoesNotExist:
            return Response({
                'error': 'Security scan results not found'
            }, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=['get'], url_path='standards')
    def standards_results(self, request, pk=None):
        """
        웹 표준 결과 조회
        GET /api/scan/{scan_id}/standards/
        """
        scan_request = self.get_object()

        if scan_request.status != 'completed':
            return Response({
                'error': 'Scan not completed'
            }, status=status.HTTP_202_ACCEPTED)

        try:
            standards_result = scan_request.standards_result
            serializer = WebStandardsResultSerializer(standards_result)
            return Response(serializer.data)
        except WebStandardsResult.DoesNotExist:
            return Response({
                'error': 'Web standards results not found'
            }, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=['get'], url_path='accessibility')
    def accessibility_results(self, request, pk=None):
        """
        접근성 결과 조회
        GET /api/scan/{scan_id}/accessibility/
        """
        scan_request = self.get_object()

        if scan_request.status != 'completed':
            return Response({
                'error': 'Scan not completed'
            }, status=status.HTTP_202_ACCEPTED)

        try:
            accessibility_result = scan_request.accessibility_result
            serializer = AccessibilityResultSerializer(accessibility_result)
            return Response(serializer.data)
        except AccessibilityResult.DoesNotExist:
            return Response({
                'error': 'Accessibility results not found'
            }, status=status.HTTP_404_NOT_FOUND)

    @action(detail=True, methods=['get'], url_path='vulnerabilities')
    def vulnerabilities(self, request, pk=None):
        """
        취약점 목록 조회
        GET /api/scan/{scan_id}/vulnerabilities/
        """
        scan_request = self.get_object()
        vulnerabilities = scan_request.vulnerabilities.all()

        # 필터링 옵션
        severity = request.query_params.get('severity')
        category = request.query_params.get('category')

        if severity:
            vulnerabilities = vulnerabilities.filter(severity=severity)
        if category:
            vulnerabilities = vulnerabilities.filter(category=category)

        serializer = VulnerabilitySerializer(vulnerabilities, many=True)
        return Response(serializer.data)


class HealthCheckView(viewsets.ViewSet):
    """헬스 체크 ViewSet"""

    permission_classes = [AllowAny]

    @action(detail=False, methods=['get'], url_path='')
    def health(self, request):
        """
        헬스 체크
        GET /api/health/
        """
        return Response({
            'status': 'healthy',
            'service': 'Weak Scanner API',
            'timestamp': timezone.now()
        })
