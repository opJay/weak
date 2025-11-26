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
            return Response(serializer.data)
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
