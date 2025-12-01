from django.shortcuts import render, get_object_or_404
from django.http import Http404
from .models import ScanRequest
import logging

logger = logging.getLogger(__name__)


def index_view(request):
    """
    메인 페이지 - URL 입력 및 스캔 옵션 설정
    """
    return render(request, 'scanner/input.html')


def results_view(request, scan_id):
    """
    결과 페이지 - UUID 기반 스캔 결과 표시
    진행 중이면 로딩 화면, 완료되면 결과 표시
    """
    # scan_id 유효성 검증
    try:
        scan_request = get_object_or_404(ScanRequest, id=scan_id)

        # scan_id를 템플릿에 전달
        context = {
            'scan_id': scan_id,
            'scan_request': scan_request,
            'status': scan_request.status,
        }

        return render(request, 'scanner/results.html', context)

    except Http404:
        # 존재하지 않는 scan_id 접근 시 404 페이지
        logger.warning(f"Invalid scan_id requested: {scan_id}")
        raise Http404("스캔 결과를 찾을 수 없습니다.")
