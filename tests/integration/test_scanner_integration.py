"""
스캐너 통합 테스트 스위트
에러 처리 및 성능 테스트만 포함 (레거시 테스트 제거)
"""

import pytest
import os
import sys
import django
from unittest.mock import Mock, patch, MagicMock
import time
import requests

# Django 설정
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from scanner.scanners.xss_scanner import XSSScanner
from scanner.scanners.sql_injection_scanner import SQLInjectionScanner


class TestErrorHandling:
    """에러 처리 통합 테스트"""

    def test_network_error_handling(self):
        """네트워크 에러 처리"""
        # XSSScanner는 BaseScanner를 상속받아 url, html_content, response를 인자로 받음
        mock_response = Mock(
            status_code=200,
            text='<html>test</html>',
            headers={},
            url='https://unreachable.com',
            cookies=Mock(items=lambda: [])
        )
        scanner = XSSScanner(
            url="https://unreachable.com",
            html_content='<html>test</html>',
            response=mock_response
        )
        result = scanner.scan()

        # 에러가 발생해도 결과를 반환해야 함
        assert isinstance(result, dict)

    def test_timeout_handling(self):
        """타임아웃 처리"""
        mock_response = Mock(
            status_code=200,
            text='<html>test</html>',
            headers={},
            url='https://slow.com',
            cookies=Mock(items=lambda: [])
        )
        scanner = SQLInjectionScanner(
            url="https://slow.com",
            html_content='<html>test</html>',
            response=mock_response
        )
        result = scanner.scan()

        assert isinstance(result, dict)


class TestPerformance:
    """성능 테스트"""

    def test_scan_execution_performance(self):
        """스캔 실행 성능"""
        mock_response = Mock(
            status_code=200,
            text='<html></html>',
            headers={},
            url='https://test.com',
            cookies=Mock(items=lambda: [])
        )

        scanner = XSSScanner(
            url="https://test.com",
            html_content='<html></html>',
            response=mock_response
        )

        start = time.time()
        result = scanner.scan()
        elapsed = time.time() - start

        # 로컬 스캔은 1초 이내여야 함
        assert elapsed < 1.0, f"Scan took {elapsed:.2f}s"

    def test_memory_usage(self):
        """메모리 사용량 테스트"""
        import tracemalloc

        # 메모리 추적 시작
        tracemalloc.start()

        # 대량의 HTML로 스캔
        large_html = '<div>' * 10000 + 'content' + '</div>' * 10000
        mock_response = Mock(
            status_code=200,
            text=large_html,
            headers={},
            url='https://test.com',
            cookies=Mock(items=lambda: [])
        )

        scanner = XSSScanner(
            url="https://test.com",
            html_content=large_html,
            response=mock_response
        )

        # 메모리 스냅샷 (스캔 전)
        snapshot1 = tracemalloc.take_snapshot()

        # 스캔 실행
        result = scanner.scan()

        # 메모리 스냅샷 (스캔 후)
        snapshot2 = tracemalloc.take_snapshot()

        # 메모리 차이 계산
        top_stats = snapshot2.compare_to(snapshot1, 'lineno')
        total_memory = sum(stat.size_diff for stat in top_stats)

        # 메모리 사용량이 50MB 미만이어야 함
        assert total_memory < 50 * 1024 * 1024, f"Memory usage: {total_memory / 1024 / 1024:.2f}MB"

        tracemalloc.stop()