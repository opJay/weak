"""
LoggingMonitoringScanner - logging_monitoring 스캐너

원본: scanners_refactored_batch7.py
자동 마이그레이션된 독립 스캐너 모듈
"""

import logging
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
import requests
import json
import time
import hashlib
import base64

# core 패키지에서 BaseScanner import
from scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class LoggingMonitoringScanner(BaseScanner):
    """로깅 및 모니터링 검사 스캐너

    OWASP Top 10 2025 A09: Logging & Alerting Failures 대응
    - 보안 이벤트 로깅 확인
    - 감사 추적 존재 여부
    """
    # 스캐너 메타데이터
    metadata = {
        'id': 'logging_monitoring',
        'name': '로깅/모니터링 검사',
        'icon': '📋',
        'description': '로깅/모니터링 검사',
        'weight': 1.5,
        'field': 'logging_monitoring_vulnerabilities',
        'category': 'business_logic',
        'enabled': True
    }

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None):
        """스캐너 초기화"""
        super().__init__(url=url or '', response=response,
                        html_content=html_content)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client
        self.vulnerabilities = []

    def _prepare(self) -> None:
        """스캔 준비"""
        self.vulnerabilities = []

    def _execute_scan(self) -> None:
        """실제 스캔 로직 실행"""
        # 1. 응답 헤더에서 로깅 정보 확인
        self._check_logging_headers()

        # 2. 에러 처리 분석
        self._analyze_error_handling()

        # 3. 보안 이벤트 기록 여부 추정
        self._estimate_security_logging()

    def _build_result(self) -> Dict[str, Any]:
        """결과 구성"""
        return {
            'vulnerabilities': self.vulnerabilities,
            'total': len(self.vulnerabilities),
            'severity': self._calculate_severity(),
            'recommendations': self._get_recommendations(),
            'has_logging_issues': len(self.vulnerabilities) > 0
        }

    def _check_logging_headers(self) -> None:
        """로깅 관련 헤더 확인"""
        if not self.response:
            return

        headers = self.response.headers if hasattr(self.response, 'headers') else {}

        # 추적 ID 헤더 확인
        trace_headers = ['X-Request-ID', 'X-Trace-ID', 'X-Correlation-ID']
        has_trace = any(h in headers for h in trace_headers)

        if not has_trace:
            self.vulnerabilities.append({
                'type': 'No Trace ID',
                'severity': 'medium',
                'description': '요청 추적을 위한 ID 헤더가 없어 로그 상관관계 분석이 어려울 수 있습니다.',
                'recommendation': 'X-Request-ID 또는 X-Trace-ID 헤더를 모든 응답에 포함하세요.'
            })

    def _analyze_error_handling(self) -> None:
        """에러 처리 분석"""
        if not self.url or not self.http_client:
            return

        # 인증이 필요할 만한 경로 테스트
        test_paths = ['/admin', '/api', '/dashboard']

        for path in test_paths[:1]:  # 첫 번째만 테스트
            test_url = self.url.rstrip('/') + path

            try:
                response = self.http_client.get(test_url, timeout=5)

                if response.status_code in [401, 403]:
                    self.vulnerabilities.append({
                        'type': 'Authentication Failure Detected',
                        'severity': 'low',
                        'description': f'{path} 경로에 대한 인증 실패 응답({response.status_code})이 확인되었습니다. 이러한 이벤트가 로깅되는지 확인이 필요합니다.',
                        'recommendation': '모든 인증/인가 실패를 로그에 기록하고 모니터링하세요.'
                    })
                    break
            except Exception:
                pass

    def _estimate_security_logging(self) -> None:
        """보안 이벤트 로깅 추정"""
        if self.response:
            headers = self.response.headers if hasattr(self.response, 'headers') else {}

            security_headers = [
                'Content-Security-Policy',
                'Strict-Transport-Security',
                'X-Content-Type-Options'
            ]

            has_security_headers = any(h in headers for h in security_headers)

            if not has_security_headers:
                self.vulnerabilities.append({
                    'type': 'Low Security Awareness',
                    'severity': 'medium',
                    'description': '보안 헤더가 없어 보안 이벤트 로깅도 미흡할 가능성이 있습니다.',
                    'recommendation': '보안 헤더를 설정하고, 보안 이벤트를 체계적으로 로깅하세요.'
                })

    def _calculate_severity(self) -> str:
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        if any(v.get('severity') == 'medium' for v in self.vulnerabilities):
            return 'medium'
        else:
            return 'low'

    def _get_recommendations(self) -> List[str]:
        """보안 권장사항"""
        return [
            '모든 인증/인가 실패를 로그에 기록하세요.',
            '중요한 비즈니스 이벤트(결제, 계정 변경 등)를 감사 로그에 남기세요.',
            '로그에 요청 ID를 포함하여 추적 가능하게 하세요.',
            '민감한 정보(비밀번호, 토큰)는 로그에 기록하지 마세요.',
            'SIEM 시스템과 통합하여 실시간 모니터링하세요.',
            '로그 보존 정책을 수립하고 정기적으로 검토하세요.'
        ]


    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

