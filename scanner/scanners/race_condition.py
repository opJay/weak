"""
RaceConditionScanner - race_condition 스캐너

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


class RaceConditionScanner(BaseScanner):
    """레이스 컨디션 취약점 스캐너

    OWASP Top 10 2025 A06: Insecure Design 대응
    - 동시 요청 처리 테스트
    - TOCTOU 취약점 탐지
    """
    # 스캐너 메타데이터
    metadata = {
        'id': 'race_condition',
        'name': '경쟁 상태 검사',
        'icon': '🏁',
        'description': '경쟁 상태 검사',
        'weight': 2,
        'field': 'race_condition_vulnerabilities',
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
        # 검사 항목: 동시 요청, 상태 변경 엔드포인트
        self.checked = 2

        # HTTP 요청 수행 (html_content가 없는 경우)
        if not self.html_content and self.url:
            try:
                import requests
                response = requests.get(self.url, timeout=5)
                self.html_content = response.text
                if hasattr(self, 'response'):
                    self.response = response
            except Exception as e:
                logger.debug(f"HTTP request failed: {e}")
                pass

        # 1. 동시 요청 테스트
        self._test_concurrent_requests()

        # 2. 상태 변경 엔드포인트 탐지
        if self.html_content:
            self._detect_state_changing_endpoints()

        # 결과 요약
        if self.vulnerabilities:
            high_count = len([v for v in self.vulnerabilities if v.get('severity') in ['critical', 'high', 'medium']])
            self._add_detail(
                id='race_condition_check',
                name='경쟁 상태 검사',
                status='fail',
                severity='medium' if high_count > 0 else 'low',
                description=f'{len(self.vulnerabilities)}개의 경쟁 상태 취약점 발견',
                value=f'발견: {len(self.vulnerabilities)}개',
                expected='경쟁 상태 취약점 없음',
                recommendation='트랜잭션 격리 수준을 설정하고, 멱등성 키를 사용하세요.'
            )
        else:
            self._add_detail(
                id='race_condition_check',
                name='경쟁 상태 검사',
                status='pass',
                severity='info',
                description='경쟁 상태 취약점이 발견되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )
    def _build_result(self) -> Dict[str, Any]:
        """결과 구성"""
        return {
            'vulnerabilities': self.vulnerabilities,
            'total': len(self.vulnerabilities),
            'severity': self._calculate_severity(),
            'recommendations': self._get_recommendations(),
            'has_race_condition': len(self.vulnerabilities) > 0
        }

    def _test_concurrent_requests(self) -> None:
        """동시 요청 테스트"""
        if not self.url or not self.http_client:
            return

        try:
            # 5개의 동시 요청
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [
                    executor.submit(self._make_request)
                    for _ in range(5)
                ]
                responses = [
                    f.result()
                    for f in concurrent.futures.as_completed(futures)
                ]

            # 응답 상태 코드 분석
            status_codes = [r.status_code for r in responses if r]

            # 모두 성공하면 동시성 제어 부재 가능성
            if all(code == 200 for code in status_codes) and len(status_codes) == 5:
                self.vulnerabilities.append({
                    'type': 'No Concurrency Control',
                    'severity': 'medium',
                    'description': '5개의 동시 요청이 모두 성공적으로 처리되어 레이스 컨디션 취약점이 있을 수 있습니다.',
                    'recommendation': '트랜잭션 격리 수준을 설정하고, 낙관적/비관적 잠금을 사용하세요.'
                })

        except Exception as e:
            logger.debug(f'Concurrent request test failed: {e}')

    def _make_request(self):
        """단일 요청 수행"""
        try:
            return self.http_client.get(self.url, timeout=3)
        except:
            return None

    def _detect_state_changing_endpoints(self) -> None:
        """상태 변경 엔드포인트 탐지"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        # POST 폼 찾기
        post_forms = soup.find_all('form', method=lambda x: x and 'post' in x.lower())

        if len(post_forms) > 0:
            self.vulnerabilities.append({
                'type': 'State Changing Forms',
                'severity': 'low',
                'description': f'{len(post_forms)}개의 POST 폼이 발견되었습니다. 레이스 컨디션 테스트가 필요할 수 있습니다.',
                'recommendation': '중요한 작업에는 멱등성 키(Idempotency Key)를 사용하세요.'
            })

    def _calculate_severity(self) -> str:
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        severities = [v.get('severity', 'low') for v in self.vulnerabilities]
        if 'critical' in severities or 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        else:
            return 'low'

    def _get_recommendations(self) -> List[str]:
        """보안 권장사항"""
        return [
            '데이터베이스 트랜잭션 격리 수준을 적절히 설정하세요 (SERIALIZABLE 권장).',
            '중요한 작업에는 낙관적 잠금(Optimistic Locking)이나 비관적 잠금을 사용하세요.',
            '멱등성 키(Idempotency Key)를 사용하여 중복 요청을 방지하세요.',
            '재고 차감 등의 critical section에는 분산 잠금(Redis, Zookeeper)을 고려하세요.'
        ]


    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

