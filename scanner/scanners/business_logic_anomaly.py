"""
BusinessLogicAnomalyScanner - business_logic_anomaly 스캐너

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


class BusinessLogicAnomalyScanner(BaseScanner):
    """비즈니스 로직 이상 탐지 스캐너

    OWASP Top 10 2025 A06: Insecure Design 대응
    - 할인/쿠폰 중복 적용
    - 비정상적인 비즈니스 플로우
    """
    # 스캐너 메타데이터
    metadata = {
        'id': 'business_logic_anomaly',
        'name': '비즈니스 로직 이상 검사',
        'icon': '🔍',
        'description': '비즈니스 로직 이상 검사',
        'weight': 1.5,
        'field': 'business_logic_anomalies',
        'category': 'business_logic',
        'enabled': True
    }

    # 비즈니스 로직 관련 파라미터
    LOGIC_PARAMS = [
        'discount', 'coupon', 'voucher', 'promo', 'code',
        'points', 'credit', 'balance', 'refund'
    ]

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
        # 검사 항목: 할인 파라미터, 비즈니스 로직 필드
        self.checked = 2

        # 1. 할인 관련 파라미터 탐지
        self._check_discount_parameters()

        # 2. 폼에서 비즈니스 로직 필드 탐지
        if self.html_content:
            self._check_business_logic_fields()

        # 결과 요약
        if self.vulnerabilities:
            high_count = len([v for v in self.vulnerabilities if v.get('severity') == 'high'])
            self._add_detail(
                id='business_logic_check',
                name='비즈니스 로직 이상 검사',
                status='fail',
                severity='high' if high_count > 0 else 'medium',
                description=f'{len(self.vulnerabilities)}개의 비즈니스 로직 취약점 발견',
                value=f'High: {high_count}개',
                expected='비즈니스 로직 취약점 없음',
                recommendation='할인 로직은 서버에서만 처리하고, 중복 적용을 방지하세요.'
            )
        else:
            self._add_detail(
                id='business_logic_check',
                name='비즈니스 로직 이상 검사',
                status='pass',
                severity='info',
                description='비즈니스 로직 취약점이 발견되지 않음',
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
            'has_logic_anomaly': len(self.vulnerabilities) > 0
        }

    def _check_discount_parameters(self) -> None:
        """할인 관련 파라미터 검사"""
        if not self.url:
            return

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        for param_name in params.keys():
            if any(logic in param_name.lower() for logic in self.LOGIC_PARAMS):
                self.vulnerabilities.append({
                    'type': 'Discount Parameter Exposure',
                    'severity': 'high',
                    'description': f'URL에 할인 관련 파라미터({param_name})가 노출되어 중복 적용이나 조작이 가능할 수 있습니다.',
                    'recommendation': '할인 로직은 서버에서만 처리하고, 중복 적용을 방지하세요.'
                })

    def _check_business_logic_fields(self) -> None:
        """비즈니스 로직 필드 검사"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        for form in soup.find_all('form'):
            for input_tag in form.find_all('input'):
                input_name = input_tag.get('name', '').lower()
                input_type = input_tag.get('type', '').lower()

                # 숨겨진 비즈니스 로직 필드
                if input_type == 'hidden' and any(l in input_name for l in self.LOGIC_PARAMS):
                    self.vulnerabilities.append({
                        'type': 'Hidden Business Logic Field',
                        'severity': 'medium',
                        'description': f'숨겨진 비즈니스 로직 필드({input_name})가 발견되어 클라이언트에서 변조 가능합니다.',
                        'recommendation': '할인, 포인트, 쿠폰 정보는 서버 세션에서 관리하고 검증하세요.'
                    })

    def _calculate_severity(self) -> str:
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        if any(v.get('severity') == 'high' for v in self.vulnerabilities):
            return 'high'
        else:
            return 'medium'

    def _get_recommendations(self) -> List[str]:
        """보안 권장사항"""
        return [
            '할인과 쿠폰은 한 번만 적용되도록 서버에서 검증하세요.',
            '포인트 적립 및 차감은 트랜잭션으로 처리하세요.',
            '환불 프로세스는 원래 결제 금액을 초과할 수 없도록 제한하세요.',
            '비정상적인 패턴(과도한 환불, 할인 등)을 모니터링하세요.',
            '비즈니스 규칙은 서버 측에서만 구현하고, 클라이언트 입력을 절대 신뢰하지 마세요.'
        ]

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata