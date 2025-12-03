"""가격 조작 취약점 스캐너"""

import re
import logging
from typing import Dict, Any
from scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class PriceManipulationScanner(BaseScanner):
    """가격 조작 취약점 스캐너"""

    metadata = {
        'id': 'price_manipulation',
        'name': '가격 조작',
        'icon': '💰',
        'description': '가격/수량 조작 취약점 검사',
        'weight': 1,
        'field': 'price_manipulation',
        'category': 'business_logic',
        'severity': 'high'
    }

    def __init__(self, url=None, html_content=None, **kwargs):
        """스캐너 초기화"""
        super().__init__(url=url or '', html_content=html_content, **kwargs)
        self.url = url or ''
        self.html_content = html_content or ''

    def _execute_scan(self) -> None:
        """가격 조작 취약점 스캔"""
        # 검사 항목: URL 파라미터, hidden 필드, 음수 값
        self.checked = 3

        # HTTP 요청 수행
        if not self.html_content and self.url:
            try:
                import requests
                response = requests.get(self.url, timeout=5)
                self.html_content = response.text
            except:
                pass

        # URL에 price/quantity 파라미터 체크
        if self.url:
            price_params = ['price=', 'amount=', 'total=', 'cost=']
            for param in price_params:
                if param in self.url:
                    self.vulnerabilities.append({
                        'type': 'Price Parameter Exposure',
                        'severity': 'high',
                        'description': f'Price parameter exposed in URL: {param}'
                    })
                    break

        # HTML에서 hidden price 필드 체크
        if self.html_content:
            if 'type="hidden"' in self.html_content and 'price' in self.html_content:
                self.vulnerabilities.append({
                    'type': 'Hidden Price Field',
                    'severity': 'medium',
                    'description': 'Hidden price field detected'
                })

            # 음수 값 체크
            if re.search(r'value=["\']?-\d+', self.html_content):
                self.vulnerabilities.append({
                    'type': 'Negative Value',
                    'severity': 'critical',
                    'description': 'Negative value accepted'
                })

        # HTTP 클라이언트를 통한 음수 값 테스트
        if self.url and hasattr(self, 'http_client') and self.http_client:
            # quantity 파라미터가 있으면 음수 값 테스트
            if 'quantity=' in self.url:
                try:
                    test_url = self.url.replace('quantity=1', 'quantity=-1')
                    response = self.http_client.get(test_url)
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            'type': 'Negative Value Accepted',
                            'severity': 'critical',
                            'description': 'Server accepts negative quantity values'
                        })
                except:
                    pass

        # 결과 요약
        if self.vulnerabilities:
            critical_count = len([v for v in self.vulnerabilities if v.get('severity') == 'critical'])
            self._add_detail(
                id='price_manipulation_check',
                name='가격 조작 취약점 검사',
                status='fail',
                severity='critical' if critical_count > 0 else 'high',
                description=f'{len(self.vulnerabilities)}개의 가격 조작 취약점 발견',
                value=f'Critical: {critical_count}개',
                expected='가격 조작 취약점 없음',
                recommendation='서버 측에서 가격과 수량을 검증하세요.'
            )
        else:
            self._add_detail(
                id='price_manipulation_check',
                name='가격 조작 취약점 검사',
                status='pass',
                severity='info',
                description='가격 조작 취약점이 발견되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_price_manipulation': len(self.vulnerabilities) > 0
        }

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

