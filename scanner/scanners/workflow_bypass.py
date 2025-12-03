"""
WorkflowBypassScanner - workflow_bypass 스캐너

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


class WorkflowBypassScanner(BaseScanner):
    """워크플로우 우회 취약점 스캐너

    OWASP Top 10 2025 A06: Insecure Design 대응
    - 단계 건너뛰기 탐지
    - 상태 변조 테스트
    """
    # 스캐너 메타데이터
    metadata = {
        'id': 'workflow_bypass',
        'name': '워크플로우 우회 검사',
        'icon': '🔀',
        'description': '워크플로우 우회 검사',
        'weight': 1.5,
        'field': 'workflow_bypass_vulnerabilities',
        'category': 'business_logic',
        'enabled': True
    }

    # 워크플로우 관련 파라미터
    WORKFLOW_PARAMS = [
        'step', 'stage', 'status', 'state', 'phase',
        'level', 'progress', 'completed'
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
        # 검사 항목: 워크플로우 파라미터, 숨겨진 상태 필드
        self.checked = 2

        # 1. 워크플로우 파라미터 탐지
        self._check_workflow_parameters()

        # 2. 숨겨진 상태 필드 탐지
        if self.html_content:
            self._check_hidden_state_fields()

        # 결과 요약
        if self.vulnerabilities:
            high_count = len([v for v in self.vulnerabilities if v.get('severity') == 'high'])
            self._add_detail(
                id='workflow_bypass_check',
                name='워크플로우 우회 검사',
                status='fail',
                severity='high' if high_count > 0 else 'medium',
                description=f'{len(self.vulnerabilities)}개의 워크플로우 우회 취약점 발견',
                value=f'High: {high_count}개',
                expected='워크플로우 우회 취약점 없음',
                recommendation='워크플로우 상태는 서버 세션에서 관리하세요.'
            )
        else:
            self._add_detail(
                id='workflow_bypass_check',
                name='워크플로우 우회 검사',
                status='pass',
                severity='info',
                description='워크플로우 우회 취약점이 발견되지 않음',
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
            'has_workflow_bypass': len(self.vulnerabilities) > 0
        }

    def _check_workflow_parameters(self) -> None:
        """URL 파라미터에서 워크플로우 관련 항목 검사"""
        if not self.url:
            return

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        for param_name in params.keys():
            if any(wf in param_name.lower() for wf in self.WORKFLOW_PARAMS):
                self.vulnerabilities.append({
                    'type': 'Workflow Parameter Exposure',
                    'severity': 'high',
                    'description': f'워크플로우 상태 파라미터({param_name})가 노출되어 단계 건너뛰기가 가능할 수 있습니다.',
                    'recommendation': '워크플로우 상태는 서버 세션에서 관리하고, 각 단계마다 권한과 전제 조건을 검증하세요.'
                })

    def _check_hidden_state_fields(self) -> None:
        """숨겨진 상태 필드 검사"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        for form in soup.find_all('form'):
            for input_tag in form.find_all('input', type='hidden'):
                input_name = input_tag.get('name', '').lower()

                if any(wf in input_name for wf in self.WORKFLOW_PARAMS):
                    self.vulnerabilities.append({
                        'type': 'Hidden Workflow Field',
                        'severity': 'high',
                        'description': f'숨겨진 워크플로우 필드({input_name})가 발견되어 클라이언트에서 변조 가능합니다.',
                        'recommendation': '상태 정보는 서버 세션에 저장하고, 각 단계 전환 시 검증하세요.'
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
            '워크플로우 상태는 서버 세션이나 데이터베이스에서만 관리하세요.',
            '각 단계 전환 시 이전 단계의 완료 여부를 서버에서 검증하세요.',
            '클라이언트에서 전송된 상태 값을 절대 신뢰하지 마세요.',
            '상태 기계(State Machine) 패턴을 사용하여 허용된 전환만 가능하도록 하세요.'
        ]


    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

