"""
TemplateInjectionScanner - template_injection 스캐너

원본: scanners_refactored_batch5.py
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


class TemplateInjectionScanner(BaseScanner):
    """SSTI (Server-Side Template Injection) 취약점 스캐너"""
    # 스캐너 메타데이터
    metadata = {
        'id': 'template_injection',
        'name': '템플릿 주입 스캔',
        'icon': '📃',
        'description': '템플릿 주입 스캔',
        'weight': 2,
        'field': 'template_injection',
        'category': 'security_advanced',
        'enabled': True
    }

    TEMPLATE_INDICATORS = [
        # Jinja2
        ('{{', '}}', 'Jinja2/Flask', 'high'),
        ('{%', '%}', 'Jinja2/Django', 'high'),

        # Other templates
        ('${', '}', 'Freemarker/Velocity', 'high'),
        ('#{', '}', 'JSF/EL', 'medium'),
        ('<%', '%>', 'JSP/ERB', 'high'),
    ]

    SSTI_PARAMS = [
        'template', 'tmpl', 'view', 'layout', 'page', 'content',
        'text', 'body', 'message', 'name', 'title'
    ]

    def __init__(self, url: str = '', html_content: str = None, **kwargs):
        """TemplateInjectionScanner 초기화"""
        super().__init__(url=url, **kwargs)
        self.html_content = html_content or ''
        self.vulnerabilities = []

    def _execute_scan(self) -> None:
        """SSTI 스캔 실행"""
        # 검사 항목: 템플릿 구문, URL 파라미터
        self.checked = 2

        try:
            # 1. HTML에서 템플릿 구문 탐지
            if self.html_content:
                self._detect_template_syntax()

            # 2. URL 파라미터에서 SSTI 가능성
            if self.url:
                self._scan_url_parameters()

        except Exception as e:
            logger.error(f"Template injection scan error: {str(e)}")

        # 결과 요약
        if self.vulnerabilities:
            critical_count = len([v for v in self.vulnerabilities if v.get('severity') == 'critical'])
            self._add_detail(
                id='template_injection_check',
                name='템플릿 주입 취약점 검사',
                status='fail',
                severity='critical' if critical_count > 0 else 'high',
                description=f'{len(self.vulnerabilities)}개의 템플릿 주입 취약점 발견',
                value=f'Critical: {critical_count}개',
                expected='템플릿 주입 취약점 없음',
                recommendation='사용자 입력을 템플릿으로 처리하지 말고, 데이터로만 사용하세요.'
            )
        else:
            self._add_detail(
                id='template_injection_check',
                name='템플릿 주입 취약점 검사',
                status='pass',
                severity='info',
                description='템플릿 주입 취약점이 발견되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _detect_template_syntax(self) -> None:
        """템플릿 구문 탐지"""
        try:
            for open_tag, close_tag, engine, severity in self.TEMPLATE_INDICATORS:
                pattern = re.escape(open_tag) + r'.*?' + re.escape(close_tag)
                matches = re.findall(pattern, self.html_content, re.DOTALL)

                if matches:
                    self.vulnerabilities.append({
                        'type': 'Template Engine Detected',
                        'severity': severity,
                        'engine': engine,
                        'examples': matches[:3],
                        'description': f'{engine} 템플릿 엔진이 감지되었습니다. SSTI에 취약할 수 있습니다.',
                        'attack_example': f'{open_tag}7*7{close_tag}',
                        'recommendation': '사용자 입력을 템플릿으로 렌더링하지 마세요. 샌드박스를 활성화하세요.'
                    })

        except Exception as e:
            logger.debug(f"Template syntax detection error: {str(e)}")

    def _scan_url_parameters(self) -> None:
        """URL 파라미터에서 SSTI 검사"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param_name in params.keys():
                if param_name.lower() in self.SSTI_PARAMS:
                    self.vulnerabilities.append({
                        'type': 'SSTI (Potential)',
                        'severity': 'critical',
                        'parameter': param_name,
                        'description': f'파라미터 "{param_name}"가 템플릿 주입에 취약할 수 있습니다.',
                        'attack_examples': [
                            '{{7*7}}',
                            '{{config}}',
                            '{{self.__dict__}}',
                            "${7*7}",
                        ],
                        'recommendation': '사용자 입력을 템플릿으로 처리하지 말고, 데이터로만 사용하세요.'
                    })

        except Exception as e:
            logger.debug(f"SSTI URL parameter scan error: {str(e)}")

    def _build_result(self) -> Dict[str, Any]:
        """스캔 결과 빌드"""
        result = super()._build_result()
        result.update({
            'vulnerabilities': self.vulnerabilities,
            'total': len(self.vulnerabilities),
            'has_ssti': len(self.vulnerabilities) > 0,
            'scanner_id': self.metadata['id']
        })
        return result


    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

