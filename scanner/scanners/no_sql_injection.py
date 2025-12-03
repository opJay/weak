"""
NoSQLInjectionScanner - 자동 수정됨

원본: scanners_refactored_batch5.py
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

from scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class NoSQLInjectionScanner(BaseScanner):
    """NoSQL Injection 취약점 스캐너"""

    metadata = {
        'id': 'nosql_injection',
        'name': 'NoSQL Injection 스캔',
        'icon': '🗄️',
        'description': 'NoSQL 데이터베이스 주입 취약점 탐지',
        'weight': 2,
        'field': 'nosql_injection',
        'category': 'security_advanced',
        'OWASP': 'A04:2025'
    }

    NOSQL_INDICATORS = [
        'mongodb', 'mongo', 'couchdb', 'redis', 'cassandra',
        'dynamodb', 'elasticsearch', 'firebase'
    ]

    NOSQL_PARAMS = [
        'id', '_id', 'user', 'username', 'email', 'search', 'query',
        'filter', 'where', 'find', 'match', 'selector'
    ]

    def __init__(self, url: str = '', response: requests.Response = None,
                 html_content: str = None, **kwargs):
        """NoSQLInjectionScanner 초기화"""
        super().__init__(url=url, **kwargs)
        self.response = response
        self.html_content = html_content or ''
        self.vulnerabilities = []
        self.uses_nosql = False

    def _execute_scan(self) -> None:
        """NoSQL Injection 스캔 실행"""
        try:
            # 1. NoSQL 데이터베이스 사용 탐지
            self._detect_nosql()

            # 2. URL 파라미터 검사
            if self.uses_nosql and self.url:
                self._scan_url_parameters()

            # 3. JSON 입력 검사
            if self.uses_nosql and self.response:
                self._scan_json_inputs()

        except Exception as e:
            logger.error(f"NoSQL injection scan error: {str(e)}")

    def _detect_nosql(self) -> None:
        """NoSQL 데이터베이스 사용 탐지"""
        try:
            # 응답 헤더나 HTML에서 NoSQL 관련 키워드 찾기
            content_lower = self.html_content.lower()
            if self.response:
                content_lower += str(self.response.headers).lower()

            for indicator in self.NOSQL_INDICATORS:
                if indicator in content_lower:
                    self.uses_nosql = True
                    break

        except Exception as e:
            logger.debug(f"NoSQL detection error: {str(e)}")

    def _scan_url_parameters(self) -> None:
        """URL 파라미터에서 NoSQL Injection 검사"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param_name, param_values in params.items():
                if param_name.lower() in self.NOSQL_PARAMS:
                    param_value = param_values[0] if param_values else ''

                    # JSON 형식이면 더 위험
                    is_json = param_value.startswith(('{', '['))

                    self.vulnerabilities.append({
                        'type': 'NoSQL Injection (Potential)',
                        'severity': 'critical' if is_json else 'high',
                        'parameter': param_name,
                        'value_type': 'JSON' if is_json else 'string',
                        'description': f'파라미터 "{param_name}"가 NoSQL Injection에 취약할 수 있습니다.',
                        'attack_examples': [
                            '{"$ne": null}',
                            '{"$gt": ""}',
                            '{"username": {"$regex": "^admin"}}',
                            '[$ne]=1',
                        ],
                        'recommendation': '입력값을 타입 체크하고, $where, $regex 등 위험한 연산자를 차단하세요.'
                    })

        except Exception as e:
            logger.debug(f"NoSQL URL parameter scan error: {str(e)}")

    def _scan_json_inputs(self) -> None:
        """JSON 입력 필드 검사"""
        try:
            # Content-Type이 JSON이면
            content_type = self.response.headers.get('Content-Type', '')

            if 'application/json' in content_type:
                self.vulnerabilities.append({
                    'type': 'NoSQL JSON API',
                    'severity': 'medium',
                    'description': 'API가 JSON을 받습니다. NoSQL Injection에 주의해야 합니다.',
                    'recommendation': '모든 JSON 입력을 검증하고, MongoDB 연산자($ne, $gt 등)를 필터링하세요.'
                })

        except Exception as e:
            logger.debug(f"NoSQL JSON input scan error: {str(e)}")

    def _build_result(self) -> Dict[str, Any]:
        """스캔 결과 빌드"""
        result = super()._build_result()
        result.update({
            'vulnerabilities': self.vulnerabilities,
            'total': len(self.vulnerabilities),
            'has_nosql_injection': len(self.vulnerabilities) > 0,
            'uses_nosql': self.uses_nosql,
            'scanner_id': self.metadata['id']
        })
        return result



    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

