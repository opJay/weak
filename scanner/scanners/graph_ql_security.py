"""
GraphQLSecurityScanner - 자동 수정됨

원본: scanners_refactored_batch6.py
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


class GraphQLSecurityScanner(BaseScanner):
    """GraphQL 보안 취약점 스캐너 - 리팩토링 버전"""

    metadata = {
        'id': 'graphql_security',
        'name': 'GraphQL 보안 검사',
        'icon': '📊',
        'description': 'GraphQL 취약점 탐지 (Introspection, Query Depth, Batch Attack)',
        'weight': 2,
        'field': 'graphql_vulnerabilities',
        'category': 'api_auth',
        'OWASP': 'A01:2025'
    }

    def __init__(self, url: str = None, response: requests.Response = None,
                 html_content: str = None, **kwargs):
        """
        Args:
            url: 스캔 대상 URL
            response: HTTP 응답 객체
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', response=response,
                        html_content=html_content, **kwargs)

    def _execute_scan(self) -> None:
        """GraphQL 보안 스캔 실행"""
        # GraphQL 사용 여부 탐지
        if not self._detect_graphql():
            self.vulnerabilities = []
            return

        # 각 보안 검사 수행
        self._check_introspection()
        self._check_query_depth()
        self._check_batch_queries()
        self._check_query_complexity()

    def _detect_graphql(self) -> bool:
        """GraphQL 사용 여부 탐지"""
        # URL에 graphql 포함
        if self.url and 'graphql' in self.url.lower():
            return True

        # HTML에서 GraphQL 패턴 찾기
        if self.html_content:
            graphql_patterns = [
                r'__typename',
                r'query\s+{',
                r'mutation\s+{',
                r'subscription\s+{',
                r'graphql',
                r'apollo'
            ]
            for pattern in graphql_patterns:
                if re.search(pattern, self.html_content, re.IGNORECASE):
                    return True

        return False

    def _check_introspection(self) -> None:
        """Introspection 활성화 검사"""
        if self.html_content and '__schema' in self.html_content:
            self.vulnerabilities.append({
                'type': 'GraphQL Introspection Enabled',
                'severity': 'medium',
                'description': 'GraphQL Introspection이 활성화되어 있어 스키마 정보가 노출됩니다.',
                'recommendation': '프로덕션 환경에서는 Introspection을 비활성화하세요.'
            })

    def _check_query_depth(self) -> None:
        """Query Depth 제한 검사"""
        if self.html_content:
            # 깊은 중첩 쿼리 패턴 찾기
            nested_pattern = r'{\s*\w+\s*{\s*\w+\s*{\s*\w+\s*{'
            if re.search(nested_pattern, self.html_content):
                self.vulnerabilities.append({
                    'type': 'Deep Query Nesting',
                    'severity': 'medium',
                    'description': '깊게 중첩된 GraphQL 쿼리가 감지되었습니다.',
                    'recommendation': 'Query Depth 제한을 구현하여 DoS 공격을 방지하세요.'
                })

    def _check_batch_queries(self) -> None:
        """Batch Query 공격 가능성 검사"""
        if self.html_content:
            # 배열 형태의 쿼리 패턴
            batch_pattern = r'\[\s*{.*?query.*?}\s*,\s*{.*?query.*?}\s*\]'
            if re.search(batch_pattern, self.html_content, re.DOTALL):
                self.vulnerabilities.append({
                    'type': 'Batch Query Attack Possible',
                    'severity': 'medium',
                    'description': 'Batch Query가 허용되어 있어 DoS 공격 위험이 있습니다.',
                    'recommendation': 'Batch Query 크기 제한을 구현하세요.'
                })

    def _check_query_complexity(self) -> None:
        """Query Complexity 제한 검사"""
        if not self.response or not hasattr(self.response, 'headers'):
            return

        # Complexity 관련 헤더 확인
        headers = self.response.headers
        if 'X-Query-Complexity' not in headers:
            self.vulnerabilities.append({
                'type': 'Missing Query Complexity Limits',
                'severity': 'low',
                'description': 'Query Complexity 제한이 설정되지 않았습니다.',
                'recommendation': 'Query Complexity 분석 및 제한을 구현하세요.'
            })



    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

