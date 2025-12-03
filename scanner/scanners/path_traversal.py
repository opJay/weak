"""
PathTraversalScanner - path_traversal 스캐너

원본: scanners_refactored_batch4.py
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


class PathTraversalScanner(BaseScanner):
    """Path Traversal / LFI 취약점 스캐너"""
    # 스캐너 메타데이터
    metadata = {
        'id': 'path_traversal',
        'name': '경로 순회 공격 스캔',
        'icon': '📂',
        'description': '경로 순회 공격 스캔',
        'weight': 1.5,
        'field': 'path_traversal',
        'category': 'security_advanced',
        'enabled': True
    }

    PATH_PARAMS = [
        'file', 'path', 'folder', 'dir', 'directory', 'page', 'document',
        'root', 'pg', 'template', 'include', 'loc', 'location', 'doc'
    ]

    TRAVERSAL_PATTERNS = [
        '../', '..\\', '%2e%2e%2f', '%2e%2e/', '..%2f', '%2e%2e%5c'
    ]

    def __init__(self, url: str = None, **kwargs):
        """
        Args:
            url: 검사할 URL
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', **kwargs)

    def _execute_scan(self) -> None:
        """Path Traversal 취약점 검사 실행"""
        # 검사 항목: URL 파라미터, URL 경로
        self.checked = 2

        if not self.url:
            self._add_detail(
                id='path_traversal_check',
                name='경로 순회 취약점 검사',
                status='pass',
                severity='info',
                description='검사할 URL 없음',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        # 파일/경로 관련 파라미터 검사
        for param_name, param_values in params.items():
            if param_name.lower() in self.PATH_PARAMS:
                param_value = param_values[0] if param_values else ''

                # 경로 순회 패턴이 포함되어 있는지 확인
                has_traversal = any(pattern in param_value for pattern in self.TRAVERSAL_PATTERNS)

                severity = 'critical' if has_traversal else 'high'

                self.issues.append({
                    'type': 'Path Traversal (Potential)',
                    'severity': severity,
                    'parameter': param_name,
                    'value': param_value,
                    'description': f'파라미터 "{param_name}"가 경로 순회 공격에 취약할 수 있습니다.',
                    'attack_examples': [
                        '../../../etc/passwd',
                        '....//....//....//etc/passwd',
                        '..%2f..%2f..%2fetc%2fpasswd',
                        'C:\\Windows\\System32\\config\\SAM',
                    ],
                    'recommendation': '파일 경로를 화이트리스트로 제한하고, 상대 경로를 제거하세요.'
                })

        # 파라미터가 없어도 경로가 있으면 잠재적 위험
        if not self.issues and parsed.path:
            path_parts = parsed.path.split('/')
            if any(part.lower() in self.PATH_PARAMS for part in path_parts):
                self.issues.append({
                    'type': 'Path Traversal (URL Path)',
                    'severity': 'medium',
                    'path': parsed.path,
                    'description': 'URL 경로가 파일 접근에 사용될 수 있어 경로 순회에 취약할 수 있습니다.',
                    'recommendation': 'URL 기반 파일 접근 시 경로 검증을 철저히 하세요.'
                })

        # 결과 요약
        if self.issues:
            critical_count = len([i for i in self.issues if i.get('severity') == 'critical'])
            self._add_detail(
                id='path_traversal_check',
                name='경로 순회 취약점 검사',
                status='fail',
                severity='critical' if critical_count > 0 else 'high',
                description=f'{len(self.issues)}개의 경로 순회 취약점 발견',
                value=f'Critical: {critical_count}개',
                expected='경로 순회 취약점 없음',
                recommendation='파일 경로를 화이트리스트로 제한하고, 상대 경로를 제거하세요.'
            )
        else:
            self._add_detail(
                id='path_traversal_check',
                name='경로 순회 취약점 검사',
                status='pass',
                severity='info',
                description='경로 순회 취약점이 발견되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_path_traversal': len(self.issues) > 0
        }


    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

