"""
OpenRedirectScanner - open_redirect 스캐너

원본: scanners_refactored_batch3.py
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


class OpenRedirectScanner(BaseScanner):
    """Open Redirect 취약점 검사 스캐너 - 리팩토링 버전"""
    # 스캐너 메타데이터
    metadata = {
        'id': 'open_redirect',
        'name': '오픈 리다이렉트 검사',
        'icon': '↗️',
        'description': '오픈 리다이렉트 검사',
        'weight': 1,
        'field': 'open_redirect',
        'category': 'security_basic',
        'enabled': True
    }

    # 스캐너 메타데이터

    # 리다이렉트 관련 파라미터 이름들
    REDIRECT_PARAMS = [
        'url', 'redirect', 'redirect_url', 'next', 'return', 'returnurl',
        'redir', 'target', 'dest', 'destination', 'continue', 'goto'
    ]

    def __init__(self, url: str = None, **kwargs):
        """
        Args:
            url: 검사할 URL
            **kwargs: BaseScanner 호환 인자
        """
        # BaseScanner 초기화
        super().__init__(url=url or '', **kwargs)

    def _execute_scan(self) -> None:
        """Open Redirect 취약점 검사 실행"""
        if not self.url:
            logger.warning("No URL provided for open redirect scan")
            return

        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            # 파라미터가 없으면 종료
            if not params:
                logger.debug(f"No query parameters in URL: {self.url}")
                return

            # 리다이렉트 관련 파라미터 찾기
            found_params = []
            for param_name in params.keys():
                if param_name.lower() in self.REDIRECT_PARAMS:
                    found_params.append(param_name)

            # 취약한 파라미터 발견 시 이슈 추가
            if found_params:
                self.issues.append({
                    'type': 'Potential Open Redirect',
                    'severity': 'medium',
                    'parameters': found_params,
                    'description': f'Open Redirect에 취약할 수 있는 파라미터 발견: {", ".join(found_params)}',
                    'evidence': f'URL: {self.url}',
                    'recommendation': '리다이렉트 URL을 화이트리스트로 검증하세요.'
                })

                # 파라미터 값이 URL 형태인지 추가 확인 (선택적)
                for param_name in found_params:
                    for value in params[param_name]:
                        # URL 패턴 체크 (http://, https://, //, ./ 등)
                        if self._is_url_like(value):
                            self.issues.append({
                                'type': 'Open Redirect with URL Value',
                                'severity': 'high',
                                'parameter': param_name,
                                'value': value[:100],  # 처음 100자만
                                'description': f'파라미터 "{param_name}"에 URL 값이 포함되어 있습니다.',
                                'recommendation': '외부 URL로의 리다이렉트를 차단하거나 화이트리스트를 사용하세요.'
                            })

        except Exception as e:
            logger.error(f"Error during open redirect scan: {str(e)}")
            # BaseScanner가 예외 처리하므로 re-raise하지 않음

    def _is_url_like(self, value: str) -> bool:
        """값이 URL 형태인지 확인"""
        if not value:
            return False

        url_patterns = [
            r'^https?://',  # http:// or https://
            r'^//',  # Protocol-relative URL
            r'^\.\/',  # Relative path
            r'^\.\./',  # Parent directory
            r'^/',  # Absolute path
        ]

        for pattern in url_patterns:
            if re.match(pattern, value, re.IGNORECASE):
                return True
        return False

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_open_redirect': len(self.issues) > 0,
            'redirect_params_found': len([i for i in self.issues if 'parameters' in i]) > 0,
            'url_values_found': len([i for i in self.issues if 'value' in i]) > 0
        }


    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

