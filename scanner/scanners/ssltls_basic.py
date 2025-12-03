"""
SSLTLSBasicScanner - 자동 수정됨

원본: scanners_refactored_batch3.py
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


class SSLTLSBasicScanner(BaseScanner):
    """SSL/TLS 기본 검사 스캐너 - check_ssl_tls 함수를 클래스로 전환"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'ssl_tls',
        'name': 'SSL/TLS 검사',
        'icon': '🔐',
        'description': 'HTTPS 및 인증서 검증',
        'weight': 1,
        'field': 'ssl_tls_result',
        'category': 'security_basic',
        'OWASP': 'A02:2025',
    }

    def __init__(self, url: str = None, **kwargs):
        """
        Args:
            url: 검사할 URL
            **kwargs: BaseScanner 호환 인자
        """
        # BaseScanner 초기화
        super().__init__(url=url or '', **kwargs)

    def _execute_scan(self) -> None:
        """SSL/TLS 기본 검사 실행"""
        self.checked = 1 if self.url else 0

        if not self.url:
            logger.warning("No URL provided for SSL/TLS scan")
            return

        parsed = urlparse(self.url)
        is_https = parsed.scheme == 'https'

        # HTTPS 사용 여부 검사
        if is_https:
            self._add_detail(
                id='https',
                name='HTTPS 프로토콜',
                status='pass',
                severity='info',
                description='HTTPS를 사용하여 통신이 암호화됩니다.',
                value=f'{parsed.scheme}://{parsed.netloc}',
                expected='https://',
                recommendation=None
            )
        else:
            self._add_detail(
                id='https',
                name='HTTPS 프로토콜',
                status='fail',
                severity='high',
                description='HTTPS를 사용하지 않아 데이터가 암호화되지 않습니다.',
                value=f'{parsed.scheme or "http"}://{parsed.netloc}',
                expected='https://',
                recommendation='SSL/TLS 인증서를 설정하고 HTTPS로 전환하세요.'
            )
            self.issues.append({
                'type': 'No HTTPS',
                'severity': 'high',
                'description': 'HTTPS를 사용하지 않습니다.',
                'recommendation': 'SSL/TLS 인증서를 설정하세요.'
            })

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환 (기존 check_ssl_tls 함수와 호환)"""
        parsed = urlparse(self.url) if self.url else None
        is_https = parsed and parsed.scheme == 'https'

        return {
            'https': is_https,
            'status': 'ok' if is_https else 'warning',
            'message': 'HTTPS를 사용합니다.' if is_https else 'HTTPS를 사용하지 않습니다. SSL/TLS 인증서를 설정하세요.'
        }



    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

