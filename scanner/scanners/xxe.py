"""
XXEScanner - 자동 수정됨

원본: scanners_refactored_batch4.py
"""

import logging
import re
import warnings
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, urljoin

# BeautifulSoup 경고 무시
from bs4 import MarkupResemblesLocatorWarning
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
from bs4 import BeautifulSoup
import requests
import json
import time
import hashlib
import base64

from scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class XXEScanner(BaseScanner):
    """XXE (XML External Entity) 취약점 스캐너"""

    metadata = {
        'id': 'xxe',
        'name': 'XXE 취약점 스캔',
        'icon': '📄',
        'description': 'XML External Entity Injection 취약점 탐지',
        'weight': 2,
        'field': 'xxe_vulnerabilities',
        'category': 'security_advanced',
        'OWASP': 'A04:2025',
    }

    def __init__(self, html_content: str = None, response: requests.Response = None, url: str = None, **kwargs):
        """
        Args:
            html_content: HTML 콘텐츠
            response: HTTP 응답 객체
            url: URL (선택적)
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', **kwargs)
        self.html_content = html_content or ''
        self.response = response

    def _execute_scan(self) -> None:
        """XXE 취약점 검사 실행"""
        if self.response:
            self._check_xml_support()

        if self.html_content:
            self._check_doctype()
            self._check_xml_upload()

    def _check_xml_support(self) -> None:
        """XML 처리 지원 여부 확인"""
        try:
            if not self.response:
                return

            content_type = self.response.headers.get('Content-Type', '')

            if any(indicator in content_type for indicator in ['xml', 'XML']):
                self.issues.append({
                    'type': 'XXE (XML Processing Detected)',
                    'severity': 'high',
                    'content_type': content_type,
                    'description': '서버가 XML을 처리하는 것으로 보입니다. XXE 공격에 취약할 수 있습니다.',
                    'attack_example': '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>''',
                    'recommendation': 'XML 파서의 외부 엔티티 처리를 비활성화하세요 (XXE prevention).'
                })
        except Exception as e:
            logger.debug(f"XXE XML support check error: {str(e)}")

    def _check_doctype(self) -> None:
        """HTML에 DOCTYPE 선언이 있는지 확인"""
        try:
            if '<!DOCTYPE' in self.html_content.upper():
                # XML DOCTYPE인지 확인
                if '<?xml' in self.html_content.lower():
                    self.issues.append({
                        'type': 'XXE (XML DOCTYPE Found)',
                        'severity': 'medium',
                        'description': 'XML DOCTYPE 선언이 발견되었습니다.',
                        'recommendation': 'XML 파서 설정을 점검하고 외부 엔티티를 비활성화하세요.'
                    })
        except Exception as e:
            logger.debug(f"XXE DOCTYPE check error: {str(e)}")

    def _check_xml_upload(self) -> None:
        """파일 업로드에서 XML 파일 허용 여부"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            file_inputs = soup.find_all('input', type='file')

            for file_input in file_inputs:
                accept = file_input.get('accept', '')
                if 'xml' in accept.lower() or not accept:  # accept가 없으면 모든 파일 허용
                    self.issues.append({
                        'type': 'XXE (XML File Upload)',
                        'severity': 'high',
                        'input_name': file_input.get('name', 'unknown'),
                        'accept_attr': accept or 'all files',
                        'description': 'XML 파일 업로드가 가능하여 XXE 공격에 취약할 수 있습니다.',
                        'recommendation': 'XML 파일 업로드 시 외부 엔티티를 차단하고, 파일 형식을 엄격히 검증하세요.'
                    })
        except Exception as e:
            logger.debug(f"XXE file upload check error: {str(e)}")

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_xxe': len(self.issues) > 0
        }



    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

