"""디렉토리 리스팅 취약점 스캐너"""

import re
import logging
import requests
from typing import Dict, Any
from scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class DirectoryListingScanner(BaseScanner):
    """디렉토리 리스팅 검사 스캐너"""

    metadata = {
        'id': 'directory_listing',
        'name': '디렉토리 리스팅 검사',
        'icon': '📁',
        'description': '디렉토리 리스팅 검사',
        'weight': 1,
        'field': 'directory_listing',
        'category': 'security_basic',
        'severity': 'medium'
    }

    def __init__(self, url=None, html_content=None, session=None, **kwargs):
        """스캐너 초기화"""
        super().__init__(url=url or '', html_content=html_content, **kwargs)
        self.url = url or ''
        self.html_content = html_content or ''
        self.session = session

    def _execute_scan(self) -> None:
        """디렉토리 리스팅 취약점 스캔"""

        # HTTP 요청 수행
        if not self.html_content and self.url:
            try:
                if self.session:
                    # session이 제공된 경우 사용
                    response = self.session.get(self.url)
                    self.html_content = response.text
                else:
                    # session이 없으면 requests 직접 사용
                    import requests
                    response = requests.get(self.url, timeout=5)
                    self.html_content = response.text
            except:
                pass

        if self.html_content:
            # Apache directory listing 패턴
            apache_patterns = [
                'Index of /',
                'Parent Directory',
                '[PARENTDIR]',
                'Apache/',
                'Apache Server',
                '<title>Index of',
                'Directory listing for'
            ]

            for pattern in apache_patterns:
                if pattern in self.html_content:
                    self.vulnerabilities.append({
                        'type': 'Directory Listing',
                        'severity': 'medium',
                        'description': f'Apache directory listing detected: {pattern}'
                    })
                    break

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_listing': len(self.vulnerabilities) > 0
        }

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

