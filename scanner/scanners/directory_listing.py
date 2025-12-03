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
        # 검사 항목: 디렉토리 리스팅 검사
        self.checked = 1

        # HTTP 요청 수행
        if not self.html_content and self.url:
            try:
                if self.session:
                    response = self.session.get(self.url)
                    self.html_content = response.text
                else:
                    import requests
                    response = requests.get(self.url, timeout=5)
                    self.html_content = response.text
            except:
                pass

        if not self.html_content:
            self._add_detail(
                id='directory_listing',
                name='디렉토리 리스팅 검사',
                status='pass',
                severity='info',
                description='검사할 콘텐츠 없음',
                value=None,
                expected=None,
                recommendation=None
            )
            return

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

        pattern_found = None
        for pattern in apache_patterns:
            if pattern in self.html_content:
                pattern_found = pattern
                self.vulnerabilities.append({
                    'type': 'Directory Listing',
                    'severity': 'medium',
                    'description': f'Apache directory listing detected: {pattern}'
                })
                break

        if pattern_found:
            self._add_detail(
                id='directory_listing',
                name='디렉토리 리스팅 검사',
                status='fail',
                severity='medium',
                description=f'디렉토리 리스팅 활성화 감지: {pattern_found}',
                value=pattern_found,
                expected='디렉토리 리스팅 비활성화',
                recommendation='웹 서버 설정에서 디렉토리 리스팅을 비활성화하세요.'
            )
        else:
            self._add_detail(
                id='directory_listing',
                name='디렉토리 리스팅 검사',
                status='pass',
                severity='info',
                description='디렉토리 리스팅이 감지되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_listing': len(self.vulnerabilities) > 0
        }

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

