"""
SensitiveFileScanner - sensitive_files 스캐너

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

class SensitiveFileScanner(BaseScanner):
    """민감한 파일 노출 검사 스캐너 - 리팩토링 버전"""
    # 스캐너 메타데이터
    metadata = {
        'id': 'sensitive_file',
        'name': '민감한 파일 노출 검사',
        'icon': '📄',
        'description': '민감한 파일 노출 검사',
        'weight': 1,
        'field': 'sensitive_files',
        'category': 'security_basic',
        'enabled': True
    }

    # 스캐너 메타데이터

    # 민감한 파일 목록
    SENSITIVE_FILES = [
        # 설정 파일 (우선순위 높음)
        '.env', '.env.local', '.env.production', 'config.php',

        # 버전 관리
        '.git/config', '.git/HEAD', '.svn/entries', '.hg/hgrc',

        # 백업 파일
        'backup.sql', 'database.sql', 'db.sql', 'dump.sql',
        'backup.zip', 'backup.tar.gz', 'site.zip', 'www.zip',

        # 추가 설정 파일
        'configuration.php', 'settings.py', 'web.config',

        # 로그 파일
        'error.log', 'access.log', 'error_log', 'debug.log',

        # 기타
        'phpinfo.php', '.htaccess', 'composer.json', 'package.json',
        'Dockerfile', 'docker-compose.yml', 'robots.txt', 'sitemap.xml',
    ]

    # Critical severity 파일들
    CRITICAL_FILES = ['.env', '.git/config', 'backup.sql', 'database.sql', 'db.sql', 'dump.sql']

    def __init__(self, url: str = None, session: requests.Session = None, **kwargs):
        """
        Args:
            url: 검사할 URL
            session: HTTP 세션 (선택적)
            **kwargs: BaseScanner 호환 인자
        """
        # BaseScanner 초기화
        super().__init__(url=url or '', **kwargs)

        # HTTP 클라이언트 설정
        if session is not None:
            self.http_client = session
        elif not hasattr(self, 'http_client'):
            self.http_client = requests.Session()

    def _execute_scan(self) -> None:
        """민감한 파일 노출 검사 실행"""
        if not self.url:
            logger.warning("No URL provided for sensitive file scan")
            return

        # URL 파싱하여 베이스 URL 추출
        parsed = urlparse(self.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 최대 10개만 테스트 (성능 고려)
        files_to_test = self.SENSITIVE_FILES[:10]

        for file_path in files_to_test:
            self._check_file(base_url, file_path)

    def _check_file(self, base_url: str, file_path: str) -> None:
        """개별 파일 검사"""
        test_url = urljoin(base_url, file_path)

        try:
            response = self.http_client.get(
                test_url,
                timeout=5,
                allow_redirects=False
            )

            # 200 OK이고 실제 컨텐츠가 있는지 확인
            if response.status_code == 200 and len(response.content) > 0:
                # False Positive 필터링: 커스텀 404 페이지 확인
                if not self._is_real_404(response):
                    # 심각도 결정
                    severity = 'critical' if file_path in self.CRITICAL_FILES else 'high'

                    self.issues.append({
                        'type': 'Sensitive File Exposed',
                        'severity': severity,
                        'file': file_path,
                        'url': test_url,
                        'size': len(response.content),
                        'description': f'민감한 파일이 노출되어 있습니다: {file_path}',
                        'evidence': self._extract_file_evidence(response.text, file_path),
                        'recommendation': '해당 파일에 대한 접근을 차단하세요.'
                    })

        except RequestException as e:
            logger.debug(f"Failed to check {test_url}: {str(e)}")
            # 네트워크 오류는 정상적일 수 있음

    def _is_real_404(self, response: requests.Response) -> bool:
        """응답이 실제로는 404 에러 페이지인지 확인 (False Positive 감소)"""
        if not response.text:
            return False

        # 404 에러 페이지 패턴들
        error_patterns = [
            '404', 'not found', 'page not found', '페이지를 찾을 수 없습니다',
            'file not found', 'error 404', '404 error', 'does not exist'
        ]

        text_lower = response.text.lower()

        # 패턴이 여러 개 매칭되면 404 페이지일 가능성이 높음
        matches = sum(1 for pattern in error_patterns if pattern in text_lower)
        return matches >= 2

    def _extract_file_evidence(self, content: str, file_path: str) -> str:
        """파일 내용의 증거 추출 (민감한 정보는 제외)"""
        if not content:
            return ""

        # 파일 타입별 증거 추출
        if file_path == '.git/config':
            if '[core]' in content:
                return "Git configuration file detected"
        elif file_path.endswith('.env'):
            # 환경 변수 키만 추출 (값은 제외)
            keys = re.findall(r'^([A-Za-z_][A-Za-z0-9_]*)=', content, re.MULTILINE)
            if keys:
                return f"Environment variables: {', '.join(keys[:5])}"
            else:
                # 키가 없어도 .env 파일이면 최소한 이 메시지 반환
                return "Environment file detected (no valid keys found)"
        elif file_path.endswith('.sql'):
            if 'CREATE TABLE' in content.upper():
                return "SQL dump file detected"
        elif file_path == 'composer.json':
            if '"require"' in content:
                return "Composer dependencies file"
        elif file_path == 'package.json':
            if '"dependencies"' in content:
                return "NPM dependencies file"

        # 일반적인 경우: 처음 100자만
        return content[:100] if len(content) > 0 else "File exists"

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        critical_count = len([i for i in self.issues if i.get('severity') == 'critical'])
        high_count = len([i for i in self.issues if i.get('severity') == 'high'])

        return {
            'has_exposed_files': len(self.issues) > 0,
            'critical_files': critical_count,
            'high_risk_files': high_count,
            'files_tested': min(10, len(self.SENSITIVE_FILES))

        }
    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata
