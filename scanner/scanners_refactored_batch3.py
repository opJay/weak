"""
리팩토링된 기본 스캐너들 - Batch 3

5개 기본 스캐너를 BaseScanner 패턴으로 리팩토링
"""

import logging
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, urljoin
import requests
from requests.exceptions import RequestException

from .base import BaseScanner

logger = logging.getLogger(__name__)


class OpenRedirectScanner(BaseScanner):
    """Open Redirect 취약점 검사 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'open_redirect',
        'name': 'Open Redirect 검사',
        'icon': '↗️',
        'description': '오픈 리다이렉트 취약점 탐지',
        'weight': 1,
        'field': 'open_redirects'
    }

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


class DirectoryListingScanner(BaseScanner):
    """디렉토리 리스팅 검사 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'directory_listing',
        'name': '디렉토리 리스팅 검사',
        'icon': '📂',
        'description': '디렉토리 목록 노출 검사',
        'weight': 0.5,
        'field': 'directory_listing'
    }

    # 디렉토리 리스팅 패턴
    DIRECTORY_PATTERNS = [
        (r'<title>Index of /', 'Apache directory listing'),
        (r'<h1>Index of /', 'Apache directory listing'),
        (r'Parent Directory', 'Directory listing with parent link'),
        (r'<a href="\.\./">\.\./</', 'Directory listing with parent link'),
        (r'Directory listing for /', 'Generic directory listing'),
    ]

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
        """디렉토리 리스팅 검사 실행"""
        # HTML 콘텐츠가 이미 제공된 경우
        if self.html_content:
            self._scan_content(self.html_content)
            return

        # URL에서 직접 가져오기
        if not self.url:
            logger.warning("No URL or HTML content for directory listing scan")
            return

        try:
            response = self.http_client.get(self.url, timeout=10)
            response.raise_for_status()
            self._scan_content(response.text)

        except RequestException as e:
            logger.error(f"Failed to fetch URL for directory listing scan: {str(e)}")
            # 네트워크 오류는 취약점이 아니므로 이슈 추가하지 않음

    def _scan_content(self, content: str) -> None:
        """HTML 콘텐츠에서 디렉토리 리스팅 패턴 검색"""
        if not content:
            return

        # 각 패턴 검사
        for pattern, description in self.DIRECTORY_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                self.issues.append({
                    'type': 'Directory Listing Enabled',
                    'severity': 'medium',
                    'pattern': description,
                    'description': '디렉토리 리스팅이 활성화되어 있습니다.',
                    'evidence': self._extract_evidence(content, pattern),
                    'recommendation': '웹 서버에서 디렉토리 리스팅을 비활성화하세요.'
                })
                # 하나라도 발견하면 종료 (중복 방지)
                break

    def _extract_evidence(self, content: str, pattern: str) -> str:
        """패턴 주변 컨텍스트 추출"""
        try:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                return content[start:end]
        except:
            pass
        return ""

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_listing': len(self.issues) > 0
        }


class HTTPMethodScanner(BaseScanner):
    """안전하지 않은 HTTP 메서드 검사 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'http_methods',
        'name': 'HTTP 메서드 검사',
        'icon': '📡',
        'description': '위험한 HTTP 메서드 활성화 검사',
        'weight': 0.5,
        'field': 'http_methods'
    }

    # 위험한 HTTP 메서드
    DANGEROUS_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS']

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
        """HTTP 메서드 검사 실행"""
        if not self.url:
            logger.warning("No URL provided for HTTP method scan")
            return

        # OPTIONS 요청으로 허용된 메서드 확인
        self._check_options_method()

        # TRACE 메서드 직접 테스트
        self._check_trace_method()

    def _check_options_method(self) -> None:
        """OPTIONS 요청으로 Allow 헤더 확인"""
        try:
            response = self.http_client.options(self.url, timeout=10)
            allowed_methods = response.headers.get('Allow', '')

            if not allowed_methods:
                logger.debug(f"No Allow header in OPTIONS response for {self.url}")
                return

            # 위험한 메서드 찾기
            dangerous_found = []
            for method in self.DANGEROUS_METHODS:
                if method in allowed_methods:
                    dangerous_found.append(method)

            if dangerous_found:
                self.issues.append({
                    'type': 'Dangerous HTTP Methods Allowed',
                    'severity': 'medium',
                    'methods': dangerous_found,
                    'description': f'위험한 HTTP 메서드가 허용되고 있습니다: {", ".join(dangerous_found)}',
                    'evidence': f'Allow: {allowed_methods}',
                    'recommendation': '불필요한 HTTP 메서드를 비활성화하세요.'
                })

        except RequestException as e:
            logger.debug(f"OPTIONS request failed: {str(e)}")
            # OPTIONS 요청 실패는 정상적일 수 있음

    def _check_trace_method(self) -> None:
        """TRACE 메서드 직접 테스트 (XST 공격 가능성)"""
        try:
            response = self.http_client.request('TRACE', self.url, timeout=10)

            # 405 Method Not Allowed가 아니면 TRACE가 활성화된 것
            if response.status_code != 405:
                self.issues.append({
                    'type': 'TRACE Method Enabled',
                    'severity': 'medium',
                    'status_code': response.status_code,
                    'description': 'TRACE 메서드가 활성화되어 있습니다. (XST 공격 가능)',
                    'evidence': f'TRACE request returned status {response.status_code}',
                    'recommendation': 'TRACE 메서드를 비활성화하세요.'
                })

                # TRACE 응답에 요청 헤더가 반사되는지 확인
                if response.text and 'TRACE' in response.text:
                    self.issues.append({
                        'type': 'XST (Cross-Site Tracing) Vulnerable',
                        'severity': 'high',
                        'description': 'TRACE 메서드가 요청을 그대로 반사합니다.',
                        'recommendation': 'TRACE 메서드를 즉시 비활성화하세요.'
                    })

        except RequestException as e:
            logger.debug(f"TRACE request failed: {str(e)}")
            # TRACE 요청 실패는 정상적일 수 있음

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_dangerous_methods': len(self.issues) > 0,
            'trace_enabled': any('TRACE' in issue.get('type', '') for issue in self.issues),
            'xst_vulnerable': any('XST' in issue.get('type', '') for issue in self.issues)
        }


class SSLTLSBasicScanner(BaseScanner):
    """SSL/TLS 기본 검사 스캐너 - check_ssl_tls 함수를 클래스로 전환"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'ssl_tls',
        'name': 'SSL/TLS 검사',
        'icon': '🔐',
        'description': 'HTTPS 및 인증서 검증',
        'weight': 1,
        'field': 'ssl_tls_result'
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
        if not self.url:
            logger.warning("No URL provided for SSL/TLS scan")
            return

        # URL 파싱
        parsed = urlparse(self.url)

        # HTTPS 사용 여부 확인
        if parsed.scheme != 'https':
            self.issues.append({
                'type': 'No HTTPS',
                'severity': 'high',
                'scheme': parsed.scheme or 'http',
                'description': 'HTTPS를 사용하지 않습니다.',
                'recommendation': 'SSL/TLS 인증서를 설정하세요.'
            })

            # HTTP인 경우 추가 경고
            if parsed.scheme == 'http':
                self.issues.append({
                    'type': 'Plain HTTP',
                    'severity': 'high',
                    'description': '평문 HTTP 프로토콜을 사용하여 데이터가 암호화되지 않습니다.',
                    'recommendation': 'HTTPS로 전환하고 HTTP를 HTTPS로 리다이렉트하세요.'
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


class SensitiveFileScanner(BaseScanner):
    """민감한 파일 노출 검사 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'sensitive_files',
        'name': '민감한 파일 노출 검사',
        'icon': '📁',
        'description': '설정 파일, 백업 파일 등 노출 검사',
        'weight': 1.5,
        'field': 'sensitive_files'
    }

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