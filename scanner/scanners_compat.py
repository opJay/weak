"""
스캐너 호환성 레이어
기존 tasks.py 코드를 수정하지 않고 리팩토링된 스캐너를 사용할 수 있도록 하는 래퍼
"""

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

# 리팩토링된 스캐너 사용 여부
USE_REFACTORED = True


class SecurityHeaderScanner:
    """SecurityHeaderScanner 호환성 래퍼"""

    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'security_headers',
        'name': '보안 헤더 검사',
        'icon': '🔒',
        'description': '보안 관련 HTTP 헤더 검사',
        'weight': 1,
        'field': 'security_headers'
    }

    def __init__(self, headers):
        self.headers = headers
        if USE_REFACTORED:
            from .scanners_refactored import SecurityHeaderScanner as RefactoredScanner
            self.scanner = RefactoredScanner(headers=headers)
        else:
            from .scanners import SecurityHeaderScanner as OriginalScanner
            self.scanner = OriginalScanner(headers)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class XSSScanner:
    """XSSScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'xss',
        'name': 'XSS 스캐너',
        'icon': '💉',
        'description': 'Cross-Site Scripting 취약점 탐지',
        'weight': 2,
        'field': 'xss'
    }

    def __init__(self, url, session=None):
        self.url = url
        self.session = session
        if USE_REFACTORED:
            from .scanners_refactored_batch2 import XSSScanner as RefactoredScanner
            self.scanner = RefactoredScanner(url=url, session=session)
        else:
            from .scanners import XSSScanner as OriginalScanner
            self.scanner = OriginalScanner(url, session)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class SQLInjectionScanner:
    """SQLInjectionScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'sql_injection',
        'name': 'SQL Injection 스캐너',
        'icon': '💾',
        'description': 'SQL 주입 취약점 탐지',
        'weight': 2,
        'field': 'sql_injection'
    }

    def __init__(self, url, session=None):
        self.url = url
        self.session = session
        if USE_REFACTORED:
            from .scanners_refactored_batch2 import SQLInjectionScanner as RefactoredScanner
            self.scanner = RefactoredScanner(url=url, session=session)
        else:
            from .scanners import SQLInjectionScanner as OriginalScanner
            self.scanner = OriginalScanner(url, session)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class CORSScanner:
    """CORSScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'cors',
        'name': 'CORS 검사',
        'icon': '🌐',
        'description': 'Cross-Origin Resource Sharing 설정 검사',
        'weight': 1,
        'field': 'cors'
    }

    def __init__(self, url, headers):
        self.url = url
        self.headers = headers
        if USE_REFACTORED:
            from .scanners_refactored import CORSScanner as RefactoredScanner
            self.scanner = RefactoredScanner(url=url, headers=headers)
        else:
            from .scanners import CORSScanner as OriginalScanner
            self.scanner = OriginalScanner(url, headers)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class CookieScanner:
    """CookieScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'cookies',
        'name': '쿠키 보안 검사',
        'icon': '🍪',
        'description': '쿠키 보안 속성 검사',
        'weight': 1,
        'field': 'cookies'
    }

    def __init__(self, response):
        self.response = response
        if USE_REFACTORED:
            from .scanners_refactored_batch1 import CookieScanner as RefactoredScanner
            self.scanner = RefactoredScanner(response=response)
        else:
            from .scanners import CookieScanner as OriginalScanner
            self.scanner = OriginalScanner(response)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class CSRFScanner:
    """CSRFScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'csrf',
        'name': 'CSRF 검사',
        'icon': '🔐',
        'description': 'CSRF 토큰 검증',
        'weight': 1.5,
        'field': 'csrf'
    }

    def __init__(self, url, session=None):
        self.url = url
        self.session = session
        if USE_REFACTORED:
            from .scanners_refactored_batch2 import CSRFScanner as RefactoredScanner
            # 리팩토링된 버전은 html_content를 받음
            if session and hasattr(session, 'get'):
                try:
                    response = session.get(url)
                    html_content = response.text
                except:
                    html_content = ''
            else:
                html_content = ''
            self.scanner = RefactoredScanner(url=url, html_content=html_content)
        else:
            from .scanners import CSRFScanner as OriginalScanner
            self.scanner = OriginalScanner(url, session)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class ClickjackingScanner:
    """ClickjackingScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'clickjacking',
        'name': '클릭재킹 검사',
        'icon': '🖱️',
        'description': '클릭재킹 방어 검사',
        'weight': 1,
        'field': 'clickjacking'
    }

    def __init__(self, headers, html_content=None):
        self.headers = headers
        self.html_content = html_content
        if USE_REFACTORED:
            from .scanners_refactored_batch1 import ClickjackingScanner as RefactoredScanner
            self.scanner = RefactoredScanner(headers=headers, html_content=html_content)
        else:
            from .scanners import ClickjackingScanner as OriginalScanner
            self.scanner = OriginalScanner(headers, html_content)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class InformationDisclosureScanner:
    """InformationDisclosureScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'info_disclosure',
        'name': '정보 노출 검사',
        'icon': '📋',
        'description': '민감한 정보 노출 탐지',
        'weight': 1.5,
        'field': 'information_disclosure'
    }

    def __init__(self, response):
        self.response = response
        # Extract HTML content from response if it's a Response object
        if hasattr(response, 'text'):
            self.html_content = response.text
        else:
            self.html_content = response

        if USE_REFACTORED:
            from .scanners_refactored_batch2 import InformationDisclosureScanner as RefactoredScanner
            self.scanner = RefactoredScanner(html_content=self.html_content)
        else:
            from .scanners import InformationDisclosureScanner as OriginalScanner
            self.scanner = OriginalScanner(response)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class MixedContentScanner:
    """MixedContentScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'mixed_content',
        'name': 'Mixed Content 검사',
        'icon': '🔀',
        'description': 'HTTPS 페이지의 HTTP 리소스 검사',
        'weight': 1,
        'field': 'mixed_content'
    }

    def __init__(self, url, html_content):
        self.url = url
        self.html_content = html_content
        if USE_REFACTORED:
            from .scanners_refactored_batch2 import MixedContentScanner as RefactoredScanner
            self.scanner = RefactoredScanner(url=url, html_content=html_content)
        else:
            from .scanners import MixedContentScanner as OriginalScanner
            self.scanner = OriginalScanner(url, html_content)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class SubresourceIntegrityScanner:
    """SubresourceIntegrityScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'sri',
        'name': 'SRI 검사',
        'icon': '🔏',
        'description': 'Subresource Integrity 검사',
        'weight': 1,
        'field': 'subresource_integrity'
    }

    def __init__(self, html_content, url=''):
        self.html_content = html_content
        self.url = url
        if USE_REFACTORED:
            from .scanners_refactored_batch1 import SubresourceIntegrityScanner as RefactoredScanner
            self.scanner = RefactoredScanner(html_content=html_content, url=url)
        else:
            from .scanners import SubresourceIntegrityScanner as OriginalScanner
            self.scanner = OriginalScanner(html_content, url)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


# Batch 3 스캐너들 (새로 리팩토링됨)
class OpenRedirectScanner:
    """OpenRedirectScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'open_redirect',
        'name': '오픈 리다이렉트 검사',
        'icon': '↗️',
        'description': '오픈 리다이렉트 취약점 탐지',
        'weight': 1.5,
        'field': 'open_redirect'
    }

    def __init__(self, url):
        self.url = url
        if USE_REFACTORED:
            from .scanners_refactored_batch3 import OpenRedirectScanner as RefactoredScanner
            self.scanner = RefactoredScanner(url=url)
        else:
            from .scanners import OpenRedirectScanner as OriginalScanner
            self.scanner = OriginalScanner(url)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class DirectoryListingScanner:
    """DirectoryListingScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'directory_listing',
        'name': '디렉토리 리스팅 검사',
        'icon': '📂',
        'description': '디렉토리 리스팅 노출 탐지',
        'weight': 1,
        'field': 'directory_listing'
    }

    def __init__(self, url, session=None):
        self.url = url
        self.session = session
        if USE_REFACTORED:
            from .scanners_refactored_batch3 import DirectoryListingScanner as RefactoredScanner
            self.scanner = RefactoredScanner(url=url, session=session)
        else:
            from .scanners import DirectoryListingScanner as OriginalScanner
            self.scanner = OriginalScanner(url, session)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class HTTPMethodScanner:
    """HTTPMethodScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'http_methods',
        'name': 'HTTP 메서드 검사',
        'icon': '🔧',
        'description': '위험한 HTTP 메서드 탐지',
        'weight': 1,
        'field': 'http_methods'
    }

    def __init__(self, url, session=None):
        self.url = url
        self.session = session
        if USE_REFACTORED:
            from .scanners_refactored_batch3 import HTTPMethodScanner as RefactoredScanner
            self.scanner = RefactoredScanner(url=url, session=session)
        else:
            from .scanners import HTTPMethodScanner as OriginalScanner
            self.scanner = OriginalScanner(url, session)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class SensitiveFileScanner:
    """SensitiveFileScanner 호환성 래퍼"""

    def __init__(self, url, session=None):
        self.url = url
        self.session = session
        if USE_REFACTORED:
            from .scanners_refactored_batch3 import SensitiveFileScanner as RefactoredScanner
            self.scanner = RefactoredScanner(url=url, session=session)
        else:
            from .scanners import SensitiveFileScanner as OriginalScanner
            self.scanner = OriginalScanner(url, session)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


# check_ssl_tls 함수 호환성 처리
def check_ssl_tls(url):
    """
    check_ssl_tls 함수 호환성 래퍼
    리팩토링된 SSLTLSBasicScanner를 사용하거나 기존 함수 사용
    """
    if USE_REFACTORED:
        from .scanners_refactored_batch3 import SSLTLSBasicScanner
        scanner = SSLTLSBasicScanner(url=url)
        result = scanner.scan()
        # 기존 함수 반환 형식으로 변환 (scan() 결과에서 필요한 필드만 추출)
        return {
            'https': result.get('https', False),
            'status': result.get('status', 'warning'),
            'message': result.get('message', 'HTTPS를 사용하지 않습니다.')
        }
    else:
        # 기존 함수 사용
        import urllib.parse
        parsed = urllib.parse.urlparse(url)

        if parsed.scheme == 'https':
            return {
                'https': True,
                'status': 'ok',
                'message': 'HTTPS를 사용합니다.'
            }
        else:
            return {
                'https': False,
                'status': 'warning',
                'message': 'HTTPS를 사용하지 않습니다. SSL/TLS 인증서를 설정하세요.'
            }

# check_ssl_tls 함수에 메타데이터 추가 (기존 코드 호환)
check_ssl_tls.metadata = {
    'id': 'ssl_tls',
    'name': 'SSL/TLS 검사',
    'icon': '🔐',
    'description': 'HTTPS 및 인증서 검증',
    'weight': 1,
    'field': 'ssl_tls_result'
}


# Batch 4 고급 스캐너들 (새로 리팩토링됨)
class SSRFScanner:
    """SSRFScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'ssrf',
        'name': 'SSRF 취약점 스캔',
        'icon': '🌍',
        'description': 'Server-Side Request Forgery 취약점 탐지',
        'weight': 2,
        'field': 'ssrf_vulnerabilities'
    }

    def __init__(self, url, html_content):
        self.url = url
        self.html_content = html_content
        if USE_REFACTORED:
            from .scanners_refactored_batch4 import SSRFScanner as RefactoredScanner
            self.scanner = RefactoredScanner(url=url, html_content=html_content)
        else:
            from .scanners_advanced import SSRFScanner as OriginalScanner
            self.scanner = OriginalScanner(url, html_content)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class XXEScanner:
    """XXEScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'xxe',
        'name': 'XXE 취약점 스캔',
        'icon': '📄',
        'description': 'XML External Entity Injection 취약점 탐지',
        'weight': 2,
        'field': 'xxe_vulnerabilities'
    }

    def __init__(self, html_content, response):
        self.html_content = html_content
        self.response = response
        if USE_REFACTORED:
            from .scanners_refactored_batch4 import XXEScanner as RefactoredScanner
            self.scanner = RefactoredScanner(html_content=html_content, response=response)
        else:
            from .scanners_advanced import XXEScanner as OriginalScanner
            self.scanner = OriginalScanner(html_content, response)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class CommandInjectionScanner:
    """CommandInjectionScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'command_injection',
        'name': '명령어 주입 스캔',
        'icon': '💻',
        'description': 'OS 명령어 주입 취약점 탐지',
        'weight': 2,
        'field': 'command_injection'
    }

    def __init__(self, url, html_content):
        self.url = url
        self.html_content = html_content
        if USE_REFACTORED:
            from .scanners_refactored_batch4 import CommandInjectionScanner as RefactoredScanner
            self.scanner = RefactoredScanner(url=url, html_content=html_content)
        else:
            from .scanners_advanced import CommandInjectionScanner as OriginalScanner
            self.scanner = OriginalScanner(url, html_content)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class PathTraversalScanner:
    """PathTraversalScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'path_traversal',
        'name': '경로 순회 공격 스캔',
        'icon': '📁',
        'description': '경로 순회(LFI/RFI) 취약점 탐지',
        'weight': 2,
        'field': 'path_traversal'
    }

    def __init__(self, url):
        self.url = url
        if USE_REFACTORED:
            from .scanners_refactored_batch4 import PathTraversalScanner as RefactoredScanner
            self.scanner = RefactoredScanner(url=url)
        else:
            from .scanners_advanced import PathTraversalScanner as OriginalScanner
            self.scanner = OriginalScanner(url)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class FileUploadScanner:
    """FileUploadScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'file_upload',
        'name': '파일 업로드 취약점 스캔',
        'icon': '📤',
        'description': '안전하지 않은 파일 업로드 탐지',
        'weight': 2,
        'field': 'file_upload'
    }

    def __init__(self, html_content):
        self.html_content = html_content
        if USE_REFACTORED:
            from .scanners_refactored_batch4 import FileUploadScanner as RefactoredScanner
            self.scanner = RefactoredScanner(html_content=html_content)
        else:
            from .scanners_advanced import FileUploadScanner as OriginalScanner
            self.scanner = OriginalScanner(html_content)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


# Batch 5 스캐너 래퍼
class DeserializationScanner:
    """DeserializationScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'deserialization',
        'name': '역직렬화 취약점 스캔',
        'icon': '📦',
        'description': 'Insecure Deserialization 취약점 탐지',
        'weight': 2,
        'field': 'deserialization'
    }

    def __init__(self, response, html_content):
        self.response = response
        self.html_content = html_content
        if USE_REFACTORED:
            from .scanners_refactored_batch5 import DeserializationScanner as RefactoredScanner
            self.scanner = RefactoredScanner(response=response, html_content=html_content)
        else:
            from .scanners_advanced import DeserializationScanner as OriginalScanner
            self.scanner = OriginalScanner(response, html_content)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class JWTSecurityScanner:
    """JWTSecurityScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'jwt_security',
        'name': 'JWT 보안 검사',
        'icon': '🔑',
        'description': 'JSON Web Token 보안 취약점 탐지',
        'weight': 2,
        'field': 'jwt_vulnerabilities'
    }

    def __init__(self, response, html_content):
        self.response = response
        self.html_content = html_content
        if USE_REFACTORED:
            from .scanners_refactored_batch5 import JWTSecurityScanner as RefactoredScanner
            self.scanner = RefactoredScanner(response=response, html_content=html_content)
        else:
            from .scanners_advanced import JWTSecurityScanner as OriginalScanner
            self.scanner = OriginalScanner(response, html_content)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class TemplateInjectionScanner:
    """TemplateInjectionScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'template_injection',
        'name': '템플릿 주입 스캔',
        'icon': '📝',
        'description': 'Server-Side Template Injection 취약점 탐지',
        'weight': 2,
        'field': 'template_injection'
    }

    def __init__(self, url, html_content):
        self.url = url
        self.html_content = html_content
        if USE_REFACTORED:
            from .scanners_refactored_batch5 import TemplateInjectionScanner as RefactoredScanner
            self.scanner = RefactoredScanner(url=url, html_content=html_content)
        else:
            from .scanners_advanced import TemplateInjectionScanner as OriginalScanner
            self.scanner = OriginalScanner(url, html_content)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class NoSQLInjectionScanner:
    """NoSQLInjectionScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'nosql_injection',
        'name': 'NoSQL Injection 스캔',
        'icon': '🗄️',
        'description': 'NoSQL 데이터베이스 주입 취약점 탐지',
        'weight': 2,
        'field': 'nosql_injection'
    }

    def __init__(self, url, response, html_content):
        self.url = url
        self.response = response
        self.html_content = html_content
        if USE_REFACTORED:
            from .scanners_refactored_batch5 import NoSQLInjectionScanner as RefactoredScanner
            self.scanner = RefactoredScanner(url=url, response=response, html_content=html_content)
        else:
            from .scanners_advanced import NoSQLInjectionScanner as OriginalScanner
            self.scanner = OriginalScanner(url, response, html_content)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()


class SSLTLSDeepScanner:
    """SSLTLSDeepScanner 호환성 래퍼"""


    # 클래스 레벨 metadata (tasks.py에서 클래스.metadata로 접근 시 사용)
    metadata = {
        'id': 'ssl_tls_deep',
        'name': 'SSL/TLS 심층 검사',
        'icon': '🔐',
        'description': 'SSL/TLS 설정 및 인증서 심층 분석',
        'weight': 2,
        'field': 'ssl_tls_vulnerabilities'
    }

    def __init__(self, url):
        self.url = url
        if USE_REFACTORED:
            from .scanners_refactored_batch5 import SSLTLSDeepScanner as RefactoredScanner
            self.scanner = RefactoredScanner(url=url)
        else:
            from .scanners_advanced import SSLTLSDeepScanner as OriginalScanner
            self.scanner = OriginalScanner(url)

    def scan(self) -> Dict[str, Any]:
        return self.scanner.scan()

