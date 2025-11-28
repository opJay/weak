"""
고급 보안 스캐너 - Batch 4 리팩토링
BaseScanner를 사용한 고급 취약점 스캐너
"""

import re
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import requests
from requests.exceptions import RequestException

from .base import BaseScanner

logger = logging.getLogger('scanner')


class SSRFScanner(BaseScanner):
    """SSRF (Server-Side Request Forgery) 취약점 스캐너"""

    metadata = {
        'id': 'ssrf',
        'name': 'SSRF 취약점 스캔',
        'icon': '🌐',
        'description': '서버가 공격자가 지정한 URL로 요청을 보내는 취약점 탐지',
        'weight': 2,
        'field': 'ssrf_vulnerabilities'
    }

    # 내부 IP 대역
    INTERNAL_IPS = [
        '127.0.0.1', '0.0.0.0', 'localhost',
        '10.0.0.1', '192.168.1.1', '172.16.0.1'
    ]

    # Cloud Metadata 엔드포인트
    CLOUD_METADATA = [
        '169.254.169.254',  # AWS, Azure, GCP
    ]

    # SSRF 관련 파라미터
    SSRF_PARAMS = [
        'url', 'uri', 'path', 'dest', 'redirect', 'link',
        'file', 'document', 'folder', 'root', 'page', 'proxy',
        'callback', 'return', 'feed', 'host', 'port', 'to', 'out'
    ]

    def __init__(self, url: str = None, html_content: str = None, **kwargs):
        """
        Args:
            url: 검사할 URL
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        # BaseScanner 초기화
        super().__init__(url=url or '', **kwargs)
        self.html_content = html_content or ''

    def _execute_scan(self) -> None:
        """SSRF 취약점 검사 실행"""
        if self.url:
            # URL 파라미터에서 SSRF 가능성 검사
            self._scan_url_parameters()

        if self.html_content:
            # 폼 입력에서 SSRF 가능성 검사
            self._scan_forms()
            # HTML 콘텐츠에서 URL 입력 필드 검사
            self._scan_url_inputs()

    def _scan_url_parameters(self) -> None:
        """URL 파라미터에서 SSRF 취약점 검사"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param_name in params.keys():
                if param_name.lower() in self.SSRF_PARAMS:
                    param_value = params[param_name][0] if params[param_name] else ''

                    # URL 형식인지 확인
                    if param_value.startswith(('http://', 'https://', '//')):
                        self.issues.append({
                            'type': 'SSRF (Potential)',
                            'severity': 'critical',
                            'parameter': param_name,
                            'value': param_value,
                            'description': f'파라미터 "{param_name}"가 SSRF 공격에 취약할 수 있습니다.',
                            'attack_vectors': [
                                '내부 네트워크 접근: http://localhost:8080',
                                'Cloud Metadata 접근: http://169.254.169.254/latest/meta-data/',
                                'File Protocol: file:///etc/passwd'
                            ],
                            'recommendation': '사용자 입력 URL을 화이트리스트로 제한하고 내부 IP를 차단하세요.'
                        })
        except Exception as e:
            logger.debug(f"SSRF URL parameter scan error: {str(e)}")

    def _scan_forms(self) -> None:
        """폼 입력 필드에서 SSRF 취약점 검사"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                inputs = form.find_all('input')
                for input_field in inputs:
                    input_name = input_field.get('name', '')
                    input_type = input_field.get('type', 'text')

                    if input_name.lower() in self.SSRF_PARAMS or input_type == 'url':
                        self.issues.append({
                            'type': 'SSRF (Form Input)',
                            'severity': 'high',
                            'input_name': input_name,
                            'input_type': input_type,
                            'form_action': form.get('action', ''),
                            'description': f'폼 입력 "{input_name}"이 SSRF 공격에 취약할 수 있습니다.',
                            'recommendation': '서버 사이드에서 URL 검증 및 내부 IP 차단을 구현하세요.'
                        })
        except Exception as e:
            logger.debug(f"SSRF form scan error: {str(e)}")

    def _scan_url_inputs(self) -> None:
        """URL 입력 필드 검사"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            url_inputs = soup.find_all('input', type='url')

            for url_input in url_inputs:
                self.issues.append({
                    'type': 'SSRF (URL Input Field)',
                    'severity': 'medium',
                    'input_name': url_input.get('name', 'unknown'),
                    'description': 'URL 입력 필드가 SSRF 공격에 사용될 수 있습니다.',
                    'recommendation': 'URL 입력을 검증하고 내부 네트워크 접근을 차단하세요.'
                })
        except Exception as e:
            logger.debug(f"SSRF URL input scan error: {str(e)}")

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_ssrf': len(self.issues) > 0
        }


class XXEScanner(BaseScanner):
    """XXE (XML External Entity) 취약점 스캐너"""

    metadata = {
        'id': 'xxe',
        'name': 'XXE 취약점 스캔',
        'icon': '📄',
        'description': 'XML External Entity Injection 취약점 탐지',
        'weight': 2,
        'field': 'xxe_vulnerabilities'
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


class CommandInjectionScanner(BaseScanner):
    """OS Command Injection 취약점 스캐너"""

    metadata = {
        'id': 'command_injection',
        'name': '명령어 주입 스캔',
        'icon': '💻',
        'description': 'OS Command Injection 취약점 탐지',
        'weight': 2,
        'field': 'command_injection'
    }

    COMMAND_PARAMS = [
        'cmd', 'command', 'exec', 'execute', 'run', 'do', 'system',
        'shell', 'bash', 'script', 'process', 'daemon', 'ping', 'host'
    ]

    COMMAND_INDICATORS = [
        r'system\(',
        r'exec\(',
        r'shell_exec\(',
        r'passthru\(',
        r'popen\(',
        r'proc_open\(',
        r'os\.system',
        r'subprocess\.',
        r'Runtime\.getRuntime\(\)\.exec',
    ]

    def __init__(self, url: str = None, html_content: str = None, **kwargs):
        """
        Args:
            url: 검사할 URL
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', **kwargs)
        self.html_content = html_content or ''

    def _execute_scan(self) -> None:
        """Command Injection 취약점 검사 실행"""
        if self.url:
            self._scan_url_parameters()

        if self.html_content:
            self._scan_code_patterns()
            self._scan_forms()

    def _scan_url_parameters(self) -> None:
        """URL 파라미터에서 명령어 주입 가능성 검사"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param_name in params.keys():
                if param_name.lower() in self.COMMAND_PARAMS:
                    param_value = params[param_name][0] if params[param_name] else ''

                    # 특수 문자나 명령어 구분자 확인
                    dangerous_chars = ['|', '&', ';', '`', '$', '>', '<', '\n']
                    if any(char in param_value for char in dangerous_chars):
                        severity = 'critical'
                    else:
                        severity = 'high'

                    self.issues.append({
                        'type': 'Command Injection (Potential)',
                        'severity': severity,
                        'parameter': param_name,
                        'value': param_value,
                        'description': f'파라미터 "{param_name}"가 OS 명령어 주입에 취약할 수 있습니다.',
                        'attack_examples': [
                            '; ls -la',
                            '| whoami',
                            '`id`',
                            '$(cat /etc/passwd)',
                            '&& net user',
                        ],
                        'recommendation': '사용자 입력을 명령어에 직접 사용하지 말고, 화이트리스트와 이스케이핑을 적용하세요.'
                    })
        except Exception as e:
            logger.debug(f"Command injection URL scan error: {str(e)}")

    def _scan_code_patterns(self) -> None:
        """HTML/JavaScript에서 명령 실행 패턴 검사"""
        try:
            for pattern in self.COMMAND_INDICATORS:
                if re.search(pattern, self.html_content):
                    self.issues.append({
                        'type': 'Command Execution Pattern Detected',
                        'severity': 'high',
                        'pattern': pattern,
                        'description': f'명령 실행 관련 패턴이 발견되었습니다: {pattern}',
                        'recommendation': '명령 실행 코드를 안전하게 구현하고 사용자 입력을 철저히 검증하세요.'
                    })
        except Exception as e:
            logger.debug(f"Command injection pattern scan error: {str(e)}")

    def _scan_forms(self) -> None:
        """폼 입력에서 명령어 주입 가능성 검사"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                inputs = form.find_all(['input', 'textarea'])
                for input_field in inputs:
                    input_name = input_field.get('name', '')

                    if input_name.lower() in self.COMMAND_PARAMS:
                        self.issues.append({
                            'type': 'Command Injection (Form Input)',
                            'severity': 'high',
                            'input_name': input_name,
                            'form_action': form.get('action', ''),
                            'description': f'폼 입력 "{input_name}"이 명령어 주입에 취약할 수 있습니다.',
                            'recommendation': '서버 사이드에서 입력 검증 및 명령어 실행 보호를 구현하세요.'
                        })
        except Exception as e:
            logger.debug(f"Command injection form scan error: {str(e)}")

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_command_injection': len(self.issues) > 0
        }


class PathTraversalScanner(BaseScanner):
    """Path Traversal / LFI 취약점 스캐너"""

    metadata = {
        'id': 'path_traversal',
        'name': '경로 순회 공격 스캔',
        'icon': '📂',
        'description': 'Path Traversal / Local File Inclusion 취약점 탐지',
        'weight': 2,
        'field': 'path_traversal'
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
        if not self.url:
            logger.warning("No URL provided for path traversal scan")
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

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_path_traversal': len(self.issues) > 0
        }


class FileUploadScanner(BaseScanner):
    """파일 업로드 취약점 스캐너"""

    metadata = {
        'id': 'file_upload',
        'name': '파일 업로드 취약점 스캔',
        'icon': '📤',
        'description': '안전하지 않은 파일 업로드 탐지',
        'weight': 2,
        'field': 'file_upload'
    }

    DANGEROUS_EXTENSIONS = [
        'php', 'php3', 'php4', 'php5', 'phtml', 'asp', 'aspx',
        'jsp', 'jspx', 'exe', 'sh', 'bat', 'cmd', 'py', 'rb',
        'pl', 'cgi', 'dll', 'so', 'jar', 'war'
    ]

    def __init__(self, html_content: str = None, url: str = None, **kwargs):
        """
        Args:
            html_content: HTML 콘텐츠
            url: URL (선택적)
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', **kwargs)
        self.html_content = html_content or ''

    def _execute_scan(self) -> None:
        """파일 업로드 취약점 검사 실행"""
        if not self.html_content:
            logger.warning("No HTML content provided for file upload scan")
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')
        file_inputs = soup.find_all('input', type='file')

        if not file_inputs:
            return

        # 파일 업로드 필드가 있으면 검사
        for idx, file_input in enumerate(file_inputs):
            self._check_file_input(file_input, idx)

    def _check_file_input(self, file_input, idx: int) -> None:
        """개별 파일 입력 검사"""
        try:
            accept = file_input.get('accept', '')
            name = file_input.get('name', f'file_{idx}')

            # accept 속성이 없거나 너무 광범위한 경우
            if not accept or accept == '*/*' or accept == '*':
                self.issues.append({
                    'type': 'Unrestricted File Upload',
                    'severity': 'critical',
                    'input_name': name,
                    'accept': accept or 'any file',
                    'description': f'파일 업로드 필드 "{name}"가 모든 파일 형식을 허용합니다.',
                    'attack_vectors': [
                        'PHP 웹쉘 업로드 (.php)',
                        'Double extension 우회 (.php.jpg)',
                        'Null byte 주입 (shell.php%00.jpg)',
                        'MIME type 우회',
                    ],
                    'recommendation': '허용할 파일 확장자를 화이트리스트로 제한하고, 서버 사이드에서 파일 내용을 검증하세요.'
                })

            # 실행 가능한 파일 허용 여부
            elif any(ext in accept.lower() for ext in self.DANGEROUS_EXTENSIONS):
                dangerous = [ext for ext in self.DANGEROUS_EXTENSIONS if ext in accept.lower()]
                self.issues.append({
                    'type': 'Dangerous File Types Allowed',
                    'severity': 'critical',
                    'input_name': name,
                    'dangerous_types': dangerous,
                    'description': f'실행 가능한 파일 형식이 허용됩니다: {", ".join(dangerous)}',
                    'recommendation': '실행 가능한 파일 업로드를 차단하세요.'
                })

            # 클라이언트 사이드 검증만 있는 경우 (JavaScript)
            else:
                # 보통은 서버 사이드 검증도 필요
                self.issues.append({
                    'type': 'File Upload Without Server Validation',
                    'severity': 'high',
                    'input_name': name,
                    'accept': accept,
                    'description': f'파일 업로드 필드가 서버 사이드 검증 없이 클라이언트 검증만 사용할 수 있습니다.',
                    'recommendation': '반드시 서버 사이드에서 파일 내용, 크기, MIME 타입을 검증하세요.'
                })

        except Exception as e:
            logger.debug(f"File input check error: {str(e)}")

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_file_upload': len(self.issues) > 0
        }