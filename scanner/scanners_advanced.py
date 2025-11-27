"""
고급 보안 취약점 스캐너
실무급 보안 테스트를 위한 Critical & High Priority 스캐너
"""
import re
import json
import base64
import socket
import ssl
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import logging
from datetime import datetime

logger = logging.getLogger('scanner')


class SSRFScanner:
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

    SSRF_PARAMS = [
        'url', 'uri', 'path', 'dest', 'redirect', 'uri', 'link',
        'file', 'document', 'folder', 'root', 'page', 'proxy',
        'callback', 'return', 'feed', 'host', 'port', 'to', 'out'
    ]

    def __init__(self, url, html_content):
        self.url = url
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """SSRF 스캔 실행"""
        try:
            # 1. URL 파라미터에서 SSRF 가능성 검사
            self._scan_url_parameters()

            # 2. 폼 입력에서 SSRF 가능성 검사
            self._scan_forms()

            # 3. HTML 콘텐츠에서 URL 입력 필드 검사
            self._scan_url_inputs()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_ssrf': len(self.vulnerabilities) > 0
            }

        except Exception as e:
            logger.error(f"SSRF scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_ssrf': False,
                'error': str(e)
            }

    def _scan_url_parameters(self):
        """URL 파라미터에서 SSRF 취약점 검사"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param_name in params.keys():
                if param_name.lower() in self.SSRF_PARAMS:
                    param_value = params[param_name][0] if params[param_name] else ''

                    # URL 형식인지 확인
                    if param_value.startswith(('http://', 'https://', '//')):
                        self.vulnerabilities.append({
                            'type': 'SSRF (Potential)',
                            'severity': 'critical',
                            'parameter': param_name,
                            'value': param_value,
                            'description': f'파라미터 "{param_name}"가 SSRF 공격에 취약할 수 있습니다.',
                            'attack_vectors': [
                                '내부 네트워크 접근: http://localhost:8080',
                                'Cloud Metadata 접근: http://169.254.169.254/latest/meta-data/',
                                'Port Scanning: http://internal-host:3306'
                            ],
                            'recommendation': 'URL 화이트리스트 검증, 내부 IP 차단, DNS Rebinding 방어를 적용하세요.'
                        })

        except Exception as e:
            logger.debug(f"SSRF URL parameter scan error: {str(e)}")

    def _scan_forms(self):
        """폼에서 SSRF 가능성 검사"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            forms = soup.find_all('form')

            for idx, form in enumerate(forms):
                inputs = form.find_all('input')

                for input_field in inputs:
                    name = input_field.get('name', '').lower()
                    input_type = input_field.get('type', 'text').lower()

                    if name in self.SSRF_PARAMS and input_type in ['text', 'url', 'hidden']:
                        self.vulnerabilities.append({
                            'type': 'SSRF (Form Input)',
                            'severity': 'critical',
                            'form_index': idx,
                            'input_name': name,
                            'input_type': input_type,
                            'description': f'폼 입력 "{name}"이 SSRF에 취약할 수 있습니다.',
                            'recommendation': '입력값을 철저히 검증하고 내부 IP 대역을 차단하세요.'
                        })

        except Exception as e:
            logger.debug(f"SSRF form scan error: {str(e)}")

    def _scan_url_inputs(self):
        """URL 입력 필드 검사"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            url_inputs = soup.find_all('input', type='url')

            if url_inputs:
                self.vulnerabilities.append({
                    'type': 'SSRF (URL Input Fields)',
                    'severity': 'high',
                    'count': len(url_inputs),
                    'description': f'{len(url_inputs)}개의 URL 입력 필드가 SSRF에 취약할 수 있습니다.',
                    'recommendation': '서버 사이드에서 URL 검증 및 내부 IP 차단 로직을 구현하세요.'
                })

        except Exception as e:
            logger.debug(f"SSRF URL input scan error: {str(e)}")


class XXEScanner:
    """XXE (XML External Entity) 취약점 스캐너"""

    metadata = {
        'id': 'xxe',
        'name': 'XXE 취약점 스캔',
        'icon': '📄',
        'description': 'XML External Entity 주입 취약점 탐지',
        'weight': 2,
        'field': 'xxe_vulnerabilities'
    }

    XXE_INDICATORS = [
        'Content-Type: application/xml',
        'Content-Type: text/xml',
        '<?xml',
        'application/soap+xml',
        'application/xhtml+xml',
    ]

    def __init__(self, url, response, html_content):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """XXE 스캔 실행"""
        try:
            # 1. XML 처리 여부 확인
            self._check_xml_support()

            # 2. DOCTYPE 선언 확인
            self._check_doctype()

            # 3. 파일 업로드에서 XML 허용 여부
            self._check_xml_upload()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_xxe': len(self.vulnerabilities) > 0
            }

        except Exception as e:
            logger.error(f"XXE scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_xxe': False,
                'error': str(e)
            }

    def _check_xml_support(self):
        """XML 처리 지원 여부 확인"""
        try:
            content_type = self.response.headers.get('Content-Type', '')

            if any(indicator in content_type for indicator in ['xml', 'XML']):
                self.vulnerabilities.append({
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

    def _check_doctype(self):
        """HTML에 DOCTYPE 선언이 있는지 확인"""
        try:
            if '<!DOCTYPE' in self.html_content.upper():
                # XML DOCTYPE인지 확인
                if '<?xml' in self.html_content.lower():
                    self.vulnerabilities.append({
                        'type': 'XXE (XML DOCTYPE Found)',
                        'severity': 'medium',
                        'description': 'XML DOCTYPE 선언이 발견되었습니다.',
                        'recommendation': 'XML 파서 설정을 점검하고 외부 엔티티를 비활성화하세요.'
                    })

        except Exception as e:
            logger.debug(f"XXE DOCTYPE check error: {str(e)}")

    def _check_xml_upload(self):
        """파일 업로드에서 XML 파일 허용 여부"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            file_inputs = soup.find_all('input', type='file')

            for file_input in file_inputs:
                accept = file_input.get('accept', '')
                if 'xml' in accept.lower() or not accept:  # accept가 없으면 모든 파일 허용
                    self.vulnerabilities.append({
                        'type': 'XXE (XML File Upload)',
                        'severity': 'high',
                        'input_name': file_input.get('name', 'unknown'),
                        'accept_attr': accept or 'all files',
                        'description': 'XML 파일 업로드가 가능하여 XXE 공격에 취약할 수 있습니다.',
                        'recommendation': 'XML 파일 업로드 시 외부 엔티티를 차단하고, 파일 형식을 엄격히 검증하세요.'
                    })

        except Exception as e:
            logger.debug(f"XXE file upload check error: {str(e)}")


class CommandInjectionScanner:
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

    def __init__(self, url, html_content):
        self.url = url
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """Command Injection 스캔"""
        try:
            # 1. URL 파라미터 검사
            self._scan_url_parameters()

            # 2. 폼 입력 검사
            self._scan_forms()

            # 3. 코드에서 위험한 함수 사용 검사 (클라이언트 사이드 힌트)
            self._scan_dangerous_functions()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_command_injection': len(self.vulnerabilities) > 0
            }

        except Exception as e:
            logger.error(f"Command injection scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_command_injection': False,
                'error': str(e)
            }

    def _scan_url_parameters(self):
        """URL 파라미터에서 Command Injection 검사"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param_name in params.keys():
                if param_name.lower() in self.COMMAND_PARAMS:
                    self.vulnerabilities.append({
                        'type': 'Command Injection (Potential)',
                        'severity': 'critical',
                        'parameter': param_name,
                        'description': f'파라미터 "{param_name}"가 OS 명령어 주입에 취약할 수 있습니다.',
                        'attack_examples': [
                            '; ls -la',
                            '| cat /etc/passwd',
                            '&& whoami',
                            '`ping -c 10 evil.com`',
                        ],
                        'recommendation': '입력값을 화이트리스트로 검증하고, 시스템 명령어 실행을 피하세요.'
                    })

        except Exception as e:
            logger.debug(f"Command injection URL parameter scan error: {str(e)}")

    def _scan_forms(self):
        """폼에서 Command Injection 가능성 검사"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            forms = soup.find_all('form')

            for idx, form in enumerate(forms):
                inputs = form.find_all('input')

                for input_field in inputs:
                    name = input_field.get('name', '').lower()

                    if name in self.COMMAND_PARAMS:
                        self.vulnerabilities.append({
                            'type': 'Command Injection (Form)',
                            'severity': 'critical',
                            'form_index': idx,
                            'input_name': name,
                            'description': f'폼 입력 "{name}"이 명령어 주입에 취약할 수 있습니다.',
                            'recommendation': '절대 사용자 입력을 시스템 명령어로 실행하지 마세요.'
                        })

        except Exception as e:
            logger.debug(f"Command injection form scan error: {str(e)}")

    def _scan_dangerous_functions(self):
        """위험한 함수 사용 검사"""
        try:
            for pattern in self.COMMAND_INDICATORS:
                if re.search(pattern, self.html_content, re.IGNORECASE):
                    self.vulnerabilities.append({
                        'type': 'Dangerous Function Usage',
                        'severity': 'high',
                        'pattern': pattern,
                        'description': f'위험한 시스템 명령 실행 함수가 발견되었습니다: {pattern}',
                        'recommendation': '시스템 명령어 실행 대신 안전한 API를 사용하세요.'
                    })
                    break  # 한 번만 보고

        except Exception as e:
            logger.debug(f"Dangerous function scan error: {str(e)}")


class DeserializationScanner:
    """Insecure Deserialization 취약점 스캐너"""

    metadata = {
        'id': 'deserialization',
        'name': '역직렬화 취약점 스캔',
        'icon': '📦',
        'description': 'Insecure Deserialization 취약점 탐지',
        'weight': 2,
        'field': 'deserialization'
    }

    SERIALIZATION_INDICATORS = [
        # Python
        ('pickle', 'Python Pickle', 'critical'),
        ('cPickle', 'Python cPickle', 'critical'),
        ('yaml.load', 'PyYAML unsafe load', 'critical'),
        ('marshal.loads', 'Python Marshal', 'high'),

        # Java
        ('ObjectInputStream', 'Java Serialization', 'critical'),
        ('readObject', 'Java readObject', 'critical'),
        ('XMLDecoder', 'Java XMLDecoder', 'high'),

        # PHP
        ('unserialize', 'PHP unserialize', 'critical'),
        ('__wakeup', 'PHP Magic Method', 'high'),

        # .NET
        ('BinaryFormatter', '.NET BinaryFormatter', 'critical'),
        ('NetDataContractSerializer', '.NET Serialization', 'high'),
    ]

    def __init__(self, response, html_content):
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """Deserialization 스캔"""
        try:
            # 1. 쿠키에서 직렬화된 데이터 확인
            self._scan_cookies()

            # 2. HTML/JS에서 직렬화 함수 사용 확인
            self._scan_serialization_functions()

            # 3. Base64 인코딩된 직렬화 데이터 탐지
            self._scan_encoded_data()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_deserialization': len(self.vulnerabilities) > 0
            }

        except Exception as e:
            logger.error(f"Deserialization scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_deserialization': False,
                'error': str(e)
            }

    def _scan_cookies(self):
        """쿠키에서 직렬화된 데이터 확인"""
        try:
            cookies = self.response.cookies

            for cookie in cookies:
                value = cookie.value

                # Base64 디코딩 시도
                try:
                    decoded = base64.b64decode(value)
                    decoded_str = decoded.decode('utf-8', errors='ignore')

                    # Pickle magic bytes 확인
                    if decoded.startswith(b'\x80') or 'pickle' in decoded_str.lower():
                        self.vulnerabilities.append({
                            'type': 'Insecure Deserialization (Cookie)',
                            'severity': 'critical',
                            'cookie_name': cookie.name,
                            'description': f'쿠키 "{cookie.name}"에 직렬화된 데이터가 포함되어 있습니다.',
                            'recommendation': 'JWT나 서명된 토큰을 사용하고, 직렬화된 객체를 쿠키에 저장하지 마세요.'
                        })

                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Deserialization cookie scan error: {str(e)}")

    def _scan_serialization_functions(self):
        """직렬화 함수 사용 확인"""
        try:
            found = []

            for pattern, name, severity in self.SERIALIZATION_INDICATORS:
                if re.search(pattern, self.html_content, re.IGNORECASE):
                    found.append({'pattern': pattern, 'name': name, 'severity': severity})

            if found:
                self.vulnerabilities.append({
                    'type': 'Unsafe Deserialization Functions',
                    'severity': found[0]['severity'],
                    'functions': [f['name'] for f in found[:3]],
                    'description': f'{len(found)}개의 안전하지 않은 역직렬화 함수가 발견되었습니다.',
                    'recommendation': '안전한 직렬화 방식(JSON 등)을 사용하고, 신뢰할 수 없는 데이터를 역직렬화하지 마세요.'
                })

        except Exception as e:
            logger.debug(f"Serialization function scan error: {str(e)}")

    def _scan_encoded_data(self):
        """인코딩된 직렬화 데이터 탐지"""
        try:
            # URL이나 HTML에서 Base64로 인코딩된 것으로 보이는 긴 문자열 찾기
            base64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
            matches = re.findall(base64_pattern, self.html_content)

            suspicious_count = 0
            for match in matches[:10]:  # 최대 10개만 검사
                try:
                    decoded = base64.b64decode(match)
                    # Pickle, Java serialization 등의 magic bytes 확인
                    if decoded.startswith((b'\x80', b'\xac\xed', b'rO0')):
                        suspicious_count += 1
                except Exception:
                    pass

            if suspicious_count > 0:
                self.vulnerabilities.append({
                    'type': 'Serialized Data in Response',
                    'severity': 'high',
                    'count': suspicious_count,
                    'description': f'{suspicious_count}개의 직렬화된 데이터가 응답에서 발견되었습니다.',
                    'recommendation': '직렬화된 객체 대신 JSON을 사용하세요.'
                })

        except Exception as e:
            logger.debug(f"Encoded data scan error: {str(e)}")


class FileUploadScanner:
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

    def __init__(self, html_content):
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """파일 업로드 스캔"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            file_inputs = soup.find_all('input', type='file')

            if not file_inputs:
                return {
                    'vulnerabilities': [],
                    'total': 0,
                    'has_file_upload': False
                }

            # 파일 업로드 필드가 있으면 검사
            for idx, file_input in enumerate(file_inputs):
                self._check_file_input(file_input, idx)

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_file_upload': len(self.vulnerabilities) > 0
            }

        except Exception as e:
            logger.error(f"File upload scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_file_upload': False,
                'error': str(e)
            }

    def _check_file_input(self, file_input, idx):
        """개별 파일 입력 검사"""
        try:
            accept = file_input.get('accept', '')
            name = file_input.get('name', f'file_{idx}')

            # accept 속성이 없거나 너무 광범위한 경우
            if not accept or accept == '*/*' or accept == '*':
                self.vulnerabilities.append({
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
                self.vulnerabilities.append({
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
                self.vulnerabilities.append({
                    'type': 'File Upload Without Server Validation',
                    'severity': 'high',
                    'input_name': name,
                    'accept': accept,
                    'description': f'파일 업로드 필드가 서버 사이드 검증 없이 클라이언트 검증만 사용할 수 있습니다.',
                    'recommendation': '반드시 서버 사이드에서 파일 내용, 크기, MIME 타입을 검증하세요.'
                })

        except Exception as e:
            logger.debug(f"File input check error: {str(e)}")


class PathTraversalScanner:
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

    def __init__(self, url):
        self.url = url
        self.vulnerabilities = []

    def scan(self):
        """Path Traversal 스캔"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            # 파일/경로 관련 파라미터 검사
            for param_name, param_values in params.items():
                if param_name.lower() in self.PATH_PARAMS:
                    param_value = param_values[0] if param_values else ''

                    # 경로 순회 패턴이 포함되어 있는지 확인
                    has_traversal = any(pattern in param_value for pattern in self.TRAVERSAL_PATTERNS)

                    severity = 'critical' if has_traversal else 'high'

                    self.vulnerabilities.append({
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
            if not self.vulnerabilities and parsed.path:
                path_parts = parsed.path.split('/')
                if any(part.lower() in self.PATH_PARAMS for part in path_parts):
                    self.vulnerabilities.append({
                        'type': 'Path Traversal (URL Path)',
                        'severity': 'medium',
                        'path': parsed.path,
                        'description': 'URL 경로가 파일 접근에 사용될 수 있어 경로 순회에 취약할 수 있습니다.',
                        'recommendation': 'URL 기반 파일 접근 시 경로 검증을 철저히 하세요.'
                    })

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_path_traversal': len(self.vulnerabilities) > 0
            }

        except Exception as e:
            logger.error(f"Path traversal scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_path_traversal': False,
                'error': str(e)
            }


class JWTSecurityScanner:
    """JWT 보안 취약점 스캐너"""

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
        self.vulnerabilities = []

    def scan(self):
        """JWT 보안 스캔"""
        try:
            # 1. JWT 토큰 탐지
            tokens = self._find_jwt_tokens()

            if not tokens:
                return {
                    'vulnerabilities': [],
                    'total': 0,
                    'has_jwt': False,
                    'message': 'JWT 토큰이 발견되지 않았습니다.'
                }

            # 2. 각 토큰 분석
            for token in tokens[:5]:  # 최대 5개만 분석
                self._analyze_jwt(token)

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_jwt': len(tokens) > 0,
                'tokens_found': len(tokens)
            }

        except Exception as e:
            logger.error(f"JWT security scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_jwt': False,
                'error': str(e)
            }

    def _find_jwt_tokens(self):
        """JWT 토큰 찾기"""
        tokens = []

        try:
            # Authorization 헤더에서
            auth_header = self.response.headers.get('Authorization', '')
            if 'Bearer' in auth_header:
                token = auth_header.replace('Bearer ', '').strip()
                if self._is_jwt(token):
                    tokens.append(('Authorization Header', token))

            # 쿠키에서
            for cookie in self.response.cookies:
                if self._is_jwt(cookie.value):
                    tokens.append((f'Cookie: {cookie.name}', cookie.value))

            # HTML/JS에서 JWT 패턴 찾기
            jwt_pattern = r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
            matches = re.findall(jwt_pattern, self.html_content)
            for match in matches[:3]:
                tokens.append(('HTML/JS', match))

        except Exception as e:
            logger.debug(f"JWT token finding error: {str(e)}")

        return tokens

    def _is_jwt(self, token):
        """JWT 형식인지 확인"""
        parts = token.split('.')
        return len(parts) == 3 and all(len(part) > 0 for part in parts)

    def _analyze_jwt(self, token_info):
        """JWT 토큰 분석"""
        try:
            location, token = token_info
            parts = token.split('.')

            if len(parts) != 3:
                return

            # 헤더 디코딩
            try:
                header_decoded = base64.urlsafe_b64decode(parts[0] + '==')
                header = json.loads(header_decoded)

                # 1. Algorithm None Attack
                alg = header.get('alg', '').lower()
                if alg == 'none':
                    self.vulnerabilities.append({
                        'type': 'JWT Algorithm None',
                        'severity': 'critical',
                        'location': location,
                        'description': 'JWT가 "alg: none"을 사용하고 있어 서명 검증을 우회할 수 있습니다.',
                        'recommendation': '서버에서 "alg: none"을 거부하도록 설정하세요.'
                    })

                # 2. Weak Algorithm (HS256 경고)
                elif alg == 'hs256':
                    self.vulnerabilities.append({
                        'type': 'JWT Weak Algorithm',
                        'severity': 'medium',
                        'location': location,
                        'algorithm': alg,
                        'description': 'JWT가 HS256(HMAC)을 사용합니다. 약한 secret key 사용 시 취약할 수 있습니다.',
                        'recommendation': 'RS256(RSA) 알고리즘 사용을 고려하고, 충분히 긴 secret key를 사용하세요.'
                    })

                # Payload 디코딩
                payload_decoded = base64.urlsafe_b64decode(parts[1] + '==')
                payload = json.loads(payload_decoded)

                # 3. No Expiration
                if 'exp' not in payload:
                    self.vulnerabilities.append({
                        'type': 'JWT No Expiration',
                        'severity': 'high',
                        'location': location,
                        'description': 'JWT에 만료 시간(exp)이 설정되지 않았습니다.',
                        'recommendation': '반드시 exp claim을 설정하여 토큰 만료를 구현하세요.'
                    })

                # 4. Sensitive Data in JWT
                sensitive_keys = ['password', 'secret', 'key', 'ssn', 'credit_card']
                found_sensitive = [key for key in payload.keys() if any(s in key.lower() for s in sensitive_keys)]

                if found_sensitive:
                    self.vulnerabilities.append({
                        'type': 'JWT Sensitive Data',
                        'severity': 'high',
                        'location': location,
                        'sensitive_fields': found_sensitive,
                        'description': f'JWT에 민감한 정보가 포함되어 있을 수 있습니다: {", ".join(found_sensitive)}',
                        'recommendation': 'JWT에 민감한 정보를 저장하지 마세요. JWT는 암호화되지 않습니다.'
                    })

            except Exception as e:
                logger.debug(f"JWT analysis error: {str(e)}")

        except Exception as e:
            logger.debug(f"JWT token analysis error: {str(e)}")


class TemplateInjectionScanner:
    """SSTI (Server-Side Template Injection) 취약점 스캐너"""

    metadata = {
        'id': 'template_injection',
        'name': '템플릿 주입 스캔',
        'icon': '📝',
        'description': 'Server-Side Template Injection 취약점 탐지',
        'weight': 2,
        'field': 'template_injection'
    }

    TEMPLATE_INDICATORS = [
        # Jinja2
        ('{{', '}}', 'Jinja2/Flask', 'high'),
        ('{%', '%}', 'Jinja2/Django', 'high'),

        # Other templates
        ('${', '}', 'Freemarker/Velocity', 'high'),
        ('#{', '}', 'JSF/EL', 'medium'),
        ('<%', '%>', 'JSP/ERB', 'high'),
    ]

    SSTI_PARAMS = [
        'template', 'tmpl', 'view', 'layout', 'page', 'content',
        'text', 'body', 'message', 'name', 'title'
    ]

    def __init__(self, url, html_content):
        self.url = url
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """SSTI 스캔"""
        try:
            # 1. HTML에서 템플릿 구문 탐지
            self._detect_template_syntax()

            # 2. URL 파라미터에서 SSTI 가능성
            self._scan_url_parameters()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_ssti': len(self.vulnerabilities) > 0
            }

        except Exception as e:
            logger.error(f"Template injection scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_ssti': False,
                'error': str(e)
            }

    def _detect_template_syntax(self):
        """템플릿 구문 탐지"""
        try:
            for open_tag, close_tag, engine, severity in self.TEMPLATE_INDICATORS:
                pattern = re.escape(open_tag) + r'.*?' + re.escape(close_tag)
                matches = re.findall(pattern, self.html_content, re.DOTALL)

                if matches:
                    self.vulnerabilities.append({
                        'type': 'Template Engine Detected',
                        'severity': severity,
                        'engine': engine,
                        'examples': matches[:3],
                        'description': f'{engine} 템플릿 엔진이 감지되었습니다. SSTI에 취약할 수 있습니다.',
                        'attack_example': f'{open_tag}7*7{close_tag}',
                        'recommendation': '사용자 입력을 템플릿으로 렌더링하지 마세요. 샌드박스를 활성화하세요.'
                    })

        except Exception as e:
            logger.debug(f"Template syntax detection error: {str(e)}")

    def _scan_url_parameters(self):
        """URL 파라미터에서 SSTI 검사"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param_name in params.keys():
                if param_name.lower() in self.SSTI_PARAMS:
                    self.vulnerabilities.append({
                        'type': 'SSTI (Potential)',
                        'severity': 'critical',
                        'parameter': param_name,
                        'description': f'파라미터 "{param_name}"가 템플릿 주입에 취약할 수 있습니다.',
                        'attack_examples': [
                            '{{7*7}}',
                            '{{config}}',
                            '{{self.__dict__}}',
                            "${7*7}",
                        ],
                        'recommendation': '사용자 입력을 템플릿으로 처리하지 말고, 데이터로만 사용하세요.'
                    })

        except Exception as e:
            logger.debug(f"SSTI URL parameter scan error: {str(e)}")


class NoSQLInjectionScanner:
    """NoSQL Injection 취약점 스캐너"""

    metadata = {
        'id': 'nosql_injection',
        'name': 'NoSQL Injection 스캔',
        'icon': '🗄️',
        'description': 'NoSQL 데이터베이스 주입 취약점 탐지',
        'weight': 2,
        'field': 'nosql_injection'
    }

    NOSQL_INDICATORS = [
        'mongodb', 'mongo', 'couchdb', 'redis', 'cassandra',
        'dynamodb', 'elasticsearch', 'firebase'
    ]

    NOSQL_PARAMS = [
        'id', '_id', 'user', 'username', 'email', 'search', 'query',
        'filter', 'where', 'find', 'match', 'selector'
    ]

    def __init__(self, url, response, html_content):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """NoSQL Injection 스캔"""
        try:
            # 1. NoSQL 데이터베이스 사용 탐지
            uses_nosql = self._detect_nosql()

            # 2. URL 파라미터 검사
            if uses_nosql:
                self._scan_url_parameters()
                self._scan_json_inputs()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_nosql_injection': len(self.vulnerabilities) > 0,
                'uses_nosql': uses_nosql
            }

        except Exception as e:
            logger.error(f"NoSQL injection scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_nosql_injection': False,
                'error': str(e)
            }

    def _detect_nosql(self):
        """NoSQL 데이터베이스 사용 탐지"""
        try:
            # 응답 헤더나 HTML에서 NoSQL 관련 키워드 찾기
            content_lower = (self.html_content + str(self.response.headers)).lower()

            for indicator in self.NOSQL_INDICATORS:
                if indicator in content_lower:
                    return True

            return False

        except Exception as e:
            logger.debug(f"NoSQL detection error: {str(e)}")
            return False

    def _scan_url_parameters(self):
        """URL 파라미터에서 NoSQL Injection 검사"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param_name, param_values in params.items():
                if param_name.lower() in self.NOSQL_PARAMS:
                    param_value = param_values[0] if param_values else ''

                    # JSON 형식이면 더 위험
                    is_json = param_value.startswith(('{', '['))

                    self.vulnerabilities.append({
                        'type': 'NoSQL Injection (Potential)',
                        'severity': 'critical' if is_json else 'high',
                        'parameter': param_name,
                        'value_type': 'JSON' if is_json else 'string',
                        'description': f'파라미터 "{param_name}"가 NoSQL Injection에 취약할 수 있습니다.',
                        'attack_examples': [
                            '{"$ne": null}',
                            '{"$gt": ""}',
                            '{"username": {"$regex": "^admin"}}',
                            '[$ne]=1',
                        ],
                        'recommendation': '입력값을 타입 체크하고, $where, $regex 등 위험한 연산자를 차단하세요.'
                    })

        except Exception as e:
            logger.debug(f"NoSQL URL parameter scan error: {str(e)}")

    def _scan_json_inputs(self):
        """JSON 입력 필드 검사"""
        try:
            # Content-Type이 JSON이면
            content_type = self.response.headers.get('Content-Type', '')

            if 'application/json' in content_type:
                self.vulnerabilities.append({
                    'type': 'NoSQL JSON API',
                    'severity': 'medium',
                    'description': 'API가 JSON을 받습니다. NoSQL Injection에 주의해야 합니다.',
                    'recommendation': '모든 JSON 입력을 검증하고, MongoDB 연산자($ne, $gt 등)를 필터링하세요.'
                })

        except Exception as e:
            logger.debug(f"NoSQL JSON input scan error: {str(e)}")


class SSLTLSDeepScanner:
    """SSL/TLS 심층 보안 검사 스캐너"""

    metadata = {
        'id': 'ssl_tls_deep',
        'name': 'SSL/TLS 심층 검사',
        'icon': '🔐',
        'description': 'SSL/TLS 설정 및 인증서 심층 분석',
        'weight': 2,
        'field': 'ssl_tls_vulnerabilities'
    }

    WEAK_CIPHERS = [
        'DES', '3DES', 'RC4', 'MD5', 'NULL', 'anon', 'EXPORT'
    ]

    def __init__(self, url):
        self.url = url
        self.vulnerabilities = []

    def scan(self):
        """SSL/TLS 심층 스캔"""
        try:
            parsed = urlparse(self.url)

            if parsed.scheme != 'https':
                return {
                    'vulnerabilities': [{
                        'type': 'No HTTPS',
                        'severity': 'critical',
                        'description': 'HTTPS를 사용하지 않습니다.',
                        'recommendation': 'HTTPS를 활성화하고 HTTP를 HTTPS로 리다이렉트하세요.'
                    }],
                    'total': 1,
                    'has_ssl_issues': True
                }

            hostname = parsed.hostname
            port = parsed.port or 443

            # SSL/TLS 연결 정보 가져오기
            self._check_ssl_version(hostname, port)
            self._check_certificate(hostname, port)

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_ssl_issues': len(self.vulnerabilities) > 0
            }

        except Exception as e:
            logger.error(f"SSL/TLS scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_ssl_issues': False,
                'error': str(e)
            }

    def _check_ssl_version(self, hostname, port):
        """SSL/TLS 버전 및 Cipher Suite 검사"""
        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()

                    # TLS 버전 검사
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self.vulnerabilities.append({
                            'type': 'Weak TLS Version',
                            'severity': 'high',
                            'version': version,
                            'description': f'약한 TLS 버전을 사용합니다: {version}',
                            'recommendation': 'TLS 1.2 이상만 사용하도록 설정하세요.'
                        })

                    # Cipher Suite 검사
                    if cipher:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.upper() for weak in self.WEAK_CIPHERS):
                            self.vulnerabilities.append({
                                'type': 'Weak Cipher Suite',
                                'severity': 'high',
                                'cipher': cipher_name,
                                'description': f'약한 암호화 알고리즘을 사용합니다: {cipher_name}',
                                'recommendation': '강력한 cipher suite만 허용하도록 설정하세요.'
                            })

        except Exception as e:
            logger.debug(f"SSL version check error: {str(e)}")

    def _check_certificate(self, hostname, port):
        """SSL 인증서 검사"""
        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    if not cert:
                        self.vulnerabilities.append({
                            'type': 'No Certificate',
                            'severity': 'critical',
                            'description': 'SSL 인증서를 가져올 수 없습니다.',
                            'recommendation': '유효한 SSL 인증서를 설치하세요.'
                        })
                        return

                    # 인증서 만료일 검사
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days

                        if days_until_expiry < 0:
                            self.vulnerabilities.append({
                                'type': 'Certificate Expired',
                                'severity': 'critical',
                                'expiry_date': not_after,
                                'description': 'SSL 인증서가 만료되었습니다.',
                                'recommendation': '인증서를 갱신하세요.'
                            })
                        elif days_until_expiry < 30:
                            self.vulnerabilities.append({
                                'type': 'Certificate Expiring Soon',
                                'severity': 'medium',
                                'expiry_date': not_after,
                                'days_remaining': days_until_expiry,
                                'description': f'SSL 인증서가 {days_until_expiry}일 후 만료됩니다.',
                                'recommendation': '인증서를 갱신하세요.'
                            })

        except ssl.SSLError as e:
            self.vulnerabilities.append({
                'type': 'SSL Error',
                'severity': 'high',
                'description': f'SSL 연결 오류: {str(e)}',
                'recommendation': 'SSL 설정을 점검하세요.'
            })
        except Exception as e:
            logger.debug(f"Certificate check error: {str(e)}")
