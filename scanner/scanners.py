"""
Advanced Vulnerability Scanners
더 정교한 취약점 탐지 로직
"""
import re
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger('scanner')


class XSSScanner:
    """XSS 취약점 스캐너"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'xss',
        'name': 'XSS 취약점 스캔',
        'icon': '⚠️',
        'description': 'Cross-Site Scripting 취약점 탐지',
        'weight': 2,
        'field': 'xss_vulnerabilities'
    }

    # XSS 테스트 페이로드
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg/onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
    ]

    # 위험한 HTML 태그/속성 패턴
    DANGEROUS_PATTERNS = [
        r'<script[^>]*>',
        r'onerror\s*=',
        r'onload\s*=',
        r'onclick\s*=',
        r'javascript:',
        r'<iframe',
        r'<embed',
        r'<object',
    ]

    def __init__(self, url, session=None):
        self.url = url
        self.session = session or requests.Session()
        self.vulnerabilities = []

    def scan(self):
        """XSS 스캔 실행"""
        try:
            # 1. Reflected XSS 검사
            self._scan_reflected_xss()

            # 2. DOM-based XSS 검사 (간단한 버전)
            self._scan_dom_xss()

            # 3. 입력 폼 검사
            self._scan_forms()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_xss': len(self.vulnerabilities) > 0
            }

        except Exception as e:
            logger.error(f"XSS scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_xss': False,
                'error': str(e)
            }

    def _scan_reflected_xss(self):
        """Reflected XSS 검사"""
        try:
            response = self.session.get(self.url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')

            # URL 파라미터에서 XSS 테스트
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param_name in params.keys():
                for payload in self.XSS_PAYLOADS[:2]:  # 처음 2개만 테스트 (안전)
                    test_params = params.copy()
                    test_params[param_name] = [payload]

                    # 주의: 실제 환경에서는 권한이 있는 경우만 테스트
                    # 여기서는 시뮬레이션만 수행
                    self.vulnerabilities.append({
                        'type': 'Reflected XSS (Potential)',
                        'severity': 'high',
                        'parameter': param_name,
                        'payload': payload,
                        'description': f'파라미터 "{param_name}"가 XSS에 취약할 수 있습니다.',
                        'recommendation': '입력값을 HTML 이스케이프 처리하세요.'
                    })

        except Exception as e:
            logger.debug(f"Reflected XSS scan error: {str(e)}")

    def _scan_dom_xss(self):
        """DOM-based XSS 검사 (패턴 기반)"""
        try:
            response = self.session.get(self.url, timeout=10)

            # 위험한 JavaScript 패턴 검색
            dangerous_js_patterns = [
                r'document\.write\(',
                r'innerHTML\s*=',
                r'outerHTML\s*=',
                r'\.html\(',
                r'eval\(',
                r'setTimeout\(',
                r'setInterval\(',
            ]

            for pattern in dangerous_js_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    self.vulnerabilities.append({
                        'type': 'DOM-based XSS (Potential)',
                        'severity': 'medium',
                        'pattern': pattern,
                        'description': f'위험한 JavaScript 패턴 발견: {pattern}',
                        'recommendation': '사용자 입력을 DOM에 직접 삽입하지 마세요.'
                    })

        except Exception as e:
            logger.debug(f"DOM XSS scan error: {str(e)}")

    def _scan_forms(self):
        """폼 입력 필드 검사"""
        try:
            response = self.session.get(self.url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')

            forms = soup.find_all('form')

            for form in forms:
                inputs = form.find_all(['input', 'textarea'])

                for input_field in inputs:
                    input_type = input_field.get('type', 'text')

                    # 텍스트 입력 필드가 XSS 필터링 없이 사용되는지 확인
                    if input_type in ['text', 'search', 'url', 'email']:
                        # CSP, X-XSS-Protection 헤더 확인
                        if not response.headers.get('Content-Security-Policy'):
                            self.vulnerabilities.append({
                                'type': 'Missing XSS Protection',
                                'severity': 'medium',
                                'element': str(input_field)[:100],
                                'description': 'CSP 헤더가 설정되지 않아 XSS 공격에 취약합니다.',
                                'recommendation': 'Content-Security-Policy 헤더를 설정하세요.'
                            })
                            break  # 한 번만 보고

        except Exception as e:
            logger.debug(f"Form scan error: {str(e)}")


class SQLInjectionScanner:
    """SQL Injection 취약점 스캐너"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'sql_injection',
        'name': 'SQL Injection 스캔',
        'icon': '💉',
        'description': 'SQL 주입 취약점 탐지',
        'weight': 2,
        'field': 'sql_injection'
    }

    # SQL Injection 테스트 페이로드
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND '1'='2",
    ]

    # SQL 에러 패턴
    ERROR_PATTERNS = [
        r'SQL syntax.*?error',
        r'mysql_fetch',
        r'Warning.*?mysql_',
        r'PostgreSQL.*?ERROR',
        r'ORA-[0-9]{5}',
        r'Microsoft SQL Server',
        r'SQLSTATE\[',
        r'sqlite3\.OperationalError',
    ]

    def __init__(self, url, session=None):
        self.url = url
        self.session = session or requests.Session()
        self.vulnerabilities = []

    def scan(self):
        """SQL Injection 스캔 실행"""
        try:
            # 1. URL 파라미터 검사
            self._scan_url_parameters()

            # 2. 폼 입력 검사
            self._scan_forms()

            # 3. SQL 에러 메시지 검사
            self._scan_error_messages()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'has_sqli': len(self.vulnerabilities) > 0
            }

        except Exception as e:
            logger.error(f"SQL Injection scan error: {str(e)}")
            return {
                'vulnerabilities': [],
                'total': 0,
                'has_sqli': False,
                'error': str(e)
            }

    def _scan_url_parameters(self):
        """URL 파라미터에서 SQL Injection 검사"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            if not params:
                return

            # 파라미터가 있으면 잠재적 취약점으로 표시
            for param_name in params.keys():
                self.vulnerabilities.append({
                    'type': 'SQL Injection (Potential)',
                    'severity': 'critical',
                    'parameter': param_name,
                    'description': f'파라미터 "{param_name}"가 SQL Injection에 취약할 수 있습니다.',
                    'recommendation': 'Prepared Statements나 ORM을 사용하세요.'
                })

        except Exception as e:
            logger.debug(f"URL parameter scan error: {str(e)}")

    def _scan_forms(self):
        """폼 입력 필드에서 SQL Injection 검사"""
        try:
            response = self.session.get(self.url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')

            forms = soup.find_all('form')

            for idx, form in enumerate(forms):
                action = form.get('action', '')
                method = form.get('method', 'get').upper()

                inputs = form.find_all('input')
                text_inputs = [inp for inp in inputs if inp.get('type') in ['text', 'password', 'hidden', None]]

                if text_inputs:
                    self.vulnerabilities.append({
                        'type': 'SQL Injection (Potential)',
                        'severity': 'high',
                        'form_index': idx,
                        'action': action,
                        'method': method,
                        'inputs': len(text_inputs),
                        'description': f'폼이 SQL Injection에 취약할 수 있습니다.',
                        'recommendation': '입력값 검증과 Prepared Statements를 사용하세요.'
                    })

        except Exception as e:
            logger.debug(f"Form scan error: {str(e)}")

    def _scan_error_messages(self):
        """SQL 에러 메시지 노출 검사"""
        try:
            # 에러를 유발할 수 있는 간단한 요청
            test_url = self.url + ("&" if "?" in self.url else "?") + "test='"

            try:
                response = self.session.get(test_url, timeout=10)

                # SQL 에러 패턴 검색
                for pattern in self.ERROR_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        self.vulnerabilities.append({
                            'type': 'SQL Error Message Disclosure',
                            'severity': 'medium',
                            'pattern': pattern,
                            'description': 'SQL 에러 메시지가 노출되고 있습니다.',
                            'recommendation': '에러 메시지를 숨기고 로깅만 수행하세요.'
                        })
                        break

            except requests.RequestException:
                pass

        except Exception as e:
            logger.debug(f"Error message scan error: {str(e)}")


class SecurityHeaderScanner:
    """보안 헤더 스캐너 (강화 버전)"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'security_headers',
        'name': '보안 헤더 검사',
        'icon': '🛡️',
        'description': 'HTTP 보안 헤더 설정 검증',
        'weight': 1,
        'field': 'security_headers'
    }

    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'description': 'HTTPS 사용을 강제합니다',
            'severity': 'high',
            'recommendation': 'Strict-Transport-Security: max-age=31536000; includeSubDomains'
        },
        'Content-Security-Policy': {
            'description': 'XSS 및 데이터 주입 공격을 방지합니다',
            'severity': 'high',
            'recommendation': "Content-Security-Policy: default-src 'self'"
        },
        'X-Frame-Options': {
            'description': '클릭재킹 공격을 방지합니다',
            'severity': 'medium',
            'recommendation': 'X-Frame-Options: DENY 또는 SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'description': 'MIME 타입 스니핑을 방지합니다',
            'severity': 'medium',
            'recommendation': 'X-Content-Type-Options: nosniff'
        },
        'Referrer-Policy': {
            'description': 'Referrer 정보 노출을 제어합니다',
            'severity': 'low',
            'recommendation': 'Referrer-Policy: strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'description': '브라우저 기능 사용을 제어합니다',
            'severity': 'low',
            'recommendation': 'Permissions-Policy: geolocation=(), microphone=()'
        },
        'X-XSS-Protection': {
            'description': 'XSS 필터를 활성화합니다 (레거시)',
            'severity': 'low',
            'recommendation': 'X-XSS-Protection: 1; mode=block'
        }
    }

    def __init__(self, headers):
        self.headers = headers
        self.results = {}
        self.missing_headers = []

    def scan(self):
        """보안 헤더 스캔"""
        for header_name, header_info in self.SECURITY_HEADERS.items():
            if header_name in self.headers:
                self.results[header_name] = {
                    'present': True,
                    'value': self.headers[header_name],
                    'status': 'ok',
                    'description': header_info['description']
                }
            else:
                self.results[header_name] = {
                    'present': False,
                    'status': 'missing',
                    'severity': header_info['severity'],
                    'description': header_info['description'],
                    'recommendation': header_info['recommendation']
                }
                self.missing_headers.append(header_name)

        return {
            'headers': self.results,
            'missing_count': len(self.missing_headers),
            'total_count': len(self.SECURITY_HEADERS)
        }


class CORSScanner:
    """CORS 설정 스캐너"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'cors',
        'name': 'CORS 설정 검사',
        'icon': '🌐',
        'description': 'Cross-Origin Resource Sharing 설정 검증',
        'weight': 1,
        'field': 'cors_misconfiguration'
    }

    def __init__(self, url, headers):
        self.url = url
        self.headers = headers
        self.issues = []

    def scan(self):
        """CORS 설정 검사"""
        acao = self.headers.get('Access-Control-Allow-Origin')
        acac = self.headers.get('Access-Control-Allow-Credentials')

        if acao:
            # 위험한 CORS 설정 검사
            if acao == '*':
                if acac and acac.lower() == 'true':
                    self.issues.append({
                        'type': 'CORS Misconfiguration',
                        'severity': 'critical',
                        'description': 'Access-Control-Allow-Origin: * 와 Credentials: true가 함께 설정되어 있습니다.',
                        'recommendation': '특정 도메인만 허용하거나 Credentials를 비활성화하세요.'
                    })
                else:
                    self.issues.append({
                        'type': 'CORS Wildcard',
                        'severity': 'medium',
                        'description': 'Access-Control-Allow-Origin: * 가 설정되어 있습니다.',
                        'recommendation': '가능한 특정 도메인만 허용하세요.'
                    })

        return {
            'issues': self.issues,
            'has_cors': acao is not None,
            'misconfigured': len(self.issues) > 0
        }


class CookieScanner:
    """쿠키 보안 스캐너"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'cookie_security',
        'name': '쿠키 보안 검사',
        'icon': '🍪',
        'description': '쿠키 보안 속성 검증',
        'weight': 1,
        'field': 'sensitive_data_exposure'
    }

    def __init__(self, response):
        self.response = response
        self.issues = []

    def scan(self):
        """쿠키 보안 검사"""
        cookies = self.response.cookies

        for cookie in cookies:
            cookie_issues = []

            # Secure 플래그 검사
            if not cookie.secure:
                cookie_issues.append('Secure 플래그가 없습니다')

            # HttpOnly 플래그 검사
            if not cookie.has_nonstandard_attr('HttpOnly'):
                cookie_issues.append('HttpOnly 플래그가 없습니다')

            # SameSite 속성 검사
            if not cookie.has_nonstandard_attr('SameSite'):
                cookie_issues.append('SameSite 속성이 없습니다')

            if cookie_issues:
                self.issues.append({
                    'type': 'Insecure Cookie',
                    'severity': 'medium',
                    'cookie_name': cookie.name,
                    'issues': cookie_issues,
                    'description': f'쿠키 "{cookie.name}"의 보안 설정이 부족합니다.',
                    'recommendation': 'Secure, HttpOnly, SameSite 속성을 설정하세요.'
                })

        return {
            'issues': self.issues,
            'total_cookies': len(cookies),
            'insecure_cookies': len(self.issues)
        }


class CSRFScanner:
    """CSRF 보호 검사 스캐너"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'csrf',
        'name': 'CSRF 보호 검사',
        'icon': '🔒',
        'description': 'Cross-Site Request Forgery 방어 검증',
        'weight': 1.5,
        'field': 'csrf_protection'
    }

    def __init__(self, url, session=None):
        self.url = url
        self.session = session or requests.Session()
        self.issues = []

    def scan(self):
        """CSRF 보호 검사"""
        try:
            response = self.session.get(self.url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')

            # 폼 검사
            forms = soup.find_all('form')

            for idx, form in enumerate(forms):
                method = form.get('method', 'get').upper()

                # POST 메서드인 폼만 검사
                if method == 'POST':
                    # CSRF 토큰 찾기
                    csrf_token = None

                    # 일반적인 CSRF 토큰 필드명
                    csrf_field_names = [
                        'csrf_token', 'csrfmiddlewaretoken', '_token',
                        'authenticity_token', '__RequestVerificationToken',
                        'csrf', '_csrf', 'token'
                    ]

                    inputs = form.find_all('input')
                    for input_field in inputs:
                        name = input_field.get('name', '').lower()
                        if any(csrf_name in name for csrf_name in csrf_field_names):
                            csrf_token = input_field.get('value')
                            break

                    if not csrf_token:
                        self.issues.append({
                            'type': 'Missing CSRF Protection',
                            'severity': 'high',
                            'form_index': idx,
                            'form_action': form.get('action', '/'),
                            'description': 'POST 폼에 CSRF 토큰이 없습니다.',
                            'recommendation': 'CSRF 토큰을 추가하여 CSRF 공격을 방지하세요.'
                        })

            return {
                'issues': self.issues,
                'total_forms': len(forms),
                'vulnerable_forms': len(self.issues),
                'has_csrf_protection': len(self.issues) == 0
            }

        except Exception as e:
            logger.error(f"CSRF scan error: {str(e)}")
            return {
                'issues': [],
                'total_forms': 0,
                'vulnerable_forms': 0,
                'has_csrf_protection': True,
                'error': str(e)
            }


class ClickjackingScanner:
    """클릭재킹 방어 검사 스캐너"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'clickjacking',
        'name': '클릭재킹 방어 검사',
        'icon': '🖱️',
        'description': 'Clickjacking 공격 방어 검증',
        'weight': 1,
        'field': 'clickjacking'
    }

    def __init__(self, headers, html_content):
        self.headers = headers
        self.html_content = html_content
        self.issues = []

    def scan(self):
        """클릭재킹 방어 검사"""
        try:
            # X-Frame-Options 헤더 검사
            x_frame_options = self.headers.get('X-Frame-Options')
            csp = self.headers.get('Content-Security-Policy')

            has_xfo = False
            has_csp_frame = False

            if x_frame_options:
                xfo_value = x_frame_options.upper()
                if xfo_value in ['DENY', 'SAMEORIGIN']:
                    has_xfo = True
                elif xfo_value.startswith('ALLOW-FROM'):
                    has_xfo = True
                    self.issues.append({
                        'type': 'Deprecated X-Frame-Options',
                        'severity': 'low',
                        'description': 'ALLOW-FROM은 더 이상 권장되지 않습니다.',
                        'recommendation': 'CSP frame-ancestors를 사용하세요.'
                    })

            # CSP frame-ancestors 검사
            if csp:
                if 'frame-ancestors' in csp:
                    has_csp_frame = True

            # 둘 다 없으면 취약
            if not has_xfo and not has_csp_frame:
                self.issues.append({
                    'type': 'Missing Clickjacking Protection',
                    'severity': 'high',
                    'description': 'X-Frame-Options 또는 CSP frame-ancestors가 설정되지 않았습니다.',
                    'recommendation': 'X-Frame-Options: DENY 또는 CSP frame-ancestors를 설정하세요.'
                })

            return {
                'issues': self.issues,
                'has_xfo': has_xfo,
                'has_csp_frame': has_csp_frame,
                'protected': has_xfo or has_csp_frame
            }

        except Exception as e:
            logger.error(f"Clickjacking scan error: {str(e)}")
            return {
                'issues': [],
                'has_xfo': False,
                'has_csp_frame': False,
                'protected': False,
                'error': str(e)
            }


class InformationDisclosureScanner:
    """정보 노출 검사 스캐너"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'information_disclosure',
        'name': '정보 노출 검사',
        'icon': '📝',
        'description': '민감한 정보 노출 탐지',
        'weight': 1,
        'field': 'insufficient_logging'
    }

    SENSITIVE_PATTERNS = [
        # 에러 메시지
        (r'Fatal error:', 'PHP Fatal Error', 'high'),
        (r'Warning: mysql_', 'MySQL Warning', 'medium'),
        (r'Traceback \(most recent call last\)', 'Python Traceback', 'high'),
        (r'Exception in thread', 'Java Exception', 'medium'),
        (r'Microsoft OLE DB Provider for SQL Server', 'SQL Server Error', 'high'),

        # 민감한 정보
        (r'password\s*=\s*["\'][^"\']+["\']', 'Password in Source', 'critical'),
        (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', 'API Key in Source', 'critical'),
        (r'secret[_-]?key\s*=\s*["\'][^"\']+["\']', 'Secret Key in Source', 'critical'),
        (r'aws[_-]?access[_-]?key', 'AWS Access Key', 'critical'),

        # 서버 정보
        (r'/home/[^/]+/', 'Linux Path Disclosure', 'low'),
        (r'C:\\\\', 'Windows Path Disclosure', 'low'),

        # 내부 IP
        (r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Internal IP (10.x.x.x)', 'low'),
        (r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}', 'Internal IP (172.16-31.x.x)', 'low'),
        (r'192\.168\.\d{1,3}\.\d{1,3}', 'Internal IP (192.168.x.x)', 'low'),
    ]

    def __init__(self, response):
        self.response = response
        self.issues = []

    def scan(self):
        """정보 노출 검사"""
        try:
            html_text = self.response.text

            # 패턴 검색
            for pattern, description, severity in self.SENSITIVE_PATTERNS:
                matches = re.findall(pattern, html_text, re.IGNORECASE)
                if matches:
                    # 중복 제거 및 최대 3개만
                    unique_matches = list(set(matches))[:3]

                    self.issues.append({
                        'type': 'Information Disclosure',
                        'severity': severity,
                        'description': f'{description} 발견: {len(unique_matches)}개',
                        'evidence': unique_matches,
                        'recommendation': '민감한 정보를 소스 코드에서 제거하고, 에러 메시지를 사용자에게 노출하지 마세요.'
                    })

            # Server 헤더 검사
            server_header = self.response.headers.get('Server')
            if server_header:
                self.issues.append({
                    'type': 'Server Header Disclosure',
                    'severity': 'low',
                    'description': f'서버 정보가 노출되고 있습니다: {server_header}',
                    'recommendation': 'Server 헤더를 제거하거나 일반적인 값으로 변경하세요.'
                })

            # X-Powered-By 헤더 검사
            powered_by = self.response.headers.get('X-Powered-By')
            if powered_by:
                self.issues.append({
                    'type': 'X-Powered-By Header Disclosure',
                    'severity': 'low',
                    'description': f'기술 스택 정보가 노출되고 있습니다: {powered_by}',
                    'recommendation': 'X-Powered-By 헤더를 제거하세요.'
                })

            return {
                'issues': self.issues,
                'total': len(self.issues),
                'has_disclosure': len(self.issues) > 0
            }

        except Exception as e:
            logger.error(f"Information disclosure scan error: {str(e)}")
            return {
                'issues': [],
                'total': 0,
                'has_disclosure': False,
                'error': str(e)
            }


class HTTPMethodScanner:
    """안전하지 않은 HTTP 메서드 검사 스캐너"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'http_methods',
        'name': 'HTTP 메서드 검사',
        'icon': '📡',
        'description': '위험한 HTTP 메서드 활성화 검사',
        'weight': 0.5,
        'field': 'http_methods'
    }

    DANGEROUS_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'OPTIONS']

    def __init__(self, url, session=None):
        self.url = url
        self.session = session or requests.Session()
        self.issues = []

    def scan(self):
        """HTTP 메서드 검사"""
        try:
            # OPTIONS 요청으로 허용된 메서드 확인
            try:
                response = self.session.options(self.url, timeout=10)
                allowed_methods = response.headers.get('Allow', '')

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
                        'recommendation': '불필요한 HTTP 메서드를 비활성화하세요.'
                    })

            except requests.RequestException:
                pass

            # TRACE 메서드 직접 테스트
            try:
                trace_response = self.session.request('TRACE', self.url, timeout=10)
                if trace_response.status_code != 405:  # Method Not Allowed가 아니면
                    self.issues.append({
                        'type': 'TRACE Method Enabled',
                        'severity': 'medium',
                        'description': 'TRACE 메서드가 활성화되어 있습니다. (XST 공격 가능)',
                        'recommendation': 'TRACE 메서드를 비활성화하세요.'
                    })
            except requests.RequestException:
                pass

            return {
                'issues': self.issues,
                'total': len(self.issues),
                'has_dangerous_methods': len(self.issues) > 0
            }

        except Exception as e:
            logger.error(f"HTTP method scan error: {str(e)}")
            return {
                'issues': [],
                'total': 0,
                'has_dangerous_methods': False,
                'error': str(e)
            }


class SensitiveFileScanner:
    """민감한 파일 노출 검사 스캐너"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'sensitive_files',
        'name': '민감한 파일 노출 검사',
        'icon': '📁',
        'description': '설정 파일, 백업 파일 등 노출 검사',
        'weight': 1.5,
        'field': 'sensitive_files'
    }

    SENSITIVE_FILES = [
        # 버전 관리
        '.git/config', '.git/HEAD', '.svn/entries', '.hg/hgrc',

        # 백업 파일
        'backup.zip', 'backup.sql', 'backup.tar.gz', 'database.sql',
        'db.sql', 'dump.sql', 'site.zip', 'www.zip',

        # 설정 파일
        '.env', '.env.local', '.env.production', 'config.php',
        'configuration.php', 'settings.py', 'web.config',

        # 로그 파일
        'error.log', 'access.log', 'error_log', 'debug.log',

        # 기타
        'phpinfo.php', '.htaccess', 'composer.json', 'package.json',
        'Dockerfile', 'docker-compose.yml', 'robots.txt', 'sitemap.xml',
    ]

    def __init__(self, url, session=None):
        self.url = url
        self.session = session or requests.Session()
        self.issues = []

    def scan(self):
        """민감한 파일 검사 (최대 10개만 테스트)"""
        try:
            parsed = urlparse(self.url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # 최대 10개만 테스트 (성능 고려)
            files_to_test = self.SENSITIVE_FILES[:10]

            for file_path in files_to_test:
                test_url = urljoin(base_url, file_path)

                try:
                    response = self.session.get(test_url, timeout=5, allow_redirects=False)

                    # 200 OK이고 실제 컨텐츠가 있으면
                    if response.status_code == 200 and len(response.content) > 0:
                        # 404 페이지가 아닌지 확인
                        if '404' not in response.text.lower() and 'not found' not in response.text.lower():
                            severity = 'critical' if file_path in ['.env', '.git/config', 'backup.sql', 'database.sql'] else 'high'

                            self.issues.append({
                                'type': 'Sensitive File Exposed',
                                'severity': severity,
                                'file': file_path,
                                'url': test_url,
                                'description': f'민감한 파일이 노출되어 있습니다: {file_path}',
                                'recommendation': '해당 파일에 대한 접근을 차단하세요.'
                            })

                except requests.RequestException:
                    pass

            return {
                'issues': self.issues,
                'total': len(self.issues),
                'has_exposed_files': len(self.issues) > 0
            }

        except Exception as e:
            logger.error(f"Sensitive file scan error: {str(e)}")
            return {
                'issues': [],
                'total': 0,
                'has_exposed_files': False,
                'error': str(e)
            }


class MixedContentScanner:
    """Mixed Content 검사 스캐너 (HTTPS 페이지에서 HTTP 리소스 로딩)"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'mixed_content',
        'name': 'Mixed Content 검사',
        'icon': '🔗',
        'description': 'HTTPS 페이지의 HTTP 리소스 검사',
        'weight': 0.5,
        'field': 'mixed_content'
    }

    def __init__(self, url, html_content):
        self.url = url
        self.html_content = html_content
        self.issues = []

    def scan(self):
        """Mixed Content 검사"""
        try:
            parsed = urlparse(self.url)

            # HTTPS 페이지에서만 검사
            if parsed.scheme != 'https':
                return {
                    'issues': [],
                    'total': 0,
                    'has_mixed_content': False,
                    'message': 'HTTPS가 아닌 페이지는 검사하지 않습니다.'
                }

            soup = BeautifulSoup(self.html_content, 'html.parser')

            # HTTP 리소스 찾기
            http_resources = []

            # 이미지
            for img in soup.find_all('img', src=True):
                src = img.get('src')
                if src.startswith('http://'):
                    http_resources.append(('image', src))

            # 스크립트
            for script in soup.find_all('script', src=True):
                src = script.get('src')
                if src.startswith('http://'):
                    http_resources.append(('script', src))

            # 스타일시트
            for link in soup.find_all('link', href=True, rel='stylesheet'):
                href = link.get('href')
                if href.startswith('http://'):
                    http_resources.append(('stylesheet', src))

            if http_resources:
                # 유형별로 그룹화
                by_type = {}
                for resource_type, resource_url in http_resources[:10]:  # 최대 10개
                    if resource_type not in by_type:
                        by_type[resource_type] = []
                    by_type[resource_type].append(resource_url)

                self.issues.append({
                    'type': 'Mixed Content',
                    'severity': 'medium',
                    'total_resources': len(http_resources),
                    'by_type': by_type,
                    'description': f'HTTPS 페이지에서 {len(http_resources)}개의 HTTP 리소스를 로딩하고 있습니다.',
                    'recommendation': '모든 리소스를 HTTPS로 변경하세요.'
                })

            return {
                'issues': self.issues,
                'total': len(self.issues),
                'has_mixed_content': len(self.issues) > 0
            }

        except Exception as e:
            logger.error(f"Mixed content scan error: {str(e)}")
            return {
                'issues': [],
                'total': 0,
                'has_mixed_content': False,
                'error': str(e)
            }


class SubresourceIntegrityScanner:
    """SRI (Subresource Integrity) 검사 스캐너"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'sri',
        'name': 'SRI 검사',
        'icon': '✓',
        'description': 'Subresource Integrity 검증',
        'weight': 0.5,
        'field': 'sri_check'
    }

    def __init__(self, html_content):
        self.html_content = html_content
        self.issues = []

    def scan(self):
        """SRI 검사"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')

            # CDN에서 로드되는 스크립트 찾기
            external_scripts = []
            external_styles = []

            # 스크립트 검사
            for script in soup.find_all('script', src=True):
                src = script.get('src')
                # 외부 도메인 (CDN 등)
                if src and ('://' in src):
                    integrity = script.get('integrity')
                    if not integrity:
                        external_scripts.append(src)

            # 스타일시트 검사
            for link in soup.find_all('link', href=True, rel='stylesheet'):
                href = link.get('href')
                if href and ('://' in href):
                    integrity = link.get('integrity')
                    if not integrity:
                        external_styles.append(href)

            if external_scripts:
                self.issues.append({
                    'type': 'Missing SRI for Scripts',
                    'severity': 'medium',
                    'count': len(external_scripts),
                    'examples': external_scripts[:3],
                    'description': f'{len(external_scripts)}개의 외부 스크립트에 SRI가 없습니다.',
                    'recommendation': 'integrity 속성을 추가하여 리소스 무결성을 검증하세요.'
                })

            if external_styles:
                self.issues.append({
                    'type': 'Missing SRI for Stylesheets',
                    'severity': 'low',
                    'count': len(external_styles),
                    'examples': external_styles[:3],
                    'description': f'{len(external_styles)}개의 외부 스타일시트에 SRI가 없습니다.',
                    'recommendation': 'integrity 속성을 추가하세요.'
                })

            return {
                'issues': self.issues,
                'total': len(self.issues),
                'missing_sri': len(self.issues) > 0
            }

        except Exception as e:
            logger.error(f"SRI scan error: {str(e)}")
            return {
                'issues': [],
                'total': 0,
                'missing_sri': False,
                'error': str(e)
            }


class DirectoryListingScanner:
    """디렉토리 리스팅 검사 스캐너"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'directory_listing',
        'name': '디렉토리 리스팅 검사',
        'icon': '📂',
        'description': '디렉토리 목록 노출 검사',
        'weight': 0.5,
        'field': 'directory_listing'
    }

    DIRECTORY_PATTERNS = [
        r'<title>Index of /',
        r'<h1>Index of /',
        r'Parent Directory',
        r'<a href="\.\./">\.\./</',
        r'Directory listing for /',
    ]

    def __init__(self, url, session=None):
        self.url = url
        self.session = session or requests.Session()
        self.issues = []

    def scan(self):
        """디렉토리 리스팅 검사"""
        try:
            response = self.session.get(self.url, timeout=10)

            # 디렉토리 리스팅 패턴 검색
            for pattern in self.DIRECTORY_PATTERNS:
                if re.search(pattern, response.text, re.IGNORECASE):
                    self.issues.append({
                        'type': 'Directory Listing Enabled',
                        'severity': 'medium',
                        'description': '디렉토리 리스팅이 활성화되어 있습니다.',
                        'recommendation': '웹 서버에서 디렉토리 리스팅을 비활성화하세요.'
                    })
                    break

            return {
                'issues': self.issues,
                'total': len(self.issues),
                'has_listing': len(self.issues) > 0
            }

        except Exception as e:
            logger.error(f"Directory listing scan error: {str(e)}")
            return {
                'issues': [],
                'total': 0,
                'has_listing': False,
                'error': str(e)
            }


class OpenRedirectScanner:
    """Open Redirect 취약점 검사 스캐너"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'open_redirect',
        'name': 'Open Redirect 검사',
        'icon': '↗️',
        'description': '오픈 리다이렉트 취약점 탐지',
        'weight': 1,
        'field': 'open_redirects'
    }

    REDIRECT_PARAMS = [
        'url', 'redirect', 'redirect_url', 'next', 'return', 'returnurl',
        'redir', 'target', 'dest', 'destination', 'continue', 'goto'
    ]

    def __init__(self, url):
        self.url = url
        self.issues = []

    def scan(self):
        """Open Redirect 검사"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            # 리다이렉트 파라미터 찾기
            found_params = []
            for param_name in params.keys():
                if param_name.lower() in self.REDIRECT_PARAMS:
                    found_params.append(param_name)

            if found_params:
                self.issues.append({
                    'type': 'Potential Open Redirect',
                    'severity': 'medium',
                    'parameters': found_params,
                    'description': f'Open Redirect에 취약할 수 있는 파라미터 발견: {", ".join(found_params)}',
                    'recommendation': '리다이렉트 URL을 화이트리스트로 검증하세요.'
                })

            return {
                'issues': self.issues,
                'total': len(self.issues),
                'has_open_redirect': len(self.issues) > 0
            }

        except Exception as e:
            logger.error(f"Open redirect scan error: {str(e)}")
            return {
                'issues': [],
                'total': 0,
                'has_open_redirect': False,
                'error': str(e)
            }
