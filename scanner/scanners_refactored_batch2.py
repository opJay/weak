"""
Batch 2 스캐너들 - XSSScanner, SQLInjectionScanner, CSRFScanner,
InformationDisclosureScanner, MixedContentScanner

BaseScanner를 상속받아 표준화된 인터페이스 제공
탐지 정확도 향상 및 테스트 가능한 구조
"""

import logging
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import requests

from .base import BaseScanner

logger = logging.getLogger(__name__)


class XSSScanner(BaseScanner):
    """Cross-Site Scripting (XSS) 취약점 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'xss',
        'name': 'XSS 취약점 스캔',
        'icon': '⚠️',
        'description': 'Cross-Site Scripting 취약점 탐지',
        'weight': 2,
        'field': 'xss_vulnerabilities'
    }

    # XSS 테스트 페이로드 (탐지용, 실제 공격 X)
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg/onload=alert('XSS')>",
        "'><script>alert('XSS')</script>",
        '"><img src=x onerror=alert(1)>',
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
    ]

    # 위험한 패턴 (HTML 콘텐츠에서 찾을 것)
    DANGEROUS_PATTERNS = [
        (r'<script[^>]*>.*?</script>', 'script tag', 'critical'),
        (r'\bon\w+\s*=\s*["\'].*?["\']', 'event handler', 'high'),  # \b 추가로 단어 경계 확인
        (r'javascript:\s*[^"\s]+', 'javascript: protocol', 'high'),
        (r'<iframe[^>]*>', 'iframe', 'medium'),
        (r'<embed[^>]*>', 'embed tag', 'medium'),
        (r'<object[^>]*>', 'object tag', 'medium'),
        (r'eval\s*\(', 'eval() function', 'high'),
        (r'document\.write\s*\(', 'document.write', 'medium'),
        (r'innerHTML\s*=', 'innerHTML assignment', 'medium'),
        (r'outerHTML\s*=', 'outerHTML assignment', 'medium'),
    ]

    # 안전하지 않은 인코딩 패턴
    UNSAFE_ENCODING_PATTERNS = [
        (r'decodeURI\(', 'URL decoding without validation'),
        (r'unescape\(', 'unescape function (deprecated)'),
        (r'document\.URL', 'direct URL access'),
        (r'document\.referrer', 'referrer access'),
        (r'location\.hash', 'hash parameter access'),
    ]

    def __init__(self, url: str = '', html_content: str = None, **kwargs):
        """
        Args:
            url: 스캔할 URL
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url, html_content=html_content, **kwargs)

        # HTML 콘텐츠 설정
        if html_content:
            self.html_content = html_content
        elif hasattr(self, 'response') and self.response:
            self.html_content = getattr(self.response, 'text', '')
        else:
            self.html_content = ''

        # 세션 설정
        if hasattr(self, 'response') and self.response:
            self.session = getattr(self.response, 'session', None)
        else:
            self.session = kwargs.get('session', requests.Session())

        self.issues = []

    def _execute_scan(self) -> None:
        """XSS 스캔 실행"""
        if not self.html_content and not self.url:
            return

        # 1. Reflected XSS 검사 (URL 파라미터)
        self._scan_reflected_xss()

        # 2. DOM-based XSS 검사 (JavaScript 패턴)
        self._scan_dom_xss()

        # 3. Stored XSS 징후 검사 (위험한 패턴)
        self._scan_stored_xss_patterns()

        # 4. 입력 폼 검사
        self._scan_forms()

        # 5. CSP 헤더 검사
        self._check_csp_header()

    def _scan_reflected_xss(self) -> None:
        """Reflected XSS 검사 - URL 파라미터"""
        if not self.url or not self.html_content:
            return

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        if not params:
            return

        # URL에 파라미터가 있고 해당 값이 HTML에 나타나는지 확인
        for param_name, values in params.items():
            for value in values:
                # HTML에서 파라미터 값이 나타나는지 확인
                if value in self.html_content:
                    # XSS 페이로드인지 확인 (script 태그 등)
                    is_xss_payload = any(pattern in value.lower() for pattern in ['<script', '<img', 'onerror', 'javascript:'])

                    # 이스케이프 되지 않은 형태로 나타나는지 확인
                    if is_xss_payload and self._is_unescaped_in_html(value):
                        self.issues.append({
                            'type': 'Reflected XSS',
                            'severity': 'high',
                            'parameter': param_name,
                            'value': value[:50],  # 처음 50자만
                            'description': f'URL 파라미터 "{param_name}"의 값이 이스케이프 없이 출력됩니다.',
                            'evidence': self._find_evidence(value),
                            'recommendation': 'HTML 엔티티 인코딩을 적용하세요.'
                        })

    def _scan_dom_xss(self) -> None:
        """DOM-based XSS 검사"""
        if not self.html_content:
            return

        # 위험한 JavaScript 패턴 검색
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', self.html_content, re.DOTALL | re.IGNORECASE)

        for script in scripts:
            # URL/hash 파라미터를 직접 사용하는 패턴
            dangerous_sources = [
                (r'location\.search', 'URL search parameters'),
                (r'location\.hash', 'URL hash'),
                (r'document\.referrer', 'document referrer'),
                (r'document\.URL', 'document URL'),
                (r'document\.documentURI', 'document URI'),
            ]

            dangerous_sinks = [
                (r'innerHTML\s*=', 'innerHTML'),
                (r'outerHTML\s*=', 'outerHTML'),
                (r'document\.write\(', 'document.write'),
                (r'eval\(', 'eval'),
                (r'setTimeout\(', 'setTimeout'),
                (r'setInterval\(', 'setInterval'),
            ]

            # Source와 Sink가 같은 스크립트 블록에 있는지 확인
            has_source = False
            source_type = None
            for pattern, desc in dangerous_sources:
                if re.search(pattern, script):
                    has_source = True
                    source_type = desc
                    break

            if has_source:
                for pattern, desc in dangerous_sinks:
                    if re.search(pattern, script):
                        self.issues.append({
                            'type': 'DOM-based XSS',
                            'severity': 'high',
                            'source': source_type,
                            'sink': desc,
                            'description': f'사용자 입력({source_type})이 {desc}로 전달될 수 있습니다.',
                            'evidence': script[:200],
                            'recommendation': '사용자 입력을 DOM에 직접 삽입하지 마세요. textContent나 setAttribute를 사용하세요.'
                        })

    def _scan_stored_xss_patterns(self) -> None:
        """Stored XSS 가능성 있는 패턴 검사"""
        if not self.html_content:
            return

        # 위험한 HTML 패턴 검색
        for pattern, desc, severity in self.DANGEROUS_PATTERNS:
            matches = re.findall(pattern, self.html_content, re.IGNORECASE)
            if matches:
                # 스크립트 태그는 하나만, 이벤트 핸들러는 최대 3개까지 보고
                report_matches = matches[:1] if 'script' in desc else matches[:3]

                for match in report_matches:
                    # 정상적인 스크립트인지 확인 (src 속성이 있는 경우 제외)
                    if 'script' in desc and 'src=' in match:
                        continue

                    self.issues.append({
                        'type': 'Potential Stored XSS',
                        'severity': severity,
                        'pattern': desc,
                        'description': f'위험한 패턴 발견: {desc}',
                        'evidence': match[:100],
                        'recommendation': '사용자 입력은 항상 이스케이프하고, CSP를 구현하세요.'
                    })

    def _scan_forms(self) -> None:
        """입력 폼의 XSS 방어 검사"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')
        forms = soup.find_all('form')

        for idx, form in enumerate(forms):
            # 폼에서 위험한 입력 타입 확인
            inputs = form.find_all(['input', 'textarea'])

            vulnerable_inputs = []
            for input_field in inputs:
                input_type = input_field.get('type', 'text')
                input_name = input_field.get('name', 'unnamed')

                # 위험한 입력 타입
                if input_type in ['text', 'search', 'url', 'email', 'textarea']:
                    # 클라이언트 측 검증만 있는지 확인
                    if input_field.get('pattern') and not input_field.get('maxlength'):
                        vulnerable_inputs.append({
                            'name': input_name,
                            'type': input_type,
                            'issue': 'pattern 검증만 있음 (클라이언트 측)'
                        })

                    # HTML5 검증에만 의존하는지
                    if input_field.get('required') and not form.get('novalidate'):
                        # 서버 측 검증 힌트가 없는 경우
                        if 'token' not in str(form).lower() and 'csrf' not in str(form).lower():
                            vulnerable_inputs.append({
                                'name': input_name,
                                'type': input_type,
                                'issue': 'HTML5 검증에만 의존'
                            })

            if vulnerable_inputs:
                self.issues.append({
                    'type': 'Form XSS Risk',
                    'severity': 'medium',
                    'form_index': idx,
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'vulnerable_inputs': vulnerable_inputs[:3],  # 최대 3개만
                    'description': '폼 입력이 XSS에 취약할 수 있습니다.',
                    'recommendation': '서버 측 입력 검증과 출력 시 이스케이프를 구현하세요.'
                })

    def _check_csp_header(self) -> None:
        """Content-Security-Policy 헤더 검사"""
        if hasattr(self, 'response') and self.response:
            headers = getattr(self.response, 'headers', {})
            csp = headers.get('Content-Security-Policy', '')

            if not csp:
                self.issues.append({
                    'type': 'Missing CSP',
                    'severity': 'medium',
                    'description': 'Content-Security-Policy 헤더가 설정되지 않았습니다.',
                    'recommendation': "CSP 헤더를 설정하여 XSS 공격을 완화하세요. 예: Content-Security-Policy: default-src 'self'"
                })
            elif 'unsafe-inline' in csp or 'unsafe-eval' in csp:
                self.issues.append({
                    'type': 'Weak CSP',
                    'severity': 'medium',
                    'description': 'CSP에 unsafe-inline 또는 unsafe-eval이 포함되어 있습니다.',
                    'evidence': csp,
                    'recommendation': 'unsafe-inline과 unsafe-eval을 제거하고 nonce나 hash를 사용하세요.'
                })

    def _is_unescaped_in_html(self, value: str) -> bool:
        """값이 HTML에서 이스케이프되지 않았는지 확인"""
        if not self.html_content or not value:
            return False

        # XSS 위험 문자가 포함되어 있는지 확인
        dangerous_chars = ['<', '>', '"', "'", '&']
        has_dangerous = any(char in value for char in dangerous_chars)

        if not has_dangerous:
            return False  # 위험한 문자가 없으면 체크할 필요 없음

        # 원본 값이 그대로 HTML에 있으면 이스케이프되지 않은 것
        if value in self.html_content:
            # 특히 <script> 태그 같은 경우는 그대로 있으면 문제
            if '<script' in value.lower() or '<img' in value.lower():
                return True

            # 일반적인 경우도 원본이 그대로 있으면 이스케이프 안 됨
            return True

        return False

    def _find_evidence(self, value: str) -> str:
        """HTML에서 증거 추출"""
        if not self.html_content or not value:
            return ''

        # 값 주변 컨텍스트 찾기
        idx = self.html_content.find(value)
        if idx != -1:
            start = max(0, idx - 50)
            end = min(len(self.html_content), idx + len(value) + 50)
            return self.html_content[start:end]
        return ''

    def _build_vulnerabilities(self) -> List[Dict[str, Any]]:
        """issues를 vulnerabilities 형식으로 변환"""
        return self.issues

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        # 심각도별 집계
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for issue in self.issues:
            severity = issue.get('severity', 'low')
            severity_counts[severity] += 1

        return {
            'has_xss': len(self.issues) > 0,
            'critical_count': severity_counts['critical'],
            'high_count': severity_counts['high'],
            'medium_count': severity_counts['medium'],
            'types': list(set(issue['type'] for issue in self.issues))
        }


class SQLInjectionScanner(BaseScanner):
    """SQL Injection 취약점 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'sql_injection',
        'name': 'SQL Injection 스캔',
        'icon': '💉',
        'description': 'SQL 주입 취약점 탐지',
        'weight': 2,
        'field': 'sql_injection'
    }

    # SQL 에러 패턴 (더 포괄적)
    ERROR_PATTERNS = [
        # MySQL
        (r'SQL syntax.*?MySQL', 'MySQL syntax error', 'critical'),
        (r'MySQL Error:', 'MySQL error', 'critical'),
        (r'You have an error in your SQL syntax', 'MySQL syntax error', 'critical'),
        (r'Warning.*?mysql_', 'MySQL warning', 'high'),
        (r'valid MySQL result', 'MySQL result error', 'high'),
        (r'MySQLSyntaxErrorException', 'MySQL exception', 'critical'),

        # PostgreSQL
        (r'PostgreSQL.*?ERROR', 'PostgreSQL error', 'critical'),
        (r'Warning.*?pg_', 'PostgreSQL warning', 'high'),
        (r'valid PostgreSQL result', 'PostgreSQL result error', 'high'),
        (r'PSQLException', 'PostgreSQL exception', 'critical'),

        # MS SQL Server
        (r'Driver.*?SQL Server', 'SQL Server driver error', 'critical'),
        (r'OLE DB.*?SQL Server', 'SQL Server OLE DB error', 'critical'),
        (r'Microsoft SQL Native Client', 'SQL Server native client error', 'critical'),
        (r'SqlException', 'SQL Server exception', 'critical'),

        # Oracle
        (r'ORA-[0-9]{5}', 'Oracle error', 'critical'),
        (r'Oracle error', 'Oracle error message', 'critical'),
        (r'Oracle.*?Driver', 'Oracle driver error', 'critical'),
        (r'OracleException', 'Oracle exception', 'critical'),

        # SQLite
        (r'sqlite3\.OperationalError', 'SQLite error', 'high'),
        (r'SQLite error', 'SQLite error message', 'high'),
        (r'sqlite3\.DatabaseError', 'SQLite database error', 'high'),

        # General
        (r'SQL error', 'Generic SQL error', 'high'),
        (r'SQLSTATE\[', 'SQL state error', 'high'),
        (r'Invalid query', 'Invalid query error', 'medium'),
        (r'Unclosed quotation mark', 'Unclosed quote', 'critical'),
    ]

    # 의심스러운 파라미터 이름
    SUSPICIOUS_PARAMS = [
        'id', 'user_id', 'product_id', 'category_id', 'item_id',
        'page', 'sort', 'order', 'filter', 'search', 'query',
        'username', 'email', 'name', 'table', 'column',
        'select', 'where', 'from', 'union', 'join'
    ]

    # 위험한 SQL 함수/키워드 (페이지에 노출되면 안 됨)
    DANGEROUS_SQL_EXPOSURE = [
        'UNION SELECT', 'DROP TABLE', 'UPDATE SET', 'DELETE FROM',
        'INSERT INTO', 'EXEC(', 'EXECUTE(', 'sp_executesql',
        'xp_cmdshell', 'INFORMATION_SCHEMA', 'sysobjects', 'syscolumns'
    ]

    def __init__(self, url: str = '', html_content: str = None, **kwargs):
        """
        Args:
            url: 스캔할 URL
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url, html_content=html_content, **kwargs)

        # HTML 콘텐츠 설정
        if html_content:
            self.html_content = html_content
        elif hasattr(self, 'response') and self.response:
            self.html_content = getattr(self.response, 'text', '')
        else:
            self.html_content = ''

        self.issues = []

    def _execute_scan(self) -> None:
        """SQL Injection 스캔 실행"""
        # 1. URL 파라미터 분석
        self._analyze_url_parameters()

        # 2. SQL 에러 메시지 검사
        self._scan_error_messages()

        # 3. 폼 입력 분석
        self._analyze_forms()

        # 4. SQL 키워드 노출 검사
        self._scan_sql_keyword_exposure()

        # 5. 시간 기반 공격 가능성 검사
        self._check_time_based_sqli_possibility()

    def _analyze_url_parameters(self) -> None:
        """URL 파라미터에서 SQL Injection 가능성 분석"""
        if not self.url:
            return

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        if not params:
            return

        for param_name, values in params.items():
            risk_level = 'low'
            risk_factors = []

            # 의심스러운 파라미터 이름인지 확인
            if param_name.lower() in self.SUSPICIOUS_PARAMS:
                risk_level = 'medium'
                risk_factors.append(f'의심스러운 파라미터 이름: {param_name}')

            # 숫자 ID 패턴인지 확인
            for value in values:
                if value.isdigit():
                    risk_level = 'high' if risk_level == 'medium' else 'medium'
                    risk_factors.append('숫자 ID 파라미터 (Blind SQLi 가능성)')

                # 특수 문자가 포함된 경우
                if any(char in value for char in ["'", '"', ';', '--', '/*']):
                    risk_level = 'high'
                    risk_factors.append('SQL 특수 문자 포함')

            if risk_factors:
                self.issues.append({
                    'type': 'SQL Injection Risk',
                    'severity': risk_level,
                    'parameter': param_name,
                    'value': values[0][:50] if values else '',
                    'risk_factors': risk_factors,
                    'description': f'파라미터 "{param_name}"가 SQL Injection에 취약할 수 있습니다.',
                    'recommendation': 'Prepared Statements 또는 파라미터화된 쿼리를 사용하세요.'
                })

    def _scan_error_messages(self) -> None:
        """SQL 에러 메시지 노출 검사"""
        if not self.html_content:
            return

        found_errors = []
        for pattern, desc, severity in self.ERROR_PATTERNS:
            matches = re.findall(pattern, self.html_content, re.IGNORECASE)
            if matches:
                found_errors.append({
                    'type': 'SQL Error Exposure',
                    'severity': severity,
                    'error_type': desc,
                    'description': f'SQL 에러 메시지가 노출됨: {desc}',
                    'evidence': matches[0][:200] if matches else '',
                    'recommendation': '프로덕션 환경에서는 상세한 에러 메시지를 숨기세요.'
                })

        # 중복 제거하고 가장 심각한 것들만 보고
        if found_errors:
            # 심각도 순으로 정렬
            found_errors.sort(key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x['severity']])
            self.issues.extend(found_errors[:3])  # 최대 3개만

    def _analyze_forms(self) -> None:
        """폼 입력 필드의 SQL Injection 위험 분석"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')
        forms = soup.find_all('form')

        for idx, form in enumerate(forms):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()

            # 위험한 입력 필드 찾기
            risky_inputs = []
            inputs = form.find_all(['input', 'textarea', 'select'])

            for input_field in inputs:
                input_name = input_field.get('name', '')
                input_type = input_field.get('type', 'text')

                # 숨겨진 필드 (ID 등)
                if input_type == 'hidden' and any(s in input_name.lower() for s in ['id', 'user', 'item', 'product']):
                    risky_inputs.append({
                        'name': input_name,
                        'type': 'hidden',
                        'risk': '숨겨진 ID 필드'
                    })

                # 검색/필터 필드
                elif any(s in input_name.lower() for s in ['search', 'query', 'filter', 'sort', 'order']):
                    risky_inputs.append({
                        'name': input_name,
                        'type': input_type,
                        'risk': '검색/정렬 필드'
                    })

                # 일반 텍스트 입력
                elif input_type in ['text', 'textarea'] and not input_field.get('pattern'):
                    risky_inputs.append({
                        'name': input_name,
                        'type': input_type,
                        'risk': '검증 없는 텍스트 입력'
                    })

            if risky_inputs:
                severity = 'high' if method == 'GET' and any('search' in i['name'].lower() for i in risky_inputs) else 'medium'

                self.issues.append({
                    'type': 'Form SQL Injection Risk',
                    'severity': severity,
                    'form_index': idx,
                    'action': action,
                    'method': method,
                    'risky_inputs': risky_inputs[:3],  # 최대 3개
                    'description': f'{method} 폼이 SQL Injection에 취약할 수 있습니다.',
                    'recommendation': '모든 입력값에 대해 파라미터화된 쿼리를 사용하세요.'
                })

    def _scan_sql_keyword_exposure(self) -> None:
        """SQL 키워드/구조 노출 검사"""
        if not self.html_content:
            return

        # HTML 주석에서 SQL 쿼리 찾기
        comments = re.findall(r'<!--(.*?)-->', self.html_content, re.DOTALL)
        for comment in comments:
            if any(keyword in comment.upper() for keyword in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE']):
                self.issues.append({
                    'type': 'SQL Query in Comments',
                    'severity': 'medium',
                    'description': 'HTML 주석에 SQL 쿼리가 포함되어 있습니다.',
                    'evidence': comment[:100],
                    'recommendation': '프로덕션 환경에서는 디버그 정보를 제거하세요.'
                })
                break

        # 위험한 SQL 구문 노출
        for keyword in self.DANGEROUS_SQL_EXPOSURE:
            if keyword in self.html_content.upper():
                self.issues.append({
                    'type': 'SQL Keyword Exposure',
                    'severity': 'high',
                    'keyword': keyword,
                    'description': f'위험한 SQL 키워드가 페이지에 노출됨: {keyword}',
                    'recommendation': 'SQL 구조가 클라이언트에게 노출되지 않도록 하세요.'
                })
                break

    def _check_time_based_sqli_possibility(self) -> None:
        """시간 기반 SQL Injection 가능성 체크"""
        if not self.url:
            return

        # 동적 콘텐츠 로딩 패턴 확인
        if self.html_content:
            # AJAX나 동적 로딩 힌트
            dynamic_patterns = [
                r'XMLHttpRequest',
                r'\.ajax\(',
                r'fetch\(',
                r'axios\.',
                r'/api/',
                r'/search',
                r'/filter'
            ]

            has_dynamic = any(re.search(p, self.html_content) for p in dynamic_patterns)

            if has_dynamic:
                self.issues.append({
                    'type': 'Time-based SQLi Possibility',
                    'severity': 'low',
                    'description': '동적 콘텐츠 로딩이 감지됨. 시간 기반 SQL Injection 테스트가 필요할 수 있습니다.',
                    'recommendation': '비동기 요청에도 파라미터화된 쿼리를 사용하고, 응답 시간 제한을 설정하세요.'
                })

    def _build_vulnerabilities(self) -> List[Dict[str, Any]]:
        """issues를 vulnerabilities 형식으로 변환"""
        return self.issues

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for issue in self.issues:
            severity = issue.get('severity', 'low')
            severity_counts[severity] += 1

        return {
            'has_sqli': len(self.issues) > 0,
            'critical_count': severity_counts['critical'],
            'error_exposure': any('Error Exposure' in i['type'] for i in self.issues),
            'form_risks': sum(1 for i in self.issues if 'Form' in i['type'])
        }


class CSRFScanner(BaseScanner):
    """CSRF (Cross-Site Request Forgery) 보호 검사 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'csrf',
        'name': 'CSRF 보호 검사',
        'icon': '🔒',
        'description': 'Cross-Site Request Forgery 방어 검증',
        'weight': 1.5,
        'field': 'csrf_protection'
    }

    # CSRF 토큰 패턴
    CSRF_TOKEN_PATTERNS = [
        r'csrf[_-]?token',
        r'authenticity[_-]?token',
        r'csrfmiddlewaretoken',
        r'__RequestVerificationToken',
        r'_csrf',
        r'x-csrf-token',
        r'x-xsrf-token'
    ]

    # 상태 변경 메서드
    STATE_CHANGING_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH']

    def __init__(self, html_content: str = None, **kwargs):
        """
        Args:
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        url = kwargs.pop('url', '')
        super().__init__(url=url, html_content=html_content, **kwargs)

        # HTML 콘텐츠 설정
        if html_content:
            self.html_content = html_content
        elif hasattr(self, 'response') and self.response:
            self.html_content = getattr(self.response, 'text', '')
        else:
            self.html_content = ''

        # 헤더 설정
        if hasattr(self, 'response') and self.response:
            self.headers = getattr(self.response, 'headers', {})
        else:
            self.headers = kwargs.get('headers', {})

        self.issues = []

    def _execute_scan(self) -> None:
        """CSRF 보호 검사 실행"""
        # 1. 폼의 CSRF 토큰 검사
        self._scan_forms_for_csrf()

        # 2. AJAX 요청의 CSRF 보호 검사
        self._scan_ajax_csrf_protection()

        # 3. SameSite 쿠키 속성 검사
        self._check_samesite_cookies()

        # 4. Referer/Origin 검증 힌트 검사
        self._check_referer_validation()

    def _scan_forms_for_csrf(self) -> None:
        """폼에서 CSRF 토큰 검사"""
        if not self.html_content:
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')
        forms = soup.find_all('form')

        for idx, form in enumerate(forms):
            method = form.get('method', 'GET').upper()
            action = form.get('action', '')

            # 상태 변경 메서드인 경우만 검사
            if method in self.STATE_CHANGING_METHODS:
                has_csrf_token = False
                csrf_field = None

                # CSRF 토큰 필드 찾기
                inputs = form.find_all('input')
                for input_field in inputs:
                    input_name = input_field.get('name', '').lower()
                    input_type = input_field.get('type', '')

                    # CSRF 토큰 패턴 매칭
                    for pattern in self.CSRF_TOKEN_PATTERNS:
                        if re.search(pattern, input_name, re.IGNORECASE):
                            has_csrf_token = True
                            csrf_field = input_name
                            # 토큰 값이 비어있는지 확인
                            if not input_field.get('value'):
                                self.issues.append({
                                    'type': 'Empty CSRF Token',
                                    'severity': 'high',
                                    'form_index': idx,
                                    'field': csrf_field,
                                    'description': 'CSRF 토큰 필드가 있지만 값이 비어있습니다.',
                                    'recommendation': '서버에서 고유한 CSRF 토큰을 생성하여 설정하세요.'
                                })
                            break

                if not has_csrf_token:
                    # 민감한 작업인지 확인
                    is_sensitive = self._is_sensitive_action(form)

                    self.issues.append({
                        'type': 'Missing CSRF Token',
                        'severity': 'critical' if is_sensitive else 'high',
                        'form_index': idx,
                        'method': method,
                        'action': action,
                        'is_sensitive': is_sensitive,
                        'description': f'{method} 폼에 CSRF 토큰이 없습니다.',
                        'recommendation': 'CSRF 토큰을 추가하여 요청의 정당성을 검증하세요.'
                    })

    def _scan_ajax_csrf_protection(self) -> None:
        """AJAX 요청의 CSRF 보호 검사"""
        if not self.html_content:
            return

        # JavaScript에서 CSRF 토큰 사용 패턴 찾기
        ajax_patterns = [
            r'XMLHttpRequest',
            r'\.ajax\(',
            r'fetch\(',
            r'axios\.'
        ]

        # CSRF 토큰이 헤더에 설정되는지 확인
        csrf_header_patterns = [
            r'setRequestHeader\s*\(\s*["\']X-CSRF',
            r'headers\s*:\s*{[^}]*csrf',
            r'["\']X-CSRF-Token["\']\s*:',
            r'["\']X-XSRF-Token["\']\s*:'
        ]

        has_ajax = any(re.search(p, self.html_content, re.IGNORECASE) for p in ajax_patterns)
        has_csrf_header = any(re.search(p, self.html_content, re.IGNORECASE) for p in csrf_header_patterns)

        if has_ajax and not has_csrf_header:
            # 메타 태그에서 CSRF 토큰 확인
            soup = BeautifulSoup(self.html_content, 'html.parser')
            csrf_meta = soup.find('meta', attrs={'name': re.compile('csrf', re.IGNORECASE)})

            if not csrf_meta:
                self.issues.append({
                    'type': 'AJAX CSRF Protection Missing',
                    'severity': 'high',
                    'description': 'AJAX 요청에 CSRF 토큰이 포함되지 않은 것 같습니다.',
                    'evidence': 'AJAX 사용은 감지되었으나 CSRF 헤더 설정이 없음',
                    'recommendation': 'AJAX 요청에 X-CSRF-Token 헤더를 추가하세요.'
                })

    def _check_samesite_cookies(self) -> None:
        """SameSite 쿠키 속성 검사"""
        # Set-Cookie 헤더 확인
        if self.headers:
            set_cookie = self.headers.get('Set-Cookie', '')
            if set_cookie:
                # SameSite 속성 확인
                if 'SameSite' not in set_cookie:
                    self.issues.append({
                        'type': 'Missing SameSite Cookie Attribute',
                        'severity': 'medium',
                        'description': '쿠키에 SameSite 속성이 설정되지 않았습니다.',
                        'recommendation': 'SameSite=Strict 또는 SameSite=Lax를 설정하여 CSRF를 방지하세요.'
                    })
                elif 'SameSite=None' in set_cookie:
                    self.issues.append({
                        'type': 'Weak SameSite Cookie',
                        'severity': 'medium',
                        'description': 'SameSite=None은 CSRF 보호를 제공하지 않습니다.',
                        'recommendation': 'SameSite=Strict 또는 Lax를 사용하세요.'
                    })

    def _check_referer_validation(self) -> None:
        """Referer/Origin 검증 힌트 찾기"""
        if not self.html_content:
            return

        # JavaScript에서 Referer/Origin 검증 패턴
        validation_patterns = [
            r'document\.referrer',
            r'origin\s*===',
            r'referer\s*===',
            r'window\.location\.origin'
        ]

        has_validation = any(re.search(p, self.html_content, re.IGNORECASE) for p in validation_patterns)

        # Referer 검증이 없고 CSRF 토큰도 없는 경우
        if not has_validation and len([i for i in self.issues if 'Missing CSRF Token' in i['type']]) > 0:
            self.issues.append({
                'type': 'No Secondary CSRF Protection',
                'severity': 'low',
                'description': 'CSRF 토큰 외에 추가적인 보호 메커니즘이 없습니다.',
                'recommendation': 'Referer/Origin 헤더 검증을 추가 보호 계층으로 구현하세요.'
            })

    def _is_sensitive_action(self, form) -> bool:
        """민감한 작업인지 판단"""
        sensitive_keywords = [
            'password', 'delete', 'remove', 'transfer', 'payment',
            'logout', 'account', 'profile', 'settings', 'admin',
            'update', 'change', 'modify', 'edit'
        ]

        form_str = str(form).lower()
        action = form.get('action', '').lower()

        return any(keyword in form_str or keyword in action for keyword in sensitive_keywords)

    def _build_vulnerabilities(self) -> List[Dict[str, Any]]:
        """issues를 vulnerabilities 형식으로 변환"""
        return self.issues

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_csrf_protection': len([i for i in self.issues if 'Missing' not in i['type']]) > 0,
            'missing_tokens': len([i for i in self.issues if 'Missing CSRF Token' in i['type']]),
            'sensitive_forms_unprotected': len([i for i in self.issues if i.get('is_sensitive', False)]),
            'total_forms': len(BeautifulSoup(self.html_content, 'html.parser').find_all('form')) if self.html_content else 0
        }


class InformationDisclosureScanner(BaseScanner):
    """정보 노출 검사 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'information_disclosure',
        'name': '정보 노출 검사',
        'icon': '📝',
        'description': '민감한 정보 노출 탐지',
        'weight': 1,
        'field': 'disclosure'
    }

    # 민감한 정보 패턴 (확장 및 개선)
    SENSITIVE_PATTERNS = [
        # 에러 메시지
        (r'Fatal error:.*?in\s+.*?on line\s+\d+', 'PHP Fatal Error with path', 'high'),
        (r'Warning:.*?in\s+.*?on line\s+\d+', 'PHP Warning with path', 'medium'),
        (r'Notice:.*?in\s+.*?on line\s+\d+', 'PHP Notice with path', 'low'),
        (r'Parse error:.*?in\s+.*?on line\s+\d+', 'PHP Parse Error', 'high'),
        (r'Traceback \(most recent call last\):', 'Python Traceback', 'high'),
        (r'at\s+\w+\.\w+\(.*?\:\d+\)', 'Java Stack Trace', 'high'),
        (r'^\s*at\s+.*?\(.*?\.cs:\d+\)', 'C# Stack Trace', 'high'),

        # 파일 경로
        (r'[C-Z]:\\\\[^<>\s"]+', 'Windows file path', 'medium'),
        (r'/(?:usr|opt|var|home|root|etc)/[^<>\s"]+', 'Unix file path', 'medium'),
        (r'/Users/[^/\s<>"]+/', 'macOS user path', 'medium'),

        # 서버 정보
        (r'Server:\s*[^\r\n]+', 'Server header', 'low'),
        (r'X-Powered-By:\s*[^\r\n]+', 'X-Powered-By header', 'low'),
        (r'X-AspNet-Version:\s*[^\r\n]+', 'ASP.NET version', 'medium'),

        # 데이터베이스 정보
        (r'Database\s+name:\s*\w+', 'Database name', 'high'),
        (r'Table\s+\'[^\']+\'', 'Database table name', 'medium'),
        (r'Column\s+\'[^\']+\'', 'Database column name', 'medium'),

        # API 키/토큰 (더미 제외)
        (r'api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,}["\']', 'API Key', 'critical'),
        (r'api[_-]?secret["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,}["\']', 'API Secret', 'critical'),
        (r'["\']?token["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{20,}["\']', 'Access Token', 'high'),

        # AWS
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key', 'critical'),
        (r'[0-9a-zA-Z/+=]{40}', 'AWS Secret Key (potential)', 'high'),

        # 이메일 주소
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email address', 'low'),

        # IP 주소 (내부)
        (r'(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}', 'Internal IP address', 'medium'),

        # 버전 정보
        (r'(?:version|v)\s*[:=]?\s*\d+\.\d+(?:\.\d+)?', 'Version information', 'low'),

        # 주석의 TODO/FIXME
        (r'(?:TODO|FIXME|HACK|XXX):\s*[^\r\n]+', 'Development comment', 'low'),
    ]

    # 무시할 패턴 (False Positive 방지)
    IGNORE_PATTERNS = [
        r'example\.com',
        r'test@example\.com',
        r'your-api-key-here',
        r'xxxx-xxxx-xxxx-xxxx',
        r'placeholder',
        r'localhost',
        r'127\.0\.0\.1'
    ]

    def __init__(self, html_content: str = None, **kwargs):
        """
        Args:
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        url = kwargs.pop('url', '')
        super().__init__(url=url, html_content=html_content, **kwargs)

        # HTML 콘텐츠 설정
        if html_content:
            self.html_content = html_content
        elif hasattr(self, 'response') and self.response:
            self.html_content = getattr(self.response, 'text', '')
        else:
            self.html_content = ''

        # 헤더 설정
        if hasattr(self, 'response') and self.response:
            self.headers = getattr(self.response, 'headers', {})
        else:
            self.headers = kwargs.get('headers', {})

        self.issues = []

    def _execute_scan(self) -> None:
        """정보 노출 검사 실행"""
        # 1. HTML 콘텐츠에서 민감한 패턴 검색
        self._scan_sensitive_patterns()

        # 2. HTML 주석 검사
        self._scan_html_comments()

        # 3. 응답 헤더 검사
        self._scan_response_headers()

        # 4. 디버그 모드 감지
        self._detect_debug_mode()

        # 5. 소스 맵 파일 검사
        self._check_source_maps()

    def _scan_sensitive_patterns(self) -> None:
        """민감한 정보 패턴 검색"""
        if not self.html_content:
            return

        found_patterns = {}

        for pattern, desc, severity in self.SENSITIVE_PATTERNS:
            matches = re.findall(pattern, self.html_content, re.MULTILINE | re.IGNORECASE)

            if matches:
                # False positive 필터링
                filtered_matches = []
                for match in matches[:3]:  # 최대 3개만
                    is_ignored = False
                    for ignore_pattern in self.IGNORE_PATTERNS:
                        if re.search(ignore_pattern, match, re.IGNORECASE):
                            is_ignored = True
                            break

                    if not is_ignored:
                        filtered_matches.append(match)

                if filtered_matches:
                    # 같은 타입은 한 번만 보고
                    if desc not in found_patterns:
                        found_patterns[desc] = {
                            'type': 'Information Disclosure',
                            'severity': severity,
                            'info_type': desc,
                            'description': f'{desc} 정보가 노출되었습니다.',
                            'evidence': filtered_matches[0][:200],
                            'count': len(filtered_matches),
                            'recommendation': self._get_recommendation(desc)
                        }

        self.issues.extend(found_patterns.values())

    def _scan_html_comments(self) -> None:
        """HTML 주석에서 민감한 정보 검사"""
        if not self.html_content:
            return

        comments = re.findall(r'<!--(.*?)-->', self.html_content, re.DOTALL)

        sensitive_comments = []
        for comment in comments:
            # 민감한 키워드 확인
            sensitive_keywords = [
                'password', 'secret', 'token', 'api', 'key',
                'credential', 'private', 'admin', 'root',
                'TODO', 'FIXME', 'HACK', 'DEBUG'
            ]

            for keyword in sensitive_keywords:
                if keyword.lower() in comment.lower():
                    sensitive_comments.append({
                        'keyword': keyword,
                        'content': comment[:100]
                    })
                    break

        if sensitive_comments:
            self.issues.append({
                'type': 'Sensitive Comments',
                'severity': 'medium',
                'description': 'HTML 주석에 민감한 정보가 포함되어 있습니다.',
                'comments': sensitive_comments[:3],  # 최대 3개
                'recommendation': '프로덕션 환경에서는 민감한 주석을 제거하세요.'
            })

    def _scan_response_headers(self) -> None:
        """응답 헤더에서 정보 노출 검사"""
        if not self.headers:
            return

        # 정보를 노출하는 헤더들
        exposing_headers = {
            'Server': ('서버 소프트웨어 정보', 'low'),
            'X-Powered-By': ('프레임워크/언어 정보', 'low'),
            'X-AspNet-Version': ('ASP.NET 버전', 'medium'),
            'X-AspNetMvc-Version': ('ASP.NET MVC 버전', 'medium'),
            'X-Generator': ('생성 도구 정보', 'low'),
            'X-Drupal-Cache': ('Drupal CMS 정보', 'low'),
            'X-Varnish': ('Varnish 캐시 정보', 'low'),
            'Via': ('프록시 서버 정보', 'low'),
            'X-Debug-Token': ('디버그 토큰', 'high'),
            'X-Debug-Token-Link': ('디버그 링크', 'high'),
        }

        for header, (desc, severity) in exposing_headers.items():
            value = self.headers.get(header)
            if value:
                self.issues.append({
                    'type': 'Header Information Disclosure',
                    'severity': severity,
                    'header': header,
                    'value': value,
                    'description': f'{desc}가 헤더에 노출되었습니다.',
                    'recommendation': f'프로덕션 환경에서는 {header} 헤더를 제거하거나 최소화하세요.'
                })

    def _detect_debug_mode(self) -> None:
        """디버그 모드 감지"""
        if not self.html_content:
            return

        debug_indicators = [
            (r'debug\s*[=:]\s*true', 'Debug mode enabled'),
            (r'DEBUG\s*=\s*True', 'Python DEBUG=True'),
            (r'WP_DEBUG.*?true', 'WordPress debug mode'),
            (r'display_errors\s*=\s*On', 'PHP display_errors=On'),
            (r'RAILS_ENV\s*=\s*development', 'Rails development mode'),
            (r'NODE_ENV\s*=\s*development', 'Node.js development mode'),
        ]

        for pattern, desc in debug_indicators:
            if re.search(pattern, self.html_content, re.IGNORECASE):
                self.issues.append({
                    'type': 'Debug Mode Enabled',
                    'severity': 'high',
                    'description': f'{desc} - 디버그 모드가 활성화되어 있습니다.',
                    'recommendation': '프로덕션 환경에서는 디버그 모드를 비활성화하세요.'
                })
                break

    def _check_source_maps(self) -> None:
        """소스 맵 파일 노출 검사"""
        if not self.html_content:
            return

        # 소스 맵 참조 찾기
        source_map_patterns = [
            r'//[#@]\s*sourceMappingURL=([^\s]+)',
            r'\.map["\']\s*\)',
            r'\.js\.map',
            r'\.css\.map'
        ]

        for pattern in source_map_patterns:
            matches = re.findall(pattern, self.html_content)
            if matches:
                self.issues.append({
                    'type': 'Source Map Exposure',
                    'severity': 'medium',
                    'description': '소스 맵 파일이 노출되어 있습니다.',
                    'evidence': matches[0] if matches else '',
                    'recommendation': '프로덕션 환경에서는 소스 맵 파일을 제거하세요.'
                })
                break

    def _get_recommendation(self, info_type: str) -> str:
        """정보 유형별 권장사항"""
        recommendations = {
            'PHP': 'display_errors를 Off로 설정하고, 에러 로깅을 사용하세요.',
            'Python': 'DEBUG=False로 설정하고, 적절한 에러 핸들링을 구현하세요.',
            'Java': '스택 트레이스를 로그 파일에만 기록하세요.',
            'API': 'API 키를 환경 변수로 관리하고, 클라이언트 코드에 포함하지 마세요.',
            'Database': '데이터베이스 구조 정보를 숨기고, 일반적인 에러 메시지를 사용하세요.',
            'path': '파일 시스템 경로를 노출하지 마세요.',
            'Email': '필요한 경우가 아니면 이메일 주소를 마스킹하세요.',
        }

        for key, rec in recommendations.items():
            if key.lower() in info_type.lower():
                return rec

        return '민감한 정보는 프로덕션 환경에서 숨기세요.'

    def _build_vulnerabilities(self) -> List[Dict[str, Any]]:
        """issues를 vulnerabilities 형식으로 변환"""
        return self.issues

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for issue in self.issues:
            severity = issue.get('severity', 'low')
            severity_counts[severity] += 1

        return {
            'has_disclosure': len(self.issues) > 0,
            'critical_count': severity_counts['critical'],
            'high_count': severity_counts['high'],
            'debug_mode': any('Debug Mode' in i['type'] for i in self.issues),
            'api_keys_exposed': any('API' in i.get('info_type', '') for i in self.issues)
        }


class MixedContentScanner(BaseScanner):
    """Mixed Content 검사 스캐너 - 리팩토링 버전
    HTTPS 페이지에서 HTTP 리소스를 로드하는 보안 취약점 탐지
    """

    # 스캐너 메타데이터
    metadata = {
        'id': 'mixed_content',
        'name': 'Mixed Content 검사',
        'icon': '🔗',
        'description': 'HTTPS 페이지의 HTTP 리소스 검사',
        'weight': 0.5,
        'field': 'mixed_content'
    }

    # Mixed Content 카테고리
    CATEGORIES = {
        'blockable': {
            'severity': 'high',
            'resources': ['script', 'iframe', 'object', 'embed'],
            'description': '능동적 혼합 콘텐츠 (브라우저가 차단)'
        },
        'optionally-blockable': {
            'severity': 'medium',
            'resources': ['img', 'audio', 'video'],
            'description': '수동적 혼합 콘텐츠 (경고만 표시)'
        },
        'upgradeable': {
            'severity': 'low',
            'resources': ['link', 'a'],
            'description': '업그레이드 가능한 리소스'
        }
    }

    def __init__(self, url: str = '', html_content: str = None, **kwargs):
        """
        Args:
            url: 페이지 URL (HTTPS 여부 확인용)
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url, html_content=html_content, **kwargs)

        # HTML 콘텐츠 설정
        if html_content:
            self.html_content = html_content
        elif hasattr(self, 'response') and self.response:
            self.html_content = getattr(self.response, 'text', '')
        else:
            self.html_content = ''

        self.issues = []
        self.is_https = self.url.startswith('https://') if self.url else False

    def _execute_scan(self) -> None:
        """Mixed Content 검사 실행"""
        # HTTPS 페이지가 아니면 검사 불필요
        if not self.is_https:
            logger.debug(f"Non-HTTPS URL, skipping mixed content scan: {self.url}")
            return

        if not self.html_content:
            return

        # 1. HTML 태그의 HTTP 리소스 검사
        self._scan_html_resources()

        # 2. 인라인 스타일의 HTTP 리소스 검사
        self._scan_inline_styles()

        # 3. JavaScript의 동적 HTTP 리소스 검사
        self._scan_javascript_resources()

        # 4. Form action의 HTTP 검사
        self._scan_form_actions()

        # 5. CSP upgrade-insecure-requests 확인
        self._check_csp_upgrade_directive()

    def _scan_html_resources(self) -> None:
        """HTML 태그에서 HTTP 리소스 검사"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 검사할 태그와 속성
        tag_attributes = {
            'script': 'src',
            'link': 'href',
            'img': 'src',
            'iframe': 'src',
            'video': 'src',
            'audio': 'src',
            'source': 'src',
            'embed': 'src',
            'object': 'data',
            'form': 'action',
            'a': 'href'
        }

        for tag_name, attr_name in tag_attributes.items():
            elements = soup.find_all(tag_name)

            for element in elements:
                url = element.get(attr_name, '')

                if self._is_http_resource(url):
                    # 카테고리 결정
                    category = self._get_resource_category(tag_name)
                    category_name = self._get_category_name(tag_name)

                    # 이미지는 너무 많을 수 있으므로 제한
                    if tag_name == 'img' and len([i for i in self.issues if 'img' in i.get('tag', '')]) >= 3:
                        continue

                    self.issues.append({
                        'type': f'Mixed Content - {category["description"]}',
                        'severity': category['severity'],
                        'tag': tag_name,
                        'attribute': attr_name,
                        'url': url[:200],  # URL 길이 제한
                        'category': category_name,
                        'description': f'HTTP 리소스가 HTTPS 페이지에서 로드됨: <{tag_name}>',
                        'recommendation': self._get_recommendation(tag_name)
                    })

    def _scan_inline_styles(self) -> None:
        """인라인 스타일에서 HTTP URL 검사"""
        # style 속성에서 HTTP URL 찾기
        # 다양한 형태의 style 속성 매칭
        style_patterns = [
            r'style\s*=\s*"([^"]+)"',
            r'style\s*=\s*\'([^\']+)\'',
            r'style\s*=\s*([^>\s]+)',
        ]

        for pattern in style_patterns:
            styles = re.findall(pattern, self.html_content, re.IGNORECASE | re.DOTALL)
            for style in styles:
                # url() 안의 HTTP URL 찾기
                http_url_patterns = [
                    r'url\s*\(\s*["\']?(http://[^"\'\)]+)',
                    r'url\s*\(\s*(http://[^\)]+)',
                ]

                for url_pattern in http_url_patterns:
                    http_urls = re.findall(url_pattern, style, re.IGNORECASE)
                    if http_urls:
                        self.issues.append({
                            'type': 'Mixed Content - Inline Style',
                            'severity': 'medium',
                            'description': '인라인 스타일에서 HTTP 리소스 참조',
                            'url': http_urls[0][:200],
                            'evidence': style[:100],
                            'recommendation': 'HTTPS URL을 사용하거나 프로토콜 상대 URL(//)을 사용하세요.'
                        })
                        return  # 하나만 찾으면 종료

    def _scan_javascript_resources(self) -> None:
        """JavaScript에서 동적으로 로드하는 HTTP 리소스 검사"""
        # JavaScript에서 HTTP URL 패턴
        js_patterns = [
            r'["\']http://[^"\']+["\']',
            r'createElement\s*\(\s*["\'](?:script|img|iframe)["\']',
            r'\.src\s*=\s*["\']http://',
            r'XMLHttpRequest.*?http://',
            r'fetch\s*\(\s*["\']http://'
        ]

        scripts = re.findall(r'<script[^>]*>(.*?)</script>', self.html_content, re.DOTALL | re.IGNORECASE)

        found_dynamic_http = False
        for script in scripts:
            for pattern in js_patterns:
                if re.search(pattern, script, re.IGNORECASE):
                    if not found_dynamic_http:  # 한 번만 보고
                        self.issues.append({
                            'type': 'Mixed Content - Dynamic Loading',
                            'severity': 'high',
                            'description': 'JavaScript에서 HTTP 리소스를 동적으로 로드',
                            'evidence': re.search(pattern, script, re.IGNORECASE).group()[:100],
                            'recommendation': 'HTTPS를 사용하거나 프로토콜을 동적으로 결정하세요 (location.protocol 사용).'
                        })
                        found_dynamic_http = True
                    break

    def _scan_form_actions(self) -> None:
        """Form action의 HTTP URL 검사"""
        soup = BeautifulSoup(self.html_content, 'html.parser')
        forms = soup.find_all('form')

        for idx, form in enumerate(forms):
            action = form.get('action', '')

            if self._is_http_resource(action):
                method = form.get('method', 'GET').upper()

                # POST 폼이 HTTP로 전송되는 것은 매우 위험
                severity = 'critical' if method == 'POST' else 'high'

                self.issues.append({
                    'type': 'Mixed Content - Form Submission',
                    'severity': severity,
                    'form_index': idx,
                    'action': action[:200],
                    'method': method,
                    'description': f'{method} 폼이 HTTP로 데이터를 전송합니다.',
                    'recommendation': 'Form action을 HTTPS URL로 변경하세요. 민감한 데이터가 노출될 수 있습니다.'
                })

    def _check_csp_upgrade_directive(self) -> None:
        """CSP upgrade-insecure-requests 지시자 확인"""
        if hasattr(self, 'response') and self.response:
            headers = getattr(self.response, 'headers', {})
            csp = headers.get('Content-Security-Policy', '')

            if csp and 'upgrade-insecure-requests' in csp:
                # 좋은 설정이지만 근본 해결은 아님
                self.issues.append({
                    'type': 'CSP Upgrade Directive',
                    'severity': 'info',
                    'description': 'upgrade-insecure-requests CSP 지시자가 설정되어 있습니다.',
                    'note': 'HTTP 리소스를 자동으로 HTTPS로 업그레이드하지만, 모든 브라우저가 지원하지 않습니다.',
                    'recommendation': '근본적으로는 모든 리소스를 HTTPS로 변경하는 것이 좋습니다.'
                })

    def _is_http_resource(self, url: str) -> bool:
        """HTTP 리소스인지 확인"""
        if not url:
            return False

        # 명시적 HTTP URL
        if url.startswith('http://'):
            # localhost나 127.0.0.1은 제외 (개발 환경)
            if 'localhost' in url or '127.0.0.1' in url:
                return False
            return True

        # 프로토콜 상대 URL은 현재 프로토콜 따라감
        if url.startswith('//'):
            return False

        # 절대 경로나 상대 경로는 현재 프로토콜 사용
        return False

    def _get_resource_category(self, tag_name: str) -> Dict:
        """리소스의 카테고리 결정"""
        for category_name, category_info in self.CATEGORIES.items():
            if tag_name in category_info['resources']:
                return category_info
        return {'severity': 'low', 'description': '기타 혼합 콘텐츠'}

    def _get_category_name(self, tag_name: str) -> str:
        """리소스의 카테고리 이름 반환"""
        for category_name, category_info in self.CATEGORIES.items():
            if tag_name in category_info['resources']:
                return category_name
        return 'other'

    def _get_recommendation(self, tag_name: str) -> str:
        """태그별 권장사항"""
        recommendations = {
            'script': 'HTTPS를 사용하세요. 스크립트는 페이지 전체를 제어할 수 있습니다.',
            'iframe': 'HTTPS iframe을 사용하거나 sandbox 속성을 추가하세요.',
            'form': 'Form action을 HTTPS로 변경하세요. 데이터가 암호화되지 않습니다.',
            'img': '이미지도 HTTPS로 제공하여 중간자 공격을 방지하세요.',
            'link': '스타일시트를 HTTPS로 제공하세요.',
            'default': 'HTTP 대신 HTTPS를 사용하거나 프로토콜 상대 URL(//)을 사용하세요.'
        }
        return recommendations.get(tag_name, recommendations['default'])

    def _build_vulnerabilities(self) -> List[Dict[str, Any]]:
        """issues를 vulnerabilities 형식으로 변환"""
        return self.issues

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        if not self.is_https:
            return {
                'is_https': False,
                'scan_skipped': True,
                'reason': 'Not an HTTPS page'
            }

        # 카테고리별 집계
        category_counts = {'blockable': 0, 'optionally-blockable': 0, 'upgradeable': 0, 'other': 0}
        for issue in self.issues:
            category = issue.get('category', 'other')
            if category in category_counts:
                category_counts[category] += 1

        return {
            'is_https': True,
            'has_mixed_content': len(self.issues) > 0,
            'blockable_count': category_counts['blockable'],
            'optionally_blockable_count': category_counts['optionally-blockable'],
            'upgradeable_count': category_counts['upgradeable'],
            'total_mixed': len(self.issues)
        }