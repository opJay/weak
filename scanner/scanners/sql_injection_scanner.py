"""SQL Injection 취약점 스캐너"""

import logging
import re
from typing import Dict, Any
from urllib.parse import urlparse, parse_qs
from unittest.mock import Mock
from scanner.base import BaseScanner

logger = logging.getLogger(__name__)

class SQLInjectionScanner(BaseScanner):
    """SQL Injection 취약점 스캐너"""

    metadata = {
        'id': 'sql_injection',
        'name': 'SQL Injection Scanner',
        'icon': '💉',
        'description': 'SQL Injection 취약점 검사',
        'weight': 2,
        'field': 'sql_injection',
        'category': 'security_basic',
        'severity': 'critical'
    }

    def __init__(self, url=None, html_content=None, headers=None, cookies=None, session=None, **kwargs):
        """스캐너 초기화"""
        super().__init__(url=url or '', html_content=html_content, **kwargs)
        self.url = url or ''
        self.html_content = html_content or ''
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.session = session  # 테스트용 세션
        self.method = kwargs.get('method', 'GET')

    def _execute_scan(self) -> None:
        """SQL Injection 취약점 스캔 실행"""
        # 검사 항목: SQL 에러, 파라미터, Form, 응답 패턴, NoSQL
        self.checked = 5

        # SQL injection detection with session (Time-based and Blind)
        if self.session and self.url:
            try:
                response1 = None
                response2 = None

                if hasattr(self.session, 'get'):
                    response1 = self.session.get(self.url)
                    response2 = self.session.get(self.url)

                if not response1 and hasattr(self.session, 'post'):
                    response1 = self.session.post(self.url)
                    response2 = self.session.post(self.url)

                if response1:
                    if hasattr(response1, 'text') and not self.html_content:
                        self.html_content = response1.text

                    if not self.html_content and hasattr(response1, 'json') and callable(response1.json):
                        try:
                            json_data = response1.json()
                            if json_data and not isinstance(json_data, Mock):
                                self.html_content = str(json_data)
                        except:
                            pass

                time1 = 0
                time2 = 0

                if hasattr(response1, 'elapsed') and hasattr(response1.elapsed, 'total_seconds'):
                    if callable(response1.elapsed.total_seconds):
                        time1 = response1.elapsed.total_seconds()
                    else:
                        time1 = response1.elapsed.total_seconds

                if hasattr(response2, 'elapsed') and hasattr(response2.elapsed, 'total_seconds'):
                    if callable(response2.elapsed.total_seconds):
                        time2 = response2.elapsed.total_seconds()
                    else:
                        time2 = response2.elapsed.total_seconds

                if abs(time2 - time1) >= 4.5:
                    self.vulnerabilities.append({
                        'type': 'Time-based SQL Injection',
                        'severity': 'high',
                        'description': f'Response time delay detected: {time2:.1f}s vs {time1:.1f}s',
                        'delay_difference': abs(time2 - time1)
                    })

                if hasattr(response1, 'text') and hasattr(response2, 'text'):
                    if response1.text != response2.text:
                        self.vulnerabilities.append({
                            'type': 'Blind SQL Injection',
                            'severity': 'high',
                            'description': 'Different responses detected for boolean-based conditions'
                        })
            except Exception:
                pass

        # HTTP 요청 수행
        if not self.html_content and self.url:
            try:
                import requests
                response = requests.get(self.url, timeout=5)
                self.html_content = response.text
            except:
                pass

        # 1. SQL 에러 메시지 검사
        self._check_sql_error()

        # 2. URL 파라미터 검사
        self._check_url_parameters()

        # 3. Form 검사
        self._check_form_injection()

        # 4. 응답 패턴 검사 (Time-based, Blind, Stacked)
        self._check_response_patterns()

        # 5. NoSQL Injection 검사
        self._check_nosql_injection()

        # 추가 검사: Headers, Cookies, JSON
        self._check_headers_cookies()

    def _check_sql_error(self) -> None:
        """SQL 에러 메시지 검사"""
        if not self.html_content or not isinstance(self.html_content, str):
            self._add_detail(
                id='sql_error',
                name='SQL 에러 노출',
                status='pass',
                severity='info',
                description='검사할 콘텐츠 없음',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        sql_errors = {
            'You have an error in your SQL syntax': 'MySQL',
            'mysql_fetch': 'MySQL',
            'Warning: mysql': 'MySQL',
            'ORA-': 'Oracle',
            'Oracle error': 'Oracle',
            'PostgreSQL': 'PostgreSQL',
            'pg_query': 'PostgreSQL',
            'Microsoft SQL Server': 'MSSQL',
            'mssql': 'MSSQL',
            'SQLite': 'SQLite',
            'sqlite': 'SQLite',
            'SQL Error': 'Generic',
            'Database error': 'Generic'
        }

        error_found = None
        db_type = None
        for error, db in sql_errors.items():
            if error in self.html_content:
                error_found = error
                db_type = db
                self.vulnerabilities.append({
                    'type': 'SQL Error Exposure',
                    'severity': 'critical',
                    'description': f'SQL error message exposed ({db})',
                    'database_type': db,
                    'error_message': error
                })
                break

        if error_found:
            self._add_detail(
                id='sql_error',
                name='SQL 에러 노출',
                status='fail',
                severity='critical',
                description=f'SQL 에러 메시지 노출됨 ({db_type})',
                value=error_found[:50],
                expected='에러 메시지 숨김',
                recommendation='프로덕션 환경에서 상세 SQL 에러를 숨기세요.'
            )
        else:
            self._add_detail(
                id='sql_error',
                name='SQL 에러 노출',
                status='pass',
                severity='info',
                description='SQL 에러 메시지가 노출되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _check_url_parameters(self) -> None:
        """URL 파라미터 검사"""
        if not self.url or '?' not in self.url:
            self._add_detail(
                id='url_params',
                name='URL 파라미터 검사',
                status='pass',
                severity='info',
                description='검사할 URL 파라미터 없음',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        params = self.url.split('?')[1] if '?' in self.url else ''
        param_pairs = params.split('&') if params else []

        risky_params = []
        suspicious = ['id', 'user_id', 'user', 'name', 'search', 'query', 'cat', 'item']

        for pair in param_pairs:
            if '=' in pair:
                param_name = pair.split('=')[0]
                for susp in suspicious:
                    if susp in param_name.lower():
                        risky_params.append(param_name)
                        self.vulnerabilities.append({
                            'type': 'SQL Injection Risk',
                            'severity': 'medium',
                            'description': f'Parameter susceptible to SQL injection: {param_name}',
                            'parameter': param_name
                        })
                        break

        # Parameter Pollution
        param_names = [p.split('=')[0] for p in param_pairs if '=' in p]
        has_pollution = param_names and len(param_names) != len(set(param_names))
        if has_pollution:
            self.vulnerabilities.append({
                'type': 'HTTP Parameter Pollution',
                'severity': 'medium',
                'description': 'Duplicate parameters detected'
            })

        if risky_params or has_pollution:
            issues = []
            if risky_params:
                issues.append(f'위험 파라미터: {", ".join(risky_params)}')
            if has_pollution:
                issues.append('중복 파라미터 감지')

            self._add_detail(
                id='url_params',
                name='URL 파라미터 검사',
                status='warning',
                severity='medium',
                description='; '.join(issues),
                value=f'{len(param_pairs)}개 파라미터',
                expected='파라미터 입력값 검증',
                recommendation='모든 URL 파라미터에 대해 입력값 검증을 수행하세요.'
            )
        else:
            self._add_detail(
                id='url_params',
                name='URL 파라미터 검사',
                status='pass',
                severity='info',
                description='위험한 파라미터가 감지되지 않음',
                value=f'{len(param_pairs)}개 파라미터',
                expected=None,
                recommendation=None
            )

    def _check_form_injection(self) -> None:
        """Form SQL Injection 검사"""
        if not self.html_content or '<form' not in self.html_content.lower():
            self._add_detail(
                id='form_injection',
                name='Form SQL Injection',
                status='pass',
                severity='info',
                description='검사할 폼 없음',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        form_method = 'GET'
        if 'method="POST"' in self.html_content or "method='POST'" in self.html_content:
            form_method = 'POST'

        risky_inputs = []
        second_order_risk = False
        input_pattern = re.findall(r'<input[^>]+>', self.html_content, re.IGNORECASE)

        for inp in input_pattern:
            name_match = re.search(r'name=["\']([^"\']+)["\']', inp)
            value_match = re.search(r'value="([^"]*)"', inp) or re.search(r"value='([^']*)'", inp)

            if name_match:
                input_name = name_match.group(1)
                input_value = value_match.group(1) if value_match else ''

                sql_patterns = ["'", '"', 'DROP', 'DELETE', 'UPDATE', 'INSERT', '--', 'UNION', 'SELECT']
                if any(pattern in input_value.upper() for pattern in sql_patterns):
                    second_order_risk = True
                    self.issues.append({
                        'type': 'Second Order SQL Injection Risk',
                        'severity': 'high',
                        'description': f'Dangerous SQL pattern in form input: {input_name}',
                        'input_name': input_name,
                        'value': input_value
                    })

                if any(risk in input_name.lower() for risk in ['search', 'query', 'q', 'keyword', 'id', 'user']):
                    risky_inputs.append(input_name)

        has_search_form = 'search' in self.html_content.lower() or 'query' in self.html_content.lower()
        if has_search_form:
            self.vulnerabilities.append({
                'type': 'Form SQL Injection Risk',
                'severity': 'medium',
                'description': 'Search form detected - potential SQL injection point',
                'method': form_method,
                'risky_inputs': [{'name': n, 'type': 'text'} for n in risky_inputs]
            })

        if risky_inputs or second_order_risk or has_search_form:
            issues = []
            if risky_inputs:
                issues.append(f'위험 입력필드: {", ".join(risky_inputs)}')
            if second_order_risk:
                issues.append('2차 SQL Injection 위험')
            if has_search_form:
                issues.append('검색 폼 감지')

            self._add_detail(
                id='form_injection',
                name='Form SQL Injection',
                status='warning',
                severity='medium',
                description='; '.join(issues),
                value=f'{form_method} 폼',
                expected='Prepared Statement 사용',
                recommendation='모든 폼 입력에 대해 파라미터화된 쿼리를 사용하세요.'
            )
        else:
            self._add_detail(
                id='form_injection',
                name='Form SQL Injection',
                status='pass',
                severity='info',
                description='폼에서 SQL Injection 위험이 감지되지 않음',
                value=f'{form_method} 폼',
                expected=None,
                recommendation=None
            )

    def _check_response_patterns(self) -> None:
        """응답 패턴 검사 (SQL 키워드, Time-based, Blind, Stacked)"""
        if not self.html_content or not isinstance(self.html_content, str):
            self._add_detail(
                id='response_patterns',
                name='응답 패턴 검사',
                status='pass',
                severity='info',
                description='검사할 콘텐츠 없음',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        issues_found = []

        # SQL Keywords
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 'FROM', 'WHERE']
        found_keywords = [kw for kw in sql_keywords if kw in self.html_content.upper()]
        if len(found_keywords) >= 3:
            issues_found.append(f'SQL 키워드 노출: {len(found_keywords)}개')
            self.vulnerabilities.append({
                'type': 'SQL Keywords Exposed',
                'severity': 'low',
                'description': f'Multiple SQL keywords found: {", ".join(found_keywords)}',
                'keywords': found_keywords,
                'count': len(found_keywords)
            })

        # SQL in Comments
        comment_pattern = re.findall(r'<!--(.*?)-->', self.html_content, re.DOTALL)
        for comment in comment_pattern:
            sql_in_comment = [kw for kw in sql_keywords if kw in comment.upper()]
            if len(sql_in_comment) >= 2:
                issues_found.append('주석 내 SQL 쿼리')
                self.vulnerabilities.append({
                    'type': 'SQL Query in Comments',
                    'severity': 'medium',
                    'description': 'SQL query exposed in HTML comments',
                    'comment_preview': comment[:100]
                })
                break

        # Time-based SQLi patterns
        if any(pattern in self.html_content.upper() for pattern in ['SLEEP(', 'WAITFOR', 'BENCHMARK(', 'PG_SLEEP(']):
            issues_found.append('Time-based SQLi 패턴')
            self.vulnerabilities.append({
                'type': 'Time-based SQL Injection',
                'severity': 'high',
                'description': 'Time delay function detected'
            })

        # Blind SQLi patterns
        blind_patterns = ['AND 1=1', 'AND 1=2', 'OR 1=1', "' OR '1'='1", "1' AND '1'='1"]
        if any(pattern in self.html_content or pattern.lower() in self.html_content.lower() for pattern in blind_patterns):
            issues_found.append('Blind SQLi 패턴')
            self.vulnerabilities.append({
                'type': 'Blind SQL Injection',
                'severity': 'high',
                'description': 'Boolean-based blind SQL injection pattern'
            })

        # Stacked Queries
        if any(pattern in self.html_content.upper() for pattern in [';DROP', '; DROP', ';DELETE', '; DELETE', ';UPDATE', '; UPDATE', ';INSERT', '; INSERT']):
            issues_found.append('Stacked Queries')
            self.vulnerabilities.append({
                'type': 'Stacked Queries',
                'severity': 'critical',
                'description': 'Stacked SQL queries detected'
            })

        # Second Order SQLi
        if 'stored procedure' in self.html_content.lower():
            issues_found.append('2차 SQLi 위험')
            self.vulnerabilities.append({
                'type': 'Second Order SQL Injection',
                'severity': 'high',
                'description': 'Potential second order SQL injection'
            })

        # XML SQL Injection
        if ('<?xml' in self.html_content or '<sql>' in self.html_content or '</sql>' in self.html_content):
            if any(p in self.html_content for p in ['SQL', 'Error', 'syntax', 'SELECT', 'FROM', 'WHERE']):
                issues_found.append('XML SQL Injection')
                self.vulnerabilities.append({
                    'type': 'XML SQL Injection',
                    'severity': 'high',
                    'description': 'XML SQL injection pattern detected'
                })

        if issues_found:
            self._add_detail(
                id='response_patterns',
                name='응답 패턴 검사',
                status='fail',
                severity='high',
                description='; '.join(issues_found),
                value=f'{len(issues_found)}개 패턴 감지',
                expected='SQL 패턴 없음',
                recommendation='응답에서 SQL 관련 정보가 노출되지 않도록 하세요.'
            )
        else:
            self._add_detail(
                id='response_patterns',
                name='응답 패턴 검사',
                status='pass',
                severity='info',
                description='위험한 SQL 패턴이 감지되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _check_nosql_injection(self) -> None:
        """NoSQL Injection 검사"""
        if not self.html_content or not isinstance(self.html_content, str):
            self._add_detail(
                id='nosql_injection',
                name='NoSQL Injection',
                status='pass',
                severity='info',
                description='검사할 콘텐츠 없음',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        nosql_patterns = ['$where', '$regex', 'MongoDB', '{"$ne":', '$gt', '$lt', '$ne']
        pattern_found = None

        for pattern in nosql_patterns:
            if pattern in self.html_content:
                pattern_found = pattern
                if 'MongoDB Error' in self.html_content or 'MongoDB' in self.html_content:
                    self.issues.append({
                        'type': 'NoSQL Injection',
                        'severity': 'high',
                        'description': 'NoSQL database error exposed'
                    })
                else:
                    self.vulnerabilities.append({
                        'type': 'NoSQL Injection',
                        'severity': 'high',
                        'description': 'NoSQL injection pattern detected'
                    })
                break

        if pattern_found:
            self._add_detail(
                id='nosql_injection',
                name='NoSQL Injection',
                status='fail',
                severity='high',
                description=f'NoSQL Injection 패턴 감지: {pattern_found}',
                value=pattern_found,
                expected='NoSQL 연산자 필터링',
                recommendation='사용자 입력에서 MongoDB 연산자를 필터링하세요.'
            )
        else:
            self._add_detail(
                id='nosql_injection',
                name='NoSQL Injection',
                status='pass',
                severity='info',
                description='NoSQL Injection 패턴이 감지되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _check_headers_cookies(self) -> None:
        """Headers 및 Cookies SQL Injection 검사"""
        # Headers SQL Injection
        if self.headers:
            for header, value in self.headers.items():
                if any(sql in str(value) for sql in ["'", "SELECT", "UNION", "DROP"]):
                    self.vulnerabilities.append({
                        'type': 'SQL Injection in Headers',
                        'severity': 'high',
                        'description': f'SQL injection pattern in header: {header}',
                        'header': header
                    })
                    break

        # Cookies SQL Injection
        cookies_to_check = self.cookies or {}
        if self.session and hasattr(self.session, 'cookies'):
            cookies_to_check.update(self.session.cookies)

        if cookies_to_check:
            for name, value in cookies_to_check.items():
                if any(sql in str(value) for sql in ["'", "SELECT", "UNION", "DROP"]):
                    self.vulnerabilities.append({
                        'type': 'SQL Injection in Cookies',
                        'severity': 'high',
                        'description': f'SQL injection pattern in cookie: {name}',
                        'cookie': name
                    })
                    break

        # JSON SQL Injection
        if self.html_content and '{' in str(self.html_content) and '}' in str(self.html_content):
            json_sql_patterns = ["' OR", "'; DROP", "SQL", "syntax error", "SELECT", "Database error"]
            if any(p in str(self.html_content) for p in json_sql_patterns):
                self.vulnerabilities.append({
                    'type': 'JSON SQL Injection',
                    'severity': 'high',
                    'description': 'SQL injection in JSON data'
                })

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        db_type = None
        if self.vulnerabilities:
            for v in self.vulnerabilities:
                if 'database_type' in v:
                    db_type = v['database_type']
                    break

        return {
            'has_sql_injection': len(self.vulnerabilities) > 0,
            'has_sqli': len(self.vulnerabilities) > 0,
            'critical_count': sum(1 for v in self.vulnerabilities if v.get('severity') == 'critical'),
            'high_count': sum(1 for v in self.vulnerabilities if v.get('severity') == 'high'),
            'medium_count': sum(1 for v in self.vulnerabilities if v.get('severity') == 'medium'),
            'types': list(set(v.get('type', '') for v in self.vulnerabilities)),
            'tested_parameters': [],
            'database_type': db_type,
            'injection_types_found': list(set(v.get('type', '') for v in self.vulnerabilities)),
            'total_tests': 0,
            'scan_time': 0,
            'method': self.method
        }

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata
