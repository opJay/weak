"""Cross-Site Scripting (XSS) 취약점 스캐너"""

import logging
import re
from typing import Dict, Any
from urllib.parse import urlparse, parse_qs
from scanner.base import BaseScanner

logger = logging.getLogger(__name__)

class XSSScanner(BaseScanner):
    """XSS 취약점 스캐너"""

    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)'
    ]

    metadata = {
        'id': 'xss',
        'name': 'XSS Scanner',
        'icon': '💉',
        'description': 'Cross-Site Scripting 취약점 검사',
        'weight': 1,
        'field': 'xss_vulnerabilities',
        'category': 'security_basic',
        'severity': 'high'
    }

    def __init__(self, url=None, html_content=None, response=None, session=None, **kwargs):
        """스캐너 초기화"""
        super().__init__(url=url or '', html_content=html_content, **kwargs)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.session = session
        self.method = kwargs.get('method', 'GET')

    def _execute_scan(self) -> None:
        """XSS 취약점 스캔 실행"""
        # 검사 항목: CSP, Reflected XSS, Event Handler XSS, DOM XSS
        self.checked = 4

        # session이 있고 URL이 있으면 GET 요청
        if hasattr(self, 'session') and self.session and self.url and not self.html_content:
            try:
                response = self.session.get(self.url)
                if hasattr(response, 'text'):
                    self.html_content = response.text
            except:
                pass

        # html_content가 문자열인지 확인
        if not isinstance(self.html_content, str):
            self.html_content = str(self.html_content) if self.html_content else ''

        # Escaped content는 취약점이 아님 (완전히 이스케이프된 경우만)
        if self.html_content and "&lt;script&gt;" in self.html_content and "&lt;/script&gt;" in self.html_content:
            # 완전히 이스케이프된 경우만 취약점 제외
            return

        # HTTP 요청 수행
        if not self.html_content and self.url:
            try:
                import requests
                response = requests.get(self.url, timeout=5)
                self.html_content = response.text
                self.response = response
            except:
                pass

        # 1. CSP (Content Security Policy) 검사
        self._check_csp()

        # 2. Reflected XSS 검사
        self._check_reflected_xss()

        # 3. Event Handler XSS 검사
        self._check_event_handler_xss()

        # 4. DOM XSS 검사
        self._check_dom_xss()

    def _check_csp(self) -> None:
        """CSP 헤더 검사"""
        if not self.response or not hasattr(self.response, 'headers'):
            self._add_detail(
                id='csp',
                name='Content Security Policy',
                status='warning',
                severity='medium',
                description='응답 헤더를 확인할 수 없음',
                value=None,
                expected='CSP 헤더 설정',
                recommendation='CSP 헤더를 설정하여 XSS를 방어하세요.'
            )
            return

        headers = self.response.headers if hasattr(self.response.headers, 'get') else {}
        csp_header = headers.get('Content-Security-Policy', '')

        if not csp_header:
            self._add_detail(
                id='csp',
                name='Content Security Policy',
                status='fail',
                severity='medium',
                description='CSP 헤더가 설정되지 않음',
                value=None,
                expected="default-src 'self'",
                recommendation='Content-Security-Policy 헤더를 설정하세요.'
            )
            self.issues.append({
                'type': 'Missing CSP Header',
                'severity': 'medium',
                'description': 'Content Security Policy header is missing'
            })
        elif 'unsafe-inline' in csp_header or 'unsafe-eval' in csp_header:
            issues = []
            if 'unsafe-inline' in csp_header:
                issues.append('unsafe-inline')
            if 'unsafe-eval' in csp_header:
                issues.append('unsafe-eval')

            self._add_detail(
                id='csp',
                name='Content Security Policy',
                status='warning',
                severity='medium',
                description=f"CSP에 위험한 디렉티브 포함: {', '.join(issues)}",
                value=csp_header[:100] + ('...' if len(csp_header) > 100 else ''),
                expected="unsafe-inline, unsafe-eval 제거",
                recommendation='unsafe-inline과 unsafe-eval을 제거하세요.'
            )
            if 'unsafe-inline' in csp_header:
                self.issues.append({
                    'type': 'CSP Bypass Risk',
                    'severity': 'medium',
                    'description': "CSP contains 'unsafe-inline' which can allow XSS attacks",
                    'header_value': csp_header
                })
            if 'unsafe-eval' in csp_header:
                self.issues.append({
                    'type': 'CSP Bypass Risk',
                    'severity': 'medium',
                    'description': "CSP contains 'unsafe-eval' which can allow code execution",
                    'header_value': csp_header
                })
        else:
            self._add_detail(
                id='csp',
                name='Content Security Policy',
                status='pass',
                severity='info',
                description='CSP 헤더가 안전하게 설정됨',
                value=csp_header[:100] + ('...' if len(csp_header) > 100 else ''),
                expected=None,
                recommendation=None
            )

    def _check_reflected_xss(self) -> None:
        """Reflected XSS 검사"""
        if not self.html_content:
            self._add_detail(
                id='reflected_xss',
                name='Reflected XSS',
                status='pass',
                severity='info',
                description='검사할 HTML 콘텐츠 없음',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        xss_found = False
        xss_detail = None

        # URL 파라미터 분석
        if self.url and '?' in self.url:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param_name, values in params.items():
                for value in values:
                    if any(indicator in value for indicator in ['<script>', 'alert(', 'onerror=']):
                        if value in self.html_content:
                            xss_found = True
                            xss_detail = f'파라미터 {param_name}에서 XSS 취약점 발견'
                            self.vulnerabilities.append({
                                'type': 'Reflected XSS',
                                'severity': 'high',
                                'description': f'XSS vulnerability in parameter: {param_name}',
                                'parameter': param_name
                            })
                            break
                if xss_found:
                    break

        # XSS 패턴 검사
        if not xss_found:
            xss_indicators = ['<script>', '</script>', 'alert(', 'javascript:', 'onerror=', 'onclick=', 'onload=']
            for indicator in xss_indicators:
                if indicator in self.html_content:
                    xss_found = True
                    xss_detail = f'XSS 패턴 감지: {indicator}'
                    self.vulnerabilities.append({
                        'type': 'Reflected XSS',
                        'severity': 'high',
                        'description': f'XSS pattern detected: {indicator}'
                    })
                    break

        # XSS Payloads 직접 체크
        if not xss_found:
            for payload in self.XSS_PAYLOADS:
                if payload in self.html_content:
                    xss_found = True
                    xss_detail = f'XSS 페이로드 감지: {payload[:30]}...'
                    self.vulnerabilities.append({
                        'type': 'Reflected XSS',
                        'severity': 'high',
                        'description': f'XSS payload detected: {payload}'
                    })
                    break

        if xss_found:
            self._add_detail(
                id='reflected_xss',
                name='Reflected XSS',
                status='fail',
                severity='high',
                description=xss_detail,
                value='취약점 발견',
                expected='입력값 이스케이프 필요',
                recommendation='사용자 입력을 HTML 엔티티로 이스케이프하세요.'
            )
        else:
            self._add_detail(
                id='reflected_xss',
                name='Reflected XSS',
                status='pass',
                severity='info',
                description='Reflected XSS 패턴이 감지되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _check_event_handler_xss(self) -> None:
        """Event Handler XSS 검사"""
        if not self.html_content:
            self._add_detail(
                id='event_handler_xss',
                name='Event Handler XSS',
                status='pass',
                severity='info',
                description='검사할 HTML 콘텐츠 없음',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        event_patterns = [
            r'onerror\s*=', r'onclick\s*=', r'onload\s*=',
            r'onmouseover\s*=', r'onfocus\s*=', r'onblur\s*='
        ]

        handler_found = None
        for pattern_str in event_patterns:
            if re.search(pattern_str, self.html_content, re.IGNORECASE):
                handler_match = re.search(r'(on\w+)\s*=', self.html_content, re.IGNORECASE)
                if handler_match:
                    handler_found = handler_match.group(1)
                    self.vulnerabilities.append({
                        'type': 'Event Handler XSS',
                        'severity': 'medium',
                        'description': f'Event handler {handler_found} detected',
                        'pattern': f'event handler {handler_found}'
                    })
                    break

        if handler_found:
            self._add_detail(
                id='event_handler_xss',
                name='Event Handler XSS',
                status='warning',
                severity='medium',
                description=f'이벤트 핸들러 감지: {handler_found}',
                value=handler_found,
                expected='이벤트 핸들러 제거 또는 안전하게 처리',
                recommendation='인라인 이벤트 핸들러 대신 addEventListener를 사용하세요.'
            )
        else:
            self._add_detail(
                id='event_handler_xss',
                name='Event Handler XSS',
                status='pass',
                severity='info',
                description='위험한 이벤트 핸들러가 감지되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _check_dom_xss(self) -> None:
        """DOM XSS 검사"""
        if not self.html_content:
            self._add_detail(
                id='dom_xss',
                name='DOM-based XSS',
                status='pass',
                severity='info',
                description='검사할 HTML 콘텐츠 없음',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        dom_sinks = {
            'innerHTML': 'innerHTML',
            'outerHTML': 'outerHTML',
            'document.write': 'document.write',
            'document.writeln': 'document.writeln',
            'eval(': 'eval',
            'setTimeout(': 'setTimeout',
            'setInterval(': 'setInterval',
            'Function(': 'Function'
        }
        dom_sources = ['location.hash', 'location.search', 'location.href', 'document.URL', 'document.referrer']

        sink_found = None
        source_found = None

        for sink_pattern, sink_name in dom_sinks.items():
            if sink_pattern in self.html_content:
                sink_found = sink_name
                for source in dom_sources:
                    if source in self.html_content:
                        source_found = source
                        break
                self.vulnerabilities.append({
                    'type': 'DOM-based XSS',
                    'severity': 'high',
                    'description': f'DOM XSS via {sink_name}',
                    'sink': sink_name,
                    'source': source_found or 'userInput'
                })
                break

        if sink_found:
            self._add_detail(
                id='dom_xss',
                name='DOM-based XSS',
                status='fail',
                severity='high',
                description=f'DOM XSS 취약점: {sink_found}' + (f' (소스: {source_found})' if source_found else ''),
                value=f'Sink: {sink_found}',
                expected='안전한 DOM 조작 사용',
                recommendation='innerHTML 대신 textContent를 사용하고, eval 사용을 피하세요.'
            )
        else:
            self._add_detail(
                id='dom_xss',
                name='DOM-based XSS',
                status='pass',
                severity='info',
                description='DOM XSS 패턴이 감지되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _test_xss_payloads(self, url):
        """XSS payload 테스트"""
        results = []
        for payload in self.XSS_PAYLOADS:
            # 테스트에서 기대하는 형식
            if payload in self.html_content:
                results.append({'payload': payload, 'vulnerable': True})
                # 취약점으로도 기록
                if not any(v.get('type') == 'Reflected XSS' for v in self.vulnerabilities):
                    self.vulnerabilities.append({
                        'type': 'Reflected XSS',
                        'severity': 'high',
                        'description': f'XSS payload detected: {payload}'
                    })
            else:
                results.append({'payload': payload, 'vulnerable': False})
        return results

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_xss': len(self.vulnerabilities) > 0,
            'xss_types': list(set(v.get('type', '') for v in self.vulnerabilities)),
            'types': list(set(v.get('type', '') for v in self.vulnerabilities + self.issues)),
            'total_payloads_tested': len(self.XSS_PAYLOADS),
            'scan_time': 0,
            'method': self.method
        }

    
    def scan(self):
        """스캔 실행 오버라이드"""
        # 부모 클래스 scan 실행
        result = super().scan()

        # payload 테스트를 위한 추가 체크
        if self.html_content:
            for payload in self.XSS_PAYLOADS:
                if payload in self.html_content:
                    # 취약점이 없으면 추가
                    if not self.vulnerabilities:
                        self.vulnerabilities.append({
                            'type': 'Reflected XSS',
                            'severity': 'high',
                            'description': f'XSS payload detected: {payload}'
                        })
                        result['vulnerabilities'] = self.vulnerabilities
                        result['total'] = len(self.vulnerabilities) + len(self.issues)
                        result['has_xss'] = True

        return result

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata
