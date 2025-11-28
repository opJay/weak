"""
리팩토링된 스캐너들 - BaseScanner를 상속받도록 마이그레이션

점진적 마이그레이션을 위해 별도 파일로 먼저 구현
"""

import logging
import re
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup
from urllib.parse import urlparse

from .base import BaseScanner, LegacyCompatibleScanner

logger = logging.getLogger(__name__)


class SecurityHeaderScanner(BaseScanner):
    """보안 헤더 스캐너 - 리팩토링 버전"""

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
            'recommendation': 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'minimum_max_age': 31536000  # 1년
        },
        'Content-Security-Policy': {
            'description': 'XSS 및 데이터 주입 공격을 방지합니다',
            'severity': 'high',
            'recommendation': "Content-Security-Policy: default-src 'self'",
            'weak_directives': ['unsafe-inline', 'unsafe-eval', '*']
        },
        'X-Frame-Options': {
            'description': '클릭재킹 공격을 방지합니다',
            'severity': 'medium',
            'recommendation': 'X-Frame-Options: DENY 또는 SAMEORIGIN',
            'valid_values': ['DENY', 'SAMEORIGIN']
        },
        'X-Content-Type-Options': {
            'description': 'MIME 타입 스니핑을 방지합니다',
            'severity': 'medium',
            'recommendation': 'X-Content-Type-Options: nosniff',
            'expected_value': 'nosniff'
        },
        'Referrer-Policy': {
            'description': 'Referrer 정보 노출을 제어합니다',
            'severity': 'low',
            'recommendation': 'Referrer-Policy: strict-origin-when-cross-origin',
            'secure_values': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer']
        },
        'Permissions-Policy': {
            'description': '브라우저 기능 사용을 제어합니다',
            'severity': 'low',
            'recommendation': 'Permissions-Policy: geolocation=(), microphone=(), camera=()'
        },
        'X-XSS-Protection': {
            'description': 'XSS 필터를 활성화합니다 (레거시)',
            'severity': 'low',
            'recommendation': 'X-XSS-Protection: 1; mode=block',
            'note': '최신 브라우저에서는 CSP를 권장합니다'
        }
    }

    def __init__(self, headers: Dict[str, str] = None, **kwargs):
        """
        Args:
            headers: HTTP 응답 헤더 딕셔너리
            **kwargs: BaseScanner 호환성을 위한 추가 인자
        """
        # BaseScanner 초기화 (URL은 선택적)
        url = kwargs.pop('url', '')
        super().__init__(url=url, **kwargs)

        # 헤더 설정
        if headers is not None:
            self.headers = headers
        elif hasattr(self, 'response') and self.response:
            self.headers = getattr(self.response, 'headers', {})
        else:
            self.headers = {}

        # 추가 속성
        self.results = {}
        self.missing_headers = []

    def _execute_scan(self) -> None:
        """보안 헤더 스캔 실행"""
        for header_name, header_info in self.SECURITY_HEADERS.items():
            if header_name in self.headers:
                # 헤더가 존재하는 경우
                header_value = self.headers[header_name]
                self._analyze_header_value(header_name, header_value, header_info)
            else:
                # 헤더가 누락된 경우
                self._report_missing_header(header_name, header_info)

    def _analyze_header_value(self, header_name: str, header_value: str, header_info: Dict) -> None:
        """헤더 값 분석 및 검증"""
        result = {
            'present': True,
            'value': header_value,
            'status': 'ok',
            'description': header_info['description']
        }

        # 헤더별 상세 검증
        if header_name == 'Strict-Transport-Security':
            result = self._validate_hsts(header_value, header_info, result)
        elif header_name == 'Content-Security-Policy':
            result = self._validate_csp(header_value, header_info, result)
        elif header_name == 'X-Frame-Options':
            result = self._validate_frame_options(header_value, header_info, result)
        elif header_name == 'X-Content-Type-Options':
            result = self._validate_content_type_options(header_value, header_info, result)
        elif header_name == 'Referrer-Policy':
            result = self._validate_referrer_policy(header_value, header_info, result)

        self.results[header_name] = result

        # 약한 설정은 취약점으로 추가
        if result['status'] == 'weak':
            self.vulnerabilities.append({
                'type': f'Weak {header_name}',
                'severity': header_info.get('severity', 'low'),
                'header': header_name,
                'value': header_value,
                'description': result.get('warning', header_info['description']),
                'recommendation': header_info['recommendation']
            })

    def _report_missing_header(self, header_name: str, header_info: Dict) -> None:
        """누락된 헤더 보고"""
        self.results[header_name] = {
            'present': False,
            'status': 'missing',
            'severity': header_info['severity'],
            'description': header_info['description'],
            'recommendation': header_info['recommendation']
        }
        self.missing_headers.append(header_name)

        # 중요 헤더 누락은 취약점으로 추가
        if header_info['severity'] in ['high', 'medium']:
            self.vulnerabilities.append({
                'type': f'Missing {header_name}',
                'severity': header_info['severity'],
                'header': header_name,
                'description': f'{header_name} 헤더가 누락되었습니다. {header_info["description"]}',
                'recommendation': header_info['recommendation']
            })

    def _validate_hsts(self, value: str, info: Dict, result: Dict) -> Dict:
        """HSTS 헤더 검증"""
        try:
            # max-age 파싱
            import re
            max_age_match = re.search(r'max-age=(\d+)', value)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                min_age = info.get('minimum_max_age', 31536000)

                if max_age < min_age:
                    result['status'] = 'weak'
                    result['warning'] = f'max-age가 너무 짧습니다 (현재: {max_age}, 권장: {min_age} 이상)'

                # includeSubDomains 확인
                if 'includeSubDomains' not in value:
                    result['note'] = 'includeSubDomains 옵션 사용을 권장합니다'
            else:
                result['status'] = 'weak'
                result['warning'] = 'max-age가 설정되지 않았습니다'

        except Exception as e:
            logger.debug(f"HSTS validation error: {e}")

        return result

    def _validate_csp(self, value: str, info: Dict, result: Dict) -> Dict:
        """CSP 헤더 검증"""
        if value is None:
            result['status'] = 'weak'
            result['warning'] = 'CSP 값이 비어있습니다'
            return result

        weak_directives = info.get('weak_directives', [])

        for directive in weak_directives:
            if directive in value:
                result['status'] = 'weak'
                result['warning'] = f'약한 CSP 지시자 발견: {directive}'
                break

        return result

    def _validate_frame_options(self, value: str, info: Dict, result: Dict) -> Dict:
        """X-Frame-Options 검증"""
        valid_values = info.get('valid_values', [])
        value_upper = value.upper()

        if value_upper not in valid_values:
            result['status'] = 'weak'
            result['warning'] = f'유효하지 않은 값: {value} (권장: {", ".join(valid_values)})'

        return result

    def _validate_content_type_options(self, value: str, info: Dict, result: Dict) -> Dict:
        """X-Content-Type-Options 검증"""
        expected = info.get('expected_value', 'nosniff')

        if value != expected:
            result['status'] = 'weak'
            result['warning'] = f'올바르지 않은 값: {value} (권장: {expected})'

        return result

    def _validate_referrer_policy(self, value: str, info: Dict, result: Dict) -> Dict:
        """Referrer-Policy 검증"""
        secure_values = info.get('secure_values', [])

        if value not in secure_values:
            result['note'] = f'더 안전한 옵션 고려: {", ".join(secure_values)}'

        return result

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'headers': self.results,
            'missing_count': len(self.missing_headers),
            'total_count': len(self.SECURITY_HEADERS),
            'missing_headers': self.missing_headers
        }


class CORSScanner(BaseScanner):
    """CORS 설정 스캐너 - 리팩토링 버전"""

    # 스캐너 메타데이터
    metadata = {
        'id': 'cors',
        'name': 'CORS 설정 검사',
        'icon': '🌐',
        'description': 'Cross-Origin Resource Sharing 설정 검증',
        'weight': 1,
        'field': 'cors_misconfiguration'
    }

    def __init__(self, url: str = None, headers: Dict[str, str] = None, **kwargs):
        """
        Args:
            url: URL (BaseScanner 호환)
            headers: HTTP 응답 헤더
            **kwargs: 추가 인자
        """
        # BaseScanner 초기화
        super().__init__(url=url or '', **kwargs)

        # 헤더 설정
        if headers is not None:
            self.headers = headers
        elif hasattr(self, 'response') and self.response:
            self.headers = getattr(self.response, 'headers', {})
        else:
            self.headers = {}

        # issues 사용 (vulnerabilities 대신)
        self.issues = []

    def _execute_scan(self) -> None:
        """CORS 설정 검사 실행"""
        acao = self.headers.get('Access-Control-Allow-Origin')
        acac = self.headers.get('Access-Control-Allow-Credentials')
        acam = self.headers.get('Access-Control-Allow-Methods')
        acah = self.headers.get('Access-Control-Allow-Headers')

        if acao:
            self._check_wildcard_origin(acao, acac)
            self._check_null_origin(acao)
            self._check_reflected_origin(acao)

        # 추가 검사: 위험한 메서드 허용
        if acam:
            self._check_dangerous_methods(acam)

        # 추가 검사: 민감한 헤더 허용
        if acah:
            self._check_sensitive_headers(acah)

    def _check_wildcard_origin(self, acao: str, acac: str) -> None:
        """와일드카드 오리진 검사"""
        if acao == '*':
            if acac and acac.lower() == 'true':
                # Critical: 와일드카드 + credentials
                self.issues.append({
                    'type': 'Critical CORS Misconfiguration',
                    'severity': 'critical',
                    'description': 'Access-Control-Allow-Origin: * 와 Credentials: true가 함께 설정되어 있습니다.',
                    'details': '모든 도메인에서 인증된 요청을 보낼 수 있어 매우 위험합니다.',
                    'recommendation': '특정 도메인만 허용하거나 Credentials를 비활성화하세요.'
                })
            else:
                # Medium: 와일드카드만
                self.issues.append({
                    'type': 'CORS Wildcard',
                    'severity': 'medium',
                    'description': 'Access-Control-Allow-Origin: * 가 설정되어 있습니다.',
                    'details': '모든 도메인에서 리소스에 접근할 수 있습니다.',
                    'recommendation': '가능한 특정 도메인만 허용하세요.'
                })

    def _check_null_origin(self, acao: str) -> None:
        """null 오리진 허용 검사"""
        if acao.lower() == 'null':
            self.issues.append({
                'type': 'Null Origin Allowed',
                'severity': 'high',
                'description': 'null 오리진이 허용되고 있습니다.',
                'details': 'sandboxed iframe 등을 통한 우회 공격이 가능합니다.',
                'recommendation': 'null 오리진을 허용하지 마세요.'
            })

    def _check_reflected_origin(self, acao: str) -> None:
        """반사된 오리진 검사 (간접 추정)"""
        # URL에서 도메인 추출
        if self.url:
            parsed = urlparse(self.url)
            if parsed.netloc and parsed.netloc in acao and acao != parsed.netloc:
                self.issues.append({
                    'type': 'Potential Origin Reflection',
                    'severity': 'medium',
                    'description': '오리진이 동적으로 반사될 가능성이 있습니다.',
                    'details': 'Origin 헤더 값을 그대로 반사하면 보안 위험이 있습니다.',
                    'recommendation': '화이트리스트 기반으로 오리진을 검증하세요.'
                })

    def _check_dangerous_methods(self, acam: str) -> None:
        """위험한 HTTP 메서드 허용 검사"""
        dangerous_methods = ['PUT', 'DELETE', 'PATCH']
        allowed_methods = [m.strip() for m in acam.upper().split(',')]

        dangerous_found = [m for m in dangerous_methods if m in allowed_methods]
        if dangerous_found:
            self.issues.append({
                'type': 'Dangerous Methods in CORS',
                'severity': 'medium',
                'methods': dangerous_found,
                'description': f'위험한 메서드가 CORS에서 허용됩니다: {", ".join(dangerous_found)}',
                'recommendation': '필요한 메서드만 허용하세요.'
            })

    def _check_sensitive_headers(self, acah: str) -> None:
        """민감한 헤더 허용 검사"""
        sensitive_headers = ['Authorization', 'Cookie', 'X-API-Key']
        allowed_headers = acah.split(',')

        sensitive_found = []
        for header in sensitive_headers:
            if header.lower() in [h.strip().lower() for h in allowed_headers]:
                sensitive_found.append(header)

        if sensitive_found:
            self.issues.append({
                'type': 'Sensitive Headers in CORS',
                'severity': 'low',
                'headers': sensitive_found,
                'description': f'민감한 헤더가 허용됩니다: {", ".join(sensitive_found)}',
                'recommendation': '꼭 필요한 경우가 아니면 민감한 헤더는 제한하세요.'
            })

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        acao = self.headers.get('Access-Control-Allow-Origin')
        return {
            'has_cors': acao is not None,
            'misconfigured': len(self.issues) > 0,
            'origin': acao
        }