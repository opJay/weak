"""
Security Header Scanner - HTTP 보안 헤더 검사

독립적인 스캐너 모듈로, 모든 정보를 자체 포함:
- 메타데이터
- 가이드 및 설명
- 스캔 로직
"""

import logging
import re
from typing import Dict, Any, List

# core 패키지에서 BaseScanner import
from scanner.base import BaseScanner

logger = logging.getLogger(__name__)


class SecurityHeaderScanner(BaseScanner):
    """HTTP 보안 헤더 스캐너"""

    # ========== 스캐너 메타데이터 ==========
    metadata = {
        'id': 'security_headers',
        'name': '보안 헤더 검사',
        'icon': '🛡️',
        'description': 'HTTP 보안 헤더 설정 검증',
        'weight': 1,
        'field': 'security_headers',
        'category': 'security_basic',
        'owasp': ['A05:2021', 'A05:2025'],  # Security Misconfiguration
        'cwe': ['CWE-693', 'CWE-16', 'CWE-1021'],
        'severity_level': 'high',
        'enabled': True,
        'aliases': []
    }

    # ========== 가이드 및 상세 설명 ==========
    guide = {
        'description': '''
            HTTP 보안 헤더는 웹 애플리케이션의 보안을 강화하는 중요한 방어 메커니즘입니다.
            브라우저가 특정 보안 정책을 적용하도록 지시하여 다양한 공격을 방어합니다.

            주요 보안 헤더:
            1. Strict-Transport-Security (HSTS): HTTPS 강제
            2. Content-Security-Policy (CSP): XSS 및 데이터 주입 방지
            3. X-Frame-Options: 클릭재킹 방지
            4. X-Content-Type-Options: MIME 스니핑 방지
            5. Referrer-Policy: Referrer 정보 제어
            6. Permissions-Policy: 브라우저 기능 제한
        ''',
        'impact': '''
            보안 헤더 미설정 시 발생 가능한 위험:
            - XSS(Cross-Site Scripting) 공격
            - 클릭재킹 공격
            - 프로토콜 다운그레이드 공격 (HTTP로 강제 전환)
            - MIME 타입 혼동 공격
            - 민감한 정보 유출 (Referrer를 통한)
            - 브라우저 기능 악용
            - 콘텐츠 주입 공격
        ''',
        'remediation': '''
            1. **Strict-Transport-Security (HSTS)**:
               ```
               Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
               ```
               - max-age: 최소 1년(31536000초) 권장
               - includeSubDomains: 모든 서브도메인 포함
               - preload: HSTS Preload List 등록

            2. **Content-Security-Policy (CSP)**:
               ```
               Content-Security-Policy: default-src 'self';
                   script-src 'self' 'nonce-{random}';
                   style-src 'self' 'nonce-{random}';
                   img-src 'self' data: https:;
                   font-src 'self';
                   connect-src 'self';
                   frame-ancestors 'none';
                   base-uri 'self';
                   form-action 'self';
               ```

            3. **X-Frame-Options**:
               ```
               X-Frame-Options: DENY
               # 또는
               X-Frame-Options: SAMEORIGIN
               ```

            4. **X-Content-Type-Options**:
               ```
               X-Content-Type-Options: nosniff
               ```

            5. **Referrer-Policy**:
               ```
               Referrer-Policy: strict-origin-when-cross-origin
               ```

            6. **Permissions-Policy**:
               ```
               Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()
               ```

            7. **추가 보안 헤더**:
               ```
               X-XSS-Protection: 0  # CSP를 대신 사용 권장
               X-Permitted-Cross-Domain-Policies: none
               Cross-Origin-Embedder-Policy: require-corp
               Cross-Origin-Opener-Policy: same-origin
               Cross-Origin-Resource-Policy: same-origin
               ```
        ''',
        'references': [
            'https://owasp.org/www-project-secure-headers/',
            'https://securityheaders.com/',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers',
            'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html',
            'https://content-security-policy.com/'
        ],
        'examples': {
            'vulnerable_config': '''
                # 보안 헤더가 설정되지 않은 서버 응답
                HTTP/1.1 200 OK
                Content-Type: text/html

                # 보안 헤더 누락 - 취약함
            ''',
            'secure_config': '''
                # 보안 헤더가 올바르게 설정된 서버 응답
                HTTP/1.1 200 OK
                Content-Type: text/html
                Strict-Transport-Security: max-age=31536000; includeSubDomains
                Content-Security-Policy: default-src 'self'
                X-Frame-Options: DENY
                X-Content-Type-Options: nosniff
                Referrer-Policy: strict-origin-when-cross-origin
                Permissions-Policy: geolocation=(), camera=(), microphone=()
            '''
        }
    }

    # ========== 보안 헤더 정의 ==========
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

    # ========== 생성자 ==========
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

    # ========== 스캔 실행 ==========
    def _execute_scan(self) -> None:
        """보안 헤더 스캔 실행"""
        # 검사 대상: 7개 보안 헤더
        self.checked = len(self.SECURITY_HEADERS)

        for header_name, header_info in self.SECURITY_HEADERS.items():
            if header_name in self.headers:
                # 헤더가 존재하는 경우
                header_value = self.headers[header_name]
                self._analyze_header_value(header_name, header_value, header_info)
            else:
                # 헤더가 누락된 경우
                self._report_missing_header(header_name, header_info)

    # ========== 헤더 분석 메서드 ==========
    def _analyze_header_value(self, header_name: str, header_value: str, header_info: Dict) -> None:
        """헤더 값 분석 및 검증"""
        header_id = header_name.lower().replace('-', '_')
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

        # 세부 항목 추가 (details)
        if result['status'] == 'weak':
            # 약한 설정
            self._add_detail(
                id=header_id,
                name=header_name,
                status='warning',
                severity=header_info.get('severity', 'low'),
                description=result.get('warning', header_info['description']),
                value=header_value,
                expected=header_info['recommendation'],
                recommendation=header_info['recommendation']
            )
            # 취약점으로도 추가
            self.vulnerabilities.append({
                'type': f'Weak {header_name}',
                'severity': header_info.get('severity', 'low'),
                'header': header_name,
                'value': header_value,
                'description': result.get('warning', header_info['description']),
                'recommendation': header_info['recommendation']
            })
        else:
            # 정상 설정
            self._add_detail(
                id=header_id,
                name=header_name,
                status='pass',
                severity='info',
                description=f'{header_name} 헤더가 올바르게 설정됨',
                value=header_value,
                expected=header_info['recommendation'],
                recommendation=None
            )

    def _report_missing_header(self, header_name: str, header_info: Dict) -> None:
        """누락된 헤더 보고"""
        header_id = header_name.lower().replace('-', '_')
        self.results[header_name] = {
            'present': False,
            'status': 'missing',
            'severity': header_info['severity'],
            'description': header_info['description'],
            'recommendation': header_info['recommendation']
        }
        self.missing_headers.append(header_name)

        # 세부 항목 추가 (details) - 모든 누락 헤더
        self._add_detail(
            id=header_id,
            name=header_name,
            status='fail',
            severity=header_info['severity'],
            description=f'{header_name} 헤더가 누락됨. {header_info["description"]}',
            value=None,
            expected=header_info['recommendation'],
            recommendation=header_info['recommendation']
        )

        # 중요 헤더 누락은 취약점으로 추가
        if header_info['severity'] in ['high', 'medium']:
            self.vulnerabilities.append({
                'type': f'Missing {header_name}',
                'severity': header_info['severity'],
                'header': header_name,
                'description': f'{header_name} 헤더가 누락되었습니다. {header_info["description"]}',
                'recommendation': header_info['recommendation']
            })

    # ========== 검증 메서드 ==========
    def _validate_hsts(self, value: str, info: Dict, result: Dict) -> Dict:
        """HSTS 헤더 검증"""
        try:
            # max-age 파싱
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

    # ========== 헬퍼 메서드 ==========
    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'headers': self.results,
            'missing_count': len(self.missing_headers),
            'total_count': len(self.SECURITY_HEADERS),
            'missing_headers': self.missing_headers,
            'security_score': max(0, 100 - (len(self.missing_headers) * 15))  # 간단한 점수 계산
        }

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata