"""
Cookie Scanner - 쿠키 보안 취약점 탐지

독립적인 스캐너 모듈로, 모든 정보를 자체 포함:
- 메타데이터
- 가이드 및 설명
- 스캔 로직
"""

import logging
import time
from typing import Dict, Any, List

# core 패키지에서 BaseScanner import
from scanner.base import BaseScanner

logger = logging.getLogger(__name__)

class CookieScanner(BaseScanner):
    """쿠키 보안 스캐너"""

    # ========== 스캐너 메타데이터 ==========
    metadata = {
        'id': 'cookie_security',
        'name': '쿠키 보안 검사',
        'icon': '🍪',
        'description': '쿠키 보안 속성 검증',
        'weight': 1,
        'field': 'sensitive_data_exposure',
        'category': 'security_basic',
        'owasp': ['A02:2021', 'A05:2021'],  # OWASP Top 10 매핑
        'cwe': ['CWE-614', 'CWE-315', 'CWE-311'],  # CWE 매핑
        'severity_level': 'medium',
        'enabled': True,
        'aliases': ['cookies']  # 호환성을 위한 별칭
    }

    # ========== 가이드 및 상세 설명 ==========
    guide = {
        'description': '''
            쿠키는 웹 애플리케이션에서 상태 정보를 저장하는 중요한 메커니즘입니다.
            안전하지 않은 쿠키 설정은 세션 하이재킹, XSS 공격, CSRF 공격 등에 노출될 수 있습니다.

            주요 쿠키 보안 속성:
            1. Secure: HTTPS 연결에서만 쿠키 전송
            2. HttpOnly: JavaScript를 통한 쿠키 접근 차단
            3. SameSite: CSRF 공격 방지를 위한 크로스 사이트 요청 제한
            4. 적절한 만료 시간 설정
        ''',
        'impact': '''
            - 세션 하이재킹을 통한 계정 탈취
            - XSS를 통한 쿠키 도용
            - CSRF 공격을 통한 권한 도용
            - 중간자 공격(MITM)을 통한 쿠키 가로채기
            - 민감한 정보 노출
            - 개인정보 유출
        ''',
        'remediation': '''
            1. **Secure 플래그 설정**:
               ```
               Set-Cookie: sessionid=abc123; Secure
               ```
               - HTTPS 연결에서만 쿠키 전송

            2. **HttpOnly 플래그 설정**:
               ```
               Set-Cookie: sessionid=abc123; HttpOnly
               ```
               - JavaScript를 통한 쿠키 접근 차단 (XSS 방어)

            3. **SameSite 속성 설정**:
               ```
               Set-Cookie: sessionid=abc123; SameSite=Strict
               // 또는
               Set-Cookie: sessionid=abc123; SameSite=Lax
               ```
               - Strict: 모든 크로스 사이트 요청에서 쿠키 차단
               - Lax: 일부 안전한 요청(GET 등)만 허용
               - None: 모든 요청 허용 (Secure 필수)

            4. **적절한 만료 시간 설정**:
               ```
               Set-Cookie: sessionid=abc123; Max-Age=3600
               ```
               - 세션 쿠키: 브라우저 종료 시 삭제
               - 영구 쿠키: 적절한 만료 시간 설정 (최대 6개월 권장)

            5. **도메인과 경로 제한**:
               ```
               Set-Cookie: sessionid=abc123; Domain=.example.com; Path=/secure
               ```

            6. **민감한 정보 저장 금지**:
               - 비밀번호, 신용카드 번호 등 민감 정보는 쿠키에 저장 금지
               - 필요시 서버 측 세션 사용

            7. **쿠키 암호화**:
               - 민감한 데이터는 암호화하여 저장
               - HMAC을 사용한 무결성 검증
        ''',
        'references': [
            'https://owasp.org/www-community/controls/SecureCookieAttribute',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies',
            'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
            'https://cwe.mitre.org/data/definitions/614.html'
        ],
        'examples': {
            'vulnerable_code': '''
                # 취약한 쿠키 설정
                response.set_cookie('session_id', user_session_id)
                response.set_cookie('user_token', auth_token, max_age=31536000)  # 1년

                // JavaScript
                document.cookie = "user_data=" + userData;
            ''',
            'secure_code': '''
                # 안전한 쿠키 설정
                response.set_cookie(
                    'session_id',
                    user_session_id,
                    secure=True,       # HTTPS only
                    httponly=True,     # No JS access
                    samesite='Strict', # CSRF protection
                    max_age=3600       # 1 hour expiry
                )

                # Django 예제
                response.set_cookie(
                    key='sessionid',
                    value=session_id,
                    max_age=None,      # Session cookie
                    expires=None,
                    path='/',
                    domain=None,
                    secure=True,
                    httponly=True,
                    samesite='Lax'
                )
            '''
        }
    }

    # ========== 생성자 ==========
    def __init__(self, response=None, **kwargs):
        """
        Args:
            response: HTTP 응답 객체
            **kwargs: BaseScanner 호환 인자
        """
        # BaseScanner 초기화
        url = kwargs.pop('url', '')
        super().__init__(url=url, response=response, **kwargs)

        # 쿠키 설정
        if response and hasattr(response, 'cookies'):
            self.cookies = response.cookies
        else:
            self.cookies = []

        # issues 사용
        self.issues = []

    # ========== 스캔 실행 ==========
    def _execute_scan(self) -> None:
        """쿠키 보안 검사 실행"""
        self.checked = 1  # 최소 1개 검사 (쿠키 존재 여부)

        if not self.cookies:
            self._add_detail(
                id='cookie_check',
                name='쿠키 존재 여부',
                status='info',
                severity='info',
                description='응답에 Set-Cookie 헤더가 없습니다.',
                value='쿠키 없음',
                expected=None,
                recommendation='쿠키를 사용하지 않는 경우 해당 없음'
            )
            return

        # 쿠키가 있는 경우 - 쿠키 존재 detail 추가
        self._add_detail(
            id='cookie_check',
            name='쿠키 존재 여부',
            status='pass',
            severity='info',
            description=f'{len(self.cookies)}개의 쿠키가 발견되었습니다.',
            value=f'{len(self.cookies)}개',
            expected=None,
            recommendation=None
        )

        self.checked = len(self.cookies) + 1  # 쿠키 존재 여부 + 각 쿠키 검사

        for cookie in self.cookies:
            cookie_id = f'cookie_{cookie.name}'
            issues_found = []
            severity = 'info'

            # 1. Secure 플래그 검사
            has_secure = cookie.secure
            if not has_secure:
                issues_found.append('Secure 없음')
                if self.url and self.url.startswith('https://'):
                    severity = 'medium'

            # 2. HttpOnly 플래그 검사
            http_only = getattr(cookie, 'httponly', None)
            if http_only is None and hasattr(cookie, '_rest'):
                http_only = cookie._rest.get('HttpOnly')
            has_httponly = bool(http_only)

            if not has_httponly:
                issues_found.append('HttpOnly 없음')
                if 'session' in cookie.name.lower():
                    severity = 'high'

            # 3. SameSite 속성 검사
            same_site = getattr(cookie, 'samesite', None)
            if same_site is None and hasattr(cookie, '_rest'):
                same_site = cookie._rest.get('SameSite')

            if not same_site:
                issues_found.append('SameSite 없음')
            elif same_site.lower() == 'none':
                issues_found.append('SameSite=None')
                severity = 'medium' if severity == 'info' else severity

            # 4. 만료 시간 검사
            long_expiry = False
            if cookie.expires and cookie.expires > time.time() + (365 * 24 * 60 * 60):
                issues_found.append('만료 1년 초과')
                long_expiry = True

            # 5. 민감한 이름 검사
            sensitive_names = ['password', 'pwd', 'token', 'api', 'secret', 'key']
            sensitive_name_found = None
            for sensitive in sensitive_names:
                if sensitive in cookie.name.lower():
                    sensitive_name_found = sensitive
                    issues_found.append(f'민감한 이름: {sensitive}')
                    severity = 'high'
                    break

            # 결과 추가
            if issues_found:
                self._add_detail(
                    id=cookie_id,
                    name=cookie.name,
                    status='fail' if severity in ['high', 'critical'] else 'warning',
                    severity=severity,
                    description=', '.join(issues_found),
                    value=f'Secure={has_secure}, HttpOnly={has_httponly}, SameSite={same_site or "없음"}',
                    expected='Secure=True, HttpOnly=True, SameSite=Strict/Lax',
                    recommendation='Secure, HttpOnly, SameSite 속성을 설정하세요.'
                )
                self.issues.append({
                    'type': 'Insecure Cookie',
                    'severity': severity,
                    'cookie_name': cookie.name,
                    'issues': issues_found,
                    'description': f'쿠키 "{cookie.name}"의 보안 설정이 부족합니다.',
                    'recommendation': 'Secure, HttpOnly, SameSite 속성을 설정하세요.'
                })
            else:
                self._add_detail(
                    id=cookie_id,
                    name=cookie.name,
                    status='pass',
                    severity='info',
                    description='모든 보안 속성이 올바르게 설정됨',
                    value=f'Secure={has_secure}, HttpOnly={has_httponly}, SameSite={same_site}',
                    expected=None,
                    recommendation=None
                )

    # ========== 헬퍼 메서드 ==========
    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'total_cookies': len(self.cookies),
            'insecure_cookies': len(self.issues),
            'secure_percentage': ((len(self.cookies) - len(self.issues)) / len(self.cookies) * 100) if self.cookies else 100,
            'has_secure_cookies': len(self.issues) == 0 if self.cookies else True

        }
    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata
