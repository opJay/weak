"""
Business Logic and Insecure Design Scanners
OWASP Top 10 2025 A06 (Insecure Design) & A09 (Logging & Alerting Failures) 대응
"""
import re
import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging
import concurrent.futures

logger = logging.getLogger('scanner')


class PriceManipulationScanner:
    """
    가격 조작 취약점 스캐너

    OWASP Top 10 2025 A06: Insecure Design 대응
    - 음수 가격/수량 입력 테스트
    - 가격 파라미터 변조 탐지
    - 과도한 할인율 적용 시도
    """

    metadata = {
        'id': 'price_manipulation',
        'name': '가격 조작 탐지',
        'icon': '💰',
        'description': '비즈니스 로직 - 가격/수량 조작 취약점 탐지',
        'weight': 1.5,
        'field': 'price_manipulation_vulnerabilities'
    }

    # 가격 관련 파라미터 패턴
    PRICE_PARAMS = [
        'price', 'amount', 'cost', 'total', 'subtotal',
        'quantity', 'qty', 'count', 'discount', 'coupon'
    ]

    def __init__(self, url, response=None, html_content=None):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """가격 조작 스캔 실행"""
        try:
            # 1. URL 파라미터에서 가격 관련 항목 탐지
            self._check_price_parameters()

            # 2. 폼에서 가격 필드 탐지
            if self.html_content:
                self._check_price_forms()

            # 3. 음수 가격 테스트
            self._test_negative_values()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'Price Manipulation Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _check_price_parameters(self):
        """URL 파라미터에서 가격 관련 항목 검사"""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        for param_name in params.keys():
            if any(price_word in param_name.lower() for price_word in self.PRICE_PARAMS):
                self.vulnerabilities.append({
                    'type': 'price_parameter_exposure',
                    'severity': 'high',
                    'title': f'가격 파라미터 노출: {param_name}',
                    'description': f'URL에 가격 관련 파라미터({param_name})가 노출되어 있어 조작 가능성이 있습니다.',
                    'evidence': f'{param_name}={params[param_name]}',
                    'recommendation': '가격은 서버 측에서만 결정하고, 클라이언트 입력을 신뢰하지 마세요.'
                })

    def _check_price_forms(self):
        """폼에서 숨겨진 가격 필드 검사"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        for form in soup.find_all('form'):
            for input_tag in form.find_all('input'):
                input_name = input_tag.get('name', '').lower()
                input_type = input_tag.get('type', '').lower()
                input_value = input_tag.get('value', '')

                # 숨겨진 가격 필드 탐지
                if input_type == 'hidden' and any(p in input_name for p in self.PRICE_PARAMS):
                    self.vulnerabilities.append({
                        'type': 'hidden_price_field',
                        'severity': 'high',
                        'title': f'숨겨진 가격 필드: {input_name}',
                        'description': 'HTML에 숨겨진 가격 필드가 존재하여 클라이언트에서 변조 가능합니다.',
                        'evidence': f'<input type="hidden" name="{input_name}" value="{input_value}">',
                        'recommendation': '가격 정보는 세션이나 서버 DB에서 관리하세요.'
                    })

    def _test_negative_values(self):
        """음수 가격/수량 테스트"""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        test_values = ['-1', '-100', '0']

        for param_name in params.keys():
            if any(p in param_name.lower() for p in self.PRICE_PARAMS):
                for test_value in test_values[:1]:  # 첫 번째 값만 테스트
                    test_params = params.copy()
                    test_params[param_name] = [test_value]

                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))

                    try:
                        response = requests.get(test_url, timeout=5)

                        if response.status_code == 200:
                            # 음수 값이 허용됨
                            self.vulnerabilities.append({
                                'type': 'negative_value_accepted',
                                'severity': 'critical',
                                'title': f'음수 값 허용: {param_name}',
                                'description': f'파라미터 {param_name}에 음수 값({test_value})이 허용되어 가격 조작이 가능합니다.',
                                'url': test_url,
                                'recommendation': '입력 값 검증을 통해 양수만 허용하세요.'
                            })
                            break  # 한 번만 보고

                    except requests.RequestException:
                        pass

    def _calculate_severity(self):
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'low')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if severity_counts['critical'] > 0:
            return 'critical'
        elif severity_counts['high'] >= 1:
            return 'high'
        else:
            return 'medium'

    def _get_recommendations(self):
        """보안 권장사항"""
        return [
            '가격과 수량은 서버 측에서만 결정하고, 클라이언트 입력을 절대 신뢰하지 마세요.',
            '모든 금액 관련 입력 값은 양수인지 검증하세요.',
            '할인율은 미리 정의된 값만 허용하세요.',
            '최종 금액은 서버에서 재계산하고 검증하세요.',
            '트랜잭션 로그를 남겨 이상 거래를 모니터링하세요.'
        ]


class RaceConditionScanner:
    """
    레이스 컨디션 취약점 스캐너

    OWASP Top 10 2025 A06: Insecure Design 대응
    - 동시 요청 처리 테스트
    - TOCTOU 취약점 탐지
    """

    metadata = {
        'id': 'race_condition',
        'name': '레이스 컨디션 탐지',
        'icon': '🏁',
        'description': '비즈니스 로직 - 동시성 제어 취약점 탐지',
        'weight': 1.5,
        'field': 'race_condition_vulnerabilities'
    }

    def __init__(self, url, response=None, html_content=None):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """레이스 컨디션 스캔 실행"""
        try:
            # 1. 동시 요청 테스트
            self._test_concurrent_requests()

            # 2. 상태 변경 엔드포인트 탐지
            if self.html_content:
                self._detect_state_changing_endpoints()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'Race Condition Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _test_concurrent_requests(self):
        """동시 요청 테스트 (간단한 버전)"""
        try:
            # 5개의 동시 요청
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self._make_request) for _ in range(5)]
                responses = [f.result() for f in concurrent.futures.as_completed(futures)]

            # 응답 상태 코드 분석
            status_codes = [r.status_code for r in responses if r]

            # 모두 성공하면 동시성 제어 부재 가능성
            if all(code == 200 for code in status_codes) and len(status_codes) == 5:
                self.vulnerabilities.append({
                    'type': 'no_concurrency_control',
                    'severity': 'medium',
                    'title': '동시성 제어 부재 가능성',
                    'description': '5개의 동시 요청이 모두 성공적으로 처리되어 레이스 컨디션 취약점이 있을 수 있습니다.',
                    'evidence': f'동시 요청 5개 모두 HTTP 200 응답',
                    'recommendation': '트랜잭션 격리 수준을 설정하고, 낙관적/비관적 잠금을 사용하세요.'
                })

        except Exception as e:
            logger.debug(f'Concurrent request test failed: {e}')

    def _make_request(self):
        """단일 요청 수행"""
        try:
            return requests.get(self.url, timeout=3)
        except:
            return None

    def _detect_state_changing_endpoints(self):
        """상태 변경 엔드포인트 탐지"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        # POST 폼 찾기
        post_forms = soup.find_all('form', method=lambda x: x and 'post' in x.lower())

        if len(post_forms) > 0:
            self.vulnerabilities.append({
                'type': 'state_changing_forms_detected',
                'severity': 'low',
                'title': f'{len(post_forms)}개의 상태 변경 폼 탐지',
                'description': 'POST 폼이 발견되었습니다. 레이스 컨디션 테스트가 필요할 수 있습니다.',
                'recommendation': '중요한 작업(결제, 재고 차감 등)에는 멱등성 키(Idempotency Key)를 사용하세요.'
            })

    def _calculate_severity(self):
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        severities = [v.get('severity', 'low') for v in self.vulnerabilities]
        if 'critical' in severities or 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        else:
            return 'low'

    def _get_recommendations(self):
        """보안 권장사항"""
        return [
            '데이터베이스 트랜잭션 격리 수준을 적절히 설정하세요 (SERIALIZABLE 권장).',
            '중요한 작업에는 낙관적 잠금(Optimistic Locking)이나 비관적 잠금을 사용하세요.',
            '멱등성 키(Idempotency Key)를 사용하여 중복 요청을 방지하세요.',
            '재고 차감 등의 critical section에는 분산 잠금(Redis, Zookeeper)을 고려하세요.'
        ]


class WorkflowBypassScanner:
    """
    워크플로우 우회 취약점 스캐너

    OWASP Top 10 2025 A06: Insecure Design 대응
    - 단계 건너뛰기 탐지
    - 상태 변조 테스트
    """

    metadata = {
        'id': 'workflow_bypass',
        'name': '워크플로우 우회 탐지',
        'icon': '🔀',
        'description': '비즈니스 로직 - 프로세스 단계 우회 탐지',
        'weight': 1,
        'field': 'workflow_bypass_vulnerabilities'
    }

    # 워크플로우 관련 파라미터
    WORKFLOW_PARAMS = [
        'step', 'stage', 'status', 'state', 'phase',
        'level', 'progress', 'completed'
    ]

    def __init__(self, url, response=None, html_content=None):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """워크플로우 우회 스캔 실행"""
        try:
            # 1. 워크플로우 파라미터 탐지
            self._check_workflow_parameters()

            # 2. 숨겨진 상태 필드 탐지
            if self.html_content:
                self._check_hidden_state_fields()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'Workflow Bypass Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _check_workflow_parameters(self):
        """URL 파라미터에서 워크플로우 관련 항목 검사"""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        for param_name in params.keys():
            if any(wf in param_name.lower() for wf in self.WORKFLOW_PARAMS):
                self.vulnerabilities.append({
                    'type': 'workflow_parameter_exposure',
                    'severity': 'high',
                    'title': f'워크플로우 파라미터 노출: {param_name}',
                    'description': f'URL에 워크플로우 상태 파라미터({param_name})가 노출되어 단계 건너뛰기가 가능할 수 있습니다.',
                    'evidence': f'{param_name}={params[param_name]}',
                    'recommendation': '워크플로우 상태는 서버 세션에서 관리하고, 각 단계마다 권한과 전제 조건을 검증하세요.'
                })

    def _check_hidden_state_fields(self):
        """숨겨진 상태 필드 검사"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        for form in soup.find_all('form'):
            for input_tag in form.find_all('input', type='hidden'):
                input_name = input_tag.get('name', '').lower()
                input_value = input_tag.get('value', '')

                if any(wf in input_name for wf in self.WORKFLOW_PARAMS):
                    self.vulnerabilities.append({
                        'type': 'hidden_workflow_field',
                        'severity': 'high',
                        'title': f'숨겨진 워크플로우 필드: {input_name}',
                        'description': 'HTML에 숨겨진 상태 필드가 존재하여 클라이언트에서 변조 가능합니다.',
                        'evidence': f'<input type="hidden" name="{input_name}" value="{input_value}">',
                        'recommendation': '상태 정보는 서버 세션에 저장하고, 각 단계 전환 시 검증하세요.'
                    })

    def _calculate_severity(self):
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        if any(v.get('severity') == 'high' for v in self.vulnerabilities):
            return 'high'
        else:
            return 'medium'

    def _get_recommendations(self):
        """보안 권장사항"""
        return [
            '워크플로우 상태는 서버 세션이나 데이터베이스에서만 관리하세요.',
            '각 단계 전환 시 이전 단계의 완료 여부를 서버에서 검증하세요.',
            '클라이언트에서 전송된 상태 값을 절대 신뢰하지 마세요.',
            '상태 기계(State Machine) 패턴을 사용하여 허용된 전환만 가능하도록 하세요.'
        ]


class AccountEnumerationScanner:
    """
    계정 열거 취약점 스캐너

    OWASP Top 10 2025 A06 + A07 대응
    - 사용자명/이메일 존재 여부 유출
    - 응답 차이 분석
    """

    metadata = {
        'id': 'account_enumeration',
        'name': '계정 열거 탐지',
        'icon': '👤',
        'description': '비즈니스 로직 - 계정 존재 여부 유출 탐지',
        'weight': 1,
        'field': 'account_enumeration_vulnerabilities'
    }

    def __init__(self, url, response=None, html_content=None):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """계정 열거 스캔 실행"""
        try:
            # 1. 로그인 폼 탐지
            if self.html_content:
                self._detect_login_forms()

            # 2. 에러 메시지 차이 탐지
            self._check_error_message_differences()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'Account Enumeration Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _detect_login_forms(self):
        """로그인 폼 탐지"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 로그인 폼 또는 비밀번호 입력이 있는 폼 찾기
        login_indicators = ['login', 'signin', 'password', 'email', 'username']

        for form in soup.find_all('form'):
            form_text = str(form).lower()
            if any(indicator in form_text for indicator in login_indicators):
                self.vulnerabilities.append({
                    'type': 'login_form_detected',
                    'severity': 'low',
                    'title': '로그인 폼 탐지',
                    'description': '로그인 폼이 발견되었습니다. 계정 열거 취약점 테스트가 필요합니다.',
                    'recommendation': '존재하지 않는 계정과 잘못된 비밀번호에 대해 동일한 에러 메시지를 표시하세요.'
                })
                break

    def _check_error_message_differences(self):
        """에러 메시지 차이 탐지"""
        if not self.html_content:
            return

        # 계정 존재 여부를 알려주는 메시지 패턴
        enumeration_patterns = [
            r'user.*not.*found',
            r'email.*not.*exist',
            r'invalid.*username',
            r'account.*does.*not.*exist',
            r'사용자.*없음',
            r'이메일.*존재.*않',
        ]

        content_lower = self.html_content.lower()

        for pattern in enumeration_patterns:
            if re.search(pattern, content_lower):
                self.vulnerabilities.append({
                    'type': 'account_enumeration_message',
                    'severity': 'medium',
                    'title': '계정 열거 가능 에러 메시지',
                    'description': '계정 존재 여부를 알려주는 에러 메시지가 발견되었습니다.',
                    'evidence': f'패턴 매칭: {pattern}',
                    'recommendation': '"잘못된 이메일 또는 비밀번호입니다"와 같은 일반적인 메시지를 사용하세요.'
                })
                break

    def _calculate_severity(self):
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        if any(v.get('severity') == 'medium' for v in self.vulnerabilities):
            return 'medium'
        else:
            return 'low'

    def _get_recommendations(self):
        """보안 권장사항"""
        return [
            '계정 존재 여부와 비밀번호 오류에 대해 동일한 에러 메시지를 표시하세요.',
            '응답 시간도 일정하게 유지하세요 (타이밍 공격 방지).',
            '비밀번호 재설정 시에도 계정 존재 여부를 알려주지 마세요.',
            'CAPTCHA를 사용하여 자동화된 계정 열거를 방지하세요.'
        ]


class ResourceExhaustionScanner:
    """
    리소스 소진 취약점 스캐너

    OWASP Top 10 2025 A06: Insecure Design 대응
    - 과도한 리소스 사용 탐지
    - 제한 없는 파일 업로드
    """

    metadata = {
        'id': 'resource_exhaustion',
        'name': '리소스 소진 탐지',
        'icon': '📈',
        'description': '비즈니스 로직 - 리소스 고갈 공격 가능성 탐지',
        'weight': 1,
        'field': 'resource_exhaustion_vulnerabilities'
    }

    def __init__(self, url, response=None, html_content=None):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """리소스 소진 스캔 실행"""
        try:
            # 1. 파일 업로드 폼 검사
            if self.html_content:
                self._check_file_upload_limits()

            # 2. API 크기 제한 검사
            self._check_request_size_limits()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'Resource Exhaustion Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _check_file_upload_limits(self):
        """파일 업로드 제한 검사"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        # 파일 업로드 input 찾기
        file_inputs = soup.find_all('input', type='file')

        for file_input in file_inputs:
            # maxsize 속성 확인
            if not file_input.get('maxsize'):
                self.vulnerabilities.append({
                    'type': 'no_file_size_limit',
                    'severity': 'medium',
                    'title': '파일 크기 제한 없음',
                    'description': '파일 업로드에 크기 제한이 명시되지 않아 대용량 파일 업로드가 가능할 수 있습니다.',
                    'recommendation': '파일 크기를 클라이언트와 서버 양쪽에서 제한하세요.'
                })
                break

    def _check_request_size_limits(self):
        """요청 크기 제한 검사"""
        # Content-Length 헤더가 있으면 제한이 있을 가능성
        if self.response:
            # 서버 응답에서 제한 확인
            headers = self.response.headers

            # Rate limiting 관련 헤더 확인
            if not any(h in headers for h in ['X-RateLimit-Limit', 'RateLimit-Limit']):
                self.vulnerabilities.append({
                    'type': 'no_rate_limiting_headers',
                    'severity': 'low',
                    'title': 'Rate Limiting 헤더 부재',
                    'description': 'Rate limiting 관련 응답 헤더가 없어 리소스 제한이 없을 수 있습니다.',
                    'recommendation': 'API Rate Limiting을 구현하고 X-RateLimit-* 헤더를 반환하세요.'
                })

    def _calculate_severity(self):
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        if any(v.get('severity') == 'medium' for v in self.vulnerabilities):
            return 'medium'
        else:
            return 'low'

    def _get_recommendations(self):
        """보안 권장사항"""
        return [
            '파일 업로드는 크기와 개수를 제한하세요 (예: 10MB, 5개).',
            'API 요청은 크기를 제한하세요 (예: 1MB).',
            'Rate Limiting을 구현하여 과도한 요청을 차단하세요.',
            '타임아웃을 설정하여 무한 루프를 방지하세요.',
            '리소스 사용량을 모니터링하고 임계값을 설정하세요.'
        ]


class LoggingMonitoringScanner:
    """
    로깅 및 모니터링 검사 스캐너

    OWASP Top 10 2025 A09: Logging & Alerting Failures 대응
    - 보안 이벤트 로깅 확인
    - 감사 추적 존재 여부
    """

    metadata = {
        'id': 'logging_monitoring',
        'name': '로깅/모니터링 검사',
        'icon': '📋',
        'description': 'A09 대응 - 로깅 및 모니터링 구현 검증',
        'weight': 1.5,
        'field': 'logging_monitoring_vulnerabilities'
    }

    def __init__(self, url, response=None, html_content=None):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """로깅/모니터링 스캔 실행"""
        try:
            # 1. 응답 헤더에서 로깅 정보 확인
            self._check_logging_headers()

            # 2. 에러 처리 분석
            self._analyze_error_handling()

            # 3. 보안 이벤트 기록 여부 추정
            self._estimate_security_logging()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'Logging & Monitoring Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _check_logging_headers(self):
        """로깅 관련 헤더 확인"""
        if not self.response:
            return

        headers = self.response.headers

        # 추적 ID 헤더 확인
        trace_headers = ['X-Request-ID', 'X-Trace-ID', 'X-Correlation-ID']
        has_trace = any(h in headers for h in trace_headers)

        if not has_trace:
            self.vulnerabilities.append({
                'type': 'no_trace_id',
                'severity': 'medium',
                'title': '요청 추적 ID 부재',
                'description': '요청 추적을 위한 ID 헤더가 없어 로그 상관관계 분석이 어려울 수 있습니다.',
                'recommendation': 'X-Request-ID 또는 X-Trace-ID 헤더를 모든 응답에 포함하세요.'
            })

    def _analyze_error_handling(self):
        """에러 처리 분석"""
        # 401/403 응답 테스트
        try:
            # 인증이 필요할 만한 경로 테스트
            test_paths = ['/admin', '/api', '/dashboard']

            for path in test_paths[:1]:  # 첫 번째만 테스트
                test_url = self.url.rstrip('/') + path

                try:
                    response = requests.get(test_url, timeout=5)

                    if response.status_code in [401, 403]:
                        # 로그인 실패 시 적절한 응답
                        self.vulnerabilities.append({
                            'type': 'auth_failure_detected',
                            'severity': 'low',
                            'title': '인증 실패 응답 확인',
                            'description': f'{path} 경로에 대한 인증 실패 응답({response.status_code})이 확인되었습니다. 이러한 이벤트가 로깅되는지 확인이 필요합니다.',
                            'recommendation': '모든 인증/인가 실패를 로그에 기록하고 모니터링하세요.'
                        })
                        break

                except requests.RequestException:
                    pass

        except Exception:
            pass

    def _estimate_security_logging(self):
        """보안 이벤트 로깅 추정"""
        # 보안 헤더가 있으면 보안을 고려하고 있을 가능성
        if self.response:
            security_headers = [
                'Content-Security-Policy',
                'Strict-Transport-Security',
                'X-Content-Type-Options'
            ]

            has_security_headers = any(h in self.response.headers for h in security_headers)

            if not has_security_headers:
                self.vulnerabilities.append({
                    'type': 'low_security_awareness',
                    'severity': 'medium',
                    'title': '보안 인식 낮음',
                    'description': '보안 헤더가 없어 보안 이벤트 로깅도 미흡할 가능성이 있습니다.',
                    'recommendation': '보안 헤더를 설정하고, 보안 이벤트를 체계적으로 로깅하세요.'
                })

    def _calculate_severity(self):
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        if any(v.get('severity') == 'medium' for v in self.vulnerabilities):
            return 'medium'
        else:
            return 'low'

    def _get_recommendations(self):
        """보안 권장사항"""
        return [
            '모든 인증/인가 실패를 로그에 기록하세요.',
            '중요한 비즈니스 이벤트(결제, 계정 변경 등)를 감사 로그에 남기세요.',
            '로그에 요청 ID를 포함하여 추적 가능하게 하세요.',
            '민감한 정보(비밀번호, 토큰)는 로그에 기록하지 마세요.',
            'SIEM 시스템과 통합하여 실시간 모니터링하세요.',
            '로그 보존 정책을 수립하고 정기적으로 검토하세요.'
        ]


class BusinessLogicAnomalyScanner:
    """
    비즈니스 로직 이상 탐지 스캐너

    OWASP Top 10 2025 A06: Insecure Design 대응
    - 할인/쿠폰 중복 적용
    - 비정상적인 비즈니스 플로우
    """

    metadata = {
        'id': 'business_logic_anomaly',
        'name': '비즈니스 로직 이상 탐지',
        'icon': '🔍',
        'description': '비즈니스 로직 - 이상 패턴 및 악용 가능성 탐지',
        'weight': 1,
        'field': 'business_logic_anomaly_vulnerabilities'
    }

    # 비즈니스 로직 관련 파라미터
    LOGIC_PARAMS = [
        'discount', 'coupon', 'voucher', 'promo', 'code',
        'points', 'credit', 'balance', 'refund'
    ]

    def __init__(self, url, response=None, html_content=None):
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities = []

    def scan(self):
        """비즈니스 로직 이상 스캔 실행"""
        try:
            # 1. 할인 관련 파라미터 탐지
            self._check_discount_parameters()

            # 2. 폼에서 비즈니스 로직 필드 탐지
            if self.html_content:
                self._check_business_logic_fields()

            return {
                'vulnerabilities': self.vulnerabilities,
                'total': len(self.vulnerabilities),
                'severity': self._calculate_severity(),
                'recommendations': self._get_recommendations()
            }

        except Exception as e:
            logger.error(f'Business Logic Anomaly Scanner error: {e}')
            return {
                'vulnerabilities': [],
                'total': 0,
                'severity': 'unknown',
                'error': str(e)
            }

    def _check_discount_parameters(self):
        """할인 관련 파라미터 검사"""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        for param_name in params.keys():
            if any(logic in param_name.lower() for logic in self.LOGIC_PARAMS):
                self.vulnerabilities.append({
                    'type': 'discount_parameter_exposure',
                    'severity': 'high',
                    'title': f'할인 파라미터 노출: {param_name}',
                    'description': f'URL에 할인 관련 파라미터({param_name})가 노출되어 중복 적용이나 조작이 가능할 수 있습니다.',
                    'evidence': f'{param_name}={params[param_name]}',
                    'recommendation': '할인 로직은 서버에서만 처리하고, 중복 적용을 방지하세요.'
                })

    def _check_business_logic_fields(self):
        """비즈니스 로직 필드 검사"""
        soup = BeautifulSoup(self.html_content, 'html.parser')

        for form in soup.find_all('form'):
            for input_tag in form.find_all('input'):
                input_name = input_tag.get('name', '').lower()
                input_type = input_tag.get('type', '').lower()

                # 숨겨진 비즈니스 로직 필드
                if input_type == 'hidden' and any(l in input_name for l in self.LOGIC_PARAMS):
                    self.vulnerabilities.append({
                        'type': 'hidden_business_logic_field',
                        'severity': 'medium',
                        'title': f'숨겨진 비즈니스 로직 필드: {input_name}',
                        'description': 'HTML에 숨겨진 비즈니스 로직 필드가 존재하여 클라이언트에서 변조 가능합니다.',
                        'recommendation': '할인, 포인트, 쿠폰 정보는 서버 세션에서 관리하고 검증하세요.'
                    })

    def _calculate_severity(self):
        """전체 심각도 계산"""
        if not self.vulnerabilities:
            return 'safe'

        if any(v.get('severity') == 'high' for v in self.vulnerabilities):
            return 'high'
        else:
            return 'medium'

    def _get_recommendations(self):
        """보안 권장사항"""
        return [
            '할인과 쿠폰은 한 번만 적용되도록 서버에서 검증하세요.',
            '포인트 적립 및 차감은 트랜잭션으로 처리하세요.',
            '환불 프로세스는 원래 결제 금액을 초과할 수 없도록 제한하세요.',
            '비정상적인 패턴(과도한 환불, 할인 등)을 모니터링하세요.',
            '비즈니스 규칙은 서버 측에서만 구현하고, 클라이언트 입력을 절대 신뢰하지 마세요.'
        ]
