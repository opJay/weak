"""
BaseScanner - 모든 스캐너의 베이스 클래스

리팩토링을 위한 표준화된 스캐너 인터페이스 제공
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Protocol, List
import requests


class HttpClient(Protocol):
    """HTTP 클라이언트 인터페이스 (의존성 주입용)"""

    def get(self, url: str, **kwargs) -> Any:
        """HTTP GET 요청"""
        ...

    def post(self, url: str, **kwargs) -> Any:
        """HTTP POST 요청"""
        ...

    def options(self, url: str, **kwargs) -> Any:
        """HTTP OPTIONS 요청"""
        ...

    def head(self, url: str, **kwargs) -> Any:
        """HTTP HEAD 요청"""
        ...


class BaseScanner(ABC):
    """
    모든 스캐너의 베이스 클래스

    표준화된 인터페이스와 공통 기능 제공:
    - 예외 처리
    - 결과 빌드
    - 심각도 계산
    - 의존성 주입
    """

    # 서브클래스에서 반드시 정의해야 할 메타데이터
    metadata: Dict[str, Any] = {}

    def __init__(
        self,
        url: str,
        response: Optional[Any] = None,
        html_content: Optional[str] = None,
        http_client: Optional[HttpClient] = None,
        session: Optional[Any] = None,
        **kwargs
    ):
        """
        표준화된 생성자

        Args:
            url: 스캔 대상 URL
            response: HTTP 응답 객체 (선택)
            html_content: HTML 콘텐츠 (선택)
            http_client: HTTP 클라이언트 (DI용, 선택)
            session: requests.Session 객체 (레거시 호환성)
            **kwargs: 추가 파라미터 (레거시 호환성)
        """
        self.url = url
        self.response = response
        self.html_content = html_content
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.issues: List[Dict[str, Any]] = []  # 일부 스캐너는 issues 사용
        self.checked: int = 0  # 검사 대상 수 (0 = 해당없음)
        self.logger = logging.getLogger(self.__class__.__name__)

        # HTTP 클라이언트 설정 (의존성 주입)
        if http_client:
            self.http_client = http_client
        elif session:
            self.http_client = session  # 레거시 호환
            self.session = session
        else:
            self.http_client = requests
            self.session = requests.Session()

        # 레거시 호환성: 추가 속성들
        for key, value in kwargs.items():
            setattr(self, key, value)

    def scan(self) -> Dict[str, Any]:
        """
        스캔 실행 (템플릿 메서드 패턴)

        Returns:
            표준화된 결과 딕셔너리
        """
        try:
            # 실제 스캔 로직 실행
            self._execute_scan()

            # 결과 빌드
            return self._build_result()

        except Exception as e:
            self.logger.error(
                f"{self.__class__.__name__} scan error: {str(e)}",
                exc_info=True
            )
            return self._build_error_result(str(e))

    @abstractmethod
    def _execute_scan(self) -> None:
        """
        실제 스캔 로직 구현 (서브클래스에서 구현)

        이 메서드에서 self.vulnerabilities 또는 self.issues에
        발견된 취약점/이슈를 추가해야 함
        """
        pass

    def _build_result(self) -> Dict[str, Any]:
        """
        표준화된 결과 반환

        Returns:
            스캔 결과 딕셔너리
        """
        # _build_vulnerabilities 메서드가 있으면 호출
        if hasattr(self, '_build_vulnerabilities'):
            vulnerabilities = self._build_vulnerabilities()
        else:
            vulnerabilities = self.vulnerabilities if self.vulnerabilities else self.issues

        # vulnerabilities와 issues 중 사용되는 것 확인
        items = self.vulnerabilities if self.vulnerabilities else self.issues
        field_name = 'vulnerabilities' if self.vulnerabilities else 'issues'

        result = {
            'vulnerabilities': vulnerabilities,  # _build_vulnerabilities 결과 사용
            field_name: items,
            'total': len(items),
            'scanner_id': self.metadata.get('id', 'unknown'),
            'checked': self.checked,
            'passed': max(0, self.checked - len(items)),
        }

        # 상태 계산
        if self.checked == 0:
            result['status'] = 'not_applicable'
        elif len(items) == 0:
            result['status'] = 'pass'
        else:
            result['status'] = 'fail'

        # 심각도 계산 및 추가
        severity = self._calculate_severity()
        if severity:
            result['severity'] = severity

        # 메타데이터의 field에 따라 추가 필드 설정
        field = self.metadata.get('field')
        if field:
            # has_xxx 형태의 필드 추가
            if field.endswith('_vulnerabilities'):
                has_field = f"has_{field.replace('_vulnerabilities', '').replace('_', '')}"
            elif field.endswith('_issues'):
                has_field = f"has_{field.replace('_issues', '').replace('_', '')}"
            else:
                has_field = f"has_{field}"

            result[has_field] = len(items) > 0

        # 서브클래스별 추가 필드 병합
        additional_fields = self._get_additional_fields()
        if additional_fields:
            result.update(additional_fields)

        return result

    def get_metadata(self) -> Dict[str, Any]:
        """스캐너 메타데이터 반환"""
        return self.metadata

    def _build_error_result(self, error: str) -> Dict[str, Any]:
        """
        에러 발생 시 반환할 결과

        Args:
            error: 에러 메시지

        Returns:
            에러 결과 딕셔너리
        """
        result = {
            'vulnerabilities': [],
            'issues': [],
            'total': 0,
            'scanner_id': self.metadata.get('id', 'unknown'),
            'error': error
        }

        # 메타데이터의 field에 따라 추가 필드 설정
        field = self.metadata.get('field')
        if field:
            if field.endswith('_vulnerabilities'):
                has_field = f"has_{field.replace('_vulnerabilities', '').replace('_', '')}"
            elif field.endswith('_issues'):
                has_field = f"has_{field.replace('_issues', '').replace('_', '')}"
            else:
                has_field = f"has_{field}"

            result[has_field] = False

        return result

    def get_metadata(self) -> Dict[str, Any]:
        """스캐너 메타데이터 반환"""
        return self.metadata

    def _calculate_severity(self) -> str:
        """
        발견된 취약점/이슈의 최고 심각도 계산

        Returns:
            심각도 문자열 ('critical', 'high', 'medium', 'low', 'safe')
        """
        items = self.vulnerabilities if self.vulnerabilities else self.issues

        if not items:
            return 'safe'

        severities = []
        for item in items:
            if isinstance(item, dict):
                severity = item.get('severity', 'low')
                severities.append(severity)

        # 최고 심각도 반환
        if 'critical' in severities:
            return 'critical'
        elif 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        elif 'low' in severities:
            return 'low'

        return 'safe'

    def _get_additional_fields(self) -> Dict[str, Any]:
        """
        서브클래스별 추가 필드 반환 (오버라이드 가능)

        Returns:
            추가 필드 딕셔너리
        """
        return {}

    def _get_recommendations(self) -> List[str]:
        """
        권장사항 목록 반환 (서브클래스에서 오버라이드 가능)

        Returns:
            권장사항 문자열 리스트
        """
        recommendations = []
        items = self.vulnerabilities if self.vulnerabilities else self.issues

        for item in items:
            if isinstance(item, dict) and 'recommendation' in item:
                recommendation = item['recommendation']
                if recommendation and recommendation not in recommendations:
                    recommendations.append(recommendation)

        return recommendations


class LegacyCompatibleScanner(BaseScanner):
    """
    레거시 스캐너와의 호환성을 위한 중간 클래스

    기존 스캐너를 점진적으로 마이그레이션할 때 사용
    """

    def __init__(self, *args, **kwargs):
        """
        유연한 생성자 - 다양한 시그니처 지원
        """
        # URL 찾기 (첫 번째 문자열 인자 또는 kwargs['url'])
        url = None
        response = None
        html_content = None
        session = None

        # 위치 인자 처리
        for arg in args:
            if isinstance(arg, str) and not url:
                url = arg
            elif hasattr(arg, 'headers'):  # response-like object
                response = arg
            elif isinstance(arg, str) and url:  # 두 번째 문자열은 html_content
                html_content = arg
            elif hasattr(arg, 'get'):  # session-like object
                session = arg

        # 키워드 인자 처리
        url = kwargs.pop('url', url) or ''
        response = kwargs.pop('response', response)
        html_content = kwargs.pop('html_content', html_content)
        session = kwargs.pop('session', session)

        # 베이스 클래스 초기화
        super().__init__(
            url=url,
            response=response,
            html_content=html_content,
            session=session,
            **kwargs
        )

    def _scan_impl(self) -> Dict[str, Any]:
        """
        레거시 scan() 메서드의 구현부
        서브클래스에서 기존 scan() 로직을 여기로 이동
        """
        raise NotImplementedError(
            "서브클래스에서 _scan_impl() 메서드를 구현해야 합니다."
        )