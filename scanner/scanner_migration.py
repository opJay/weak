"""
스캐너 마이그레이션 매핑
리팩토링된 스캐너와 기존 스캐너 간의 매핑을 관리

점진적 마이그레이션을 위해 이 파일에서 어떤 스캐너를 사용할지 결정
"""

import logging
from typing import Type, Any

logger = logging.getLogger(__name__)

# 마이그레이션 활성화 플래그
USE_REFACTORED_SCANNERS = True  # True로 설정하면 리팩토링된 스캐너 사용

def get_scanner_class(scanner_name: str) -> Type[Any]:
    """
    스캐너 이름으로 적절한 클래스 반환

    Args:
        scanner_name: 스캐너 클래스 이름

    Returns:
        스캐너 클래스
    """
    if not USE_REFACTORED_SCANNERS:
        # 기존 스캐너 사용
        return _get_original_scanner(scanner_name)

    # 리팩토링된 스캐너 매핑
    refactored_mapping = {
        # Batch 1 - scanners_refactored.py
        'SecurityHeaderScanner': ('scanners_refactored', 'SecurityHeaderScanner'),
        'CORSScanner': ('scanners_refactored', 'CORSScanner'),

        # Batch 1 - scanners_refactored_batch1.py
        'CookieScanner': ('scanners_refactored_batch1', 'CookieScanner'),
        'ClickjackingScanner': ('scanners_refactored_batch1', 'ClickjackingScanner'),
        'SubresourceIntegrityScanner': ('scanners_refactored_batch1', 'SubresourceIntegrityScanner'),

        # Batch 2 - scanners_refactored_batch2.py
        'XSSScanner': ('scanners_refactored_batch2', 'XSSScanner'),
        'SQLInjectionScanner': ('scanners_refactored_batch2', 'SQLInjectionScanner'),
        'CSRFScanner': ('scanners_refactored_batch2', 'CSRFScanner'),
        'InformationDisclosureScanner': ('scanners_refactored_batch2', 'InformationDisclosureScanner'),
        'MixedContentScanner': ('scanners_refactored_batch2', 'MixedContentScanner'),
    }

    # 리팩토링된 스캐너가 있는지 확인
    if scanner_name in refactored_mapping:
        module_name, class_name = refactored_mapping[scanner_name]
        try:
            module = __import__(f'scanner.{module_name}', fromlist=[class_name])
            scanner_class = getattr(module, class_name)
            logger.info(f"Using refactored scanner: {scanner_name} from {module_name}")
            return scanner_class
        except (ImportError, AttributeError) as e:
            logger.warning(f"Failed to import refactored scanner {scanner_name}: {e}")
            # 실패시 기존 스캐너로 폴백
            return _get_original_scanner(scanner_name)

    # 리팩토링되지 않은 스캐너는 기존 것 사용
    return _get_original_scanner(scanner_name)


def _get_original_scanner(scanner_name: str) -> Type[Any]:
    """
    기존 스캐너 클래스 가져오기

    Args:
        scanner_name: 스캐너 클래스 이름

    Returns:
        기존 스캐너 클래스
    """
    # 스캐너별 모듈 매핑
    original_mapping = {
        # scanners.py
        'SecurityHeaderScanner': 'scanners',
        'XSSScanner': 'scanners',
        'SQLInjectionScanner': 'scanners',
        'CORSScanner': 'scanners',
        'CookieScanner': 'scanners',
        'CSRFScanner': 'scanners',
        'ClickjackingScanner': 'scanners',
        'InformationDisclosureScanner': 'scanners',
        'HTTPMethodScanner': 'scanners',
        'SensitiveFileScanner': 'scanners',
        'MixedContentScanner': 'scanners',
        'SubresourceIntegrityScanner': 'scanners',
        'DirectoryListingScanner': 'scanners',
        'OpenRedirectScanner': 'scanners',

        # scanners_advanced.py
        'SSRFScanner': 'scanners_advanced',
        'XXEScanner': 'scanners_advanced',
        'CommandInjectionScanner': 'scanners_advanced',
        'DeserializationScanner': 'scanners_advanced',
        'FileUploadScanner': 'scanners_advanced',
        'PathTraversalScanner': 'scanners_advanced',
        'JWTSecurityScanner': 'scanners_advanced',
        'TemplateInjectionScanner': 'scanners_advanced',
        'NoSQLInjectionScanner': 'scanners_advanced',
        'SSLTLSDeepScanner': 'scanners_advanced',

        # scanners_api.py
        'RESTAPISecurityScanner': 'scanners_api',
        'GraphQLSecurityScanner': 'scanners_api',
        'OAuthSecurityScanner': 'scanners_api',
        'SessionSecurityScanner': 'scanners_api',
        'PasswordPolicyScanner': 'scanners_api',
        'RateLimitingScanner': 'scanners_api',
        'LDAPInjectionScanner': 'scanners_api',
        'AuthorizationScanner': 'scanners_api',

        # 기타
        'SoftwareSupplyChainScanner': 'scanners_supply_chain',
        'ExceptionHandlingScanner': 'scanners_exception',
    }

    module_name = original_mapping.get(scanner_name, 'scanners')

    try:
        module = __import__(f'scanner.{module_name}', fromlist=[scanner_name])
        scanner_class = getattr(module, scanner_name)
        return scanner_class
    except (ImportError, AttributeError) as e:
        logger.error(f"Failed to import original scanner {scanner_name}: {e}")
        raise


def is_refactored(scanner_name: str) -> bool:
    """
    스캐너가 리팩토링되었는지 확인

    Args:
        scanner_name: 스캐너 클래스 이름

    Returns:
        리팩토링 여부
    """
    refactored_scanners = {
        'SecurityHeaderScanner', 'CORSScanner',
        'CookieScanner', 'ClickjackingScanner', 'SubresourceIntegrityScanner',
        'XSSScanner', 'SQLInjectionScanner', 'CSRFScanner',
        'InformationDisclosureScanner', 'MixedContentScanner'
    }

    return scanner_name in refactored_scanners


def get_scanner_init_args(scanner_name: str, **kwargs) -> dict:
    """
    스캐너 초기화 인자 준비
    리팩토링된 스캐너와 기존 스캐너의 인터페이스 차이 처리

    Args:
        scanner_name: 스캐너 클래스 이름
        **kwargs: 스캐너에 전달할 인자

    Returns:
        스캐너 초기화 인자
    """
    # 리팩토링된 스캐너들은 BaseScanner 인터페이스 사용
    if USE_REFACTORED_SCANNERS and is_refactored(scanner_name):
        # BaseScanner 호환 인자 매핑
        init_args = {}

        # URL
        if 'url' in kwargs:
            init_args['url'] = kwargs['url']

        # HTML 콘텐츠
        if 'html_content' in kwargs:
            init_args['html_content'] = kwargs['html_content']
        elif 'content' in kwargs:
            init_args['html_content'] = kwargs['content']

        # Response 객체
        if 'response' in kwargs:
            init_args['response'] = kwargs['response']

        # Headers
        if 'headers' in kwargs:
            init_args['headers'] = kwargs['headers']

        # Session
        if 'session' in kwargs:
            init_args['session'] = kwargs['session']

        return init_args

    # 기존 스캐너는 그대로 전달
    return kwargs