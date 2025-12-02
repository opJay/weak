"""
Scanner ID Registry - 중앙 집중식 ID 관리 시스템

모든 스캐너 ID와 그 매핑 정보를 한 곳에서 관리합니다.
이 파일이 scanner ID의 single source of truth입니다.

규칙:
1. canonical_id: 표준 ID (주로 단수형)
2. aliases: 별칭 목록 (호환성을 위해 유지)
3. field: 데이터베이스 필드명
4. category: 스캐너 카테고리
"""

from typing import Dict, List, Optional, Any


class ScannerRegistry:
    """Scanner ID 중앙 레지스트리"""

    # Scanner ID 정의
    # canonical_id를 키로 사용
    SCANNER_DEFINITIONS: Dict[str, Dict[str, Any]] = {
        # ========================================
        # 보안 스캐너 - 기본
        # ========================================
        'security_headers': {
            'aliases': [],
            'field': 'security_headers',
            'category': 'security_basic',
            'description': 'HTTP 보안 헤더 검사'
        },
        'ssl_tls': {
            'aliases': [],
            'field': 'ssl_tls_result',
            'category': 'security_basic',
            'description': 'SSL/TLS 기본 검사'
        },
        'xss': {
            'aliases': [],
            'field': 'xss_vulnerabilities',
            'category': 'security_basic',
            'description': 'Cross-Site Scripting 취약점'
        },
        'sql_injection': {
            'aliases': [],
            'field': 'sql_injection',
            'category': 'security_basic',
            'description': 'SQL Injection 취약점'
        },
        'cors': {
            'aliases': [],
            'field': 'cors_misconfiguration',
            'category': 'security_basic',
            'description': 'CORS 설정 검사'
        },
        'cookie_security': {
            'aliases': ['cookies'],  # scanners_compat.py 호환
            'field': 'sensitive_data_exposure',
            'category': 'security_basic',
            'description': '쿠키 보안 속성'
        },
        'csrf': {
            'aliases': [],
            'field': 'csrf_protection',
            'category': 'security_basic',
            'description': 'CSRF 토큰 검증'
        },
        'clickjacking': {
            'aliases': [],
            'field': 'clickjacking',
            'category': 'security_basic',
            'description': '클릭재킹 방어'
        },
        'information_disclosure': {
            'aliases': ['info_disclosure'],  # scanners_compat.py 호환
            'field': 'sensitive_data_exposure',
            'category': 'security_basic',
            'description': '민감정보 노출'
        },
        'http_methods': {
            'aliases': [],
            'field': 'http_methods',
            'category': 'security_basic',
            'description': '위험한 HTTP 메서드'
        },
        'sensitive_files': {
            'aliases': [],
            'field': 'sensitive_files',
            'category': 'security_basic',
            'description': '민감한 파일 노출'
        },
        'mixed_content': {
            'aliases': [],
            'field': 'mixed_content',
            'category': 'security_basic',
            'description': 'HTTPS 페이지의 HTTP 리소스'
        },
        'subresource_integrity': {
            'aliases': ['sri'],
            'field': 'subresource_integrity',
            'category': 'security_basic',
            'description': 'SRI 검사'
        },
        'directory_listing': {
            'aliases': [],
            'field': 'directory_listing',
            'category': 'security_basic',
            'description': '디렉토리 리스팅'
        },
        'open_redirect': {
            'aliases': [],
            'field': 'open_redirects',
            'category': 'security_basic',
            'description': '오픈 리다이렉트'
        },

        # ========================================
        # 보안 스캐너 - 고급
        # ========================================
        'ssrf': {
            'aliases': [],
            'field': 'ssrf_vulnerabilities',
            'category': 'security_advanced',
            'description': 'Server-Side Request Forgery'
        },
        'xxe': {
            'aliases': [],
            'field': 'xxe_vulnerabilities',
            'category': 'security_advanced',
            'description': 'XML External Entity'
        },
        'command_injection': {
            'aliases': [],
            'field': 'command_injection',
            'category': 'security_advanced',
            'description': 'OS Command Injection'
        },
        'deserialization': {
            'aliases': [],
            'field': 'deserialization',
            'category': 'security_advanced',
            'description': 'Insecure Deserialization'
        },
        'file_upload': {
            'aliases': [],
            'field': 'file_upload',
            'category': 'security_advanced',
            'description': '파일 업로드 취약점'
        },
        'path_traversal': {
            'aliases': [],
            'field': 'path_traversal',
            'category': 'security_advanced',
            'description': '경로 순회 공격'
        },
        'jwt_security': {
            'aliases': ['jwt'],
            'field': 'jwt_vulnerabilities',
            'category': 'security_advanced',
            'description': 'JWT 보안 취약점'
        },
        'template_injection': {
            'aliases': ['ssti'],
            'field': 'template_injection',
            'category': 'security_advanced',
            'description': 'Server-Side Template Injection'
        },
        'nosql_injection': {
            'aliases': ['nosql'],
            'field': 'nosql_injection',
            'category': 'security_advanced',
            'description': 'NoSQL Injection'
        },
        'ssl_tls_deep': {
            'aliases': [],
            'field': 'ssl_tls_vulnerabilities',
            'category': 'security_advanced',
            'description': 'SSL/TLS 심층 검사'
        },

        # ========================================
        # API 및 인증/인가
        # ========================================
        'rest_api_security': {
            'aliases': ['rest_api'],
            'field': 'rest_api_vulnerabilities',
            'category': 'api_auth',
            'description': 'REST API 보안'
        },
        'graphql_security': {
            'aliases': ['graphql'],
            'field': 'graphql_vulnerabilities',
            'category': 'api_auth',
            'description': 'GraphQL 보안'
        },
        'oauth_security': {
            'aliases': ['oauth'],
            'field': 'oauth_vulnerabilities',
            'category': 'api_auth',
            'description': 'OAuth 인증 취약점'
        },
        'session_security': {
            'aliases': ['session'],
            'field': 'session_vulnerabilities',
            'category': 'api_auth',
            'description': '세션 관리 취약점'
        },
        'password_policy': {
            'aliases': [],
            'field': 'password_policy',
            'category': 'api_auth',
            'description': '비밀번호 정책'
        },
        'rate_limiting': {
            'aliases': [],
            'field': 'rate_limiting',
            'category': 'api_auth',
            'description': 'Rate Limiting 검사'
        },
        'ldap_injection': {
            'aliases': [],
            'field': 'ldap_injection',
            'category': 'api_auth',
            'description': 'LDAP Injection'
        },
        'authorization': {
            'aliases': [],
            'field': 'authorization_vulnerabilities',
            'category': 'api_auth',
            'description': 'BOLA/IDOR'
        },

        # ========================================
        # 비즈니스 로직 및 공급망
        # ========================================
        'supply_chain': {
            'aliases': [],
            'field': 'supply_chain_vulnerabilities',
            'category': 'business_logic',
            'description': '공급망 보안'
        },
        'exception_handling': {
            'aliases': [],
            'field': 'exception_handling_vulnerabilities',
            'category': 'business_logic',
            'description': '예외 처리'
        },
        'price_manipulation': {
            'aliases': [],
            'field': 'price_manipulation_vulnerabilities',
            'category': 'business_logic',
            'description': '가격/수량 조작'
        },
        'race_condition': {
            'aliases': [],
            'field': 'race_condition_vulnerabilities',
            'category': 'business_logic',
            'description': '동시성 취약점'
        },
        'workflow_bypass': {
            'aliases': [],
            'field': 'workflow_bypass_vulnerabilities',
            'category': 'business_logic',
            'description': '워크플로우 우회'
        },
        'account_enumeration': {
            'aliases': [],
            'field': 'account_enumeration_vulnerabilities',
            'category': 'business_logic',
            'description': '계정 열거'
        },
        'resource_exhaustion': {
            'aliases': [],
            'field': 'resource_exhaustion_vulnerabilities',
            'category': 'business_logic',
            'description': '리소스 소진'
        },
        'logging_monitoring': {
            'aliases': [],
            'field': 'logging_monitoring_vulnerabilities',
            'category': 'business_logic',
            'description': '로깅/모니터링'
        },
        'business_logic_anomaly': {
            'aliases': [],
            'field': 'business_logic_anomaly_vulnerabilities',
            'category': 'business_logic',
            'description': '비즈니스 로직 이상'
        },

        # ========================================
        # 공급망 보안 강화
        # ========================================
        'package_integrity': {
            'aliases': [],
            'field': 'package_integrity_vulnerabilities',
            'category': 'supply_chain',
            'description': '패키지 무결성 검증'
        },
        'typosquatting': {
            'aliases': [],
            'field': 'typosquatting_vulnerabilities',
            'category': 'supply_chain',
            'description': '타이포스쿼팅 탐지'
        },
        'outdated_dependency': {
            'aliases': ['outdated_dependencies'],  # scanners_compat.py 호환
            'field': 'outdated_dependency_vulnerabilities',
            'category': 'supply_chain',
            'description': '오래된 종속성 검사'
        },
        'license_compliance': {
            'aliases': [],
            'field': 'license_compliance_vulnerabilities',
            'category': 'supply_chain',
            'description': '라이선스 준수 검사'
        },

        # ========================================
        # 데이터 무결성 강화
        # ========================================
        'jwt_advanced': {
            'aliases': [],
            'field': 'jwt_advanced_vulnerabilities',
            'category': 'data_integrity',
            'description': 'JWT 고급 보안 검증'
        },
        'serialization_integrity': {
            'aliases': [],
            'field': 'serialization_integrity_vulnerabilities',
            'category': 'data_integrity',
            'description': '직렬화 무결성 검증'
        },
        'api_integrity': {
            'aliases': [],
            'field': 'api_integrity_vulnerabilities',
            'category': 'data_integrity',
            'description': 'API 응답 무결성 검사'
        },
        'checksum_validation': {
            'aliases': [],
            'field': 'checksum_validation_vulnerabilities',
            'category': 'data_integrity',
            'description': '체크섬 검증'
        }
    }

    @classmethod
    def get_canonical_id(cls, scanner_id: str) -> Optional[str]:
        """
        주어진 scanner_id의 표준 ID를 반환
        별칭이 주어져도 표준 ID를 반환
        """
        # 이미 표준 ID인 경우
        if scanner_id in cls.SCANNER_DEFINITIONS:
            return scanner_id

        # 별칭인 경우 표준 ID 찾기
        for canonical_id, definition in cls.SCANNER_DEFINITIONS.items():
            if scanner_id in definition.get('aliases', []):
                return canonical_id

        return None

    @classmethod
    def get_field_name(cls, scanner_id: str) -> Optional[str]:
        """scanner_id에 대한 데이터베이스 필드명 반환"""
        canonical_id = cls.get_canonical_id(scanner_id)
        if canonical_id:
            return cls.SCANNER_DEFINITIONS[canonical_id]['field']
        return None

    @classmethod
    def get_all_ids(cls) -> List[str]:
        """모든 scanner ID (별칭 포함) 반환"""
        all_ids = []
        for canonical_id, definition in cls.SCANNER_DEFINITIONS.items():
            all_ids.append(canonical_id)
            all_ids.extend(definition.get('aliases', []))
        return all_ids

    @classmethod
    def get_ids_by_category(cls, category: str) -> List[str]:
        """특정 카테고리의 모든 scanner ID 반환"""
        ids = []
        for canonical_id, definition in cls.SCANNER_DEFINITIONS.items():
            if definition.get('category') == category:
                ids.append(canonical_id)
        return ids

    @classmethod
    def validate_id(cls, scanner_id: str) -> bool:
        """scanner_id가 유효한지 검증"""
        return cls.get_canonical_id(scanner_id) is not None

    @classmethod
    def get_field_mapping(cls) -> Dict[str, str]:
        """
        api/views.py의 field_mapping과 호환되는 형식으로
        모든 ID와 필드 매핑 반환
        """
        mapping = {}
        for canonical_id, definition in cls.SCANNER_DEFINITIONS.items():
            field = definition['field']
            # 표준 ID 추가
            mapping[canonical_id] = field
            # 별칭 추가
            for alias in definition.get('aliases', []):
                mapping[alias] = field
        return mapping

    @classmethod
    def get_category_statistics(cls) -> Dict[str, int]:
        """카테고리별 스캐너 수 통계"""
        stats = {}
        for definition in cls.SCANNER_DEFINITIONS.values():
            category = definition.get('category', 'unknown')
            stats[category] = stats.get(category, 0) + 1
        return stats


# 편의 함수들
def get_field_name_for_scanner(scanner_id: str) -> Optional[str]:
    """scanner_id에 대한 필드명 반환 (api/views.py와 호환)"""
    return ScannerRegistry.get_field_name(scanner_id)


def validate_scanner_id(scanner_id: str) -> bool:
    """scanner_id 유효성 검증"""
    return ScannerRegistry.validate_id(scanner_id)


def get_all_scanner_ids() -> List[str]:
    """모든 scanner ID 목록 반환"""
    return ScannerRegistry.get_all_ids()


if __name__ == '__main__':
    # 테스트 및 통계 출력
    print("=" * 60)
    print("Scanner Registry 통계")
    print("=" * 60)

    print(f"\n📊 총 스캐너 수: {len(ScannerRegistry.SCANNER_DEFINITIONS)}")

    print("\n📂 카테고리별 스캐너 수:")
    for category, count in sorted(ScannerRegistry.get_category_statistics().items()):
        print(f"  - {category}: {count}개")

    print("\n🔄 별칭이 있는 스캐너:")
    for canonical_id, definition in ScannerRegistry.SCANNER_DEFINITIONS.items():
        aliases = definition.get('aliases', [])
        if aliases:
            print(f"  - {canonical_id}: {', '.join(aliases)}")

    print("\n✅ 테스트:")
    test_ids = ['cookies', 'info_disclosure', 'outdated_dependencies', 'xss', 'invalid_id']
    for test_id in test_ids:
        canonical = ScannerRegistry.get_canonical_id(test_id)
        field = ScannerRegistry.get_field_name(test_id)
        if canonical:
            print(f"  '{test_id}' → canonical: '{canonical}', field: '{field}'")
        else:
            print(f"  '{test_id}' → ❌ 유효하지 않은 ID")

    print("\n" + "=" * 60)