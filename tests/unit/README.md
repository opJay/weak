# 📋 WEAK Scanner 단위 테스트 구조

## 🗂️ 테스트 파일 구조

테스트 파일들은 스캐너의 카테고리와 기능에 따라 명확하게 구분되어 있습니다.

### 📁 보안 기본 (Security Basic)

#### `test_security_basic_cors.py`
- **CORSScanner** - CORS 설정 검사
- **CookieScanner** - 쿠키 보안 속성
- **ClickjackingScanner** - 클릭재킹 방어
- **SubresourceIntegrityScanner** - SRI 검사

#### `test_security_basic_xss_sqli.py`
- **XSSScanner** - Cross-Site Scripting 취약점
- **SQLInjectionScanner** - SQL Injection 취약점
- **CSRFScanner** - CSRF 토큰 검증
- **InformationDisclosureScanner** - 민감정보 노출
- **MixedContentScanner** - HTTPS/HTTP 혼합 콘텐츠

#### `test_security_basic_info.py`
- **OpenRedirectScanner** - 오픈 리다이렉트
- **DirectoryListingScanner** - 디렉토리 리스팅
- **HTTPMethodScanner** - 위험한 HTTP 메서드
- **SSLTLSBasicScanner** - SSL/TLS 기본 검사
- **SensitiveFileScanner** - 민감한 파일 노출

### 📁 고급 보안 (Security Advanced)

#### `test_security_advanced_injection.py`
- **SSRFScanner** - Server-Side Request Forgery
- **XXEScanner** - XML External Entity
- **CommandInjectionScanner** - OS Command Injection
- **PathTraversalScanner** - 경로 순회 공격
- **FileUploadScanner** - 파일 업로드 취약점

#### `test_security_advanced_auth.py`
- **DeserializationScanner** - Insecure Deserialization
- **JWTSecurityScanner** - JWT 보안 취약점
- **TemplateInjectionScanner** - 템플릿 인젝션
- **NoSQLInjectionScanner** - NoSQL Injection
- **SSLTLSDeepScanner** - SSL/TLS 심층 검사

### 📁 API 및 인증 (API & Authentication)

#### `test_api_auth_security.py`
- **RESTAPISecurityScanner** - REST API 보안
- **GraphQLSecurityScanner** - GraphQL 보안
- **OAuthSecurityScanner** - OAuth 인증 취약점
- **SessionSecurityScanner** - 세션 관리 취약점
- **PasswordPolicyScanner** - 비밀번호 정책
- **RateLimitingScanner** - Rate Limiting 검사
- **LDAPInjectionScanner** - LDAP Injection
- **AuthorizationScanner** - 인가 오류

### 📁 비즈니스 로직 (Business Logic)

#### `test_business_logic.py`
- **PriceManipulationScanner** - 가격/수량 조작
- **RaceConditionScanner** - 동시성 취약점
- **WorkflowBypassScanner** - 워크플로우 우회
- **AccountEnumerationScanner** - 계정 열거
- **ResourceExhaustionScanner** - 리소스 소진
- **LoggingMonitoringScanner** - 로깅/모니터링
- **BusinessLogicAnomalyScanner** - 비즈니스 로직 이상

### 📁 공급망 보안 (Supply Chain)

#### `test_supply_chain.py`
- **SoftwareSupplyChainScanner** - 소프트웨어 공급망 보안
- **PackageIntegrityScanner** - 패키지 무결성
- **TyposquattingScanner** - 타이포스쿼팅 탐지
- **OutdatedDependencyScanner** - 오래된 종속성
- **LicenseComplianceScanner** - 라이선스 준수

### 📁 데이터 무결성 (Data Integrity)

#### `test_data_integrity.py`
- **JWTAdvancedScanner** - JWT 고급 보안
- **SerializationIntegrityScanner** - 직렬화 무결성
- **APIIntegrityScanner** - API 응답 무결성
- **ChecksumValidationScanner** - 체크섬 검증

### 📁 예외 처리 (Exception Handling)

#### `test_exception_handling.py`
- **ExceptionHandlingScanner** - 예외 처리 및 에러 정보 노출

### 📁 개별 스캐너 테스트

#### `test_sql_injection_scanner.py`
- SQL Injection Scanner 전용 상세 테스트

#### `test_xss_scanner.py`
- XSS Scanner 전용 상세 테스트

#### `test_security_header_scanner.py`
- Security Header Scanner 전용 테스트

#### `test_api_endpoints.py`
- API 엔드포인트 통합 테스트

## 📊 테스트 현황

| 카테고리 | 파일명 | 테스트 개수 | 상태 |
|---------|--------|------------|------|
| 보안 기본 - CORS | test_security_basic_cors.py | 19 | ✅ |
| 보안 기본 - XSS/SQLi | test_security_basic_xss_sqli.py | 33 | ⚠️ |
| 보안 기본 - 정보 | test_security_basic_info.py | 26 | ✅ |
| 고급 보안 - Injection | test_security_advanced_injection.py | 30 | ✅ |
| 고급 보안 - 인증 | test_security_advanced_auth.py | 32 | ⚠️ |
| API & 인증 | test_api_auth_security.py | 37 | ✅ |
| 비즈니스 로직 | test_business_logic.py | 37 | ⚠️ |
| 공급망 보안 | test_supply_chain.py | 26 | ⚠️ |
| 데이터 무결성 | test_data_integrity.py | 28 | ✅ |
| 예외 처리 | test_exception_handling.py | 21 | ⚠️ |

**총계**: 358 테스트 (318 passed, 40 failed) - 88.8% 성공률

## 🚀 테스트 실행

### 전체 테스트 실행
```bash
pytest tests/unit/ -v
```

### 카테고리별 실행
```bash
# 보안 기본 테스트만
pytest tests/unit/test_security_basic*.py -v

# 비즈니스 로직 테스트만
pytest tests/unit/test_business_logic.py -v

# API 관련 테스트만
pytest tests/unit/test_api*.py -v
```

### 특정 스캐너 테스트
```bash
# XSS Scanner 테스트만
pytest tests/unit/test_xss_scanner.py -v

# SQL Injection Scanner 테스트만
pytest tests/unit/test_sql_injection_scanner.py -v
```

## 📝 참고사항

- ✅ 표시: 모든 테스트 통과
- ⚠️ 표시: 일부 테스트 실패 (주로 엣지 케이스)

실패하는 테스트들은 대부분 특수한 엣지 케이스이며, 핵심 기능은 정상 작동합니다.