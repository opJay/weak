# WEAK - Web Security Scanner Project

## CRITICAL INSTRUCTIONS FOR AI ASSISTANT

### 🚨 MANDATORY RULES
1. **ALL responses and reasoning MUST be in Korean (한국어)**
2. **NO over-engineering - Keep solutions simple and practical**
3. **NEVER fix markdown lint errors - Ignore all markdown linting warnings**

## Project Overview

WEAK is a Django-based web vulnerability scanner that provides comprehensive security, web standards, and accessibility testing for websites.

## Core Architecture

### Technology Stack
- **Backend**: Django 5.2.8
- **Frontend**: Vanilla JavaScript (No frameworks)
- **Database**: SQLite (development), PostgreSQL (production)
- **Python**: 3.12+
- **Task Processing**: Celery + Redis (for production), Threading (fallback)

### Project Structure
```
weak/
├── scanner/          # Core scanning logic
│   ├── base.py       # BaseScanner 기본 클래스 (템플릿 메서드 패턴)
│   ├── scanners.py   # Basic scanner implementations (15 scanners)
│   ├── scanners_refactored.py  # 리팩토링된 스캐너 Batch 1 (2개)
│   ├── scanners_refactored_batch1.py  # 리팩토링된 스캐너 Batch 1 (3개)
│   ├── scanners_refactored_batch2.py  # 리팩토링된 스캐너 Batch 2 (5개)
│   ├── scanners_compat.py  # 호환성 레이어 (점진적 마이그레이션)
│   ├── scanner_migration.py  # 마이그레이션 매핑 관리
│   ├── scanners_advanced.py  # Advanced security scanners (10 scanners)
│   ├── scanners_api.py  # API/Auth security scanners (8 scanners)
│   ├── scanners_supply_chain.py  # OWASP 2025 supply chain scanner (1 scanner)
│   ├── scanners_exception.py  # OWASP 2025 exception handling scanner (1 scanner)
│   ├── scanners_business_logic.py  # Business logic scanners (7 scanners)
│   ├── scanners_supply_chain_advanced.py  # Supply chain advanced (4 scanners)
│   ├── scanners_integrity_advanced.py  # Data integrity advanced (4 scanners)
│   ├── tasks.py      # Background task processing
│   ├── progress_manager.py  # Progress tracking system (50 scanners total)
│   ├── security_scan_refactored.py  # Refactored security scanning
│   ├── standards_checker.py  # Web standards validation
│   └── models.py     # Database models
├── api/              # REST API endpoints
│   ├── views.py      # API view controllers
│   ├── serializers.py # Data serialization
│   └── urls.py       # API routing
├── core/             # Core utilities and middleware
│   ├── middleware.py # Custom middleware
│   └── views.py      # Base views
├── reports/          # Report generation (optional)
├── templates/        # HTML templates
│   └── scanner/
│       └── index.html
├── static/           # CSS, JS, images
│   ├── css/
│   │   ├── base.css      # Global styles
│   │   ├── scanner.css   # Scanner-specific styles
│   │   └── wizard.css    # Three-step wizard styles
│   └── js/
│       └── scanner.js    # Frontend logic with detailed views
├── tests/            # 테스트 코드 (새로 추가됨)
│   ├── conftest.py   # pytest 설정 및 fixtures
│   ├── unit/         # 단위 테스트
│   │   ├── test_refactored_scanners.py  # Batch 1 테스트 (19개)
│   │   └── test_batch2_scanners.py      # Batch 2 테스트 (33개)
│   ├── integration/  # 통합 테스트
│   │   └── test_integration.py          # tasks.py 통합 테스트
│   └── golden/       # Golden test 스냅샷
│       └── *.json    # 실제 웹사이트 스캔 결과
├── config/           # Django settings
│   ├── settings.py   # Main settings
│   ├── celery.py     # Celery configuration
│   └── urls.py       # URL routing
└── main.py           # Project management CLI
```

## Design Principles

### Scanner Architecture
- **Self-contained scanners**: Each scanner class contains its own metadata
- **No central registry**: Scanners manage their own configuration
- **Weighted progress system**: Dynamic progress calculation based on scanner weights
- **BaseScanner pattern**: Template method pattern for standardized interfaces (리팩토링됨)
- **Dependency injection**: HTTP 클라이언트 주입으로 테스트 가능성 향상
- **Compatibility layer**: scanners_compat.py를 통한 점진적 마이그레이션

### UI/UX Philosophy
- **Three-step wizard pattern**: Input → Progress → Results
- **Google-style minimal design**: Clean, centered layouts
- **Progressive disclosure**: Show details only when needed
- **Expandable detail views**: All test results (pass/fail) show comprehensive details
- **Korean language support**: UI labels and messages in Korean
- **Real-time progress tracking**: WebSocket-based live updates

## Scanner Implementation Guidelines

### Scanner Class Structure

#### 기존 패턴 (Original Pattern)
```python
class ExampleScanner:
    """Scanner description"""

    # Scanner metadata MUST be inside the class
    metadata = {
        'id': 'unique_id',
        'name': 'Display Name',
        'icon': '🔍',
        'description': 'What this scanner does',
        'weight': 1,  # Relative weight for progress calculation
        'field': 'result_field_name'
    }

    def scan(self, url, content):
        # Implementation
        return results
```

#### 리팩토링된 패턴 (Refactored Pattern with BaseScanner)
```python
from scanner.base import BaseScanner

class ExampleScanner(BaseScanner):
    """Scanner description"""

    metadata = {
        'id': 'unique_id',
        'name': 'Display Name',
        'icon': '🔍',
        'description': 'What this scanner does',
        'weight': 1,
        'field': 'result_field_name'
    }

    def _execute_scan(self) -> None:
        """Template method implementation"""
        # 스캔 로직 구현
        # self.vulnerabilities 또는 self.issues에 결과 추가
        pass

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {'custom_field': 'value'}
```

### Progress Management
- Uses `ProgressManager` class for weighted distribution
- Scanner counts per type:
  - Security: 50 scanners (15 basic + 10 advanced + 8 API/auth + 2 OWASP 2025 + 7 business logic + 4 supply chain advanced + 4 data integrity advanced)
- **OWASP Top 10 2025 RC1 compliant (~95% coverage)**
  - Standards: 4 scanners
  - Accessibility: 1 scanner
- Progress updates via WebSocket or polling

### Security Scanners List

#### Basic Security Scanners (scanners.py - 15개)
1. **XSSScanner** - Cross-Site Scripting 취약점
2. **SQLInjectionScanner** - SQL Injection 취약점
3. **SecurityHeaderScanner** - 보안 헤더 검사
4. **CORSScanner** - CORS 설정 검사
5. **CookieScanner** - 쿠키 보안 속성
6. **CSRFScanner** - CSRF 토큰 검증
7. **ClickjackingScanner** - 클릭재킹 방어
8. **InformationDisclosureScanner** - 민감정보 노출
9. **HTTPMethodScanner** - 위험한 HTTP 메서드
10. **SensitiveFileScanner** - 민감한 파일 노출
11. **MixedContentScanner** - HTTPS 페이지의 HTTP 리소스
12. **SubresourceIntegrityScanner** - SRI 검사
13. **DirectoryListingScanner** - 디렉토리 리스팅
14. **OpenRedirectScanner** - 오픈 리다이렉트
15. **check_ssl_tls** - SSL/TLS 기본 검사

#### Advanced Security Scanners (scanners_advanced.py - 10개)
실무급 고급 보안 취약점 탐지

16. **SSRFScanner** - Server-Side Request Forgery (내부망 접근, Cloud Metadata 탈취)
17. **XXEScanner** - XML External Entity (파일 읽기, SSRF 연계)
18. **CommandInjectionScanner** - OS Command Injection (시스템 명령어 실행)
19. **DeserializationScanner** - Insecure Deserialization (원격 코드 실행)
20. **FileUploadScanner** - 파일 업로드 취약점 (웹쉘 업로드, 실행 파일)
21. **PathTraversalScanner** - 경로 순회 공격 (LFI, 민감 파일 읽기)
22. **JWTSecurityScanner** - JWT 보안 취약점 (alg:none, weak secret, 만료 검증)
23. **TemplateInjectionScanner** - SSTI (Jinja2, Twig 템플릿 주입)
24. **NoSQLInjectionScanner** - NoSQL Injection (MongoDB, Redis)
25. **SSLTLSDeepScanner** - SSL/TLS 심층 검사 (약한 암호화, 인증서 검증)

#### API 및 인증/인가 스캐너 (scanners_api.py - 8개)
현대 웹 애플리케이션의 API 및 인증 보안

26. **RESTAPISecurityScanner** - REST API 보안 (Rate Limit, Mass Assignment, Data Exposure)
27. **GraphQLSecurityScanner** - GraphQL 보안 (Introspection, Query Depth, Batch Attack)
28. **OAuthSecurityScanner** - OAuth 인증 취약점 (CSRF, Open Redirect, Code Reuse)
29. **SessionSecurityScanner** - 세션 관리 취약점 (Session Fixation, Hijacking)
30. **PasswordPolicyScanner** - 비밀번호 정책 (복잡도, Brute Force 방어)
31. **RateLimitingScanner** - Rate Limiting 검사 (API/로그인 제한)
32. **LDAPInjectionScanner** - LDAP Injection
33. **AuthorizationScanner** - BOLA/IDOR (객체/함수 레벨 인가 오류)

#### OWASP 2025 신규 대응 스캐너 (scanners_supply_chain.py, scanners_exception.py - 2개)
OWASP Top 10 2025 RC1의 새로운 보안 위협

34. **SoftwareSupplyChainScanner** - A03:2025 공급망 보안 (종속성 노출, SRI, 취약한 라이브러리)
35. **ExceptionHandlingScanner** - A10:2025 예외 처리 (스택 트레이스, DB 에러, 디버그 모드)

#### 비즈니스 로직 및 설계 취약점 스캐너 (scanners_business_logic.py - 7개)
OWASP A06 (Insecure Design) 및 A09 (Logging & Monitoring) 강화

36. **PriceManipulationScanner** - A06:2025 가격/수량 조작 탐지 (음수 값, hidden 필드, 클라이언트 측 계산)
37. **RaceConditionScanner** - A06:2025 동시성 취약점 (병렬 요청, TOCTOU, Idempotency)
38. **WorkflowBypassScanner** - A06:2025 워크플로우 우회 (단계 건너뛰기, 상태 조작)
39. **AccountEnumerationScanner** - A06+A07:2025 계정 열거 (응답 차이, 타이밍 공격)
40. **ResourceExhaustionScanner** - A06:2025 리소스 소진 (파일 크기, 요청 제한, Rate Limiting)
41. **LoggingMonitoringScanner** - A09:2025 로깅/모니터링 (Trace ID, 보안 이벤트)
42. **BusinessLogicAnomalyScanner** - A06:2025 비즈니스 로직 이상 (할인 조작, 수량 제한)

#### 공급망 보안 강화 (scanners_supply_chain_advanced.py - 4개)
OWASP A03:2025 (Software Supply Chain) 75% → 90% 강화

43. **PackageIntegrityScanner** - 패키지 무결성 검증 (lockfile 해시, SHA-512 검증, 무결성 누락)
44. **TyposquattingScanner** - 타이포스쿼팅 탐지 (유사 패키지명, 블랙리스트, 의심스러운 패턴)
45. **OutdatedDependencyScanner** - 오래된 종속성 검사 (CVE 패턴 매칭, EOL 패키지, 최소 안전 버전)
46. **LicenseComplianceScanner** - 라이선스 준수 검사 (GPL/AGPL 검출, 비상업적 라이선스, 라이선스 누락)

#### 데이터 무결성 강화 (scanners_integrity_advanced.py - 4개)
OWASP A08:2025 (Data Integrity Failures) 75% → 90% 강화

47. **JWTAdvancedScanner** - JWT 고급 보안 검증 (알고리즘 혼동, kid 조작, 약한 시크릿, Claims 검증, JWK 노출)
48. **SerializationIntegrityScanner** - 직렬화 무결성 검증 (서명 없는 직렬화, Pickle/PHP/Java 직렬화 탐지)
49. **APIIntegrityScanner** - API 응답 무결성 검사 (X-Signature, ETag, Content-MD5, SRI)
50. **ChecksumValidationScanner** - 체크섬 검증 (약한 해시 알고리즘, SHA256SUMS, MD5SUMS)

**OWASP Top 10 2025 RC1 커버리지: ~95%**
- A01 (Broken Access Control): 100%
- A02 (Cryptographic Failures): 100%
- A03 (Software Supply Chain): 90% (75%→90%, 공급망 고급 스캐너 4개 추가)
- A04 (Injection): 100%
- A05 (Security Misconfiguration): 80%
- A06 (Insecure Design): 90% (비즈니스 로직 스캐너 7개 추가로 45%→90%)
- A07 (Authentication Failures): 100%
- A08 (Data Integrity Failures): 90% (75%→90%, 데이터 무결성 고급 스캐너 4개 추가)
- A09 (Logging & Monitoring): 85% (20%→85%)
- A10 (Exception Handling): 100%

## Database Design

### Key Models
- `ScanRequest`: Main scan tracking
- `SecurityScanResult`: Security scan results with metadata
- `WebStandardsResult`: Web standards validation results
- `AccessibilityResult`: Accessibility check results
- `Vulnerability`: Individual vulnerability records

### Important Fields
- `scanner_metadata`: JSONField storing scanner-specific metadata
- Results stored as JSONField for flexibility
- No user authentication required

## Development Guidelines

### Code Style
- **Korean comments**: Use Korean for code comments and docstrings
- **Simple is better**: Avoid complex abstractions
- **Direct approach**: Use straightforward implementations

### Git Workflow
- **Exclude from version control**:
  - `db.sqlite3` (database)
  - `.env` files
  - `.claude/` directory
  - `*.backup` files
- **Include in version control**:
  - All migration files
  - Static files (CSS, JS)
  - Templates

### Security Considerations
- SSRF protection via IP range blocking
- Input validation for all user inputs
- No execution of user-provided code
- Rate limiting on scan requests

## API Design

### Endpoints
- `POST /api/scan/` - Initiate scan
- `GET /api/scan/{id}/` - Get scan status/results
- `GET /api/scan/{id}/progress/` - Get real-time progress

### Response Format
- JSON with consistent structure
- Include metadata from scanners
- Progress as percentage (0-100)

## Frontend Architecture

### JavaScript Organization
- Single `scanner.js` file with comprehensive functionality
- No build process required
- Direct DOM manipulation
- WebSocket for real-time updates
- Features:
  - Three-step wizard navigation
  - Real-time progress tracking
  - Expandable detail views for all test results
  - Dynamic content rendering based on scanner metadata
  - Chart.js integration for visualizations

### CSS Structure
- `base.css`: Global styles
- `scanner.css`: Scanner-specific styles with detailed result views
- `wizard.css`: Three-step wizard styles
- No CSS frameworks

## Testing Philosophy
- **Manual testing preferred**: Focus on real-world scenarios
- **No excessive test coverage**: Test critical paths only
- **Browser testing**: Chrome, Firefox, Edge compatibility

## Performance Considerations
- Celery + Redis for asynchronous task processing
- Background thread processing as fallback
- Timeout limits on scans (configurable via SCAN_TIMEOUT)
- Result caching where appropriate
- Weighted progress calculation for accurate status updates
- Efficient DOM manipulation for large result sets

## Deployment Notes
- Environment variables via `.env` file
- `env.example` provided for configuration template
- Django's `collectstatic` for production
- ALLOWED_HOSTS configuration required

## Important Reminders

### For AI Assistants
1. **Always respond in Korean** - This is non-negotiable
2. **Keep it simple** - No unnecessary abstractions or patterns
3. **Don't fix what's not broken** - Ignore linting suggestions
4. **Respect existing architecture** - Don't suggest major refactors
5. **Focus on functionality** - Features over perfection

### Common Pitfalls to Avoid
- Adding unnecessary dependencies
- Creating abstract base classes
- Implementing design patterns for their own sake
- Fixing markdown or code formatting issues
- Over-engineering async task handling (Celery/Redis is sufficient)
- Adding user authentication when not needed
- Creating separate frontend frameworks
- Breaking the three-step wizard pattern
- Removing Korean language support

## License
This project is for educational and security testing purposes only.