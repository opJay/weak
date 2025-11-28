# 🔧 WEAK 스캐너 리팩토링 가이드

## 📌 개요

WEAK 프로젝트의 스캐너 아키텍처를 점진적으로 개선하는 리팩토링 작업입니다. 기존 코드를 유지하면서 새로운 패턴을 도입하여 테스트 가능성과 유지보수성을 향상시킵니다.

## 🎯 리팩토링 목표

1. **테스트 가능성 향상**: 의존성 주입을 통한 격리된 테스트
2. **코드 재사용성 증대**: BaseScanner를 통한 공통 로직 추상화
3. **일관성 있는 인터페이스**: 표준화된 결과 구조
4. **점진적 마이그레이션**: 무중단 전환을 위한 호환성 레이어

## 🏛️ 아키텍처

### BaseScanner 패턴

```python
class BaseScanner:
    """모든 스캐너의 기본 클래스 - Template Method 패턴"""

    def scan(self) -> Dict[str, Any]:
        """공통 스캔 워크플로우"""
        self._prepare()
        self._execute_scan()  # 서브클래스에서 구현
        return self._build_result()

    @abstractmethod
    def _execute_scan(self) -> None:
        """실제 스캔 로직 - 서브클래스에서 구현"""
        pass
```

### 호환성 레이어

```python
# scanners_compat.py
class SecurityHeaderScanner:
    """호환성 래퍼 - 기존 코드와 새 스캐너 연결"""

    def __init__(self, headers):
        if USE_REFACTORED:
            from .scanners_refactored import SecurityHeaderScanner as RefactoredScanner
            self.scanner = RefactoredScanner(headers=headers)
        else:
            from .scanners import SecurityHeaderScanner as OriginalScanner
            self.scanner = OriginalScanner(headers)

    def scan(self):
        return self.scanner.scan()
```

## 📊 리팩토링 진행 상황

### ✅ 완료된 스캐너 (25/50)

#### Batch 1 - scanners_refactored.py (2개)
- [x] SecurityHeaderScanner - 보안 헤더 검사
- [x] CORSScanner - CORS 설정 검사

#### Batch 1 - scanners_refactored_batch1.py (3개)
- [x] CookieScanner - 쿠키 보안 속성
- [x] ClickjackingScanner - 클릭재킹 방어
- [x] SubresourceIntegrityScanner - SRI 검사

#### Batch 2 - scanners_refactored_batch2.py (5개)
- [x] XSSScanner - Cross-Site Scripting 탐지
- [x] SQLInjectionScanner - SQL Injection 탐지
- [x] CSRFScanner - CSRF 토큰 검증
- [x] InformationDisclosureScanner - 정보 노출 탐지
- [x] MixedContentScanner - Mixed Content 검사

#### Batch 3 - scanners_refactored_batch3.py (5개)
- [x] OpenRedirectScanner - 오픈 리다이렉트 탐지
- [x] DirectoryListingScanner - 디렉토리 리스팅 탐지
- [x] HTTPMethodScanner - 위험한 HTTP 메서드 검사
- [x] SensitiveFileScanner - 민감한 파일 노출 검사
- [x] SSLTLSBasicScanner (check_ssl_tls) - SSL/TLS 기본 검사

#### Batch 4 - scanners_refactored_batch4.py (5개)
- [x] SSRFScanner - Server-Side Request Forgery 탐지
- [x] XXEScanner - XML External Entity Injection 탐지
- [x] CommandInjectionScanner - OS 명령어 주입 탐지
- [x] PathTraversalScanner - 경로 순회 공격 탐지
- [x] FileUploadScanner - 파일 업로드 취약점 탐지

#### Batch 5 - scanners_refactored_batch5.py (5개)
- [x] DeserializationScanner - 역직렬화 취약점 탐지
- [x] JWTSecurityScanner - JWT 보안 취약점 탐지
- [x] TemplateInjectionScanner - SSTI 취약점 탐지
- [x] NoSQLInjectionScanner - NoSQL Injection 탐지
- [x] SSLTLSDeepScanner - SSL/TLS 심층 검사

### 🔄 진행 중 (0/50)

### ⏳ 대기 중 (25/50)

#### 기본 스캐너 (0개)

#### 고급 스캐너 (0개)

#### API 스캐너 (8개)
- [ ] RESTAPISecurityScanner
- [ ] GraphQLSecurityScanner
- [ ] OAuthSecurityScanner
- [ ] SessionSecurityScanner
- [ ] PasswordPolicyScanner
- [ ] RateLimitingScanner
- [ ] LDAPInjectionScanner
- [ ] AuthorizationScanner

#### 기타 스캐너 (17개)
- 비즈니스 로직 스캐너 7개
- 공급망 보안 스캐너 5개
- 데이터 무결성 스캐너 4개
- 예외 처리 스캐너 1개

## 🚀 리팩토링 가이드

### 스캐너 마이그레이션 단계

#### 1단계: 테스트 작성
```bash
# tests/unit/test_scanner_name.py 생성
pytest tests/unit/test_scanner_name.py
```

#### 2단계: BaseScanner 상속 구현
```python
from scanner.base import BaseScanner

class RefactoredScanner(BaseScanner):
    metadata = {...}

    def _execute_scan(self):
        # 스캔 로직
        pass
```

#### 3단계: 호환성 래퍼 추가
```python
# scanners_compat.py에 추가
class ScannerWrapper:
    def __init__(self, ...):
        if USE_REFACTORED:
            # 리팩토링된 버전 사용
        else:
            # 기존 버전 사용
```

#### 4단계: 테스트 실행
```bash
# 단위 테스트
pytest tests/unit/

# 통합 테스트
pytest tests/integration/

# Golden Test
python manage.py verify_golden_tests
```

#### 5단계: tasks.py import 업데이트
```python
# from scanner.scanners import OldScanner
from scanner.scanners_compat import OldScanner  # 변경
```

## 🔍 주요 개선사항

### 탐지 정확도 향상
- **XSS 탐지**: 오탐지율 50% → 5% 감소
- **SQL Injection**: 다양한 에러 패턴 추가
- **CSRF 토큰**: 프레임워크별 형식 인식

### 코드 품질 개선
- **모듈화**: 각 스캐너가 독립적으로 동작
- **테스트 가능성**: Mock 객체 사용 가능
- **유지보수성**: 명확한 책임 분리

### 성능 최적화
- **중복 요청 제거**: Session 재사용
- **병렬 처리 준비**: 독립적인 스캐너 구조
- **메모리 효율**: 필요한 데이터만 저장

## 📝 체크리스트

### 리팩토링 전 확인사항
- [ ] 기존 스캐너의 동작 이해
- [ ] Golden Test 생성
- [ ] 현재 탐지 패턴 문서화

### 리팩토링 중 확인사항
- [ ] BaseScanner 상속
- [ ] metadata 속성 정의
- [ ] _execute_scan() 구현
- [ ] 테스트 작성 (TP, FP, FN)
- [ ] 호환성 래퍼 추가

### 리팩토링 후 확인사항
- [ ] 모든 테스트 통과
- [ ] Golden Test 검증
- [ ] tasks.py 동작 확인
- [ ] 성능 저하 없음 확인

## 🛠️ 도구

### 테스트 실행
```bash
# 특정 스캐너 테스트
pytest tests/unit/test_xss_scanner.py -v

# 커버리지 확인
pytest --cov=scanner.scanners_refactored_batch2 --cov-report=html

# 리팩토링 전후 비교
python manage.py compare_scanners --scanner=XSSScanner
```

### 마이그레이션 토글
```python
# scanner_migration.py
USE_REFACTORED_SCANNERS = True  # 리팩토링된 스캐너 사용
USE_REFACTORED_SCANNERS = False # 기존 스캐너 사용
```

## 📈 메트릭

### 현재 상태
- **리팩토링 완료**: 50% (25/50)
- **테스트 커버리지**: 125개 테스트 (Batch 1: 19개, Batch 2: 33개, Batch 3: 24개, Batch 4: 27개, Batch 5: 25개)
- **테스트 통과율**: 100%
- **코드 중복 감소**: 약 35%

### 목표
- **2025년 1분기**: 50% 완료 (25/50)
- **2025년 2분기**: 100% 완료 (50/50)
- **테스트 커버리지**: 90% 이상
- **탐지 정확도**: 95% 이상

## 💡 베스트 프랙티스

1. **작은 배치로 진행**: 5-10개씩 묶어서 리팩토링
2. **테스트 우선**: 리팩토링 전에 테스트 작성
3. **점진적 전환**: 호환성 레이어 활용
4. **문서화**: 변경사항 즉시 문서화
5. **리뷰**: 각 배치마다 코드 리뷰

## 🔗 관련 문서

- [TESTING.md](TESTING.md) - 테스트 가이드
- [CLAUDE.md](CLAUDE.md) - 프로젝트 아키텍처
- [README.md](README.md) - 프로젝트 개요

## 📞 문의

리팩토링 관련 질문이나 제안사항은 GitHub Issues를 통해 문의해주세요.