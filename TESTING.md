# WEAK 프로젝트 테스팅 가이드

## 📋 개요

WEAK 프로젝트는 포괄적인 테스팅 전략을 통해 스캐너의 정확도와 코드 품질을 보장합니다. 단순한 코드 실행 확인이 아닌 **실제 탐지 정확도**에 중점을 둡니다.

## 🎯 테스팅 철학

### 핵심 원칙
- **탐지 정확도 우선**: 코드 커버리지보다 실제 취약점 탐지 능력 검증
- **False Positive 최소화**: 오탐지 방지를 위한 엄격한 검증
- **False Negative 방지**: 실제 취약점 놓치지 않도록 다양한 케이스 테스트
- **실제 환경 시뮬레이션**: Mock 객체를 활용한 현실적인 테스트 환경

### 테스트 유형
1. **True Positive (TP)**: 실제 취약점을 정확히 탐지
2. **True Negative (TN)**: 안전한 코드를 안전하다고 판단
3. **False Positive (FP)**: 안전한 코드를 취약하다고 오탐지
4. **False Negative (FN)**: 취약한 코드를 놓침

## 🏗️ 테스트 인프라

### 디렉토리 구조
```
tests/
├── conftest.py              # pytest 설정 및 공통 fixtures
├── unit/                    # 단위 테스트
│   ├── test_refactored_scanners.py    # Batch 1 스캐너 (19개 테스트)
│   └── test_batch2_scanners.py        # Batch 2 스캐너 (33개 테스트)
├── integration/             # 통합 테스트
│   └── test_integration.py # tasks.py와의 통합
└── golden/                  # Golden Test 스냅샷
    └── *.json              # 실제 웹사이트 스캔 결과
```

### 주요 컴포넌트

#### BaseScanner 테스트
- Template Method 패턴 검증
- 표준화된 결과 구조 확인
- 의존성 주입 동작 테스트

#### 호환성 레이어 테스트
- 기존 코드와의 호환성 확인
- 점진적 마이그레이션 검증
- 무중단 전환 보장

## 🚀 테스트 실행

### 기본 명령어

```bash
# 모든 테스트 실행
pytest

# 특정 디렉토리 테스트
pytest tests/unit/

# 특정 파일 테스트
pytest tests/unit/test_batch2_scanners.py

# 특정 테스트 함수
pytest tests/unit/test_batch2_scanners.py::test_xss_scanner_true_positive

# 상세 출력
pytest -v

# 실패한 테스트만 재실행
pytest --lf

# 코드 커버리지와 함께
pytest --cov=scanner --cov-report=html
```

### Golden Test

```bash
# Golden Test 생성 (실제 웹사이트 스캔)
python manage.py generate_golden_tests

# Golden Test 검증 (회귀 테스트)
python manage.py verify_golden_tests

# 특정 URL에 대한 Golden Test
python manage.py generate_golden_tests --url https://example.com
```

## 📊 현재 테스트 커버리지

### 리팩토링 완료 스캐너 (15개)

#### Batch 1 (5개 스캐너, 19개 테스트)
- ✅ **SecurityHeaderScanner**: 보안 헤더 검증
- ✅ **CORSScanner**: CORS 설정 검사
- ✅ **CookieScanner**: 쿠키 보안 속성
- ✅ **ClickjackingScanner**: 클릭재킹 방어
- ✅ **SubresourceIntegrityScanner**: SRI 검사

#### Batch 2 (5개 스캐너, 33개 테스트)
- ✅ **XSSScanner**: Cross-Site Scripting 탐지
- ✅ **SQLInjectionScanner**: SQL Injection 탐지
- ✅ **CSRFScanner**: CSRF 토큰 검증
- ✅ **InformationDisclosureScanner**: 정보 노출 탐지
- ✅ **MixedContentScanner**: Mixed Content 검사

#### Batch 3 (5개 스캐너, 24개 테스트)
- ✅ **OpenRedirectScanner**: 오픈 리다이렉트 탐지
- ✅ **DirectoryListingScanner**: 디렉토리 리스팅 탐지
- ✅ **HTTPMethodScanner**: 위험한 HTTP 메서드 검사
- ✅ **SensitiveFileScanner**: 민감한 파일 노출 검사
- ✅ **SSLTLSBasicScanner**: SSL/TLS 기본 검사

### 테스트 통계
- **총 단위 테스트**: 76개
- **통합 테스트**: 4개
- **전체 테스트**: 80개
- **테스트 통과율**: 100%

## 🔍 테스트 작성 가이드

### 스캐너 테스트 템플릿

```python
import pytest
from unittest.mock import Mock
from scanner.scanners_refactored import ExampleScanner

class TestExampleScanner:
    """ExampleScanner 테스트"""

    @pytest.fixture
    def mock_response(self):
        """Mock HTTP 응답"""
        response = Mock()
        response.headers = {}
        response.text = ""
        response.status_code = 200
        return response

    def test_true_positive(self, mock_response):
        """True Positive: 실제 취약점 탐지"""
        # Given: 취약한 콘텐츠
        mock_response.text = "<script>alert('XSS')</script>"

        # When: 스캔 실행
        scanner = ExampleScanner(response=mock_response)
        result = scanner.scan()

        # Then: 취약점이 탐지되어야 함
        assert result['vulnerabilities_count'] > 0
        assert any('XSS' in v['type'] for v in result['vulnerabilities'])

    def test_false_positive_prevention(self, mock_response):
        """False Positive 방지: 안전한 코드 오탐지 방지"""
        # Given: 안전한 콘텐츠
        mock_response.text = "<div>Safe content</div>"

        # When: 스캔 실행
        scanner = ExampleScanner(response=mock_response)
        result = scanner.scan()

        # Then: 취약점이 없어야 함
        assert result['vulnerabilities_count'] == 0

    def test_edge_case(self, mock_response):
        """엣지 케이스: 특수한 상황 처리"""
        # Given: 특수한 입력
        mock_response.text = None

        # When: 스캔 실행
        scanner = ExampleScanner(response=mock_response)
        result = scanner.scan()

        # Then: 에러 없이 처리되어야 함
        assert 'error' not in result
```

### 테스트 작성 체크리스트

- [ ] True Positive 케이스 최소 3개
- [ ] False Positive 방지 케이스 최소 2개
- [ ] Edge case 처리 확인
- [ ] 에러 핸들링 테스트
- [ ] Mock 객체 적절히 활용
- [ ] 테스트 이름이 명확한지 확인
- [ ] 주석으로 테스트 의도 설명

## 🐛 디버깅 팁

### 테스트 실패 시

1. **상세 출력으로 실행**
   ```bash
   pytest -vv tests/unit/test_batch2_scanners.py::test_xss_scanner_true_positive
   ```

2. **디버거 사용**
   ```python
   import pdb; pdb.set_trace()  # 코드에 추가
   ```

3. **로그 확인**
   ```bash
   pytest --log-cli-level=DEBUG
   ```

### 일반적인 문제 해결

#### Import 오류
```python
# conftest.py에서 경로 설정 확인
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
```

#### Mock 객체 설정
```python
# 올바른 Mock 설정
mock_response = Mock()
mock_response.headers = {'Content-Type': 'text/html'}
mock_response.text = "<html>...</html>"
```

## 🔄 CI/CD 통합

### GitHub Actions 설정

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.12'

    - name: Install dependencies
      run: |
        pip install uv
        uv pip install -r requirements.txt
        uv pip install pytest pytest-django pytest-cov

    - name: Run tests
      run: |
        pytest --cov=scanner --cov-report=xml

    - name: Upload coverage
      uses: codecov/codecov-action@v3
```

## 📈 향후 계획

### 단기 목표
- [ ] 나머지 40개 스캐너 리팩토링 및 테스트 추가
- [ ] 성능 테스트 추가
- [ ] E2E 테스트 구현

### 장기 목표
- [ ] 테스트 자동화 강화
- [ ] Mutation testing 도입
- [ ] 실제 취약점 DB 기반 테스트 케이스 확장

## 💡 베스트 프랙티스

1. **테스트는 문서다**: 테스트 코드가 스캐너의 동작을 설명하도록 작성
2. **독립성 유지**: 각 테스트는 독립적으로 실행 가능해야 함
3. **빠른 실행**: 단위 테스트는 빠르게 실행되어야 함
4. **의미 있는 assertion**: 단순 통과/실패가 아닌 구체적 검증
5. **리팩토링 친화적**: 구현 변경에도 테스트는 유효해야 함

## 📚 참고 자료

- [pytest 공식 문서](https://docs.pytest.org/)
- [Django Testing](https://docs.djangoproject.com/en/5.2/topics/testing/)
- [Testing Best Practices](https://testdriven.io/blog/testing-best-practices/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)