# 📚 WEAK 스캐너 개발 가이드

## 목차
1. [스캐너 아키텍처 개요](#스캐너-아키텍처-개요)
2. [새 스캐너 추가하기](#새-스캐너-추가하기)
3. [메타데이터 표준](#메타데이터-표준)
4. [스캔 로직 구현](#스캔-로직-구현)
5. [테스트 작성](#테스트-작성)
6. [베스트 프랙티스](#베스트-프랙티스)

## 스캐너 아키텍처 개요

WEAK의 스캐너 시스템은 **자동 디스커버리**와 **메타데이터 기반 관리**를 핵심으로 합니다.

```
scanner/
├── core/
│   ├── base.py          # BaseScanner 클래스
│   └── registry.py      # 자동 디스커버리 시스템
├── scanners/            # 개별 스캐너 파일들 (자동 발견)
│   ├── xss_scanner.py
│   ├── sql_injection_scanner.py
│   └── ...
└── scanners_compat.py   # 하위 호환성 레이어
```

## 새 스캐너 추가하기

### 1단계: 스캐너 파일 생성

`scanner/scanners/` 디렉토리에 새 파일을 생성합니다.

```python
# scanner/scanners/my_new_scanner.py

from scanner.core.base import BaseScanner
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)


class MyNewScanner(BaseScanner):
    """새로운 보안 스캐너 설명"""

    # 필수 메타데이터
    metadata = {
        'id': 'my_new_scanner',           # 고유 식별자 (snake_case)
        'name': '새 스캐너 이름',           # 한글 표시명
        'icon': '🔍',                     # 이모지 아이콘
        'description': '스캐너 설명',      # 상세 설명
        'weight': 1.5,                    # 진행률 가중치 (0.5~2)
        'field': 'my_new_scanner_result', # DB 필드명
        'category': 'security_basic',     # 카테고리 (아래 참고)
        'OWASP': 'A01:2025',              # OWASP Top 10 매핑
        'CWE': ['CWE-79', 'CWE-116'],     # CWE ID 목록 (선택)
        'enabled': True                   # 활성화 여부 (선택)
    }

    def __init__(self, url: str = None, response: Any = None,
                 html_content: str = None, **kwargs):
        """스캐너 초기화"""
        super().__init__(url=url, response=response,
                        html_content=html_content, **kwargs)
        self.vulnerabilities = []
        self.issues = []

    def _execute_scan(self) -> None:
        """실제 스캔 로직 구현 (필수)"""
        # 스캔 로직 구현
        if self._detect_vulnerability():
            self.vulnerabilities.append({
                'type': 'Vulnerability Type',
                'severity': 'high',  # critical, high, medium, low, info
                'title': '취약점 제목',
                'description': '상세 설명',
                'location': self.url,
                'evidence': '증거 데이터',
                'remediation': '해결 방법'
            })

    def _detect_vulnerability(self) -> bool:
        """취약점 탐지 로직"""
        # 실제 탐지 로직 구현
        return False

    def _build_result(self) -> Dict[str, Any]:
        """결과 구성 (선택적 오버라이드)"""
        result = super()._build_result()
        result.update({
            'custom_field': 'custom_value',
            'total_issues': len(self.vulnerabilities)
        })
        return result
```

### 2단계: 카테고리 선택

스캐너는 다음 카테고리 중 하나에 속해야 합니다:

| 카테고리 | 설명 | 예시 |
|---------|------|------|
| `security_basic` | 기본 보안 검사 | XSS, SQL Injection, CORS |
| `security_advanced` | 고급 보안 검사 | SSRF, XXE, Deserialization |
| `api_auth` | API 및 인증/인가 | OAuth, JWT, Session |
| `business_logic` | 비즈니스 로직 | Price Manipulation, Race Condition |
| `supply_chain` | 공급망 보안 | Package Integrity, Typosquatting |
| `data_integrity` | 데이터 무결성 | JWT Advanced, Serialization |

### 3단계: 스캐너 등록 (자동)

파일을 저장하면 자동으로 레지스트리가 발견합니다. 별도 등록 불필요!

```python
# 테스트 코드에서 확인
from scanner.core.registry import scanner_registry

scanners = scanner_registry.discover_scanners()
assert 'my_new_scanner' in scanners
```

## 메타데이터 표준

### 필수 필드

| 필드 | 타입 | 설명 | 예시 |
|-----|------|------|------|
| `id` | string | 고유 식별자 (snake_case) | `'xss'`, `'sql_injection'` |
| `name` | string | 한글 표시명 | `'XSS 취약점 스캔'` |
| `icon` | string | 이모지 아이콘 | `'🔍'`, `'⚠️'` |
| `description` | string | 상세 설명 | `'Cross-Site Scripting 취약점 탐지'` |
| `weight` | float | 진행률 가중치 (0.5~2) | `1.5` |
| `field` | string | DB 필드명 | `'xss_vulnerabilities'` |
| `category` | string | 카테고리 | `'security_basic'` |

### 선택 필드

| 필드 | 타입 | 설명 | 예시 |
|-----|------|------|------|
| `OWASP` | string | OWASP Top 10 매핑 | `'A03:2025'` |
| `CWE` | list | CWE ID 목록 | `['CWE-79', 'CWE-116']` |
| `enabled` | bool | 활성화 여부 | `True` |
| `aliases` | list | 별칭 목록 | `['xss_scan', 'cross_site_scripting']` |
| `severity_weight` | dict | 심각도별 가중치 | `{'critical': 10, 'high': 5}` |

## 스캔 로직 구현

### 기본 패턴

```python
def _execute_scan(self) -> None:
    """스캔 실행"""
    # 1. 대상 확인
    if not self._is_applicable():
        return

    # 2. 취약점 탐지
    vulnerabilities = self._detect_vulnerabilities()

    # 3. 결과 저장
    for vuln in vulnerabilities:
        self.vulnerabilities.append(vuln)

    # 4. 점수 계산 (선택)
    self.score = self._calculate_score()
```

### HTTP 요청 처리

```python
def _test_endpoint(self, payload: str) -> bool:
    """엔드포인트 테스트"""
    try:
        # self.session 사용 (자동 제공)
        response = self.session.get(
            self.url,
            params={'q': payload},
            timeout=5
        )

        # 응답 분석
        if self._analyze_response(response):
            return True

    except requests.RequestException as e:
        logger.debug(f"Request failed: {e}")

    return False
```

### HTML 파싱

```python
def _analyze_html(self) -> None:
    """HTML 분석"""
    if not self.html_content:
        return

    soup = BeautifulSoup(self.html_content, 'html.parser')

    # 폼 검사
    forms = soup.find_all('form')
    for form in forms:
        if self._check_form_vulnerability(form):
            self.issues.append({
                'element': str(form)[:100],
                'issue': 'Missing CSRF token'
            })
```

## 테스트 작성

### 단위 테스트 예시

```python
# tests/unit/test_my_new_scanner.py

import pytest
from unittest.mock import Mock, patch
from scanner.scanners.my_new_scanner import MyNewScanner


class TestMyNewScanner:
    """MyNewScanner 단위 테스트"""

    def test_metadata(self):
        """메타데이터 검증"""
        assert MyNewScanner.metadata['id'] == 'my_new_scanner'
        assert 'category' in MyNewScanner.metadata

    def test_detect_vulnerability(self):
        """취약점 탐지 테스트"""
        scanner = MyNewScanner(url='http://test.com')

        # Mock 응답 설정
        mock_response = Mock()
        mock_response.text = '<script>alert(1)</script>'
        mock_response.status_code = 200

        with patch.object(scanner, 'session') as mock_session:
            mock_session.get.return_value = mock_response

            scanner._execute_scan()

            assert len(scanner.vulnerabilities) > 0
            assert scanner.vulnerabilities[0]['severity'] == 'high'

    @pytest.mark.parametrize('payload,expected', [
        ('<script>alert(1)</script>', True),
        ('normal text', False),
        ('"><script>alert(1)</script>', True)
    ])
    def test_payload_detection(self, payload, expected):
        """다양한 페이로드 테스트"""
        scanner = MyNewScanner()
        result = scanner._is_vulnerable_payload(payload)
        assert result == expected
```

## 베스트 프랙티스

### 1. 에러 처리
```python
def _execute_scan(self) -> None:
    try:
        # 위험한 작업
        self._perform_scan()
    except requests.Timeout:
        logger.warning(f"Timeout scanning {self.url}")
        self.issues.append({
            'type': 'timeout',
            'message': 'Scan timeout'
        })
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
```

### 2. 성능 최적화
```python
# 타임아웃 설정
response = self.session.get(url, timeout=5)

# 요청 수 제한
MAX_REQUESTS = 10
for i, endpoint in enumerate(endpoints[:MAX_REQUESTS]):
    # ...

# 캐싱 활용
@lru_cache(maxsize=128)
def _check_pattern(self, text: str) -> bool:
    # ...
```

### 3. 로깅
```python
logger.debug(f"Starting scan for {self.url}")
logger.info(f"Found {len(self.vulnerabilities)} vulnerabilities")
logger.warning(f"Suspicious pattern detected: {pattern}")
logger.error(f"Scan failed: {error}")
```

### 4. 취약점 심각도 가이드

| 심각도 | 설명 | 예시 |
|-------|------|------|
| `critical` | 즉각적인 시스템 침해 가능 | RCE, SQL Injection (DB 접근) |
| `high` | 중요 데이터 노출/변조 가능 | XSS (인증), SSRF |
| `medium` | 제한적 영향 | XSS (비인증), Information Disclosure |
| `low` | 최소한의 영향 | Missing Headers, Verbose Errors |
| `info` | 정보성 | Version Disclosure, Comments |

## 자주 묻는 질문 (FAQ)

### Q: 스캐너가 자동으로 발견되지 않아요
A: 다음을 확인하세요:
- 파일이 `scanner/scanners/` 디렉토리에 있는지
- 클래스가 `BaseScanner`를 상속받는지
- `metadata` 딕셔너리가 정의되어 있는지
- `metadata['id']`가 설정되어 있는지

### Q: 외부 라이브러리를 사용하고 싶어요
A: requirements.txt에 추가하고, import 시 try-except로 감싸세요:
```python
try:
    import special_library
    HAS_SPECIAL = True
except ImportError:
    HAS_SPECIAL = False
    logger.warning("special_library not installed")
```

### Q: 비동기 스캔을 구현하고 싶어요
A: 현재는 동기 방식이지만, `async` 메서드를 추가할 수 있습니다:
```python
async def _async_scan(self):
    # aiohttp 등 사용
    pass
```

## 기여 가이드

1. 새 스캐너 추가 시 PR 생성
2. 단위 테스트 필수 포함
3. 메타데이터 완성도 확인
4. 코드 리뷰 후 머지

## 문의

질문이나 제안사항은 GitHub Issues로 등록해주세요.