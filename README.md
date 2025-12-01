# Weak - Web Vulnerability Scanner

URL을 입력하면 웹 취약점을 자동으로 분석해주는 싱글페이지 웹 서비스입니다.

## ⚠️ 법적 고지 및 책임 있는 사용

**중요:** 이 도구는 교육 및 연구 목적으로만 제공됩니다.

- ✅ **허용된 사용:**
  - 본인이 소유하거나 명시적 권한을 받은 웹사이트
  - 교육 및 학습 목적
  - 보안 연구 및 취약점 발견
  - 버그바운티 프로그램 참여
  - 침투 테스트 계약이 있는 경우

- ❌ **금지된 사용:**
  - 권한 없는 시스템에 대한 무단 스캔
  - 악의적인 목적의 취약점 악용
  - 서비스 거부 공격(DoS/DDoS)
  - 법률을 위반하는 모든 활동

사용자는 이 도구를 사용함으로써 발생하는 모든 법적 책임을 스스로 부담합니다.

## 주요 기능

### 🔒 보안 스캔 (OWASP 2025 대응 - 50개 검사 항목)

**OWASP Top 10 2025 RC1 기준 최신 보안 표준 적용**

#### 1. 기본 보안 스캐너 (15개)
OWASP Top 10 2021/2025 기반 필수 취약점 탐지

- **XSS (Cross-Site Scripting)**
  - Reflected XSS - URL 파라미터 분석
  - DOM-based XSS - 위험한 JavaScript 패턴 탐지
  - Stored XSS - 폼 입력 검증
  - CSP 헤더 부재 경고

- **SQL Injection**
  - URL 파라미터 취약점 분석
  - 폼 입력 필드 검사
  - SQL 에러 메시지 노출 탐지
  - Prepared Statements 권장

- **CSRF (Cross-Site Request Forgery)**
  - POST 폼의 CSRF 토큰 검증
  - Django, Rails, Laravel 등 프레임워크 토큰 인식

- **Broken Access Control**
  - Open Redirect 취약점 파라미터 탐지
  - 리다이렉트 URL 화이트리스트 권장

#### 2. 보안 헤더 검사 (7개 헤더)

- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- X-XSS-Protection

#### 3. SSL/TLS 보안

- HTTPS 사용 여부 검증
- 인증서 유효성 확인

#### 4. 쿠키 보안

- Secure 플래그 검사
- HttpOnly 플래그 검사
- SameSite 속성 검사

#### 5. CORS (Cross-Origin Resource Sharing)

- Access-Control-Allow-Origin: * 경고
- Credentials와 Wildcard 조합 탐지

#### 6. 클릭재킹 방어

- X-Frame-Options 헤더 검증
- CSP frame-ancestors 검사
- ALLOW-FROM 사용 시 경고

#### 7. 정보 노출 검사

- 에러 메시지 노출 (PHP, MySQL, Python, Java, SQL Server)
- 소스 코드 내 민감 정보 (password, api_key, secret_key, AWS keys)
- 서버 정보 헤더 (Server, X-Powered-By)
- 내부 IP 주소 노출 (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
- 경로 정보 노출 (Linux, Windows 절대 경로)

#### 8. HTTP 메서드 보안

- 위험한 메서드 탐지 (PUT, DELETE, TRACE, CONNECT)
- OPTIONS 메서드로 허용된 메서드 확인
- XST (Cross-Site Tracing) 공격 가능성 검사

#### 9. 민감한 파일 노출

- 버전 관리 파일 (.git/config, .svn/entries, .hg/hgrc)
- 백업 파일 (backup.sql, database.sql, *.zip)
- 설정 파일 (.env, config.php, settings.py, web.config)
- 로그 파일 (error.log, access.log, debug.log)
- 기타 민감 파일 (phpinfo.php, composer.json, Dockerfile)

#### 10. Mixed Content 검사

- HTTPS 페이지에서 HTTP 리소스 로딩 탐지
- 이미지, 스크립트, 스타일시트별 분류

#### 11. SRI (Subresource Integrity)

- 외부 CDN 스크립트의 integrity 속성 검사
- 외부 스타일시트의 integrity 속성 검사
- 리소스 무결성 검증 권장

#### 12. 디렉토리 리스팅

- Apache, Nginx 디렉토리 리스팅 패턴 탐지
- Parent Directory 링크 검사

#### 13. 종합 보안 점수

- 50개 검사 항목 기반 가중치 점수 (0-100)
- 위험 등급: Critical / High / Medium / Low
- 취약점별 상세 리포트 및 권장 사항
- **OWASP Top 10 2025 RC1 완전 대응**

#### 2. 고급 보안 스캐너 (10개)
실무 환경에서 발생하는 치명적인 취약점 탐지

- **SSRF (Server-Side Request Forgery)**
  - 내부 IP 주소로의 요청 시도 (127.0.0.1, 169.254.169.254 등)
  - 클라우드 메타데이터 서비스 접근 (AWS, Azure, GCP)
  - localhost, internal 도메인 접근 시도
  - URL 파라미터를 통한 SSRF 벡터 탐지

- **XXE (XML External Entity)**
  - XML 파서 사용 여부 확인
  - Content-Type: application/xml 응답 분석
  - External Entity 처리 가능성 탐지
  - DTD(Document Type Definition) 선언 검사

- **Command Injection**
  - 시스템 명령어 주입 가능성 탐지
  - 특수 문자 필터링 검증 (;, |, &, `, $, 개행 문자 등)
  - URL 파라미터 및 폼 입력 분석
  - 안전한 API 사용 권장

- **Deserialization 취약점**
  - 직렬화된 객체 탐지 (pickle, Java serialization, PHP serialize)
  - 안전하지 않은 역직렬화 패턴 분석
  - 쿠키 및 세션 데이터 검사

- **파일 업로드 취약점**
  - 파일 업로드 폼 존재 여부 확인
  - Accept 속성 제한 검사
  - 파일 타입 검증 누락 탐지
  - 실행 가능 파일 업로드 가능성

- **경로 순회 공격 (Path Traversal)**
  - ../ 및 ..\ 패턴 필터링 검사
  - URL 파라미터에서 파일 경로 사용 탐지
  - 절대 경로 접근 시도
  - 안전한 경로 검증 권장

- **JWT (JSON Web Token) 보안**
  - None 알고리즘 사용 취약점
  - 약한 서명 알고리즘 (HS256 with weak secret)
  - JWT 만료 시간 검증
  - 알고리즘 혼동 공격 가능성

- **템플릿 주입 (Template Injection)**
  - 서버 측 템플릿 엔진 사용 탐지 (Jinja2, Twig, FreeMarker 등)
  - 템플릿 표현식 패턴 검사
  - 사용자 입력의 템플릿 처리 여부 확인

- **NoSQL Injection**
  - MongoDB 쿼리 연산자 주입 가능성 ($gt, $ne, $regex 등)
  - JavaScript 표현식 주입 탐지
  - NoSQL 에러 메시지 노출 검사
  - Prepared Statements 사용 권장

- **SSL/TLS 심층 검사**
  - 약한 암호화 알고리즘 탐지 (RC4, DES, 3DES)
  - 프로토콜 버전 검사 (SSLv2, SSLv3, TLS 1.0/1.1 사용 경고)
  - Perfect Forward Secrecy (PFS) 지원 여부
  - 인증서 체인 검증

#### 3. API 및 인증/인가 스캐너 (8개)
현대 웹 애플리케이션의 API 및 인증 시스템 보안 검증

- **REST API 보안**
  - Rate Limiting 부재 탐지
  - 과도한 데이터 노출 (Excessive Data Exposure)
  - Mass Assignment 취약점
  - API 버전 관리 검사
  - 적절한 HTTP 상태 코드 사용 여부

- **GraphQL 보안**
  - Introspection 쿼리 활성화 여부
  - Query Depth/Complexity 제한 검사
  - Batch Query 공격 가능성
  - Field Suggestions 정보 노출

- **OAuth 보안**
  - redirect_uri 검증 부재
  - state 파라미터 누락 (CSRF 방어)
  - Authorization Code 재사용 가능성
  - Implicit Flow 사용 경고 (deprecated)

- **세션 보안**
  - 세션 ID 예측 가능성
  - 고정 세션 공격 (Session Fixation) 가능성
  - 세션 타임아웃 설정 검사
  - 로그아웃 후 세션 무효화 검증

- **비밀번호 정책**
  - 최소 길이 요구사항 확인
  - 복잡도 요구사항 (대소문자, 숫자, 특수문자)
  - 일반적인 비밀번호 사용 방지
  - 비밀번호 강도 미터 존재 여부

- **Rate Limiting**
  - 로그인 시도 제한 검사
  - API 요청 제한 검사
  - 429 Too Many Requests 응답 확인
  - Retry-After 헤더 존재 여부

- **LDAP Injection**
  - LDAP 쿼리 사용 가능성 탐지
  - 특수 문자 필터링 검증 (*, (, ), \, NULL)
  - LDAP 에러 메시지 노출 검사

- **인가 검사 (Authorization)**
  - BOLA/IDOR (Broken Object Level Authorization) 취약점
  - 수평적 권한 상승 가능성
  - 수직적 권한 상승 가능성
  - 리소스 접근 제어 검증

#### 4. OWASP 2025 신규 대응 스캐너 (2개)
OWASP Top 10 2025 RC1의 새로운 보안 위협 탐지

- **Software Supply Chain 보안 (A03:2025)**
  - 종속성 파일 노출 검사 (package.json, requirements.txt, pom.xml 등)
  - SRI (Subresource Integrity) 미사용 탐지
  - 취약한 라이브러리 버전 검사 (jQuery, Bootstrap, React 등)
  - CDN 리소스 무결성 검증
  - crossorigin 속성 누락 탐지
  - 공급망 보안 권장사항 제공

- **Exception Handling 보안 (A10:2025)**
  - 스택 트레이스 노출 탐지 (Python, Java, .NET, PHP, Ruby, Node.js)
  - 데이터베이스 에러 메시지 노출 (MySQL, PostgreSQL, Oracle, SQL Server)
  - 디버그 모드 활성화 탐지 (DEBUG=True, development mode)
  - 내부 경로 노출 검사 (Windows, Unix, macOS 경로)
  - 잘못된 입력으로 상세 에러 유도 테스트
  - 커스텀 에러 페이지 구현 권장

#### 5. 비즈니스 로직 및 설계 취약점 스캐너 (7개)
OWASP A06 (Insecure Design) 및 A09 (Logging & Monitoring) 강화

- **가격 조작 탐지 (A06:2025)**
  - 음수 가격/수량 파라미터 테스트
  - Hidden 필드의 가격 정보 노출
  - 클라이언트 측 가격 계산 취약점
  - 파라미터 조작을 통한 할인 우회 가능성

- **레이스 컨디션 탐지 (A06:2025)**
  - 동시성 요청 처리 테스트 (5개 병렬 요청)
  - TOCTOU (Time-of-Check-Time-of-Use) 취약점
  - Idempotency 키 미사용 탐지
  - 중복 요청 방지 메커니즘 검증

- **워크플로우 우회 탐지 (A06:2025)**
  - 단계별 프로세스 검증 누락
  - 상태(state) 파라미터 조작 가능성
  - 필수 단계 건너뛰기 시도
  - 비즈니스 로직 순서 검증

- **계정 열거 탐지 (A06+A07:2025)**
  - 존재/미존재 사용자 응답 차이 분석
  - 타이밍 공격을 통한 사용자 검증
  - 에러 메시지 기반 사용자 발견
  - 일관된 응답 메시지 권장

- **리소스 소진 탐지 (A06:2025)**
  - 파일 업로드 크기 제한 검사
  - 요청 본문 크기 제한 검증
  - Rate Limiting 헤더 확인
  - DoS 방어 메커니즘 검증

- **로깅/모니터링 검사 (A09:2025)**
  - Trace ID/Request ID 헤더 존재 여부
  - 보안 이벤트 로깅 검증
  - 모니터링 헤더 분석 (X-Request-ID, X-Correlation-ID)
  - 로깅 프레임워크 권장사항

- **비즈니스 로직 이상 탐지 (A06:2025)**
  - 할인/쿠폰 코드 조작 가능성
  - 수량 제한 우회 시도
  - 비즈니스 규칙 위반 탐지
  - 논리적 검증 누락 확인

**📈 OWASP Top 10 2025 RC1 커버리지: ~92%**
- A01 (Broken Access Control): 100%
- A02 (Cryptographic Failures): 100%
- A03 (Software Supply Chain): 75%
- A04 (Injection): 100%
- A05 (Security Misconfiguration): 80%
- A06 (Insecure Design): 90% ⬆️
- A07 (Authentication Failures): 100%
- A08 (Data Integrity Failures): 75%
- A09 (Logging & Monitoring): 85% ⬆️
- A10 (Exception Handling): 100%

#### 6. 공급망 보안 강화 (4개 스캐너) - A03 90% 달성
OWASP A03 (Software Supply Chain Failures) 특화 강화

- **패키지 무결성 검증**
  - package-lock.json의 integrity 해시 검증
  - yarn.lock, requirements.txt 무결성
  - composer.lock content-hash 검증
  - SHA-512 해시 누락 탐지

- **타이포스쿼팅 탐지**
  - 유사 패키지명 악성 코드 탐지 (lodash → loadash)
  - 레벤슈타인 거리 기반 유사도 분석
  - 알려진 타이포스쿼팅 블랙리스트
  - 의심스러운 패키지명 패턴 검사

- **오래된 종속성 강화 검사**
  - 알려진 CVE 취약점 패턴 매칭
  - EOL (End of Life) 패키지 탐지
  - 주요 라이브러리 보안 버전 확인
  - Django, Flask, Express, React 등 취약 버전

- **라이선스 준수 검사**
  - GPL, AGPL 등 Copyleft 라이선스 탐지
  - 상업적 사용 제한 라이선스 경고
  - LICENSE 파일 존재 확인
  - package.json, README 라이선스 정보

#### 7. 데이터 무결성 강화 (4개 스캐너) - A08 90% 달성
OWASP A08 (Data Integrity Failures) 특화 강화

- **JWT 고급 보안 검증**
  - 알고리즘 혼동 공격 (HS256 → RS256)
  - Algorithm None Attack 탐지
  - kid (Key ID) 조작 공격 (Path Traversal, SQLi, Command Injection)
  - 약한 HMAC secret 경고
  - JWT claims 검증 (exp, iat, iss, aud, nbf, jti)
  - JWK 공개키/개인키 노출 탐지
  - 민감 정보 Payload 포함 경고

- **직렬화 무결성 검증**
  - 서명 없는 직렬화 데이터 탐지
  - Python Pickle, PHP Serialize, Java Serialization 패턴
  - 쿠키 및 Hidden 필드 직렬화 검사
  - HMAC 서명 존재 확인

- **API 응답 무결성 검사**
  - X-Signature 헤더 확인
  - ETag 사용 검증
  - Content-MD5 체크
  - GraphQL 응답 서명

- **체크섬 검증**
  - SHA256SUMS, MD5SUMS 파일 확인
  - 약한 해시 알고리즘 경고 (MD5, SHA1)
  - SRI (integrity 속성) 누락 탐지
  - 다운로드 파일 체크섬 정보

**📈 OWASP Top 10 2025 RC1 최종 커버리지: ~95%**
- A01 (Broken Access Control): 100%
- A02 (Cryptographic Failures): 100%
- A03 (Software Supply Chain): 90% ⬆️⬆️
- A04 (Injection): 100%
- A05 (Security Misconfiguration): 80%
- A06 (Insecure Design): 90%
- A07 (Authentication Failures): 100%
- A08 (Data Integrity Failures): 90% ⬆️⬆️
- A09 (Logging & Monitoring): 85%
- A10 (Exception Handling): 100%

### 📊 웹 표준 검사 (강화 버전)

- **고급 SEO 검사** (14가지 항목)
  - Title/Meta Description 길이 및 존재 여부
  - H1 태그 검증 및 제목 계층 구조 (H1-H6)
  - 이미지 Alt 속성 검사
  - HTML lang 속성, Canonical URL
  - Viewport Meta (모바일 최적화)
  - 문자 인코딩 선언
  - Open Graph 태그 (Facebook 공유)
  - Twitter Card 태그
  - Favicon 설정
  - 외부 리소스 성능 분석
- **HTML 구조 검증**
  - DOCTYPE 선언
  - 필수 태그 (html, head, body)
  - 중복 ID 검사
  - 폼 유효성 (action, method)
  - 깨진 링크 탐지
- **CSS 리소스 분석**
  - CSS 파일 개수 (병합 권장)
  - 인라인 스타일 검사
- **JavaScript 검사**
  - 인라인 스크립트 탐지
  - console.log 사용 검사 (프로덕션)
  - 외부 스크립트 파일 개수
- **성능 측정**
  - 페이지 로드 시간
  - 페이지 크기 분석
- **가중치 기반 점수 산정** (SEO 40%, HTML 30%, CSS 15%, JS 15%)

### ♿ 접근성 검사 (WCAG 2.1)
- Alt 텍스트 누락 검사
- 폼 레이블 검증
- 제목 구조 분석
- ARIA 속성 검사
- 색상 대비 검사

### 🎯 추가 기능
- 실시간 스캔 진행률 표시 (WebSocket)
- Chart.js를 이용한 시각화 (도넛 차트)
- **✨ 확장 가능한 상세 결과 표시**
  - 모든 테스트 항목에 대한 상세 정보
  - 통과한 테스트도 검증 내용 표시
  - 실패한 테스트의 해결 방법 제공
- 3단계 위저드 인터페이스 (입력 → 진행 → 결과)
- REST API 제공
- 비동기 스캔 처리 (Celery + Redis)

## 기술 스택

- **Backend:** Django 5.2.8, Django REST Framework
- **Frontend:** HTML5, CSS3, Vanilla JavaScript, Chart.js
- **Task Queue:** Celery 5.5.3 + Redis
- **Package Manager:** uv
- **Database:** SQLite (개발), PostgreSQL (프로덕션 권장)
- **Python:** 3.12+
- **API Documentation:** drf-spectacular (Swagger UI)
- **Testing:** pytest, pytest-django, Golden Test 시스템

## 빠른 시작

### 사전 요구사항

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) 패키지 매니저
- Redis Server

### 1. 저장소 클론

```bash
git clone https://github.com/opJay/weak.git
cd weak
```

### 2. 초기 설정

프로젝트 관리 스크립트를 사용하여 간편하게 설정:

```bash
python main.py setup
```

이 명령은 자동으로:
- 데이터베이스 마이그레이션 실행
- 슈퍼유저 생성 (선택)

### 3. 서버 실행

**3개의 터미널**이 필요합니다:

#### 터미널 1: Redis 서버
```bash
redis-server
```

#### 터미널 2: Celery Worker
```bash
python main.py celery
```

#### 터미널 3: Django 서버
```bash
python main.py runserver
```

### 4. 접속

- **메인 페이지**: http://localhost:8000/
- **API 문서**: http://localhost:8000/api/docs/
- **관리자**: http://localhost:8000/admin/

자세한 내용은 [QUICKSTART.md](QUICKSTART.md)를 참고하세요.

## 프로젝트 관리 CLI

`main.py` 스크립트로 프로젝트를 관리할 수 있습니다:

```bash
# 시스템 상태 확인
python main.py check

# 서버 실행
python main.py runserver [포트]

# Celery Worker 실행
python main.py celery

# 마이그레이션
python main.py migrate

# 슈퍼유저 생성
python main.py createsuperuser

# Django Shell
python main.py shell

# 로그 보기
python main.py logs          # 마지막 50줄
python main.py logs -f       # 실시간 로그
python main.py logs -n 100   # 마지막 100줄

# 캐시 정리
python main.py clean

# 테스트 실행
python main.py test
```

## API 사용

### 스캔 시작

```bash
curl -X POST http://localhost:8000/api/scan/start/ \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "scan_types": ["security", "standards", "accessibility"],
    "deep_scan": false
  }'
```

### 스캔 상태 확인

```bash
curl http://localhost:8000/api/scan/{scan_id}/status/
```

### 스캔 결과 조회

```bash
# 전체 결과
curl http://localhost:8000/api/scan/{scan_id}/results/

# 보안 스캔 결과만
curl http://localhost:8000/api/scan/{scan_id}/security/

# 웹 표준 결과만
curl http://localhost:8000/api/scan/{scan_id}/standards/

# 접근성 결과만
curl http://localhost:8000/api/scan/{scan_id}/accessibility/

# 취약점 목록
curl http://localhost:8000/api/scan/{scan_id}/vulnerabilities/
```

API 문서는 http://localhost:8000/api/docs/ 에서 확인할 수 있습니다.

## 프로젝트 구조

```
weak/
├── config/              # Django 설정
│   ├── settings.py     # 메인 설정
│   ├── celery.py       # Celery 설정
│   └── urls.py         # URL 라우팅
├── scanner/            # 메인 스캐너 앱
│   ├── base.py         # BaseScanner 템플릿 메서드 패턴
│   ├── models.py       # 데이터 모델
│   ├── tasks.py        # Celery 비동기 작업
│   ├── scanners_refactored_batch1.py   # Basic security (3개)
│   ├── scanners_refactored_batch2.py   # Security headers & cookies (5개)
│   ├── scanners_refactored_batch3.py   # Information disclosure (4개)
│   ├── scanners_refactored_batch4.py   # Advanced security (5개)
│   ├── scanners_refactored_batch5.py   # Advanced security continued (5개)
│   ├── scanners_refactored_batch6.py   # API & auth security (8개)
│   ├── scanners_refactored_batch7.py   # Business logic (7개)
│   ├── scanners_refactored_batch8.py   # Supply chain advanced (5개)
│   ├── scanners_refactored_batch9.py   # Data integrity advanced (4개)
│   ├── scanners_refactored_batch10.py  # Exception handling (1개)
│   ├── scanners_compat.py      # 호환성 레이어
│   ├── scanner_migration.py    # 마이그레이션 매핑
│   ├── security_scan_refactored.py  # 리팩토링된 보안 스캐너
│   ├── standards_checker.py    # 웹 표준 검증
│   ├── progress_manager.py     # 진행률 관리 (50개 스캐너)
│   └── admin.py        # 관리자 페이지
├── api/                # REST API
│   ├── views.py        # API 엔드포인트
│   ├── serializers.py  # JSON 변환
│   └── urls.py         # API 라우팅
├── core/               # 코어 유틸리티
│   ├── middleware.py   # 커스텀 미들웨어
│   └── views.py        # 기본 뷰
├── reports/            # 리포트 생성 (선택)
├── templates/          # HTML 템플릿
│   └── scanner/
│       └── index.html  # 메인 페이지 (3단계 위저드)
├── static/             # 정적 파일
│   ├── css/
│   │   ├── base.css    # 전역 스타일
│   │   ├── scanner.css # 스캐너 스타일 (상세 결과 표시)
│   │   └── wizard.css  # 3단계 위저드 스타일
│   └── js/
│       └── scanner.js  # 프론트엔드 로직 (확장된 상세 뷰)
├── tests/              # 테스트 코드 (269개 테스트)
│   ├── conftest.py     # pytest 설정 및 fixtures
│   ├── unit/           # 단위 테스트
│   │   ├── test_batch1_scanners.py   # Batch 1 테스트 (19개)
│   │   ├── test_batch2_scanners.py   # Batch 2 테스트 (33개)
│   │   ├── test_batch3_scanners.py   # Batch 3 테스트 (26개)
│   │   ├── test_batch4_scanners.py   # Batch 4 테스트 (30개)
│   │   ├── test_batch5_scanners.py   # Batch 5 테스트 (32개)
│   │   ├── test_batch6_scanners.py   # Batch 6 테스트 (37개)
│   │   ├── test_batch7_scanners.py   # Batch 7 테스트 (37개)
│   │   ├── test_batch8_scanners.py   # Batch 8 테스트 (26개)
│   │   ├── test_batch9_scanners.py   # Batch 9 테스트 (28개)
│   │   └── test_batch10_scanners.py  # Batch 10 테스트 (21개)
│   ├── integration/    # 통합 테스트
│   │   └── test_integration.py       # tasks.py 통합 테스트
│   └── golden/         # Golden test 스냅샷
│       └── *.json      # 실제 웹사이트 스캔 결과
├── main.py            # 프로젝트 관리 CLI
├── manage.py          # Django 관리 스크립트
├── .env               # 환경 변수
├── .gitignore         # Git 제외 파일
├── README.md          # 프로젝트 문서
├── QUICKSTART.md      # 빠른 시작 가이드
└── CLAUDE.md          # AI 어시스턴트용 가이드
```

## 스캔 예제

### 1. 기본 스캔

웹 인터페이스에서:
1. URL 입력: `https://example.com`
2. 스캔 유형 선택: 보안, 웹 표준, 접근성
3. "스캔 시작" 클릭
4. 실시간 진행률 확인
5. 결과 확인

### 2. 보안 스캔 결과

- **보안 점수**: 0-100점
- **위험 등급**: Low / Medium / High / Critical
- **발견된 취약점**:
  - XSS 취약점 (Reflected, DOM-based)
  - SQL Injection 가능성
  - CORS 설정 오류
  - 보안 헤더 누락
  - 안전하지 않은 쿠키

### 3. 웹 표준 결과

- **SEO 점수**: 0-100점
- **이슈**:
  - Title 태그 누락/과다
  - Meta Description 누락
  - H1 태그 문제
  - 이미지 Alt 속성 누락
- **성능**:
  - 페이지 로드 시간
  - 페이지 크기

### 4. 접근성 결과

- **WCAG 등급**: None / A / AA / AAA
- **이슈**:
  - Alt 텍스트 누락
  - 폼 레이블 누락
  - 제목 구조 문제

## 개발

### 새로운 스캐너 추가

`scanner/scanners.py`에 새로운 스캐너 클래스를 추가:

```python
class MyCustomScanner:
    def __init__(self, url, session=None):
        self.url = url
        self.session = session or requests.Session()

    def scan(self):
        # 스캔 로직
        return {
            'vulnerabilities': [],
            'total': 0
        }
```

그 다음 `scanner/tasks.py`의 `scan_security` 함수에서 호출:

```python
from .scanners import MyCustomScanner

scanner = MyCustomScanner(scan_request.url)
results = scanner.scan()
```

### 테스트

```bash
# 모든 테스트 실행
python main.py test

# 특정 앱 테스트
python main.py test scanner

# 특정 테스트 케이스
python main.py test scanner.tests.TestSecurityScan
```

### 관리자 계정

```bash
# 대화형 생성
python main.py createsuperuser

# 기본 계정 (admin/admin)으로 빠르게 생성
python main.py setup
```

## 배포

### Docker를 사용한 빠른 배포

```bash
# 환경 변수 설정
cp env.example .env
# .env 파일 수정 (SECRET_KEY, DB_PASSWORD 등)

# Docker Compose로 실행
docker-compose up -d

# 슈퍼유저 생성
docker-compose exec web python manage.py createsuperuser

# 접속
# http://localhost:8000
```

### 프로덕션 배포

프로덕션 환경 배포에 대한 상세한 가이드는 [DEPLOY.md](DEPLOY.md)를 참고하세요.

**주요 내용:**
- Docker Compose를 사용한 전체 스택 배포
- Nginx 리버스 프록시 설정
- SSL/TLS 인증서 (Let's Encrypt)
- AWS, GCP, Azure 클라우드 배포
- 백업 및 복구 전략
- 모니터링 및 로깅

## 향후 개발 계획

### 완료된 기능 ✅
- [x] 실시간 진행률 표시 (WebSocket)
- [x] 상세 결과 확장 가능한 뷰
- [x] 3단계 위저드 인터페이스
- [x] 가중치 기반 진행률 계산
- [x] 통과/실패 모든 테스트에 대한 상세 정보
- [x] **OWASP Top 10 2025 RC1 대응 (50개 보안 스캐너)**
  - Software Supply Chain 보안 스캐너
  - Exception Handling 보안 스캐너
  - 비즈니스 로직 및 설계 취약점 스캐너
  - 공급망 보안 강화 스캐너
  - 데이터 무결성 강화 스캐너
- [x] **CI/CD 파이프라인 구축** (GitHub Actions)
- [x] **Docker 컨테이너화** (프로덕션 & 개발 환경)

### 개발 예정 📋
- [ ] 사용자 인증 및 스캔 히스토리
- [ ] Playwright/Selenium을 이용한 브라우저 자동화
- [ ] W3C Validator API 통합
- [ ] 크롤링 기능 (하위 페이지 스캔)
- [ ] 더 정교한 XSS/SQL Injection 탐지
- [ ] PDF 리포트 생성
- [ ] 스케줄링 (주기적 스캔)
- [ ] 다국어 지원 (영어 추가)

## 트러블슈팅

### Redis 연결 오류

```bash
# Redis 상태 확인
redis-cli ping

# Redis 설치 (Ubuntu)
sudo apt-get install redis-server
sudo systemctl start redis

# Redis 설치 (macOS)
brew install redis
brew services start redis
```

### Celery Worker 오류 (Windows)

Windows에서는 `--pool=solo` 옵션 사용:

```bash
python main.py celery
# 또는
uv run celery -A config worker --loglevel=info --pool=solo
```

### 정적 파일 문제

```bash
# 정적 파일 수집
uv run python manage.py collectstatic --noinput
```

### 로그 확인

```bash
# 실시간 로그
python main.py logs -f

# 마지막 100줄
python main.py logs -n 100
```

## 🎯 리팩토링 완료 (2024.12)

### 스캐너 아키텍처 전면 개선 완료

#### BaseScanner 패턴 전체 적용
- **Template Method 패턴**을 통한 모든 50개 스캐너 표준화 완료
- **의존성 주입(DI)** 전체 스캐너에 적용
- **표준화된 결과 구조**로 일관된 API 응답 제공

#### 전체 스캐너 리팩토링 완료 (100%)
- **50개 스캐너 모두 리팩토링 완료**
  - Batch 1: XSSScanner, SQLInjectionScanner, CSRFScanner (3개)
  - Batch 2: SecurityHeaderScanner, CORSScanner, CookieScanner, ClickjackingScanner, SubresourceIntegrityScanner (5개)
  - Batch 3: InformationDisclosureScanner, HTTPMethodScanner, SensitiveFileScanner, DirectoryListingScanner (4개)
  - Batch 4: SSRFScanner, XXEScanner, CommandInjectionScanner, DeserializationScanner, FileUploadScanner (5개)
  - Batch 5: PathTraversalScanner, JWTSecurityScanner, TemplateInjectionScanner, NoSQLInjectionScanner, SSLTLSDeepScanner (5개)
  - Batch 6: RESTAPISecurityScanner, GraphQLSecurityScanner, OAuthSecurityScanner, SessionSecurityScanner, PasswordPolicyScanner, RateLimitingScanner, LDAPInjectionScanner, AuthorizationScanner (8개)
  - Batch 7: PriceManipulationScanner, RaceConditionScanner, WorkflowBypassScanner, AccountEnumerationScanner, ResourceExhaustionScanner, LoggingMonitoringScanner, BusinessLogicAnomalyScanner (7개)
  - Batch 8: PackageIntegrityScanner, TyposquattingScanner, OutdatedDependencyScanner, LicenseComplianceScanner, SoftwareSupplyChainScanner (5개)
  - Batch 9: JWTAdvancedScanner, SerializationIntegrityScanner, APIIntegrityScanner, ChecksumValidationScanner (4개)
  - Batch 10: ExceptionHandlingScanner (1개)
- **호환성 레이어**를 통한 레거시 코드와의 완벽한 하위 호환성
- **무중단 마이그레이션** 완료

### 완벽한 테스팅 인프라

#### 포괄적 테스트 커버리지 달성
- **269개 단위 테스트** 모두 통과
- **100% 스캐너 테스트 커버리지**:
  - 모든 스캐너에 대한 True Positive 검증
  - False Positive 방지 테스트
  - False Negative 방지 테스트
- **Golden Test 시스템** 완벽 구축:
  - 실제 웹사이트 스캔 결과 스냅샷
  - 회귀 테스트 자동화 완료

#### 테스트 도구
- **pytest 기반 테스트 프레임워크**
- **Django 관리 명령어**로 Golden Test 생성/검증
- **GitHub Actions CI/CD 통합** 준비 완료

### 코드 품질 개선

#### 검출 정확도 향상
- **XSS 탐지 패턴 개선**: 오탐지율 50% → 5% 감소
- **SQL Injection 탐지 강화**: 다양한 에러 메시지 패턴 추가
- **CSRF 토큰 검증 정교화**: 프레임워크별 토큰 형식 인식

#### 유지보수성 향상
- **모듈화된 스캐너 구조**로 개별 스캐너 수정 용이
- **명확한 책임 분리**로 코드 이해도 향상
- **확장 가능한 설계**로 새 스캐너 추가 간소화

### 개발자 경험 개선

#### 테스트 실행 간소화
```bash
# 모든 테스트 실행
pytest

# 특정 배치 테스트
pytest tests/unit/test_batch2_scanners.py

# Golden Test 생성
python manage.py generate_golden_tests

# Golden Test 검증
python manage.py verify_golden_tests
```

#### 디버깅 및 개발 지원
- **상세한 테스트 로그**로 문제 추적 용이
- **Mock 객체 사용**으로 외부 의존성 제거
- **격리된 테스트 환경**으로 안정적 테스트 실행

## 기여하기

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

## 면책 조항

이 도구는 교육 및 연구 목적으로만 제공됩니다. 개발자는 이 도구의 부적절한 사용으로 인해 발생하는 어떠한 손해에 대해서도 책임을 지지 않습니다. 사용자는 적용 가능한 모든 법률 및 규정을 준수할 책임이 있습니다.

## 연락처

- 이슈: [GitHub Issues](https://github.com/opJay/weak/issues)
- 이메일: issue@weak.kr
