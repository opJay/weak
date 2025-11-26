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

### 🔒 보안 스캔 (초강화 버전 - 15개 검사 항목)

#### 1. OWASP Top 10 취약점 탐지

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

- 15개 검사 항목 기반 가중치 점수 (0-100)
- 위험 등급: Critical / High / Medium / Low
- 취약점별 상세 리포트 및 권장 사항

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
- 실시간 스캔 진행률 표시
- Chart.js를 이용한 시각화
- 취약점 상세 리포트
- REST API 제공
- 비동기 스캔 처리 (Celery)

## 기술 스택

- **Backend:** Django 5.2.8, Django REST Framework
- **Frontend:** HTML5, CSS3, Vanilla JavaScript, Chart.js
- **Task Queue:** Celery 5.5.3 + Redis
- **Package Manager:** uv
- **Database:** SQLite (개발), PostgreSQL (프로덕션 권장)
- **Python:** 3.12+
- **API Documentation:** drf-spectacular (Swagger UI)

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
│   ├── settings.py
│   ├── celery.py       # Celery 설정
│   └── urls.py
├── scanner/            # 메인 스캐너 앱
│   ├── models.py       # 데이터 모델
│   ├── tasks.py        # Celery 비동기 작업
│   ├── scanners.py     # 취약점 스캐너 (NEW!)
│   └── admin.py        # 관리자 페이지
├── api/                # REST API
│   ├── views.py        # API 엔드포인트
│   ├── serializers.py  # JSON 변환
│   └── urls.py
├── templates/          # HTML 템플릿
│   └── scanner/
│       └── index.html  # 메인 페이지
├── static/             # 정적 파일
│   ├── css/
│   │   ├── base.css
│   │   └── scanner.css
│   └── js/
│       └── scanner.js  # 프론트엔드 로직
├── main.py            # 프로젝트 관리 CLI (NEW!)
├── .env               # 환경 변수
├── README.md
└── QUICKSTART.md      # 상세 가이드
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

## 향후 개발 계획

- [ ] Playwright/Selenium을 이용한 브라우저 자동화
- [ ] W3C Validator API 통합
- [ ] 크롤링 기능 (하위 페이지 스캔)
- [ ] 더 정교한 XSS/SQL Injection 탐지
- [ ] PDF 리포트 생성
- [ ] 사용자 인증 및 스캔 히스토리
- [ ] 스케줄링 (주기적 스캔)
- [ ] Docker 컨테이너화

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
- 이메일: your.email@example.com

---

**Made with ❤️ for Security Research**
