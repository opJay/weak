# Weak Scanner - 빠른 시작 가이드

이 가이드는 Weak Scanner를 로컬 환경에서 실행하는 방법을 설명합니다.

## 사전 요구사항

- Python 3.12+
- Redis Server (Celery 메시지 브로커)
- uv (Python 패키지 관리자)

## 1. Redis 서버 설치 및 실행

### Windows

1. **Redis 다운로드 및 설치**
   - [Redis for Windows](https://github.com/microsoftarchive/redis/releases) 다운로드
   - 또는 WSL2 사용

2. **Redis 실행**
   ```bash
   # Redis 서버 시작
   redis-server
   ```

### macOS

```bash
# Homebrew로 설치
brew install redis

# Redis 실행
redis-server
```

### Linux

```bash
# Ubuntu/Debian
sudo apt-get install redis-server
sudo systemctl start redis

# Redis 상태 확인
redis-cli ping
# 응답: PONG
```

## 2. 환경 설정

프로젝트의 `.env` 파일이 이미 생성되어 있습니다. 필요에 따라 수정하세요:

```bash
DEBUG=True
SECRET_KEY=your-secret-key-here
ALLOWED_HOSTS=localhost,127.0.0.1
REDIS_URL=redis://localhost:6379/0
```

## 3. 데이터베이스 설정

데이터베이스 마이그레이션은 이미 완료되었습니다. 확인만 하세요:

```bash
uv run python manage.py migrate
```

## 4. 애플리케이션 실행

총 **3개의 터미널**이 필요합니다:

### 터미널 1: Redis 서버

```bash
redis-server
```

> Redis는 백그라운드에서 계속 실행되어야 합니다.

### 터미널 2: Celery Worker

```bash
# Celery worker 시작
uv run celery -A config worker --loglevel=info

# Windows의 경우 (eventlet 사용)
uv run celery -A config worker --loglevel=info --pool=solo
```

> Celery worker는 백그라운드 스캔 작업을 처리합니다.

### 터미널 3: Django 개발 서버

```bash
# Django 서버 시작
uv run python manage.py runserver
```

## 5. 애플리케이션 접속

브라우저에서 다음 주소로 접속:

- **메인 페이지**: http://localhost:8000/
- **API 문서**: http://localhost:8000/api/docs/
- **관리자 페이지**: http://localhost:8000/admin/

## 6. 관리자 계정 생성 (선택사항)

Django 관리자 페이지에 접속하려면 superuser를 생성해야 합니다:

```bash
uv run python manage.py createsuperuser
```

안내에 따라 사용자명, 이메일, 비밀번호를 입력하세요.

## 7. 스캔 테스트

### 웹 인터페이스 사용

1. http://localhost:8000/ 접속
2. 스캔할 URL 입력 (예: `https://example.com`)
3. 스캔 유형 선택 (보안, 웹 표준, 접근성)
4. "스캔 시작" 버튼 클릭
5. 실시간으로 진행 상황 확인
6. 결과 확인

### API 직접 호출 (cURL)

```bash
# 스캔 시작
curl -X POST http://localhost:8000/api/scan/start/ \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "scan_types": ["security", "standards", "accessibility"],
    "deep_scan": false
  }'

# 응답 예시
# {
#   "scan_id": "123e4567-e89b-12d3-a456-426614174000",
#   "status": "pending",
#   "url": "https://example.com",
#   "message": "Scan request created successfully"
# }

# 스캔 상태 확인
curl http://localhost:8000/api/scan/{scan_id}/status/

# 스캔 결과 조회
curl http://localhost:8000/api/scan/{scan_id}/results/
```

## 8. 트러블슈팅

### Redis 연결 오류

```
ConnectionRefusedError: [Errno 111] Connection refused
```

**해결방법**: Redis 서버가 실행 중인지 확인하세요.

```bash
redis-cli ping
```

### Celery Worker 오류 (Windows)

Windows에서 Celery가 작동하지 않는 경우:

```bash
# eventlet 설치
uv add eventlet

# solo pool 모드로 실행
uv run celery -A config worker --loglevel=info --pool=solo
```

### 포트 충돌

8000번 포트가 이미 사용 중인 경우:

```bash
# 다른 포트로 실행
uv run python manage.py runserver 8080
```

### 정적 파일 문제

정적 파일이 로드되지 않는 경우:

```bash
# 정적 파일 수집
uv run python manage.py collectstatic --noinput
```

## 9. 개발 팁

### 로그 확인

로그 파일 위치: `logs/scanner.log`

```bash
# 실시간 로그 보기
tail -f logs/scanner.log

# Windows
Get-Content logs/scanner.log -Wait
```

### API 문서

Swagger UI에서 모든 API 엔드포인트를 테스트할 수 있습니다:
http://localhost:8000/api/docs/

### 데이터베이스 초기화

데이터베이스를 초기화하려면:

```bash
# 데이터베이스 파일 삭제
rm db.sqlite3

# 마이그레이션 재실행
uv run python manage.py migrate

# Superuser 재생성
uv run python manage.py createsuperuser
```

## 10. 주의사항

⚠️ **법적 고지**

- 이 도구는 **교육 및 연구 목적**으로만 사용되어야 합니다
- **권한이 있는 웹사이트**만 스캔하세요
- 무단으로 타인의 웹사이트를 스캔하는 것은 불법입니다
- 사용자는 모든 법적 책임을 집니다

## 11. 다음 단계

### 완료된 기능 ✅
- [x] **OWASP Top 10 2025 RC1 완전 대응 (42개 보안 스캐너, ~92% 커버리지)**
  - 기본 보안 스캐너 15개 (OWASP Top 10 2021/2025 기반)
  - 고급 보안 스캐너 10개 (SSRF, XXE, Command Injection 등)
  - API 및 인증/인가 스캐너 8개 (REST API, GraphQL, OAuth 등)
  - OWASP 2025 신규 스캐너 2개 (Supply Chain, Exception Handling)
  - 비즈니스 로직 스캐너 7개 (가격 조작, 레이스 컨디션, 워크플로우 우회 등)

### 개발 예정 📋
- [ ] Playwright/Selenium을 사용한 브라우저 자동화
- [ ] W3C Validator API 통합
- [ ] 크롤링 기능 (하위 페이지 자동 스캔)
- [ ] 결과 PDF 리포트 생성
- [ ] 사용자 인증 및 스캔 히스토리
- [ ] 스케줄링 (주기적 스캔)

## 도움이 필요하신가요?

- **이슈**: [GitHub Issues](https://github.com/opJay/weak/issues)
- **문서**: [README.md](README.md)
- **라이선스**: MIT License

---

Happy Scanning! 🔍
