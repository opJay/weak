# 보안 가이드 (Security Guide)

## ⚠️ 중요: 개발 서버 보안

Django 개발 서버(`runserver`)는 **절대로** 프로덕션 환경이나 공개 인터넷에 노출되어서는 안 됩니다!

## 🚨 현재 발생 중인 문제

외부에서 해킹 시도가 감지되고 있습니다:
- SSL/TLS 핸드셰이크 시도
- 포트 스캔
- 악의적인 User-Agent
- SQL Injection 시도
- XSS 공격

## 🛡️ 즉시 적용된 보안 조치

### 1. 보안 미들웨어 추가 ✅

다음 3개의 보안 미들웨어가 자동으로 활성화되었습니다:

#### SecurityMiddleware
- 악의적인 User-Agent 차단 (masscan, nmap, sqlmap 등)
- 의심스러운 요청 패턴 차단 (SQL Injection, XSS 등)
- Rate Limiting (1분에 30 요청 제한)
- 요청 본문 검사

#### IPBlockingMiddleware
- IP 기반 차단
- 반복적인 악의적 요청 자동 차단
- 동적 IP 블랙리스트

#### RequestLoggingMiddleware
- 모든 의심스러운 요청 로깅
- 처리 시간 모니터링
- 400+ 에러 자동 기록

### 2. 서버 바인딩 제한 ✅

`main.py runserver` 명령은 이제 **127.0.0.1 (localhost)에만** 바인딩됩니다.
- ✅ 외부에서 직접 접근 불가
- ✅ 로컬 머신에서만 접근 가능

## 🔥 Windows 방화벽 설정 (즉시 실행 필요!)

### 방법 1: PowerShell로 포트 차단

관리자 권한으로 PowerShell 실행 후:

```powershell
# 8000번 포트 외부 접근 차단
New-NetFirewallRule -DisplayName "Block Django Dev Server" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Block -RemoteAddress Any

# 6379번 포트 (Redis) 외부 접근 차단
New-NetFirewallRule -DisplayName "Block Redis" -Direction Inbound -LocalPort 6379 -Protocol TCP -Action Block -RemoteAddress Any

# 확인
Get-NetFirewallRule -DisplayName "Block Django Dev Server"
```

### 방법 2: Windows Defender 방화벽 GUI

1. **시작** → **Windows Defender 방화벽** 검색
2. **고급 설정** 클릭
3. **인바운드 규칙** → **새 규칙**
4. **포트** 선택 → **다음**
5. **TCP**, **특정 로컬 포트: 8000** → **다음**
6. **연결 차단** → **다음**
7. 모든 프로필 체크 → **다음**
8. 이름: "Django Dev Server Block" → **마침**

### 방법 3: 서버를 완전히 중지

가장 안전한 방법:

```bash
# 실행 중인 모든 Django 프로세스 종료
taskkill /F /IM python.exe

# 또는 Ctrl+C로 개발 서버 종료
```

## 🔒 현재 활성화된 보안 기능

### 자동 차단 기능

다음 조건에서 자동으로 요청을 차단합니다:

#### 1. 악의적인 User-Agent
```
masscan, nmap, sqlmap, nikto, nessus, acunetix,
burpsuite, metasploit, zgrab, shodan, censys
```

#### 2. 의심스러운 요청 패턴
```
../, ..\, <script, javascript:, eval(,
union select, drop table, exec(, cmd=, ; cat
```

#### 3. Rate Limiting
- **제한**: 1분에 30 요청
- **예외**: localhost (127.0.0.1)는 무제한
- **초과 시**: HTTP 429 (Too Many Requests)

### 로깅

모든 의심스러운 요청은 `logs/scanner.log`에 기록됩니다:

```bash
# 실시간 로그 확인
python main.py logs -f

# 마지막 100줄 확인
python main.py logs -n 100
```

## 📊 공격 모니터링

### 1. 로그 확인

```bash
# 차단된 요청 확인
grep "Blocked request" logs/scanner.log

# Rate limit 초과 확인
grep "Rate limit exceeded" logs/scanner.log

# 의심스러운 패턴 확인
grep "Suspicious request" logs/scanner.log
```

### 2. IP 확인

공격자 IP를 확인하려면:

```bash
# Windows PowerShell
Get-Content logs/scanner.log | Select-String "Blocked request"

# 특정 IP 검색
Get-Content logs/scanner.log | Select-String "123.456.789.0"
```

## 🚀 안전하게 개발 서버 실행하기

### 올바른 방법 ✅

```bash
# 1. 방화벽 설정 확인

# 2. localhost에만 바인딩하여 실행
python main.py runserver

# 또는 명시적으로
uv run python manage.py runserver 127.0.0.1:8000
```

### 잘못된 방법 ❌

```bash
# 절대 하지 마세요!
python manage.py runserver 0.0.0.0:8000  # 모든 네트워크 인터페이스에 바인딩
python manage.py runserver 8000          # IP 미지정 시 0.0.0.0과 동일
```

## 🌐 프로덕션 배포 (나중에 필요시)

개발이 완료되고 실제 서비스를 배포하려면:

### 1. 프로덕션 WSGI 서버 사용

Django 개발 서버 대신 Gunicorn, uWSGI 등 사용:

```bash
# Gunicorn 설치
uv add gunicorn

# Gunicorn 실행
gunicorn config.wsgi:application --bind 0.0.0.0:8000
```

### 2. Nginx 리버스 프록시

Nginx를 앞단에 두고 SSL/TLS 처리:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 3. Docker 컨테이너

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY . .

RUN pip install uv
RUN uv sync

EXPOSE 8000
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000"]
```

## 🔍 공격 유형별 대응

### 1. SSL/TLS 핸드셰이크 공격

**증상**: `Bad request syntax (\x16\x03\x01...)`

**원인**: 봇이 HTTPS로 접근 시도 (개발 서버는 HTTP만 지원)

**대응**:
- ✅ 이미 처리됨: Django가 자동으로 거부
- 방화벽으로 외부 접근 차단

### 2. 포트 스캔

**증상**: 짧은 시간에 여러 포트로 연결 시도

**대응**:
```powershell
# Windows Firewall 로그 활성화
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True
```

### 3. SQL Injection / XSS

**증상**: 요청에 `union select`, `<script>` 등 포함

**대응**:
- ✅ SecurityMiddleware가 자동 차단
- 로그 확인: `python main.py logs -f`

## 🆘 긴급 대응

### 공격이 계속되는 경우

```bash
# 1. 즉시 서버 중지
Ctrl+C

# 2. 방화벽 확인
netsh advfirewall firewall show rule name=all | findstr 8000

# 3. 모든 Python 프로세스 종료
taskkill /F /IM python.exe

# 4. 네트워크 연결 확인
netstat -ano | findstr :8000

# 5. 특정 프로세스 종료
taskkill /PID <PID번호> /F
```

### IP 영구 차단

특정 IP를 완전히 차단하려면:

```powershell
# PowerShell (관리자)
New-NetFirewallRule -DisplayName "Block Attacker IP" -Direction Inbound -RemoteAddress 123.456.789.0 -Action Block
```

## 📝 보안 체크리스트

개발 시작 전 확인:

- [ ] `ALLOWED_HOSTS`가 `localhost,127.0.0.1`로 설정되어 있는가?
- [ ] 서버가 `127.0.0.1`에만 바인딩되는가?
- [ ] Windows 방화벽이 8000번 포트 외부 접근을 차단하는가?
- [ ] Redis가 외부 접근을 허용하지 않는가?
- [ ] `DEBUG=True`는 개발 환경에서만 사용하는가?
- [ ] `.env` 파일이 `.gitignore`에 포함되어 있는가?
- [ ] 로그 파일을 정기적으로 확인하는가?

## 🔗 추가 리소스

- [Django Security Best Practices](https://docs.djangoproject.com/en/5.0/topics/security/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Django Deployment Checklist](https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/)

## 📧 보안 문제 보고

보안 취약점을 발견하셨나요?

- **이메일**: security@yourproject.com
- **GitHub Security Advisory**: Private하게 보고 가능

---

**⚠️ 기억하세요**: 개발 서버는 개발용입니다. 절대로 프로덕션에서 사용하지 마세요!
