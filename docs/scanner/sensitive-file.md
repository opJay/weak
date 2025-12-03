# 민감한 파일 노출 검사 (Sensitive File Scanner)

## 개요

웹 서버에서 민감한 파일이 외부에 노출되어 있는지 검사합니다. 노출된 민감 파일은 공격자에게 시스템 정보, 인증 정보, 데이터베이스 접근 정보 등을 제공할 수 있어 심각한 보안 위협이 됩니다.

## 검사 방식

- 각 파일 경로에 HTTP GET 요청
- 200 OK 응답 시 파일 노출로 판단
- False Positive 감소를 위한 커스텀 404 페이지 필터링
- 파일 내용 분석을 통한 증거 추출

## 검사 파일 목록 (총 66개)

### 환경 설정 (Critical)

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `.env` | 환경 변수 파일 (API 키, DB 비밀번호 등) | Critical |
| `.env.local` | 로컬 환경 변수 | Critical |
| `.env.production` | 프로덕션 환경 변수 | Critical |
| `.env.development` | 개발 환경 변수 | Critical |

### 버전 관리 (Critical)

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `.git/config` | Git 설정 (원격 저장소 URL, 인증 정보) | Critical |
| `.git/HEAD` | Git 현재 브랜치 정보 | High |
| `.gitignore` | Git 무시 파일 목록 (민감 파일 힌트) | Medium |
| `.svn/entries` | SVN 메타데이터 | High |
| `.svn/wc.db` | SVN 작업 복사본 DB | High |
| `.hg/hgrc` | Mercurial 설정 | High |

### 백업/덤프 (Critical)

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `backup.sql` | SQL 백업 덤프 | Critical |
| `database.sql` | 데이터베이스 덤프 | Critical |
| `db.sql` | DB 덤프 | Critical |
| `dump.sql` | SQL 덤프 | Critical |
| `backup.zip` | 사이트 백업 압축 파일 | High |
| `backup.tar.gz` | 사이트 백업 압축 파일 | High |
| `site.zip` | 사이트 압축 파일 | High |
| `www.zip` | 웹 디렉토리 압축 파일 | High |

### Java/Spring

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `application.properties` | Spring 설정 (DB 접속 정보 등) | High |
| `application.yml` | Spring YAML 설정 | High |
| `application-dev.yml` | 개발 환경 Spring 설정 | High |
| `WEB-INF/web.xml` | Java 웹 애플리케이션 설정 | High |
| `META-INF/context.xml` | Tomcat 컨텍스트 설정 | High |
| `pom.xml` | Maven 프로젝트 설정 | Medium |
| `build.gradle` | Gradle 빌드 설정 | Medium |

### Node.js

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `package.json` | npm 패키지 정보 | Medium |
| `package-lock.json` | npm 의존성 잠금 파일 | Medium |
| `yarn.lock` | Yarn 의존성 잠금 파일 | Medium |
| `.npmrc` | npm 설정 (레지스트리 토큰 등) | High |
| `.yarnrc` | Yarn 설정 | High |

### Python/Django/Flask

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `settings.py` | Django 설정 | High |
| `local_settings.py` | Django 로컬 설정 (비밀 키 등) | Critical |
| `requirements.txt` | Python 의존성 목록 | Medium |
| `Pipfile` | Pipenv 의존성 | Medium |
| `uwsgi.ini` | uWSGI 서버 설정 | High |
| `gunicorn.conf.py` | Gunicorn 서버 설정 | High |

### Ruby/Rails

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `Gemfile` | Ruby 의존성 목록 | Medium |
| `config/database.yml` | Rails DB 설정 | Critical |
| `config/secrets.yml` | Rails 비밀 키 설정 | Critical |

### PHP

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `config.php` | PHP 설정 파일 | High |
| `configuration.php` | Joomla 설정 | High |
| `wp-config.php` | WordPress 설정 (DB 정보) | Critical |
| `phpinfo.php` | PHP 정보 노출 | High |
| `.htaccess` | Apache 설정 | High |
| `composer.json` | Composer 의존성 | Medium |
| `composer.lock` | Composer 잠금 파일 | Medium |

### .NET

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `web.config` | ASP.NET 설정 | High |
| `appsettings.json` | .NET Core 설정 | High |
| `appsettings.Development.json` | 개발 환경 설정 | High |
| `connectionstrings.config` | DB 연결 문자열 | High |

### 클라우드/인프라

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `.aws/credentials` | AWS 인증 정보 | Critical |
| `.aws/config` | AWS 설정 | High |
| `firebase.json` | Firebase 설정 | High |
| `serviceAccountKey.json` | GCP 서비스 계정 키 | Critical |
| `terraform.tfstate` | Terraform 상태 (인프라 정보) | Critical |
| `terraform.tfvars` | Terraform 변수 | High |

### CI/CD

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `.gitlab-ci.yml` | GitLab CI 설정 | Medium |
| `Jenkinsfile` | Jenkins 파이프라인 | Medium |
| `.travis.yml` | Travis CI 설정 | Medium |
| `.github/workflows/main.yml` | GitHub Actions 설정 | Medium |

### Docker/컨테이너

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `Dockerfile` | Docker 이미지 빌드 설정 | Medium |
| `docker-compose.yml` | Docker Compose 설정 | High |
| `docker-compose.override.yml` | Docker Compose 오버라이드 | High |
| `.dockerenv` | Docker 환경 파일 | Medium |

### 서버 설정

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `nginx.conf` | Nginx 설정 | High |
| `httpd.conf` | Apache 설정 | High |
| `server.xml` | Tomcat 서버 설정 | High |
| `php.ini` | PHP 설정 | High |
| `my.cnf` | MySQL 설정 | High |
| `redis.conf` | Redis 설정 | High |

### 인증서/키 (Critical)

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `server.key` | SSL 개인 키 | Critical |
| `server.crt` | SSL 인증서 | High |
| `private.pem` | 개인 키 | Critical |
| `id_rsa` | SSH 개인 키 | Critical |

### 로그

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `error.log` | 에러 로그 | High |
| `access.log` | 접근 로그 | Medium |
| `debug.log` | 디버그 로그 | High |
| `app.log` | 애플리케이션 로그 | Medium |

### IDE/개발 도구

| 파일 | 설명 | 위험도 |
|------|------|--------|
| `.idea/workspace.xml` | IntelliJ 설정 | Medium |
| `.vscode/settings.json` | VS Code 설정 | Medium |
| `.vscode/launch.json` | VS Code 디버그 설정 | Medium |

## 위험도 분류

| 등급 | 설명 | 대응 |
|------|------|------|
| **Critical** | 즉각적인 시스템 침해 가능 | 즉시 접근 차단 및 키 로테이션 |
| **High** | 중요 정보 노출, 추가 공격에 활용 가능 | 빠른 시일 내 접근 차단 |
| **Medium** | 시스템 구조 정보 노출 | 접근 차단 권장 |
| **Info** | 정보 수집 목적으로 활용 가능 | 필요시 접근 제한 |

## 대응 방안

### 1. 웹 서버 설정

**Nginx**
```nginx
location ~ /\. {
    deny all;
}
location ~* \.(sql|bak|backup|log|env|ini|conf|yml|yaml|json|xml|key|pem)$ {
    deny all;
}
```

**Apache (.htaccess)**
```apache
<FilesMatch "\.(sql|bak|backup|log|env|ini|conf|yml|yaml|json|xml|key|pem)$">
    Require all denied
</FilesMatch>
<DirectoryMatch "^\.|\/\.">
    Require all denied
</DirectoryMatch>
```

### 2. 배포 시 제외

- `.gitignore`에 민감 파일 추가
- 배포 스크립트에서 민감 파일 제외
- CI/CD 파이프라인에서 민감 파일 검사

### 3. 파일 권한 설정

```bash
# 민감 파일 권한 제한
chmod 600 .env
chmod 600 config/database.yml
chmod 600 *.key *.pem
```

## OWASP 매핑

- **A01:2021 - Broken Access Control**: 민감 파일 접근 제어 실패
- **A05:2021 - Security Misconfiguration**: 서버 설정 오류로 인한 파일 노출

## 관련 CWE

- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- CWE-552: Files or Directories Accessible to External Parties
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
