# Weak Scanner - 배포 가이드

이 문서는 Weak Scanner를 프로덕션 환경에 배포하는 방법을 설명합니다.

## 목차

- [Docker를 사용한 배포](#docker를-사용한-배포)
- [프로덕션 배포](#프로덕션-배포)
- [클라우드 플랫폼 배포](#클라우드-플랫폼-배포)
- [백업 및 복구](#백업-및-복구)
- [모니터링](#모니터링)
- [트러블슈팅](#트러블슈팅)

## Docker를 사용한 배포

### 사전 요구사항

- Docker Engine 20.10+
- Docker Compose 2.0+
- 최소 2GB RAM, 10GB 디스크 공간

### 1. 환경 변수 설정

`.env` 파일을 생성하고 프로덕션 설정을 입력합니다:

```bash
cp env.example .env
```

`.env` 파일 수정:

```bash
# Django Settings
DEBUG=False
SECRET_KEY=<강력한-비밀-키-생성>
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# Database (PostgreSQL)
DB_PASSWORD=<강력한-데이터베이스-비밀번호>

# Redis
REDIS_URL=redis://redis:6379/0

# Celery
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=django-db

# Security
CSRF_TRUSTED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# Scan Settings
SCAN_TIMEOUT=300
MAX_CRAWL_DEPTH=3
MAX_PAGES_TO_SCAN=50
USER_AGENT=Weak-Scanner/1.0 (Educational Purpose)

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/weak_scanner.log

# Rate Limiting
RATE_LIMIT_ENABLED=True
RATE_LIMIT_PER_IP=100
RATE_LIMIT_PER_DOMAIN=10

# Performance
WORKER_THREADS=4
CACHE_TIMEOUT=3600

# Concurrent Scan Limit
MAX_CONCURRENT_SCANS=5
```

### 2. Docker Compose로 실행

#### 프로덕션 환경

```bash
# Docker 이미지 빌드
docker-compose build

# 서비스 시작 (백그라운드)
docker-compose up -d

# 로그 확인
docker-compose logs -f

# 서비스 중지
docker-compose down

# 볼륨까지 삭제 (주의: 데이터 손실)
docker-compose down -v
```

#### 개발 환경

```bash
# 개발 환경 실행
docker-compose -f docker-compose.dev.yml up

# 백그라운드 실행
docker-compose -f docker-compose.dev.yml up -d
```

### 3. 초기 설정

```bash
# 슈퍼유저 생성
docker-compose exec web python manage.py createsuperuser

# 정적 파일 수집 (자동 실행되지만 수동 실행도 가능)
docker-compose exec web python manage.py collectstatic --noinput
```

### 4. 헬스 체크

```bash
# 서비스 상태 확인
docker-compose ps

# 웹 서버 헬스 체크
curl http://localhost:8000/api/health/

# Redis 연결 확인
docker-compose exec redis redis-cli ping

# PostgreSQL 연결 확인
docker-compose exec db pg_isready -U weak_user
```

## 프로덕션 배포

### 1. Nginx 리버스 프록시 설정

#### Nginx 설치

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nginx

# CentOS/RHEL
sudo yum install nginx
```

#### Nginx 설정 파일

`/etc/nginx/sites-available/weak` 파일 생성:

```nginx
upstream weak_backend {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    # HTTP to HTTPS 리다이렉트
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # SSL 인증서 (Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # SSL 설정 강화
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # 보안 헤더
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # 클라이언트 최대 업로드 크기
    client_max_body_size 10M;

    # 정적 파일
    location /static/ {
        alias /var/www/weak/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # 미디어 파일
    location /media/ {
        alias /var/www/weak/media/;
        expires 30d;
    }

    # Django 애플리케이션
    location / {
        proxy_pass http://weak_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;

        # 타임아웃 설정 (스캔 작업 고려)
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }

    # 로그
    access_log /var/log/nginx/weak_access.log;
    error_log /var/log/nginx/weak_error.log;
}
```

#### Nginx 활성화

```bash
# 심볼릭 링크 생성
sudo ln -s /etc/nginx/sites-available/weak /etc/nginx/sites-enabled/

# 설정 테스트
sudo nginx -t

# Nginx 재시작
sudo systemctl restart nginx
```

### 2. SSL/TLS 인증서 설정 (Let's Encrypt)

#### Certbot 설치

```bash
# Ubuntu/Debian
sudo apt install certbot python3-certbot-nginx

# CentOS/RHEL
sudo yum install certbot python3-certbot-nginx
```

#### 인증서 발급

```bash
# Nginx용 인증서 자동 발급 및 설정
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# 인증서 자동 갱신 설정 (cron)
sudo certbot renew --dry-run
```

#### 자동 갱신 (systemd timer)

```bash
# 타이머 활성화
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer

# 타이머 상태 확인
sudo systemctl status certbot.timer
```

### 3. 방화벽 설정

```bash
# Ubuntu/Debian (ufw)
sudo ufw allow 'Nginx Full'
sudo ufw allow 22/tcp
sudo ufw enable

# CentOS/RHEL (firewalld)
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload
```

### 4. 도메인 연결

DNS 설정에서 A 레코드 추가:

```
Type: A
Name: @
Value: <서버-IP-주소>
TTL: 3600

Type: A
Name: www
Value: <서버-IP-주소>
TTL: 3600
```

## 클라우드 플랫폼 배포

### 1. AWS ECS (Elastic Container Service)

#### ECR에 이미지 푸시

```bash
# AWS CLI 로그인
aws ecr get-login-password --region ap-northeast-2 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.ap-northeast-2.amazonaws.com

# 이미지 빌드 및 태그
docker build -t weak-scanner .
docker tag weak-scanner:latest <account-id>.dkr.ecr.ap-northeast-2.amazonaws.com/weak-scanner:latest

# 이미지 푸시
docker push <account-id>.dkr.ecr.ap-northeast-2.amazonaws.com/weak-scanner:latest
```

#### ECS 작업 정의 (Task Definition)

`ecs-task-definition.json`:

```json
{
  "family": "weak-scanner",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "containerDefinitions": [
    {
      "name": "weak-web",
      "image": "<account-id>.dkr.ecr.ap-northeast-2.amazonaws.com/weak-scanner:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "DEBUG",
          "value": "False"
        }
      ],
      "secrets": [
        {
          "name": "SECRET_KEY",
          "valueFrom": "arn:aws:secretsmanager:ap-northeast-2:<account-id>:secret:weak/secret-key"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/weak-scanner",
          "awslogs-region": "ap-northeast-2",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### 2. Google Cloud Run

```bash
# gcloud CLI 설정
gcloud config set project <project-id>

# Container Registry에 이미지 푸시
docker build -t gcr.io/<project-id>/weak-scanner .
docker push gcr.io/<project-id>/weak-scanner

# Cloud Run 배포
gcloud run deploy weak-scanner \
  --image gcr.io/<project-id>/weak-scanner \
  --platform managed \
  --region asia-northeast1 \
  --allow-unauthenticated \
  --set-env-vars DEBUG=False \
  --set-secrets SECRET_KEY=weak-secret-key:latest \
  --memory 2Gi \
  --cpu 2 \
  --timeout 300
```

### 3. Azure Container Instances

```bash
# Azure CLI 로그인
az login

# 리소스 그룹 생성
az group create --name weak-scanner-rg --location koreacentral

# Container Registry 생성
az acr create --resource-group weak-scanner-rg --name weakscanner --sku Basic

# 이미지 빌드 및 푸시
az acr build --registry weakscanner --image weak-scanner:latest .

# Container Instance 배포
az container create \
  --resource-group weak-scanner-rg \
  --name weak-scanner \
  --image weakscanner.azurecr.io/weak-scanner:latest \
  --dns-name-label weak-scanner \
  --ports 8000 \
  --environment-variables DEBUG=False \
  --secure-environment-variables SECRET_KEY=<secret-key> \
  --cpu 2 \
  --memory 2
```

## 백업 및 복구

### 데이터베이스 백업

#### PostgreSQL 백업

```bash
# 전체 백업
docker-compose exec db pg_dump -U weak_user weak_db > backup_$(date +%Y%m%d_%H%M%S).sql

# gzip 압축
docker-compose exec db pg_dump -U weak_user weak_db | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz

# 자동 백업 스크립트 (cron)
# /etc/cron.d/weak-backup
0 2 * * * root docker-compose -f /path/to/weak/docker-compose.yml exec -T db pg_dump -U weak_user weak_db | gzip > /backup/weak_$(date +\%Y\%m\%d).sql.gz
```

#### PostgreSQL 복구

```bash
# 복구
cat backup.sql | docker-compose exec -T db psql -U weak_user weak_db

# gzip 압축 파일 복구
gunzip -c backup.sql.gz | docker-compose exec -T db psql -U weak_user weak_db
```

### Redis 백업

```bash
# RDB 스냅샷 생성
docker-compose exec redis redis-cli BGSAVE

# RDB 파일 복사
docker cp weak_redis:/data/dump.rdb ./backup/redis_dump_$(date +%Y%m%d).rdb
```

## 모니터링

### 1. 로그 관리

#### Docker 로그 확인

```bash
# 실시간 로그
docker-compose logs -f

# 특정 서비스 로그
docker-compose logs -f web
docker-compose logs -f celery

# 로그 저장
docker-compose logs > logs/docker_$(date +%Y%m%d).log
```

#### 로그 로테이션

`/etc/logrotate.d/weak`:

```
/var/www/weak/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 weak weak
    sharedscripts
    postrotate
        docker-compose -f /var/www/weak/docker-compose.yml exec web python manage.py flush_logs
    endscript
}
```

### 2. 모니터링 도구

#### Prometheus + Grafana

`docker-compose.monitoring.yml`:

```yaml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    ports:
      - "9090:9090"
    networks:
      - weak_network

  grafana:
    image: grafana/grafana:latest
    volumes:
      - grafana_data:/var/lib/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    networks:
      - weak_network

volumes:
  prometheus_data:
  grafana_data:
```

#### 헬스 체크 엔드포인트

Django 앱에 헬스 체크 엔드포인트 추가 (`api/views.py`):

```python
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.db import connection

@api_view(['GET'])
def health_check(request):
    """헬스 체크 엔드포인트"""
    try:
        # 데이터베이스 연결 확인
        connection.ensure_connection()

        return Response({
            'status': 'healthy',
            'database': 'connected'
        })
    except Exception as e:
        return Response({
            'status': 'unhealthy',
            'error': str(e)
        }, status=503)
```

## 트러블슈팅

### 1. 컨테이너가 시작되지 않음

```bash
# 로그 확인
docker-compose logs

# 특정 서비스 재시작
docker-compose restart web

# 이미지 재빌드
docker-compose build --no-cache
docker-compose up -d
```

### 2. 데이터베이스 연결 오류

```bash
# PostgreSQL 로그 확인
docker-compose logs db

# 연결 테스트
docker-compose exec web python manage.py dbshell

# 마이그레이션 재실행
docker-compose exec web python manage.py migrate
```

### 3. 메모리 부족

```bash
# 리소스 사용량 확인
docker stats

# 컨테이너 리소스 제한 (docker-compose.yml)
services:
  web:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G
```

### 4. 디스크 공간 부족

```bash
# 사용하지 않는 이미지 삭제
docker image prune -a

# 사용하지 않는 볼륨 삭제
docker volume prune

# 전체 정리 (주의)
docker system prune -a --volumes
```

## 추가 리소스

- [Docker 공식 문서](https://docs.docker.com/)
- [Django 배포 가이드](https://docs.djangoproject.com/en/5.0/howto/deployment/)
- [Nginx 설정 가이드](https://nginx.org/en/docs/)
- [Let's Encrypt 문서](https://letsencrypt.org/docs/)

## 지원

문제가 발생하면 GitHub Issues에 보고해주세요: [GitHub Issues](https://github.com/opJay/weak/issues)
