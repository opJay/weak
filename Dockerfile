# ============================================
# Weak Scanner - Docker Image
# ============================================
# 멀티스테이지 빌드를 사용한 프로덕션 최적화 이미지

# ============================================
# Stage 1: Builder
# ============================================
FROM python:3.12-slim AS builder

# 환경 변수 설정
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_SYSTEM_PYTHON=1

# 작업 디렉토리 설정
WORKDIR /app

# uv 설치
RUN pip install --no-cache-dir uv

# 의존성 파일 복사
COPY pyproject.toml uv.lock* ./

# 의존성 설치
# uv.lock이 있으면 lock 파일에서, 없으면 pyproject.toml에서 직접 설치
# --system 플래그로 가상환경이 아닌 시스템에 직접 설치
RUN if [ -f uv.lock ]; then \
        uv pip install --system -r pyproject.toml; \
    else \
        uv pip install --system \
            django \
            djangorestframework \
            django-cors-headers \
            celery \
            redis \
            requests \
            beautifulsoup4 \
            lxml \
            python-decouple \
            dj-database-url \
            drf-spectacular \
            gunicorn \
            psycopg2-binary; \
    fi

# 애플리케이션 파일 복사 (의존성 설치 후)
COPY . .

# ============================================
# Stage 2: Runtime
# ============================================
FROM python:3.12-slim

# 환경 변수 설정
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DJANGO_SETTINGS_MODULE=config.settings

# 시스템 패키지 설치
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# non-root 사용자 생성
RUN groupadd -r weak && \
    useradd -r -g weak -d /app -s /sbin/nologin weak

# 작업 디렉토리 설정
WORKDIR /app

# Builder 스테이지에서 Python 패키지 복사
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# 애플리케이션 파일 복사
COPY --chown=weak:weak . .

# 로그 디렉토리 생성
RUN mkdir -p /app/logs && \
    chown -R weak:weak /app/logs

# static 디렉토리 생성
RUN mkdir -p /app/staticfiles && \
    chown -R weak:weak /app/staticfiles

# entrypoint 스크립트 실행 권한 부여
RUN chmod +x /app/entrypoint.sh

# 포트 노출
EXPOSE 8000

# non-root 사용자로 전환
USER weak

# entrypoint 설정
ENTRYPOINT ["/app/entrypoint.sh"]

# 기본 명령어 (Gunicorn)
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "300"]
