#!/bin/bash
# ============================================
# Weak Scanner - Docker Entrypoint Script
# ============================================
# 컨테이너 시작 시 실행되는 초기화 스크립트

set -e

echo "========================================"
echo "Weak Scanner - Starting..."
echo "========================================"

# 로그 디렉토리 권한 설정 (볼륨 마운트 대응)
echo "[0/4] Setting up log directory..."
mkdir -p /app/logs
# chown은 root 권한이 필요하므로 실패해도 계속 진행
chown -R weak:weak /app/logs 2>/dev/null || true
chmod -R 777 /app/logs 2>/dev/null || true

# 데이터베이스 연결 대기
echo "[1/4] Waiting for database..."
if [ -n "$DATABASE_URL" ]; then
    # PostgreSQL 사용 시
    until python -c "import psycopg2; psycopg2.connect('$DATABASE_URL')" 2>/dev/null; do
        echo "PostgreSQL is unavailable - sleeping"
        sleep 2
    done
    echo "PostgreSQL is up!"
else
    # SQLite 사용 시
    echo "Using SQLite database"
fi

# Redis 연결 대기
echo "[2/4] Waiting for Redis..."
if [ -n "$REDIS_URL" ]; then
    until python -c "import redis; redis.Redis.from_url('$REDIS_URL').ping()" 2>/dev/null; do
        echo "Redis is unavailable - sleeping"
        sleep 2
    done
    echo "Redis is up!"
fi

# 데이터베이스 마이그레이션 실행
if [ "$SKIP_MIGRATIONS" != "true" ]; then
    echo "[3/4] Running database migrations..."
    python manage.py migrate --noinput
else
    echo "[3/4] Skipping migrations (handled by web container)"
fi

# 정적 파일 수집 (WhiteNoise를 위해 항상 실행)
echo "[4/4] Collecting static files..."
python manage.py collectstatic --noinput --clear

echo "========================================"
echo "Weak Scanner - Initialization Complete"
echo "========================================"

# 전달된 명령어 실행
exec "$@"
