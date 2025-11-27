"""
Celery 설정 파일
비동기 스캔 작업을 처리하기 위한 Celery 설정
"""
import os
from celery import Celery
from decouple import config

# Django settings 모듈 설정
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# Celery 앱 생성
app = Celery('weak')

# Django settings에서 설정 로드 (CELERY_ prefix가 있는 설정들)
app.config_from_object('django.conf:settings', namespace='CELERY')

# Django 앱에서 tasks.py 파일을 자동으로 검색
app.autodiscover_tasks()

# Celery Beat 스케줄 (선택사항 - 주기적 작업이 필요한 경우)
app.conf.beat_schedule = {
    # 예: 매일 자정에 오래된 스캔 결과 정리
    # 'cleanup-old-scans': {
    #     'task': 'scanner.tasks.cleanup_old_scans',
    #     'schedule': crontab(hour=0, minute=0),
    # },
}

# 기본 태스크 설정 (기본 'celery' 큐 사용)
# app.conf.task_routes = {
#     'scanner.tasks.*': {'queue': 'scanner'},
# }

@app.task(bind=True, ignore_result=True)
def debug_task(self):
    """디버깅용 테스트 태스크"""
    print(f'Request: {self.request!r}')
