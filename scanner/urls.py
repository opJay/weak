"""
Scanner 앱 URL 설정
"""
from django.urls import path
from . import views

app_name = 'scanner'

urlpatterns = [
    # 메인 페이지 - URL 입력 및 옵션 설정
    path('', views.index_view, name='home'),

    # 결과 페이지 - UUID 기반 스캔 결과 표시
    path('<uuid:scan_id>/', views.results_view, name='results'),
]