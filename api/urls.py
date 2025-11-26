"""
API URL Configuration
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ScanViewSet, HealthCheckView

# Router 설정
router = DefaultRouter()
router.register(r'scan', ScanViewSet, basename='scan')
router.register(r'health', HealthCheckView, basename='health')

app_name = 'api'

urlpatterns = [
    path('', include(router.urls)),
]
