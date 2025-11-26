"""
Security Middleware
악의적인 요청 차단 및 Rate Limiting
"""
import logging
from django.http import HttpResponseForbidden, JsonResponse
from django.core.cache import cache
from django.conf import settings
import time

logger = logging.getLogger('scanner')


class SecurityMiddleware:
    """보안 미들웨어"""

    def __init__(self, get_response):
        self.get_response = get_response

        # 차단할 User-Agent 패턴
        self.blocked_user_agents = [
            'masscan',
            'nmap',
            'sqlmap',
            'nikto',
            'nessus',
            'acunetix',
            'burpsuite',
            'metasploit',
            'zgrab',
            'shodan',
            'censys',
        ]

        # 의심스러운 요청 패턴
        self.suspicious_patterns = [
            '../',
            '..\\',
            '<script',
            'javascript:',
            'eval(',
            'union select',
            'drop table',
            'exec(',
            'cmd=',
            '; cat ',
        ]

    def __call__(self, request):
        # 1. User-Agent 검사
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()

        if any(blocked in user_agent for blocked in self.blocked_user_agents):
            logger.warning(f'Blocked request from suspicious User-Agent: {user_agent[:100]}')
            return HttpResponseForbidden('Access Denied')

        # 2. Rate Limiting (IP 기반)
        if not self._check_rate_limit(request):
            logger.warning(f'Rate limit exceeded for IP: {self._get_client_ip(request)}')
            return JsonResponse({
                'error': 'Rate limit exceeded',
                'message': '너무 많은 요청이 감지되었습니다. 잠시 후 다시 시도하세요.'
            }, status=429)

        # 3. 의심스러운 요청 패턴 검사
        full_path = request.get_full_path()
        if any(pattern in full_path.lower() for pattern in self.suspicious_patterns):
            logger.warning(f'Suspicious request pattern detected: {full_path[:200]}')
            return HttpResponseForbidden('Invalid Request')

        # 4. 요청 본문 검사 (POST/PUT)
        if request.method in ['POST', 'PUT', 'PATCH']:
            try:
                body = request.body.decode('utf-8', errors='ignore')
                if any(pattern in body.lower() for pattern in self.suspicious_patterns):
                    logger.warning(f'Suspicious request body detected from {self._get_client_ip(request)}')
                    return HttpResponseForbidden('Invalid Request')
            except Exception:
                pass

        response = self.get_response(request)

        return response

    def _get_client_ip(self, request):
        """클라이언트 IP 추출"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def _check_rate_limit(self, request):
        """Rate Limiting 검사"""
        ip = self._get_client_ip(request)

        # 로컬호스트는 제한 없음
        if ip in ['127.0.0.1', 'localhost', '::1']:
            return True

        # 캐시 키 생성
        cache_key = f'rate_limit:{ip}'

        # 현재 요청 수 가져오기
        request_count = cache.get(cache_key, 0)

        # 제한 확인 (1분에 최대 30 요청)
        if request_count >= 30:
            return False

        # 요청 수 증가
        cache.set(cache_key, request_count + 1, 60)

        return True


class IPBlockingMiddleware:
    """IP 차단 미들웨어"""

    def __init__(self, get_response):
        self.get_response = get_response

        # 자동으로 차단할 IP 범위 (알려진 스캐너)
        self.blocked_ip_ranges = [
            # 예: '1.2.3.0/24',
        ]

    def __call__(self, request):
        ip = self._get_client_ip(request)

        # 차단된 IP 확인
        if self._is_blocked_ip(ip):
            logger.warning(f'Blocked request from banned IP: {ip}')
            return HttpResponseForbidden('Your IP has been blocked')

        # 동적 차단 확인 (반복적인 악의적 요청)
        if self._is_temporarily_blocked(ip):
            logger.warning(f'Temporarily blocked IP: {ip}')
            return HttpResponseForbidden('Too many suspicious requests. Please try again later.')

        response = self.get_response(request)

        return response

    def _get_client_ip(self, request):
        """클라이언트 IP 추출"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def _is_blocked_ip(self, ip):
        """IP가 차단 목록에 있는지 확인"""
        # 캐시에서 차단 목록 확인
        blocked_ips = cache.get('blocked_ips', set())
        return ip in blocked_ips

    def _is_temporarily_blocked(self, ip):
        """임시 차단 확인"""
        cache_key = f'temp_block:{ip}'
        return cache.get(cache_key, False)

    @staticmethod
    def block_ip(ip, duration=3600):
        """IP를 일시적으로 차단"""
        cache_key = f'temp_block:{ip}'
        cache.set(cache_key, True, duration)
        logger.info(f'IP {ip} temporarily blocked for {duration} seconds')


class RequestLoggingMiddleware:
    """요청 로깅 미들웨어"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # 요청 시작 시간
        start_time = time.time()

        # 요청 정보 로깅
        ip = self._get_client_ip(request)
        method = request.method
        path = request.get_full_path()
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:200]

        # 응답 처리
        response = self.get_response(request)

        # 처리 시간 계산
        duration = time.time() - start_time

        # 로깅 (의심스러운 요청만)
        if response.status_code >= 400 or duration > 5:
            logger.info(
                f'Request: {method} {path} | '
                f'IP: {ip} | '
                f'Status: {response.status_code} | '
                f'Duration: {duration:.2f}s | '
                f'UA: {user_agent}'
            )

        return response

    def _get_client_ip(self, request):
        """클라이언트 IP 추출"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
