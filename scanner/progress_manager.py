"""
Progress Manager
스캔 진행률을 중앙에서 관리하는 시스템
"""

class ProgressManager:
    """스캔 진행률 관리 클래스"""

    # 각 스캔 타입별 스캐너 정의 (이름, 가중치)
    SCANNERS = {
        'security': [
            # 기본 보안 스캐너 (15개)
            ('보안 헤더 검사', 1),
            ('SSL/TLS 검사', 1),
            ('XSS 취약점 스캔', 2),  # 더 중요한 검사는 가중치 높게
            ('SQL Injection 스캔', 2),
            ('CORS 설정 검사', 1),
            ('쿠키 보안 검사', 1),
            ('CSRF 보호 검사', 1.5),
            ('클릭재킹 방어 검사', 1),
            ('정보 노출 검사', 1),
            ('HTTP 메서드 검사', 0.5),
            ('민감한 파일 노출 검사', 1.5),
            ('Mixed Content 검사', 0.5),
            ('SRI 검사', 0.5),
            ('디렉토리 리스팅 검사', 0.5),
            ('Open Redirect 검사', 1),
            # 고급 보안 스캐너 (10개 - scanners_advanced.py)
            ('SSRF 취약점 검사', 2),
            ('XXE 취약점 검사', 2),
            ('Command Injection 검사', 2),
            ('Deserialization 취약점 검사', 2),
            ('파일 업로드 취약점 검사', 2),
            ('경로 순회 공격 검사', 2),
            ('JWT 보안 검사', 2),
            ('템플릿 주입 검사', 2),
            ('NoSQL Injection 검사', 2),
            ('SSL/TLS 심층 검사', 2),
            # API 및 인증/인가 스캐너 (8개 - scanners_api.py)
            ('REST API 보안 검사', 2),
            ('GraphQL 보안 검사', 2),
            ('OAuth 보안 검사', 2),
            ('Session 보안 검사', 2),
            ('Password Policy 검사', 1.5),
            ('Rate Limiting 검사', 1.5),
            ('LDAP Injection 검사', 1.5),
            ('Authorization 검사', 2),
            # OWASP 2025 신규 대응 스캐너 (2개)
            ('Software Supply Chain 검사', 2),
            ('Exception Handling 검사', 1.5),
            # 비즈니스 로직 및 설계 취약점 스캐너 (7개)
            ('가격 조작 탐지', 1.5),
            ('레이스 컨디션 탐지', 1.5),
            ('워크플로우 우회 탐지', 1),
            ('계정 열거 탐지', 1),
            ('리소스 소진 탐지', 1),
            ('로깅/모니터링 검사', 1.5),
            ('비즈니스 로직 이상 탐지', 1),
            # 공급망 보안 강화 (4개 - A03 90%)
            ('패키지 무결성 검증', 2),
            ('타이포스쿼팅 탐지', 1.5),
            ('오래된 종속성 검사', 2),
            ('라이선스 준수 검사', 1.5),
            # 데이터 무결성 강화 (4개 - A08 90%)
            ('JWT 고급 보안 검증', 3),
            ('직렬화 무결성 검증', 2),
            ('API 응답 무결성 검사', 2),
            ('체크섬 검증', 1.5),
        ],
        'standards': [
            ('SEO 검사', 2),
            ('HTML 구조 검증', 2),
            ('CSS 분석', 1.5),
            ('JavaScript 검사', 1.5),
        ],
        'accessibility': [
            ('기본 접근성 검사', 1),  # Only one scanner is actually implemented
        ]
    }

    def __init__(self, scan_types=None):
        """
        초기화

        Args:
            scan_types: 실행할 스캔 타입 리스트 ['security', 'standards', 'accessibility']
        """
        if scan_types is None:
            scan_types = ['security', 'standards', 'accessibility']

        # 유효한 스캔 타입만 필터링
        self.scan_types = [st for st in scan_types if st in self.SCANNERS]
        self.progress_map = self._calculate_progress_map()
        self.current_indices = {st: -1 for st in self.scan_types}

    def _calculate_progress_map(self):
        """각 스캐너별 진행률 맵 계산"""
        if not self.scan_types:
            return {}

        progress_map = {}

        # 전체 범위를 스캔 타입 수로 나눔
        total_range = 100
        range_per_type = total_range / len(self.scan_types)

        current_start = 0

        for scan_type in self.scan_types:
            scanners = self.SCANNERS[scan_type]

            # 이 스캔 타입의 범위
            type_start = current_start
            type_end = current_start + range_per_type

            # 가중치 합계 계산
            total_weight = sum(weight for _, weight in scanners)

            # 각 스캐너별 진행률 계산
            scanner_progress = type_start
            progress_map[scan_type] = []

            for i, (scanner_name, weight) in enumerate(scanners):
                # 이 스캐너가 차지하는 비율
                scanner_range = (weight / total_weight) * (type_end - type_start)

                progress_map[scan_type].append({
                    'name': scanner_name,
                    'index': i,
                    'start': round(scanner_progress, 1),
                    'end': round(scanner_progress + scanner_range, 1),
                })

                scanner_progress += scanner_range

            current_start = type_end

        return progress_map

    def next_progress(self, scan_type):
        """
        다음 스캐너의 진행률 반환 (순차 실행용)

        Args:
            scan_type: 'security', 'standards', 'accessibility'

        Returns:
            (진행률, 스캐너 이름) 튜플
        """
        if scan_type not in self.progress_map:
            return (0, None)

        self.current_indices[scan_type] += 1
        index = self.current_indices[scan_type]

        if index >= len(self.progress_map[scan_type]):
            return (100, None)

        scanner_info = self.progress_map[scan_type][index]
        return (scanner_info['end'], scanner_info['name'])

    def get_progress(self, scan_type, scanner_index):
        """
        특정 스캐너의 진행률 반환

        Args:
            scan_type: 'security', 'standards', 'accessibility'
            scanner_index: 스캐너 인덱스 (0부터 시작)

        Returns:
            진행률 (0-100)
        """
        if scan_type not in self.progress_map:
            return 0

        if scanner_index >= len(self.progress_map[scan_type]):
            return 100

        return self.progress_map[scan_type][scanner_index]['end']

    def get_scanner_count(self, scan_type):
        """특정 스캔 타입의 스캐너 개수 반환"""
        if scan_type in self.SCANNERS:
            return len(self.SCANNERS[scan_type])
        return 0

    def get_scanner_name(self, scan_type, scanner_index):
        """스캐너 이름 반환"""
        if scan_type in self.SCANNERS and scanner_index < len(self.SCANNERS[scan_type]):
            return self.SCANNERS[scan_type][scanner_index][0]
        return None

    def get_scan_end_progress(self, scan_type):
        """
        특정 스캔 타입의 종료 진행률을 반환

        Args:
            scan_type: 'security', 'standards', 'accessibility'

        Returns:
            해당 스캔 타입의 종료 진행률
        """
        if scan_type not in self.scan_types:
            return 100.0

        # 스캔 타입의 인덱스 찾기
        scan_index = self.scan_types.index(scan_type)

        # 각 스캔 타입이 차지하는 범위 계산
        range_per_type = 100 / len(self.scan_types)

        # 종료 진행률 계산
        end_progress = (scan_index + 1) * range_per_type

        return min(100.0, round(end_progress, 1))

    def print_progress_map(self):
        """진행률 맵 출력 (디버깅용)"""
        for scan_type, scanners in self.progress_map.items():
            print(f"\n[{scan_type.upper()}]")
            for scanner in scanners:
                print(f"  {scanner['name']}: {scanner['start']:.1f}% → {scanner['end']:.1f}%")


# 사용 예제
if __name__ == '__main__':
    # 모든 스캔 타입 실행
    pm = ProgressManager(['security', 'standards', 'accessibility'])
    pm.print_progress_map()

    print("\n특정 스캐너 진행률:")
    print(f"Security scanner 0: {pm.get_progress('security', 0)}%")
    print(f"Security scanner 5: {pm.get_progress('security', 5)}%")

    # 일부 스캔만 실행
    print("\n보안과 접근성만 실행할 때:")
    pm2 = ProgressManager(['security', 'accessibility'])
    pm2.print_progress_map()

    # 순차 실행 테스트
    print("\n순차 실행 시뮬레이션:")
    pm3 = ProgressManager(['security'])
    for i in range(5):
        progress, name = pm3.next_progress('security')
        print(f"  {name}: {progress:.1f}%")