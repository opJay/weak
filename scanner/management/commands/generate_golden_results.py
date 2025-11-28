"""
황금 테스트(Golden Test) 생성기

현재 스캐너들의 동작을 스냅샷으로 저장하여,
리팩토링 후에도 동일한 결과가 나오는지 검증하는 용도
"""

import json
import logging
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path

from django.core.management.base import BaseCommand
from django.db import transaction

from scanner.models import ScanRequest, SecurityScanResult
from scanner.tasks import scan_security

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = '현재 스캐너들의 동작을 황금 테스트(Golden Test)로 저장합니다.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--urls',
            nargs='+',
            default=[
                'http://testphp.vulnweb.com/',  # 취약한 테스트 사이트
                'https://www.google.com/',      # 안전한 사이트
            ],
            help='테스트할 URL 목록'
        )
        parser.add_argument(
            '--output',
            type=str,
            default='tests/golden_results.json',
            help='황금 테스트 결과를 저장할 파일 경로'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='기존 황금 테스트 파일을 덮어씁니다'
        )

    def handle(self, *args, **options):
        urls = options['urls']
        output_path = Path(options['output'])
        force = options['force']

        # 기존 파일 확인
        if output_path.exists() and not force:
            self.stdout.write(
                self.style.ERROR(
                    f'황금 테스트 파일이 이미 존재합니다: {output_path}\n'
                    '--force 옵션을 사용하여 덮어쓸 수 있습니다.'
                )
            )
            return

        # 출력 디렉토리 생성
        output_path.parent.mkdir(parents=True, exist_ok=True)

        self.stdout.write(
            self.style.SUCCESS(
                f'황금 테스트 생성 시작\n'
                f'테스트 URL: {urls}'
            )
        )

        golden_results = {
            'metadata': {
                'created_at': datetime.now().isoformat(),
                'urls': urls,
                'scanner_count': self._get_scanner_count(),
            },
            'results': {}
        }

        for url in urls:
            self.stdout.write(f'\n스캔 중: {url}')

            try:
                # 스캔 요청 생성
                with transaction.atomic():
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    scan_request = ScanRequest.objects.create(
                        url=url,
                        target_domain=parsed.netloc or 'unknown',
                        scan_types=['security'],
                        ip_address='127.0.0.1',  # 로컬 테스트용
                        user_agent='GoldenTestGenerator/1.0'
                    )
                    scan_request_id = scan_request.id

                # 보안 스캔 실행
                self.stdout.write('  - 보안 스캔 실행 중...')
                scan_security(scan_request_id)

                # 결과 조회
                scan_request.refresh_from_db()
                security_result = SecurityScanResult.objects.get(
                    scan_request=scan_request
                )

                # 결과 수집
                golden_results['results'][url] = self._extract_scan_results(
                    security_result
                )

                self.stdout.write(
                    self.style.SUCCESS(
                        f'  ✓ 스캔 완료 - {self._count_vulnerabilities(security_result)}개 취약점 발견'
                    )
                )

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'  ✗ 스캔 실패: {str(e)}')
                )
                golden_results['results'][url] = {
                    'error': str(e),
                    'status': 'failed'
                }

        # 결과 저장
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(golden_results, f, indent=2, ensure_ascii=False)

        self.stdout.write(
            self.style.SUCCESS(
                f'\n황금 테스트 생성 완료!\n'
                f'저장 위치: {output_path.absolute()}\n'
                f'총 {len(golden_results["results"])}개 URL 테스트 완료'
            )
        )

    def _get_scanner_count(self) -> int:
        """현재 등록된 스캐너 개수 반환"""
        from scanner.progress_manager import ProgressManager
        # SCANNERS는 딕셔너리이고, security 키에 스캐너 목록이 있음
        total = 0
        for scanner_type, scanners in ProgressManager.SCANNERS.items():
            total += len(scanners)
        return total

    def _extract_scan_results(self, security_result: SecurityScanResult) -> Dict[str, Any]:
        """SecurityScanResult에서 황금 테스트에 필요한 정보 추출"""

        # 모든 스캐너 필드를 수집
        scanner_fields = [
            'xss_vulnerabilities',
            'sql_injection',
            'headers',
            'cors',
            'cookies',
            'csrf',
            'clickjacking',
            'disclosure',
            'http_methods',
            'sensitive_files',
            'mixed_content',
            'sri',
            'directory_listing',
            'open_redirect',
            'ssrf',
            'xxe',
            'command_injection',
            'deserialization',
            'file_upload',
            'path_traversal',
            'jwt_security',
            'template_injection',
            'nosql_injection',
            'ssl_tls_deep',
            'rest_api_security',
            'graphql_security',
            'oauth_security',
            'session_security',
            'password_policy',
            'rate_limiting',
            'ldap_injection',
            'authorization',
            'supply_chain',
            'exception_handling',
            'price_manipulation',
            'race_condition',
            'workflow_bypass',
            'account_enumeration',
            'resource_exhaustion',
            'logging_monitoring',
            'business_logic_anomaly',
            'package_integrity',
            'typosquatting',
            'outdated_dependency',
            'license_compliance',
            'jwt_advanced',
            'serialization_integrity',
            'api_integrity',
            'checksum_validation',
        ]

        results = {}

        for field in scanner_fields:
            try:
                value = getattr(security_result, field, None)
                if value is not None:
                    # 취약점 개수와 심각도만 저장 (상세 내용은 제외)
                    if isinstance(value, dict):
                        results[field] = {
                            'total': value.get('total', 0),
                            'has_vulnerabilities': self._has_vulnerabilities(value),
                            'severity': self._extract_severity(value)
                        }
                    else:
                        results[field] = value
            except Exception as e:
                logger.warning(f'필드 추출 실패 {field}: {str(e)}')
                results[field] = {'error': str(e)}

        # 메타데이터 추가
        results['metadata'] = {
            'scan_completed': security_result.scan_completed,
            'error_message': security_result.error_message,
        }

        return results

    def _has_vulnerabilities(self, result: Dict) -> bool:
        """결과에 취약점이 있는지 확인"""
        if 'vulnerabilities' in result:
            return len(result['vulnerabilities']) > 0
        elif 'issues' in result:
            return len(result['issues']) > 0
        elif 'total' in result:
            return result['total'] > 0
        return False

    def _extract_severity(self, result: Dict) -> str:
        """결과에서 심각도 추출"""
        if 'severity' in result:
            return result['severity']

        # vulnerabilities에서 최고 심각도 계산
        if 'vulnerabilities' in result:
            vulnerabilities = result['vulnerabilities']
            if not vulnerabilities:
                return 'safe'

            severities = [v.get('severity', 'low') for v in vulnerabilities]
            if 'critical' in severities:
                return 'critical'
            elif 'high' in severities:
                return 'high'
            elif 'medium' in severities:
                return 'medium'
            return 'low'

        return 'unknown'

    def _count_vulnerabilities(self, security_result: SecurityScanResult) -> int:
        """전체 취약점 개수 계산"""
        total = 0

        # 각 필드에서 취약점 개수 합산
        for field_name in dir(security_result):
            if field_name.startswith('_'):
                continue

            field_value = getattr(security_result, field_name, None)
            if isinstance(field_value, dict):
                if 'vulnerabilities' in field_value:
                    total += len(field_value.get('vulnerabilities', []))
                elif 'issues' in field_value:
                    total += len(field_value.get('issues', []))
                elif 'total' in field_value:
                    total += field_value.get('total', 0)

        return total