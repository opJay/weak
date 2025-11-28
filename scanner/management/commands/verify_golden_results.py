"""
황금 테스트(Golden Test) 검증기

리팩토링 후 스캐너들이 기존과 동일한 결과를 내는지 검증
"""

import json
import logging
from typing import Dict, Any, List, Tuple
from pathlib import Path
from datetime import datetime

from django.core.management.base import BaseCommand
from django.db import transaction

from scanner.models import ScanRequest, SecurityScanResult
from scanner.tasks import scan_security

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = '황금 테스트 결과와 현재 스캐너 결과를 비교하여 회귀를 검증합니다.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--input',
            type=str,
            default='tests/golden_results.json',
            help='황금 테스트 결과 파일 경로'
        )
        parser.add_argument(
            '--output',
            type=str,
            default='tests/verification_report.json',
            help='검증 결과 리포트 저장 경로'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='상세한 차이점 출력'
        )

    def handle(self, *args, **options):
        input_path = Path(options['input'])
        output_path = Path(options['output'])
        verbose = options['verbose']

        # 황금 테스트 파일 확인
        if not input_path.exists():
            self.stdout.write(
                self.style.ERROR(
                    f'황금 테스트 파일을 찾을 수 없습니다: {input_path}\n'
                    'python manage.py generate_golden_results 명령으로 먼저 생성하세요.'
                )
            )
            return

        # 황금 테스트 로드
        with open(input_path, 'r', encoding='utf-8') as f:
            golden_results = json.load(f)

        self.stdout.write(
            self.style.SUCCESS(
                f'황금 테스트 검증 시작\n'
                f'생성 시간: {golden_results["metadata"]["created_at"]}\n'
                f'스캐너 개수: {golden_results["metadata"]["scanner_count"]}'
            )
        )

        verification_report = {
            'metadata': {
                'verified_at': datetime.now().isoformat(),
                'golden_created_at': golden_results['metadata']['created_at'],
                'status': 'passed',  # 기본값, 실패 시 failed로 변경
            },
            'results': {},
            'summary': {
                'total_urls': 0,
                'passed': 0,
                'failed': 0,
                'differences': []
            }
        }

        # 각 URL에 대해 검증
        for url, golden_result in golden_results['results'].items():
            self.stdout.write(f'\n검증 중: {url}')

            try:
                # 현재 스캐너로 다시 스캔
                with transaction.atomic():
                    scan_request = ScanRequest.objects.create(
                        url=url,
                        scan_types=['security']
                    )
                    scan_request_id = scan_request.id

                self.stdout.write('  - 현재 스캐너로 스캔 중...')
                scan_security(scan_request_id)

                # 결과 조회
                scan_request.refresh_from_db()
                security_result = SecurityScanResult.objects.get(
                    scan_request=scan_request
                )

                # 결과 비교
                current_result = self._extract_scan_results(security_result)
                differences = self._compare_results(golden_result, current_result)

                verification_report['results'][url] = {
                    'status': 'passed' if len(differences) == 0 else 'failed',
                    'differences': differences
                }

                if len(differences) == 0:
                    self.stdout.write(
                        self.style.SUCCESS('  ✓ 검증 통과 - 결과 동일')
                    )
                    verification_report['summary']['passed'] += 1
                else:
                    self.stdout.write(
                        self.style.WARNING(
                            f'  ⚠ 차이점 발견 - {len(differences)}개 항목 불일치'
                        )
                    )
                    verification_report['summary']['failed'] += 1
                    verification_report['metadata']['status'] = 'failed'

                    if verbose:
                        for diff in differences[:5]:  # 처음 5개만 출력
                            self.stdout.write(f'    - {diff["scanner"]}: {diff["type"]}')

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'  ✗ 검증 실패: {str(e)}')
                )
                verification_report['results'][url] = {
                    'status': 'error',
                    'error': str(e)
                }
                verification_report['summary']['failed'] += 1
                verification_report['metadata']['status'] = 'failed'

            verification_report['summary']['total_urls'] += 1

        # 리포트 저장
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(verification_report, f, indent=2, ensure_ascii=False)

        # 최종 결과 출력
        self._print_summary(verification_report, output_path)

    def _extract_scan_results(self, security_result: SecurityScanResult) -> Dict[str, Any]:
        """SecurityScanResult에서 황금 테스트 비교용 정보 추출"""

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
                    # 취약점 개수와 심각도만 비교
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

    def _compare_results(self, golden: Dict, current: Dict) -> List[Dict]:
        """황금 테스트와 현재 결과 비교"""
        differences = []

        # 메타데이터 제외하고 각 스캐너 결과 비교
        for scanner_name in golden.keys():
            if scanner_name == 'metadata':
                continue

            golden_value = golden.get(scanner_name, {})
            current_value = current.get(scanner_name, {})

            # 취약점 개수 비교
            golden_total = golden_value.get('total', 0)
            current_total = current_value.get('total', 0)

            if golden_total != current_total:
                differences.append({
                    'scanner': scanner_name,
                    'type': 'vulnerability_count',
                    'golden': golden_total,
                    'current': current_total,
                    'delta': current_total - golden_total
                })

            # 심각도 비교
            golden_severity = golden_value.get('severity', 'unknown')
            current_severity = current_value.get('severity', 'unknown')

            if golden_severity != current_severity:
                differences.append({
                    'scanner': scanner_name,
                    'type': 'severity_change',
                    'golden': golden_severity,
                    'current': current_severity
                })

            # 취약점 존재 여부 비교
            golden_has = golden_value.get('has_vulnerabilities', False)
            current_has = current_value.get('has_vulnerabilities', False)

            if golden_has != current_has:
                differences.append({
                    'scanner': scanner_name,
                    'type': 'detection_change',
                    'golden': golden_has,
                    'current': current_has
                })

        # 새로 추가되거나 제거된 스캐너 확인
        golden_scanners = set(golden.keys()) - {'metadata'}
        current_scanners = set(current.keys()) - {'metadata'}

        for scanner in current_scanners - golden_scanners:
            differences.append({
                'scanner': scanner,
                'type': 'new_scanner',
                'message': '황금 테스트에 없는 새 스캐너'
            })

        for scanner in golden_scanners - current_scanners:
            differences.append({
                'scanner': scanner,
                'type': 'missing_scanner',
                'message': '현재 결과에서 누락된 스캐너'
            })

        return differences

    def _print_summary(self, report: Dict, output_path: Path = None):
        """검증 결과 요약 출력"""
        summary = report['summary']

        self.stdout.write('\n' + '='*60)
        self.stdout.write('검증 결과 요약')
        self.stdout.write('='*60)

        self.stdout.write(f'총 URL: {summary["total_urls"]}')
        self.stdout.write(f'통과: {summary["passed"]}')
        self.stdout.write(f'실패: {summary["failed"]}')

        if report['metadata']['status'] == 'passed':
            self.stdout.write(
                self.style.SUCCESS('\n✓ 모든 황금 테스트 통과!')
            )
        else:
            self.stdout.write(
                self.style.WARNING('\n⚠ 일부 테스트에서 차이점 발견')
            )

            # 주요 차이점 요약
            all_differences = []
            for url, result in report['results'].items():
                if 'differences' in result:
                    all_differences.extend(result['differences'])

            if all_differences:
                self.stdout.write('\n주요 차이점:')

                # 타입별로 그룹화
                diff_types = {}
                for diff in all_differences:
                    diff_type = diff['type']
                    if diff_type not in diff_types:
                        diff_types[diff_type] = []
                    diff_types[diff_type].append(diff)

                for diff_type, diffs in diff_types.items():
                    self.stdout.write(f'  - {diff_type}: {len(diffs)}개')

        if output_path:
            self.stdout.write('\n리포트 저장 위치:')
            self.stdout.write(f'  {output_path.absolute()}')