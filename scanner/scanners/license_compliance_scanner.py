"""라이선스 준수 검사 스캐너"""

import json
from typing import Dict, Any
from scanner.base import BaseScanner


class LicenseComplianceScanner(BaseScanner):
    """라이선스 준수 검사 스캐너"""

    metadata = {
        'id': 'license_compliance',
        'name': 'License Compliance',
        'field': 'license_compliance',
        'weight': 1,
        'category': 'supply_chain',
        'severity': 'medium',
        'description': '라이선스 준수 검사 (GPL, AGPL, 상업적 사용 제한)',
        'owasp': ['A03:2025']
    }

    def __init__(self, url: str = None, html_content: str = None,
                 response: Any = None, http_client: Any = None):
        super().__init__(url=url or '', response=response,
                        html_content=html_content)
        self.url = url or ''
        self.html_content = html_content or ''
        self.response = response
        self.http_client = http_client
        self.vulnerabilities = []

        # Copyleft 라이선스 (강한 제약)
        self.copyleft_licenses = [
            'GPL', 'GPLv2', 'GPLv3', 'GPL-2.0', 'GPL-3.0',
            'AGPL', 'AGPLv3', 'AGPL-3.0',
            'LGPL', 'LGPLv2', 'LGPLv3', 'LGPL-2.1', 'LGPL-3.0'
        ]

        # 상업적 사용 제한 라이선스
        self.commercial_restricted = [
            'CC-BY-NC', 'CC-BY-NC-SA', 'CC-BY-NC-ND',
            'NonCommercial', 'NC', 'Educational',
            'Academic', 'Research'
        ]

        # 일반적으로 호환성 문제가 있는 조합
        self.incompatible_combinations = [
            ('MIT', 'GPL'),
            ('Apache', 'GPL'),
            ('BSD', 'GPL')
        ]

    def _prepare(self):
        """스캔 준비"""
        pass

    def _execute_scan(self):
        """스캔 실행"""
        # 검사 항목: 라이선스 파일, 종속성 라이선스, 호환성
        self.checked = 3

        # 1. 라이선스 파일 검사
        self._check_license_files()

        # 2. 종속성 라이선스 검사
        self._check_dependency_licenses()

        # 3. 라이선스 호환성 검사
        self._check_license_compatibility()

        # 결과 요약
        if self.vulnerabilities:
            high_count = len([v for v in self.vulnerabilities if v.get('severity') == 'high'])
            self._add_detail(
                id='license_compliance_check',
                name='라이선스 준수 검사',
                status='fail',
                severity='high' if high_count > 0 else 'medium',
                description=f'{len(self.vulnerabilities)}개의 라이선스 준수 문제 발견',
                value=f'High: {high_count}개',
                expected='라이선스 준수 문제 없음',
                recommendation='Copyleft 및 상업적 제한 라이선스를 점검하세요.'
            )
        else:
            self._add_detail(
                id='license_compliance_check',
                name='라이선스 준수 검사',
                status='pass',
                severity='info',
                description='라이선스 준수 문제가 발견되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _check_license_files(self):
        """라이선스 파일 검사"""
        if not self.http_client:
            return

        base_url = self.url.rstrip('/')
        license_files = ['LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING']

        license_found = False
        project_license = None

        for license_file in license_files:
            try:
                response = self.http_client.get(f"{base_url}/{license_file}")
                if response and hasattr(response, 'status_code') and response.status_code == 200:
                    content = response.text if hasattr(response, 'text') else str(response.content)
                    license_found = True

                    # Copyleft 라이선스 검사
                    for copyleft in self.copyleft_licenses:
                        if copyleft.upper() in content.upper():
                            project_license = copyleft
                            self.vulnerabilities.append({
                                'type': 'copyleft_license',
                                'file': license_file,
                                'license': copyleft,
                                'severity': 'medium',
                                'message': f'Copyleft 라이선스 {copyleft} 사용 (코드 공개 의무)'
                            })
                            break

                    # 상업적 사용 제한 검사
                    for restricted in self.commercial_restricted:
                        if restricted.upper() in content.upper():
                            self.vulnerabilities.append({
                                'type': 'commercial_restriction',
                                'file': license_file,
                                'license': restricted,
                                'severity': 'high',
                                'message': f'상업적 사용 제한 라이선스: {restricted}'
                            })
                            break

                    break
            except:
                pass

        # 라이선스 파일이 없는 경우
        if not license_found:
            self.vulnerabilities.append({
                'type': 'missing_license',
                'severity': 'low',
                'message': '프로젝트 라이선스 파일이 없습니다'
            })

    def _check_dependency_licenses(self):
        """종속성 라이선스 검사"""
        if not self.http_client:
            return

        base_url = self.url.rstrip('/')

        # package.json에서 라이선스 검사
        try:
            response = self.http_client.get(f"{base_url}/package.json")
            if response and hasattr(response, 'status_code') and response.status_code == 200:
                content = response.text if hasattr(response, 'text') else str(response.content)

                try:
                    package_data = json.loads(content)

                    # 프로젝트 자체 라이선스
                    project_license = package_data.get('license', '')

                    # dependencies 검사
                    dependencies = package_data.get('dependencies', {})

                    # 각 종속성의 라이선스 검사 (package-lock.json이 필요)
                    try:
                        lock_response = self.http_client.get(f"{base_url}/package-lock.json")
                        if lock_response and hasattr(lock_response, 'status_code') and lock_response.status_code == 200:
                            lock_content = lock_response.text if hasattr(lock_response, 'text') else str(lock_response.content)
                            lock_data = json.loads(lock_content)

                            packages = lock_data.get('packages', {})
                            copyleft_deps = []
                            restricted_deps = []

                            for pkg_name, pkg_info in packages.items():
                                if isinstance(pkg_info, dict):
                                    license_field = pkg_info.get('license', '')

                                    # Copyleft 검사
                                    for copyleft in self.copyleft_licenses:
                                        if copyleft.upper() in str(license_field).upper():
                                            copyleft_deps.append((pkg_name, copyleft))
                                            break

                                    # 상업적 제한 검사
                                    for restricted in self.commercial_restricted:
                                        if restricted.upper() in str(license_field).upper():
                                            restricted_deps.append((pkg_name, restricted))
                                            break

                            # Copyleft 종속성 보고
                            if copyleft_deps:
                                self.vulnerabilities.append({
                                    'type': 'copyleft_dependencies',
                                    'count': len(copyleft_deps),
                                    'examples': copyleft_deps[:3],
                                    'severity': 'medium',
                                    'message': f'{len(copyleft_deps)}개의 Copyleft 종속성 발견'
                                })

                            # 상업적 제한 종속성 보고
                            if restricted_deps:
                                self.vulnerabilities.append({
                                    'type': 'restricted_dependencies',
                                    'count': len(restricted_deps),
                                    'examples': restricted_deps[:3],
                                    'severity': 'high',
                                    'message': f'{len(restricted_deps)}개의 상업적 사용 제한 종속성'
                                })
                    except:
                        pass
                except:
                    pass
        except:
            pass

    def _check_license_compatibility(self):
        """라이선스 호환성 검사"""
        if not self.http_client:
            return

        base_url = self.url.rstrip('/')

        # package.json에서 프로젝트 라이선스 가져오기
        try:
            response = self.http_client.get(f"{base_url}/package.json")
            if response and hasattr(response, 'status_code') and response.status_code == 200:
                content = response.text if hasattr(response, 'text') else str(response.content)

                try:
                    package_data = json.loads(content)
                    project_license = package_data.get('license', '').upper()

                    # MIT/Apache/BSD와 GPL 종속성 혼합 검사
                    if any(lic in project_license for lic in ['MIT', 'APACHE', 'BSD']):
                        # package-lock.json에서 GPL 종속성 찾기
                        try:
                            lock_response = self.http_client.get(f"{base_url}/package-lock.json")
                            if lock_response and hasattr(lock_response, 'status_code') and lock_response.status_code == 200:
                                lock_content = lock_response.text if hasattr(lock_response, 'text') else str(lock_response.content)

                                if 'GPL' in lock_content.upper() and 'LGPL' not in lock_content.upper():
                                    self.vulnerabilities.append({
                                        'type': 'license_incompatibility',
                                        'project_license': project_license,
                                        'conflicting': 'GPL',
                                        'severity': 'medium',
                                        'message': f'{project_license}와 GPL 라이선스 호환성 문제'
                                    })
                        except:
                            pass
                except:
                    pass
        except:
            pass

    def _build_result(self) -> Dict[str, Any]:
        """결과 생성"""
        passed = len(self.vulnerabilities) == 0

        return {
            'passed': passed,
            'vulnerabilities': self.vulnerabilities,
            'severity': 'low' if passed else self._calculate_severity(),
            'message': self._generate_message()
        }

    def _calculate_severity(self) -> str:
        """심각도 계산"""
        if any(v.get('severity') == 'high' for v in self.vulnerabilities):
            return 'high'
        elif any(v.get('severity') == 'medium' for v in self.vulnerabilities):
            return 'medium'
        return 'low'

    def _generate_message(self) -> str:
        """메시지 생성"""
        if not self.vulnerabilities:
            return '라이선스 준수 문제가 발견되지 않았습니다'

        issues = []
        vuln_types = set(v.get('type') for v in self.vulnerabilities)

        if 'missing_license' in vuln_types:
            issues.append('라이선스 파일 누락')
        if 'copyleft_license' in vuln_types or 'copyleft_dependencies' in vuln_types:
            issues.append('Copyleft 라이선스')
        if 'commercial_restriction' in vuln_types or 'restricted_dependencies' in vuln_types:
            issues.append('상업적 사용 제한')
        if 'license_incompatibility' in vuln_types:
            issues.append('라이선스 호환성 문제')

        return f"라이선스 준수 문제 발견: {', '.join(issues)}"

    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

