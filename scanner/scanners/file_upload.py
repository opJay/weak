"""
FileUploadScanner - file_upload 스캐너

원본: scanners_refactored_batch4.py
자동 마이그레이션된 독립 스캐너 모듈
"""

import logging
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
import requests
import json
import time
import hashlib
import base64

# core 패키지에서 BaseScanner import
from scanner.base import BaseScanner

logger = logging.getLogger(__name__)

class FileUploadScanner(BaseScanner):
    """파일 업로드 취약점 스캐너"""
    # 스캐너 메타데이터
    metadata = {
        'id': 'file_upload',
        'name': '파일 업로드 취약점 스캔',
        'icon': '📤',
        'description': '파일 업로드 취약점 스캔',
        'weight': 2,
        'field': 'file_upload_vulnerabilities',
        'category': 'security_advanced',
        'enabled': True
    }

    DANGEROUS_EXTENSIONS = [
        'php', 'php3', 'php4', 'php5', 'phtml', 'asp', 'aspx',
        'jsp', 'jspx', 'exe', 'sh', 'bat', 'cmd', 'py', 'rb',
        'pl', 'cgi', 'dll', 'so', 'jar', 'war'
    ]

    def __init__(self, html_content: str = None, url: str = None, **kwargs):
        """
        Args:
            html_content: HTML 콘텐츠
            url: URL (선택적)
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', **kwargs)
        self.html_content = html_content or ''

    def _execute_scan(self) -> None:
        """파일 업로드 취약점 검사 실행"""
        # 검사 항목: 파일 업로드 검사
        self.checked = 1

        if not self.html_content:
            self._add_detail(
                id='file_upload_check',
                name='파일 업로드 취약점 검사',
                status='pass',
                severity='info',
                description='검사할 HTML 콘텐츠 없음',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        soup = BeautifulSoup(self.html_content, 'html.parser')
        file_inputs = soup.find_all('input', type='file')

        if not file_inputs:
            self._add_detail(
                id='file_upload_check',
                name='파일 업로드 취약점 검사',
                status='pass',
                severity='info',
                description='파일 업로드 필드가 없음',
                value=None,
                expected=None,
                recommendation=None
            )
            return

        # 파일 업로드 필드가 있으면 검사
        for idx, file_input in enumerate(file_inputs):
            self._check_file_input(file_input, idx)

        # 결과 요약
        if self.issues:
            critical_count = len([i for i in self.issues if i.get('severity') == 'critical'])
            self._add_detail(
                id='file_upload_check',
                name='파일 업로드 취약점 검사',
                status='fail',
                severity='critical' if critical_count > 0 else 'high',
                description=f'{len(self.issues)}개의 파일 업로드 취약점 발견 ({len(file_inputs)}개 필드 검사)',
                value=f'Critical: {critical_count}개',
                expected='파일 업로드 취약점 없음',
                recommendation='허용할 파일 확장자를 화이트리스트로 제한하고, 서버 사이드에서 파일 내용을 검증하세요.'
            )
        else:
            self._add_detail(
                id='file_upload_check',
                name='파일 업로드 취약점 검사',
                status='pass',
                severity='info',
                description=f'{len(file_inputs)}개 파일 업로드 필드 검사 완료',
                value=None,
                expected=None,
                recommendation=None
            )

    def _check_file_input(self, file_input, idx: int) -> None:
        """개별 파일 입력 검사"""
        try:
            accept = file_input.get('accept', '')
            name = file_input.get('name', f'file_{idx}')

            # accept 속성이 없거나 너무 광범위한 경우
            if not accept or accept == '*/*' or accept == '*':
                self.issues.append({
                    'type': 'Unrestricted File Upload',
                    'severity': 'critical',
                    'input_name': name,
                    'accept': accept or 'any file',
                    'description': f'파일 업로드 필드 "{name}"가 모든 파일 형식을 허용합니다.',
                    'attack_vectors': [
                        'PHP 웹쉘 업로드 (.php)',
                        'Double extension 우회 (.php.jpg)',
                        'Null byte 주입 (shell.php%00.jpg)',
                        'MIME type 우회',
                    ],
                    'recommendation': '허용할 파일 확장자를 화이트리스트로 제한하고, 서버 사이드에서 파일 내용을 검증하세요.'
                })

            # 실행 가능한 파일 허용 여부
            elif any(ext in accept.lower() for ext in self.DANGEROUS_EXTENSIONS):
                dangerous = [ext for ext in self.DANGEROUS_EXTENSIONS if ext in accept.lower()]
                self.issues.append({
                    'type': 'Dangerous File Types Allowed',
                    'severity': 'critical',
                    'input_name': name,
                    'dangerous_types': dangerous,
                    'description': f'실행 가능한 파일 형식이 허용됩니다: {", ".join(dangerous)}',
                    'recommendation': '실행 가능한 파일 업로드를 차단하세요.'
                })

            # 클라이언트 사이드 검증만 있는 경우 (JavaScript)
            else:
                # 보통은 서버 사이드 검증도 필요
                self.issues.append({
                    'type': 'File Upload Without Server Validation',
                    'severity': 'high',
                    'input_name': name,
                    'accept': accept,
                    'description': f'파일 업로드 필드가 서버 사이드 검증 없이 클라이언트 검증만 사용할 수 있습니다.',
                    'recommendation': '반드시 서버 사이드에서 파일 내용, 크기, MIME 타입을 검증하세요.'
                })

        except Exception as e:
            logger.debug(f"File input check error: {str(e)}")

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_file_upload': len(self.issues) > 0

        }
    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata
