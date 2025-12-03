"""
CommandInjectionScanner - command_injection 스캐너

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


class CommandInjectionScanner(BaseScanner):
    """OS Command Injection 취약점 스캐너"""
    # 스캐너 메타데이터
    metadata = {
        'id': 'command_injection',
        'name': '명령어 주입 스캔',
        'icon': '💻',
        'description': '명령어 주입 스캔',
        'weight': 2,
        'field': 'command_injection',
        'category': 'security_advanced',
        'enabled': True
    }

    COMMAND_PARAMS = [
        'cmd', 'command', 'exec', 'execute', 'run', 'do', 'system',
        'shell', 'bash', 'script', 'process', 'daemon', 'ping', 'host'
    ]

    COMMAND_INDICATORS = [
        r'system\(',
        r'exec\(',
        r'shell_exec\(',
        r'passthru\(',
        r'popen\(',
        r'proc_open\(',
        r'os\.system',
        r'subprocess\.',
        r'Runtime\.getRuntime\(\)\.exec',
    ]

    def __init__(self, url: str = None, html_content: str = None, **kwargs):
        """
        Args:
            url: 검사할 URL
            html_content: HTML 콘텐츠
            **kwargs: BaseScanner 호환 인자
        """
        super().__init__(url=url or '', **kwargs)
        self.html_content = html_content or ''

    def _execute_scan(self) -> None:
        """Command Injection 취약점 검사 실행"""
        if self.url:
            self._scan_url_parameters()

        if self.html_content:
            self._scan_code_patterns()
            self._scan_forms()

    def _scan_url_parameters(self) -> None:
        """URL 파라미터에서 명령어 주입 가능성 검사"""
        try:
            parsed = urlparse(self.url)
            params = parse_qs(parsed.query)

            for param_name in params.keys():
                if param_name.lower() in self.COMMAND_PARAMS:
                    param_value = params[param_name][0] if params[param_name] else ''

                    # 특수 문자나 명령어 구분자 확인
                    dangerous_chars = ['|', '&', ';', '`', '$', '>', '<', '\n']
                    if any(char in param_value for char in dangerous_chars):
                        severity = 'critical'
                    else:
                        severity = 'high'

                    self.issues.append({
                        'type': 'Command Injection (Potential)',
                        'severity': severity,
                        'parameter': param_name,
                        'value': param_value,
                        'description': f'파라미터 "{param_name}"가 OS 명령어 주입에 취약할 수 있습니다.',
                        'attack_examples': [
                            '; ls -la',
                            '| whoami',
                            '`id`',
                            '$(cat /etc/passwd)',
                            '&& net user',
                        ],
                        'recommendation': '사용자 입력을 명령어에 직접 사용하지 말고, 화이트리스트와 이스케이핑을 적용하세요.'
                    })
        except Exception as e:
            logger.debug(f"Command injection URL scan error: {str(e)}")

    def _scan_code_patterns(self) -> None:
        """HTML/JavaScript에서 명령 실행 패턴 검사"""
        try:
            for pattern in self.COMMAND_INDICATORS:
                if re.search(pattern, self.html_content):
                    self.issues.append({
                        'type': 'Command Execution Pattern Detected',
                        'severity': 'high',
                        'pattern': pattern,
                        'description': f'명령 실행 관련 패턴이 발견되었습니다: {pattern}',
                        'recommendation': '명령 실행 코드를 안전하게 구현하고 사용자 입력을 철저히 검증하세요.'
                    })
        except Exception as e:
            logger.debug(f"Command injection pattern scan error: {str(e)}")

    def _scan_forms(self) -> None:
        """폼 입력에서 명령어 주입 가능성 검사"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                inputs = form.find_all(['input', 'textarea'])
                for input_field in inputs:
                    input_name = input_field.get('name', '')

                    if input_name.lower() in self.COMMAND_PARAMS:
                        self.issues.append({
                            'type': 'Command Injection (Form Input)',
                            'severity': 'high',
                            'input_name': input_name,
                            'form_action': form.get('action', ''),
                            'description': f'폼 입력 "{input_name}"이 명령어 주입에 취약할 수 있습니다.',
                            'recommendation': '서버 사이드에서 입력 검증 및 명령어 실행 보호를 구현하세요.'
                        })
        except Exception as e:
            logger.debug(f"Command injection form scan error: {str(e)}")

    def _get_additional_fields(self) -> Dict[str, Any]:
        """추가 필드 반환"""
        return {
            'has_command_injection': len(self.issues) > 0
        }


    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

