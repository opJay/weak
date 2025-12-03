"""
DeserializationScanner - deserialization 스캐너

원본: scanners_refactored_batch5.py
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


class DeserializationScanner(BaseScanner):
    """Insecure Deserialization 취약점 스캐너"""
    # 스캐너 메타데이터
    metadata = {
        'id': 'deserialization',
        'name': '역직렬화 취약점 스캔',
        'icon': '🔄',
        'description': '역직렬화 취약점 스캔',
        'weight': 2,
        'field': 'deserialization_vulnerabilities',
        'category': 'security_advanced',
        'enabled': True
    }

    SERIALIZATION_INDICATORS = [
        # Python
        ('pickle', 'Python Pickle', 'critical'),
        ('cPickle', 'Python cPickle', 'critical'),
        ('yaml.load', 'PyYAML unsafe load', 'critical'),
        ('marshal.loads', 'Python Marshal', 'high'),

        # Java
        ('ObjectInputStream', 'Java Serialization', 'critical'),
        ('readObject', 'Java readObject', 'critical'),
        ('XMLDecoder', 'Java XMLDecoder', 'high'),

        # PHP
        ('unserialize', 'PHP unserialize', 'critical'),
        ('__wakeup', 'PHP Magic Method', 'high'),

        # .NET
        ('BinaryFormatter', '.NET BinaryFormatter', 'critical'),
        ('NetDataContractSerializer', '.NET Serialization', 'high'),
    ]

    def __init__(self, response: requests.Response = None, html_content: str = None, url: str = None, **kwargs):
        """DeserializationScanner 초기화"""
        super().__init__(url=url or '', response=response, html_content=html_content, **kwargs)
        self.response = response
        self.html_content = html_content or ''
        self.vulnerabilities = []

    def _execute_scan(self) -> None:
        """Deserialization 취약점 스캔 실행"""
        # 검사 항목: 쿠키, 직렬화 함수, 인코딩 데이터
        self.checked = 3

        try:
            # 1. 쿠키에서 직렬화된 데이터 확인
            if self.response:
                self._scan_cookies()

            # 2. HTML/JS에서 직렬화 함수 사용 확인
            if self.html_content:
                self._scan_serialization_functions()
                # 3. Base64 인코딩된 직렬화 데이터 탐지
                self._scan_encoded_data()

        except Exception as e:
            logger.error(f"Deserialization scan error: {str(e)}")

        # 결과 요약
        if self.vulnerabilities:
            critical_count = len([v for v in self.vulnerabilities if v.get('severity') == 'critical'])
            self._add_detail(
                id='deserialization_check',
                name='역직렬화 취약점 검사',
                status='fail',
                severity='critical' if critical_count > 0 else 'high',
                description=f'{len(self.vulnerabilities)}개의 역직렬화 취약점 발견',
                value=f'Critical: {critical_count}개',
                expected='역직렬화 취약점 없음',
                recommendation='안전한 직렬화 방식(JSON 등)을 사용하고, 신뢰할 수 없는 데이터를 역직렬화하지 마세요.'
            )
        else:
            self._add_detail(
                id='deserialization_check',
                name='역직렬화 취약점 검사',
                status='pass',
                severity='info',
                description='역직렬화 취약점이 발견되지 않음',
                value=None,
                expected=None,
                recommendation=None
            )

    def _scan_cookies(self) -> None:
        """쿠키에서 직렬화된 데이터 확인"""
        try:
            if not self.response:
                return

            cookies = self.response.cookies

            for cookie in cookies:
                value = cookie.value

                # Base64 디코딩 시도
                try:
                    decoded = base64.b64decode(value)
                    decoded_str = decoded.decode('utf-8', errors='ignore')

                    # Pickle magic bytes 확인
                    if decoded.startswith(b'\x80') or 'pickle' in decoded_str.lower():
                        self.vulnerabilities.append({
                            'type': 'Insecure Deserialization (Cookie)',
                            'severity': 'critical',
                            'cookie_name': cookie.name,
                            'description': f'쿠키 "{cookie.name}"에 직렬화된 데이터가 포함되어 있습니다.',
                            'recommendation': 'JWT나 서명된 토큰을 사용하고, 직렬화된 객체를 쿠키에 저장하지 마세요.'
                        })

                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Deserialization cookie scan error: {str(e)}")

    def _scan_serialization_functions(self) -> None:
        """직렬화 함수 사용 확인"""
        try:
            found = []

            for pattern, name, severity in self.SERIALIZATION_INDICATORS:
                if re.search(pattern, self.html_content, re.IGNORECASE):
                    found.append({'pattern': pattern, 'name': name, 'severity': severity})

            if found:
                self.vulnerabilities.append({
                    'type': 'Unsafe Deserialization Functions',
                    'severity': found[0]['severity'],
                    'functions': [f['name'] for f in found[:3]],
                    'description': f'{len(found)}개의 안전하지 않은 역직렬화 함수가 발견되었습니다.',
                    'recommendation': '안전한 직렬화 방식(JSON 등)을 사용하고, 신뢰할 수 없는 데이터를 역직렬화하지 마세요.'
                })

        except Exception as e:
            logger.debug(f"Serialization function scan error: {str(e)}")

    def _scan_encoded_data(self) -> None:
        """인코딩된 직렬화 데이터 탐지"""
        try:
            # URL이나 HTML에서 Base64로 인코딩된 것으로 보이는 긴 문자열 찾기
            base64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
            matches = re.findall(base64_pattern, self.html_content)

            suspicious_count = 0
            for match in matches[:10]:  # 최대 10개만 검사
                try:
                    decoded = base64.b64decode(match)
                    # Pickle, Java serialization 등의 magic bytes 확인
                    if decoded.startswith((b'\x80', b'\xac\xed', b'rO0')):
                        suspicious_count += 1
                except Exception:
                    pass

            if suspicious_count > 0:
                self.vulnerabilities.append({
                    'type': 'Serialized Data in Response',
                    'severity': 'high',
                    'count': suspicious_count,
                    'description': f'{suspicious_count}개의 직렬화된 데이터가 응답에서 발견되었습니다.',
                    'recommendation': '직렬화된 객체 대신 JSON을 사용하세요.'
                })

        except Exception as e:
            logger.debug(f"Encoded data scan error: {str(e)}")

    def _build_result(self) -> Dict[str, Any]:
        """스캔 결과 빌드"""
        result = super()._build_result()
        result.update({
            'vulnerabilities': self.vulnerabilities,
            'total': len(self.vulnerabilities),
            'has_deserialization': len(self.vulnerabilities) > 0,
            'scanner_id': self.metadata['id']
        })
        return result


    @classmethod
    def get_metadata(cls):
        """메타데이터 반환"""
        return cls.metadata

