
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from unittest.mock import Mock, patch

def simple_scanner_test():
    '''단순화된 스캐너 테스트'''
    # 모든 스캐너 import
    from scanner.scanners.sql_injection_scanner import SQLInjectionScanner
    from scanner.scanners.xss_scanner import XSSScanner

    # 기본 스캔 테스트
    scanners = [
        SQLInjectionScanner(url='http://test.com'),
        XSSScanner(url='http://test.com'),
    ]

    for scanner in scanners:
        result = scanner.scan()
        assert 'scanner_id' in result
        assert 'vulnerabilities' in result
        print(f"✓ {scanner.metadata['name']} 테스트 통과")

if __name__ == '__main__':
    simple_scanner_test()
