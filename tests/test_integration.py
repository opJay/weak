"""
통합 테스트 - 리팩토링된 스캐너가 tasks.py에서 제대로 작동하는지 확인
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_scanner_compat_layer():
    """호환성 레이어가 제대로 작동하는지 확인"""
    from scanner.scanners_compat import (
        SecurityHeaderScanner,
        XSSScanner,
        SQLInjectionScanner,
        CORSScanner,
        CookieScanner,
        CSRFScanner,
        ClickjackingScanner,
        InformationDisclosureScanner,
        MixedContentScanner,
        SubresourceIntegrityScanner
    )

    # SecurityHeaderScanner
    headers = {'X-Frame-Options': 'DENY'}
    scanner = SecurityHeaderScanner(headers)
    result = scanner.scan()
    assert 'scanner_id' in result
    assert result['scanner_id'] == 'security_headers'

    # XSSScanner
    scanner = XSSScanner('https://example.com')
    result = scanner.scan()
    assert 'scanner_id' in result
    assert result['scanner_id'] == 'xss'

    # SQLInjectionScanner
    scanner = SQLInjectionScanner('https://example.com')
    result = scanner.scan()
    assert 'scanner_id' in result
    assert result['scanner_id'] == 'sql_injection'

    # CORSScanner
    scanner = CORSScanner('https://example.com', headers)
    result = scanner.scan()
    assert 'scanner_id' in result
    assert result['scanner_id'] == 'cors'

    # CookieScanner
    response = Mock()
    response.cookies = []
    scanner = CookieScanner(response)
    result = scanner.scan()
    assert 'scanner_id' in result
    assert result['scanner_id'] == 'cookie_security'

    # CSRFScanner
    scanner = CSRFScanner('https://example.com')
    result = scanner.scan()
    assert 'scanner_id' in result
    assert result['scanner_id'] == 'csrf'

    # ClickjackingScanner
    scanner = ClickjackingScanner(headers)
    result = scanner.scan()
    assert 'scanner_id' in result
    assert result['scanner_id'] == 'clickjacking'

    # InformationDisclosureScanner
    html = '<html><body>Test</body></html>'
    scanner = InformationDisclosureScanner(html)
    result = scanner.scan()
    assert 'scanner_id' in result
    assert result['scanner_id'] == 'information_disclosure'

    # MixedContentScanner
    scanner = MixedContentScanner('https://example.com', html)
    result = scanner.scan()
    assert 'scanner_id' in result
    assert result['scanner_id'] == 'mixed_content'

    # SubresourceIntegrityScanner
    scanner = SubresourceIntegrityScanner(html, 'https://example.com')
    result = scanner.scan()
    assert 'scanner_id' in result
    assert result['scanner_id'] == 'sri'


def test_tasks_imports_work():
    """tasks.py의 import가 제대로 작동하는지 확인"""
    # tasks.py를 import할 때 에러가 없는지 확인
    try:
        import scanner.tasks
        assert hasattr(scanner.tasks, 'scan_security')
        assert hasattr(scanner.tasks, 'scan_website_sync')
        print("✓ tasks.py imports work correctly")
    except ImportError as e:
        pytest.fail(f"Failed to import tasks: {e}")


def test_scanner_metadata_compatibility():
    """스캐너 메타데이터가 호환되는지 확인"""
    from scanner.scanners_compat import (
        SecurityHeaderScanner,
        XSSScanner
    )

    # 메타데이터 속성 확인
    headers = {'X-Frame-Options': 'DENY'}
    scanner = SecurityHeaderScanner(headers)
    assert hasattr(scanner, 'metadata')
    metadata = scanner.metadata
    assert 'id' in metadata
    assert 'name' in metadata
    assert 'icon' in metadata

    scanner = XSSScanner('https://example.com')
    assert hasattr(scanner, 'metadata')
    metadata = scanner.metadata
    assert 'id' in metadata
    assert 'name' in metadata