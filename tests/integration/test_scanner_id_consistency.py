"""
Scanner ID 일치성 테스트
모든 스캐너 ID가 API field_mapping에 있는지 검증
"""

import pytest
import re
from pathlib import Path


class TestScannerIDConsistency:
    """Scanner ID 일치성 테스트"""

    def _extract_compat_ids(self):
        """scanners_compat.py에서 모든 scanner ID 추출"""
        compat_file = Path('scanner/scanners_compat.py')
        content = compat_file.read_text(encoding='utf-8')
        pattern = r"'id':\s*'([^']+)'"
        ids = re.findall(pattern, content)
        return set(ids)

    def _extract_field_mapping_ids(self):
        """api/views.py에서 field_mapping의 모든 키 추출"""
        views_file = Path('api/views.py')
        content = views_file.read_text(encoding='utf-8')

        # field_mapping = { 부분 찾기
        start = content.find('field_mapping = {')
        assert start != -1, "field_mapping not found in api/views.py"

        # 다음 'return field_mapping.get' 까지 추출
        end = content.find('return field_mapping.get', start)
        assert end != -1, "field_mapping end not found"

        mapping_content = content[start:end]

        # 'key': 'value' 패턴에서 key만 추출
        pattern = r"'([^']+)':\s*'[^']+'"
        keys = re.findall(pattern, mapping_content)
        return set(keys)

    def test_all_compat_ids_in_field_mapping(self):
        """모든 scanners_compat.py ID가 field_mapping에 있는지 확인"""
        compat_ids = self._extract_compat_ids()
        mapping_keys = self._extract_field_mapping_ids()

        missing_in_mapping = compat_ids - mapping_keys

        if missing_in_mapping:
            error_msg = (
                f"다음 scanners_compat.py ID들이 field_mapping에 없습니다:\n"
                + "\n".join(f"  - '{id}'" for id in sorted(missing_in_mapping))
            )
            pytest.fail(error_msg)

    def test_no_duplicate_ids_in_compat(self):
        """scanners_compat.py에 중복된 ID가 없는지 확인"""
        compat_file = Path('scanner/scanners_compat.py')
        content = compat_file.read_text(encoding='utf-8')
        pattern = r"'id':\s*'([^']+)'"
        ids = re.findall(pattern, content)

        # 중복 찾기
        seen = set()
        duplicates = []
        for id in ids:
            if id in seen:
                duplicates.append(id)
            seen.add(id)

        if duplicates:
            error_msg = (
                f"다음 ID들이 scanners_compat.py에 중복되어 있습니다:\n"
                + "\n".join(f"  - '{id}'" for id in sorted(set(duplicates)))
            )
            pytest.fail(error_msg)

    def test_field_mapping_values_unique(self):
        """field_mapping의 값들이 적절히 매핑되었는지 확인"""
        views_file = Path('api/views.py')
        content = views_file.read_text(encoding='utf-8')

        # field_mapping 추출
        start = content.find('field_mapping = {')
        end = content.find('return field_mapping.get', start)
        mapping_content = content[start:end]

        # 'key': 'value' 패턴 추출
        pattern = r"'([^']+)':\s*'([^']+)'"
        mappings = re.findall(pattern, mapping_content)

        # 같은 필드를 가리키는 ID들 그룹화
        field_to_ids = {}
        for id, field in mappings:
            if field not in field_to_ids:
                field_to_ids[field] = []
            field_to_ids[field].append(id)

        # 정보 출력 (디버깅용)
        print("\n📊 Field Mapping 통계:")
        multi_id_fields = {
            field: ids for field, ids in field_to_ids.items()
            if len(ids) > 1
        }
        if multi_id_fields:
            print(f"  - 여러 ID가 같은 필드를 가리키는 경우: {len(multi_id_fields)}개")
            for field, ids in sorted(multi_id_fields.items()):
                print(f"    * {field}: {', '.join(sorted(ids))}")

    def test_scanner_api_endpoint_with_compat_ids(self):
        """
        실제 API 엔드포인트가 scanners_compat.py ID들을 처리할 수 있는지 확인
        (단위 테스트 - 실제 서버 없이 로직만 확인)
        """
        from api.views import ScanViewSet

        viewset = ScanViewSet()

        # 문제가 되었던 ID들 테스트
        critical_ids = ['cookies', 'info_disclosure', 'outdated_dependencies']

        for scanner_id in critical_ids:
            field_name = viewset._get_field_name_for_scanner(scanner_id)
            assert field_name is not None, (
                f"scanner_id '{scanner_id}'가 field_mapping에 없습니다. "
                f"400 Bad Request 에러가 발생할 것입니다."
            )
            print(f"  ✅ '{scanner_id}' → '{field_name}'")

    def test_all_refactored_scanner_ids_mapped(self):
        """리팩토링된 스캐너들의 ID도 모두 매핑되었는지 확인"""
        import glob
        batch_files = glob.glob('scanner/scanners_refactored_batch*.py')

        all_scanner_ids = set()
        for file_path in batch_files:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # metadata = { 'id': 'xxx' 패턴 찾기
                pattern = r"'id':\s*'([^']+)'"
                ids = re.findall(pattern, content)
                all_scanner_ids.update(ids)

        # field_mapping 키 추출
        mapping_keys = self._extract_field_mapping_ids()

        # 누락된 ID 찾기
        missing_ids = all_scanner_ids - mapping_keys

        if missing_ids:
            error_msg = (
                f"다음 리팩토링된 스캐너 ID들이 field_mapping에 없습니다:\n"
                + "\n".join(f"  - '{id}'" for id in sorted(missing_ids))
            )
            pytest.fail(error_msg)

        print(f"\n  ✅ 모든 리팩토링된 스캐너 ID ({len(all_scanner_ids)}개)가 매핑되었습니다.")


if __name__ == '__main__':
    # 직접 실행 시 모든 테스트 수행
    import sys

    test_instance = TestScannerIDConsistency()

    print("=" * 60)
    print("Scanner ID 일치성 테스트")
    print("=" * 60)

    try:
        print("\n[1] scanners_compat.py ID → field_mapping 확인...")
        test_instance.test_all_compat_ids_in_field_mapping()
        print("  ✅ 통과")

        print("\n[2] 중복 ID 확인...")
        test_instance.test_no_duplicate_ids_in_compat()
        print("  ✅ 통과")

        print("\n[3] Field mapping 분석...")
        test_instance.test_field_mapping_values_unique()

        print("\n[4] API 엔드포인트 로직 테스트...")
        test_instance.test_scanner_api_endpoint_with_compat_ids()

        print("\n[5] 리팩토링된 스캐너 ID 매핑 확인...")
        test_instance.test_all_refactored_scanner_ids_mapped()

        print("\n" + "=" * 60)
        print("✅ 모든 테스트 통과!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ 테스트 실패: {e}")
        print("=" * 60)
        sys.exit(1)