"""
Scanner ID 일치성 테스트
모든 스캐너 ID가 API field_mapping에 있는지 검증
"""

import pytest
import re
from pathlib import Path


class TestScannerIDConsistency:
    """Scanner ID 일치성 테스트"""

    def _extract_all_scanner_ids(self):
        """모든 리팩토링된 스캐너 파일에서 scanner ID 추출"""
        import glob
        import os
        # 테스트 실행 위치에 상관없이 프로젝트 루트 기준으로 경로 설정
        root_dir = Path(__file__).parent.parent.parent
        os.chdir(root_dir)

        batch_files = glob.glob('scanner/scanners_refactored_batch*.py')
        batch_files.extend(glob.glob('scanner/scanners*.py'))  # 기존 scanners.py 파일들도 포함

        all_scanner_ids = set()
        for file_path in batch_files:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # metadata = { 'id': 'xxx' 패턴 찾기
                pattern = r"'id':\s*'([^']+)'"
                ids = re.findall(pattern, content)
                all_scanner_ids.update(ids)

        return all_scanner_ids

    def _extract_field_mapping_ids(self):
        """api/views.py에서 field_mapping의 모든 키 추출"""
        root_dir = Path(__file__).parent.parent.parent
        views_file = root_dir / 'api' / 'views.py'
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

    def test_all_scanner_ids_in_field_mapping(self):
        """모든 스캐너 ID가 field_mapping에 있는지 확인"""
        scanner_ids = self._extract_all_scanner_ids()
        mapping_keys = self._extract_field_mapping_ids()

        missing_in_mapping = scanner_ids - mapping_keys

        if missing_in_mapping:
            error_msg = (
                f"다음 스캐너 ID들이 field_mapping에 없습니다:\n"
                + "\n".join(f"  - '{id}'" for id in sorted(missing_in_mapping))
            )
            pytest.fail(error_msg)

    def test_no_duplicate_scanner_ids(self):
        """스캐너 파일들에 중복된 ID가 없는지 확인"""
        import glob
        import os
        root_dir = Path(__file__).parent.parent.parent
        os.chdir(root_dir)

        batch_files = glob.glob('scanner/scanners_refactored_batch*.py')
        batch_files.extend(glob.glob('scanner/scanners*.py'))

        all_ids = []
        for file_path in batch_files:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                pattern = r"'id':\s*'([^']+)'"
                ids = re.findall(pattern, content)
                all_ids.extend(ids)

        # 중복 찾기
        seen = set()
        duplicates = []
        for id in all_ids:
            if id in seen:
                duplicates.append(id)
            seen.add(id)

        if duplicates:
            error_msg = (
                f"다음 ID들이 스캐너 파일들에 중복되어 있습니다:\n"
                + "\n".join(f"  - '{id}'" for id in sorted(set(duplicates)))
            )
            pytest.fail(error_msg)

    def test_field_mapping_values_unique(self):
        """field_mapping의 값들이 적절히 매핑되었는지 확인"""
        root_dir = Path(__file__).parent.parent.parent
        views_file = root_dir / 'api' / 'views.py'
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

    def test_critical_scanner_id_mappings(self):
        """
        중요한 스캐너 ID들이 field_mapping에서 처리될 수 있는지 확인
        (최근 400 Bad Request 에러를 일으켰던 ID들 포함)
        """
        from api.views import ScanViewSet

        viewset = ScanViewSet()

        # 문제가 되었던 ID들과 핵심 ID들 테스트
        critical_ids = [
            'xss', 'sql_injection', 'security_headers',
            'cookies', 'cookie_security',  # 별칭 처리
            'info_disclosure', 'information_disclosure',  # 별칭 처리
            'outdated_dependencies'  # software_supply_chain은 별도 ID로 존재하지 않음
        ]

        failed = []
        for scanner_id in critical_ids:
            field_name = viewset._get_field_name_for_scanner(scanner_id)
            if field_name is None:
                failed.append(scanner_id)
            else:
                print(f"  ✅ '{scanner_id}' → '{field_name}'")

        if failed:
            pytest.fail(
                f"다음 중요한 scanner ID들이 field_mapping에 없습니다:\n"
                + "\n".join(f"  - '{id}'" for id in failed)
            )

    def test_all_refactored_scanner_ids_mapped(self):
        """리팩토링된 스캐너들의 ID도 모두 매핑되었는지 확인"""
        import glob
        import os
        root_dir = Path(__file__).parent.parent.parent
        os.chdir(root_dir)

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
        print("\n[1] 모든 스캐너 ID → field_mapping 확인...")
        test_instance.test_all_scanner_ids_in_field_mapping()
        print("  ✅ 통과")

        print("\n[2] 중복 ID 확인...")
        test_instance.test_no_duplicate_scanner_ids()
        print("  ✅ 통과")

        print("\n[3] Field mapping 분석...")
        test_instance.test_field_mapping_values_unique()

        print("\n[4] 중요 scanner ID 매핑 테스트...")
        test_instance.test_critical_scanner_id_mappings()

        print("\n[5] 리팩토링된 스캐너 ID 매핑 확인...")
        test_instance.test_all_refactored_scanner_ids_mapped()

        print("\n" + "=" * 60)
        print("✅ 모든 테스트 통과!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ 테스트 실패: {e}")
        print("=" * 60)
        sys.exit(1)