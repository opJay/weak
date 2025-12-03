"""
테스트 실행 스크립트
다양한 테스트 시나리오 실행
"""

import sys
import subprocess
import argparse
from pathlib import Path


def run_command(cmd: str) -> int:
    """명령 실행 및 결과 반환"""
    print(f"\n🚀 실행: {cmd}")
    print("-" * 60)
    result = subprocess.run(cmd, shell=True)
    return result.returncode


def run_unit_tests():
    """단위 테스트 실행"""
    print("\n" + "=" * 60)
    print("📝 단위 테스트 실행")
    print("=" * 60)

    return run_command("pytest tests/unit/ -v --tb=short")


def run_integration_tests():
    """통합 테스트 실행"""
    print("\n" + "=" * 60)
    print("🔗 통합 테스트 실행")
    print("=" * 60)

    return run_command("pytest tests/integration/ -v --tb=short")


def run_specific_scanner_test(scanner_name: str):
    """특정 스캐너 테스트 실행"""
    print("\n" + "=" * 60)
    print(f"🎯 {scanner_name} 스캐너 테스트")
    print("=" * 60)

    test_file = f"tests/unit/test_{scanner_name}_scanner.py"
    if Path(test_file).exists():
        return run_command(f"pytest {test_file} -v")
    else:
        print(f"⚠️  테스트 파일을 찾을 수 없음: {test_file}")
        return 1


def run_coverage_test():
    """커버리지 테스트 실행"""
    print("\n" + "=" * 60)
    print("📊 커버리지 분석")
    print("=" * 60)

    commands = [
        "coverage erase",
        "coverage run -m pytest tests/",
        "coverage report -m",
        "coverage html"
    ]

    for cmd in commands:
        if run_command(cmd) != 0:
            return 1

    print("\n✅ 커버리지 리포트 생성: htmlcov/index.html")
    return 0


def run_quick_test():
    """빠른 테스트 (네트워크 제외)"""
    print("\n" + "=" * 60)
    print("⚡ 빠른 테스트 실행 (네트워크 제외)")
    print("=" * 60)

    return run_command("pytest tests/ -v -m 'not network and not slow'")


def run_all_tests():
    """모든 테스트 실행"""
    print("\n" + "=" * 60)
    print("🎯 전체 테스트 스위트 실행")
    print("=" * 60)

    return run_command("pytest tests/ -v")


def run_scanner_validation():
    """스캐너 메타데이터 및 구조 검증"""
    print("\n" + "=" * 60)
    print("🔍 스캐너 구조 검증")
    print("=" * 60)

    validation_script = """
import sys
from scanner.core.registry import scanner_registry

# 스캐너 발견
scanners = scanner_registry.discover_scanners(force_reload=True)
print(f"✅ 발견된 스캐너: {len(scanners)}개\\n")

# 카테고리별 분류
categories = {}
for scanner_id, scanner_class in scanners.items():
    category = scanner_class.metadata.get('category', 'unknown')
    categories[category] = categories.get(category, 0) + 1

print("📊 카테고리별 분포:")
for category, count in sorted(categories.items()):
    print(f"  • {category}: {count}개")

# 메타데이터 검증
errors = []
for scanner_id, scanner_class in scanners.items():
    metadata = scanner_class.metadata
    required = ['id', 'name', 'field', 'category', 'weight']

    for field in required:
        if field not in metadata:
            errors.append(f"{scanner_id}: {field} 누락")

if errors:
    print(f"\\n❌ 메타데이터 오류 {len(errors)}개:")
    for error in errors[:5]:
        print(f"  • {error}")
    sys.exit(1)
else:
    print("\\n✅ 모든 스캐너 메타데이터 정상")
    sys.exit(0)
"""

    result = subprocess.run([sys.executable, "-c", validation_script], capture_output=True, text=True, encoding='utf-8')
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    return result.returncode


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(description='WEAK 스캐너 테스트 실행')
    parser.add_argument(
        'mode',
        choices=['all', 'unit', 'integration', 'quick', 'coverage', 'validate'],
        nargs='?',
        default='quick',
        help='테스트 모드 선택'
    )
    parser.add_argument(
        '--scanner',
        help='특정 스캐너만 테스트 (예: xss, sql_injection)'
    )

    args = parser.parse_args()

    print("\n" + "🧪 " * 20)
    print("WEAK 스캐너 테스트 시스템")
    print("🧪 " * 20)

    # 특정 스캐너 테스트
    if args.scanner:
        result = run_specific_scanner_test(args.scanner)
    else:
        # 모드별 실행
        if args.mode == 'all':
            result = run_all_tests()
        elif args.mode == 'unit':
            result = run_unit_tests()
        elif args.mode == 'integration':
            result = run_integration_tests()
        elif args.mode == 'coverage':
            result = run_coverage_test()
        elif args.mode == 'validate':
            result = run_scanner_validation()
        else:  # quick
            result = run_quick_test()

    # 결과 출력
    print("\n" + "=" * 60)
    if result == 0:
        print("✅ 테스트 성공!")
    else:
        print("❌ 테스트 실패!")
    print("=" * 60)

    return result


if __name__ == "__main__":
    sys.exit(main())