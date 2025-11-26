#!/usr/bin/env python
"""
Weak Scanner - 프로젝트 관리 스크립트
개발 환경을 쉽게 설정하고 실행할 수 있는 CLI 도구
"""
import os
import sys
import subprocess
import argparse
import time


def run_command(command, description=None, check=True):
    """명령어 실행 헬퍼"""
    if description:
        print(f"\n{'='*60}")
        print(f"  {description}")
        print(f"{'='*60}\n")

    try:
        if isinstance(command, str):
            result = subprocess.run(command, shell=True, check=check)
        else:
            result = subprocess.run(command, check=check)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"\n❌ 오류 발생: {e}")
        return False
    except KeyboardInterrupt:
        print("\n\n⚠️  사용자에 의해 중단되었습니다.")
        return False


def check_redis():
    """Redis 서버 연결 확인"""
    print("\n🔍 Redis 서버 확인 중...")
    try:
        result = subprocess.run(
            ["redis-cli", "ping"],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode == 0 and "PONG" in result.stdout:
            print("✅ Redis 서버 정상 작동 중")
            return True
        else:
            print("❌ Redis 서버 응답 없음")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("❌ Redis 서버가 실행되지 않았거나 redis-cli를 찾을 수 없습니다.")
        print("   Redis 설치: https://redis.io/download")
        return False


def migrate(args):
    """데이터베이스 마이그레이션"""
    print("\n📦 데이터베이스 마이그레이션 시작...\n")

    # makemigrations
    if not run_command("uv run python manage.py makemigrations", "마이그레이션 파일 생성"):
        return False

    # migrate
    if not run_command("uv run python manage.py migrate", "마이그레이션 적용"):
        return False

    print("\n✅ 마이그레이션 완료!")
    return True


def create_superuser(args):
    """슈퍼유저 생성"""
    print("\n👤 슈퍼유저 생성\n")

    username = input("사용자명 (기본값: admin): ").strip() or "admin"
    email = input("이메일 (기본값: admin@weak.local): ").strip() or "admin@weak.local"
    password = input("비밀번호 (기본값: admin): ").strip() or "admin"

    command = f"""
from django.contrib.auth.models import User;
if not User.objects.filter(username='{username}').exists():
    User.objects.create_superuser('{username}', '{email}', '{password}');
    print('✅ 슈퍼유저 생성 완료: {username}');
else:
    print('⚠️  이미 존재하는 사용자입니다: {username}');
"""

    return run_command(
        f'uv run python manage.py shell -c "{command}"',
        "슈퍼유저 생성 중"
    )


def runserver(args):
    """Django 개발 서버 실행"""
    port = args.port or "8000"

    print(f"\n🚀 Django 개발 서버 시작 (포트: {port})...\n")
    print("   ⚠️  보안: 127.0.0.1 (localhost)에만 바인딩됩니다")
    print("   접속 주소: http://localhost:{}/".format(port))
    print("   API 문서: http://localhost:{}/api/docs/".format(port))
    print("   관리자: http://localhost:{}/admin/".format(port))
    print("\n   종료하려면 Ctrl+C를 누르세요.\n")

    # 127.0.0.1에만 바인딩 (외부 접근 차단)
    run_command(f"uv run python manage.py runserver 127.0.0.1:{port}", check=False)


def celery_worker(args):
    """Celery Worker 실행"""
    print("\n🔧 Celery Worker 시작...\n")
    print("   종료하려면 Ctrl+C를 누르세요.\n")

    # Windows의 경우 --pool=solo 사용
    pool_option = "--pool=solo" if sys.platform == "win32" else ""

    command = f"uv run celery -A config worker --loglevel=info {pool_option}".strip()
    run_command(command, check=False)


def celery_beat(args):
    """Celery Beat 실행 (주기적 작업)"""
    print("\n⏰ Celery Beat 시작...\n")
    print("   종료하려면 Ctrl+C를 누르세요.\n")

    run_command("uv run celery -A config beat --loglevel=info", check=False)


def test(args):
    """테스트 실행"""
    print("\n🧪 테스트 실행 중...\n")

    test_path = args.path or ""
    command = f"uv run python manage.py test {test_path}".strip()

    return run_command(command, "테스트 실행")


def shell(args):
    """Django Shell 실행"""
    print("\n🐍 Django Shell 시작...\n")
    run_command("uv run python manage.py shell", check=False)


def check_health(args):
    """시스템 상태 확인"""
    print("\n🏥 시스템 상태 확인\n")

    # Redis 확인
    redis_ok = check_redis()

    # Django 확인
    print("\n🔍 Django 설정 확인 중...")
    django_ok = run_command(
        "uv run python manage.py check",
        check=False
    )

    # 요약
    print("\n" + "="*60)
    print("  상태 요약")
    print("="*60)
    print(f"  Redis:  {'✅ 정상' if redis_ok else '❌ 오류'}")
    print(f"  Django: {'✅ 정상' if django_ok else '❌ 오류'}")
    print("="*60 + "\n")

    if redis_ok and django_ok:
        print("✅ 모든 시스템이 정상입니다!")
        return True
    else:
        print("⚠️  일부 시스템에 문제가 있습니다.")
        return False


def setup(args):
    """초기 설정 (마이그레이션 + 슈퍼유저)"""
    print("\n🔧 초기 설정 시작...\n")

    # 마이그레이션
    if not migrate(args):
        return False

    # 슈퍼유저 생성 확인
    print("\n슈퍼유저를 생성하시겠습니까? (y/n): ", end="")
    if input().lower() == 'y':
        create_superuser(args)

    print("\n✅ 초기 설정 완료!")
    print("\n다음 명령어로 서버를 시작하세요:")
    print("  1. Redis: redis-server")
    print("  2. Celery: python main.py celery")
    print("  3. Django: python main.py runserver")


def logs(args):
    """로그 보기"""
    log_file = "logs/scanner.log"

    if not os.path.exists(log_file):
        print(f"\n❌ 로그 파일을 찾을 수 없습니다: {log_file}")
        return False

    print(f"\n📋 로그 파일: {log_file}\n")

    if args.follow:
        # 실시간 로그 (tail -f)
        if sys.platform == "win32":
            run_command(f'powershell Get-Content {log_file} -Wait', check=False)
        else:
            run_command(f'tail -f {log_file}', check=False)
    else:
        # 마지막 N줄 출력
        lines = args.lines or 50
        if sys.platform == "win32":
            run_command(f'powershell Get-Content {log_file} -Tail {lines}', check=False)
        else:
            run_command(f'tail -n {lines} {log_file}', check=False)


def clean(args):
    """캐시 및 임시 파일 정리"""
    print("\n🧹 정리 시작...\n")

    patterns = [
        "**/__pycache__",
        "**/*.pyc",
        "**/*.pyo",
        ".pytest_cache",
        "*.log"
    ]

    import glob
    import shutil

    for pattern in patterns:
        for path in glob.glob(pattern, recursive=True):
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                    print(f"  삭제: {path}/")
                else:
                    os.remove(path)
                    print(f"  삭제: {path}")
            except Exception as e:
                print(f"  오류: {path} - {e}")

    print("\n✅ 정리 완료!")


def main():
    """메인 함수"""
    parser = argparse.ArgumentParser(
        description="Weak Scanner - 프로젝트 관리 도구",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예제:
  python main.py setup          # 초기 설정
  python main.py runserver      # Django 서버 시작
  python main.py celery         # Celery Worker 시작
  python main.py check          # 시스템 상태 확인
  python main.py logs -f        # 실시간 로그 보기
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='사용 가능한 명령어')

    # setup
    subparsers.add_parser('setup', help='초기 설정 (마이그레이션 + 슈퍼유저)')

    # migrate
    subparsers.add_parser('migrate', help='데이터베이스 마이그레이션')

    # createsuperuser
    subparsers.add_parser('createsuperuser', help='슈퍼유저 생성')

    # runserver
    parser_runserver = subparsers.add_parser('runserver', help='Django 개발 서버 실행')
    parser_runserver.add_argument('port', nargs='?', help='포트 번호 (기본값: 8000)')

    # celery
    subparsers.add_parser('celery', help='Celery Worker 실행')

    # celery-beat
    subparsers.add_parser('celery-beat', help='Celery Beat 실행')

    # test
    parser_test = subparsers.add_parser('test', help='테스트 실행')
    parser_test.add_argument('path', nargs='?', help='테스트 경로')

    # shell
    subparsers.add_parser('shell', help='Django Shell 실행')

    # check
    subparsers.add_parser('check', help='시스템 상태 확인')

    # logs
    parser_logs = subparsers.add_parser('logs', help='로그 보기')
    parser_logs.add_argument('-f', '--follow', action='store_true', help='실시간 로그 보기')
    parser_logs.add_argument('-n', '--lines', type=int, help='표시할 줄 수 (기본값: 50)')

    # clean
    subparsers.add_parser('clean', help='캐시 및 임시 파일 정리')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # 명령어 실행
    commands = {
        'setup': setup,
        'migrate': migrate,
        'createsuperuser': create_superuser,
        'runserver': runserver,
        'celery': celery_worker,
        'celery-beat': celery_beat,
        'test': test,
        'shell': shell,
        'check': check_health,
        'logs': logs,
        'clean': clean,
    }

    command_func = commands.get(args.command)
    if command_func:
        command_func(args)
    else:
        print(f"❌ 알 수 없는 명령어: {args.command}")
        parser.print_help()


if __name__ == "__main__":
    main()
