"""
ScannerRegistry - 스캐너 자동 디스커버리 및 관리 시스템

scanners/ 디렉토리에서 모든 스캐너를 자동으로 발견하고 등록
"""

import os
import sys
import inspect
import logging
import importlib
from pathlib import Path
from typing import Dict, List, Type, Any, Optional
from .base import BaseScanner


class ScannerRegistry:
    """
    스캐너 자동 디스커버리 및 중앙 관리 시스템

    기능:
    - scanners/ 디렉토리에서 모든 스캐너 자동 발견
    - 메타데이터 기반 카테고리 분류
    - 스캐너 인스턴스 생성 및 관리
    - field mapping 자동 생성
    """

    _instance = None
    _scanners: Dict[str, Type[BaseScanner]] = {}
    _initialized = False

    def __new__(cls):
        """싱글톤 패턴"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """레지스트리 초기화"""
        if not self._initialized:
            self.logger = logging.getLogger(self.__class__.__name__)
            self._scanners = {}
            self._categories = {
                'security_basic': [],
                'security_advanced': [],
                'api_auth': [],
                'business_logic': [],
                'supply_chain': [],
                'data_integrity': [],
            }
            self._field_mapping = {}
            self._initialized = True

    def discover_scanners(self, force_reload: bool = False) -> Dict[str, Type[BaseScanner]]:
        """
        scanners/ 디렉토리에서 모든 스캐너 자동 발견

        Args:
            force_reload: True일 경우 캐시 무시하고 재로드

        Returns:
            발견된 스캐너 딕셔너리 {scanner_id: scanner_class}
        """
        if self._scanners and not force_reload:
            return self._scanners

        self._scanners = {}
        scanners_dir = Path(__file__).parent.parent / 'scanners'

        if not scanners_dir.exists():
            self.logger.warning(f"Scanners directory not found: {scanners_dir}")
            return self._scanners

        # scanners 디렉토리를 sys.path에 추가
        scanner_parent = str(scanners_dir.parent)
        if scanner_parent not in sys.path:
            sys.path.insert(0, scanner_parent)

        # 모든 *.py 파일 검색 (__init__.py 제외)
        for file_path in scanners_dir.glob('*.py'):
            if file_path.name == '__init__.py':
                continue
            try:
                # 모듈 이름 (확장자 제외)
                module_name = file_path.stem

                # 모듈 임포트
                module_full_name = f'scanner.scanners.{module_name}'

                # 이미 로드된 모듈이면 리로드
                if module_full_name in sys.modules and force_reload:
                    module = importlib.reload(sys.modules[module_full_name])
                else:
                    module = importlib.import_module(f'scanners.{module_name}', package='scanner')

                # 모듈에서 BaseScanner 서브클래스 찾기
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and
                        issubclass(obj, BaseScanner) and
                        obj != BaseScanner and
                        hasattr(obj, 'metadata')):

                        # 메타데이터에서 ID 추출
                        scanner_id = obj.metadata.get('id')
                        if scanner_id:
                            self._scanners[scanner_id] = obj

                            # 카테고리별 분류
                            category = obj.metadata.get('category', 'security_basic')
                            if category in self._categories:
                                self._categories[category].append(scanner_id)

                            # field mapping 추가
                            field = obj.metadata.get('field')
                            if field:
                                self._field_mapping[scanner_id] = field

                                # 별칭 처리
                                aliases = obj.metadata.get('aliases', [])
                                for alias in aliases:
                                    self._field_mapping[alias] = field

                            self.logger.debug(f"Discovered scanner: {scanner_id} from {module_name}")

            except Exception as e:
                self.logger.error(f"Failed to load scanner from {file_path}: {str(e)}", exc_info=True)

        self.logger.info(f"Discovered {len(self._scanners)} scanners")
        return self._scanners

    def get_scanner_class(self, scanner_id: str) -> Optional[Type[BaseScanner]]:
        """
        스캐너 ID로 클래스 가져오기

        Args:
            scanner_id: 스캐너 ID

        Returns:
            스캐너 클래스 또는 None
        """
        if not self._scanners:
            self.discover_scanners()

        return self._scanners.get(scanner_id)

    def get_scanners_by_category(self, category: str) -> List[Type[BaseScanner]]:
        """
        카테고리별 스캐너 목록 가져오기

        Args:
            category: 카테고리 이름

        Returns:
            스캐너 클래스 목록
        """
        if not self._scanners:
            self.discover_scanners()

        scanner_ids = self._categories.get(category, [])
        return [self._scanners[sid] for sid in scanner_ids if sid in self._scanners]

    def get_security_scanners(self) -> List[Type[BaseScanner]]:
        """
        모든 보안 스캐너 가져오기

        Returns:
            보안 스캐너 클래스 목록
        """
        scanners = []
        for category in ['security_basic', 'security_advanced', 'api_auth',
                        'business_logic', 'supply_chain', 'data_integrity']:
            scanners.extend(self.get_scanners_by_category(category))
        return scanners

    def get_field_mapping(self) -> Dict[str, str]:
        """
        스캐너 ID -> DB 필드 매핑 가져오기

        Returns:
            {scanner_id: field_name} 딕셔너리
        """
        if not self._scanners:
            self.discover_scanners()

        return self._field_mapping.copy()

    def get_scanner_metadata(self, scanner_id: str) -> Optional[Dict[str, Any]]:
        """
        스캐너 메타데이터 가져오기

        Args:
            scanner_id: 스캐너 ID

        Returns:
            메타데이터 딕셔너리 또는 None
        """
        scanner_class = self.get_scanner_class(scanner_id)
        if scanner_class:
            return scanner_class.metadata.copy()
        return None

    def create_scanner_instance(self, scanner_id: str, **kwargs) -> Optional[BaseScanner]:
        """
        스캐너 인스턴스 생성

        Args:
            scanner_id: 스캐너 ID
            **kwargs: 스캐너 생성자 인자

        Returns:
            스캐너 인스턴스 또는 None
        """
        scanner_class = self.get_scanner_class(scanner_id)
        if scanner_class:
            try:
                return scanner_class(**kwargs)
            except Exception as e:
                self.logger.error(f"Failed to create scanner instance for {scanner_id}: {str(e)}")
        return None

    def get_all_scanner_info(self) -> List[Dict[str, Any]]:
        """
        모든 스캐너의 정보 목록 가져오기

        Returns:
            스캐너 정보 딕셔너리 목록
        """
        if not self._scanners:
            self.discover_scanners()

        info_list = []
        for scanner_id, scanner_class in self._scanners.items():
            info = scanner_class.metadata.copy()
            info['id'] = scanner_id
            info['class_name'] = scanner_class.__name__
            info['module'] = scanner_class.__module__
            info_list.append(info)

        return info_list

    def get_scanner_count_by_category(self) -> Dict[str, int]:
        """
        카테고리별 스캐너 수 가져오기

        Returns:
            {category: count} 딕셔너리
        """
        if not self._scanners:
            self.discover_scanners()

        return {
            category: len(scanner_ids)
            for category, scanner_ids in self._categories.items()
        }

    def validate_scanner(self, scanner_id: str) -> bool:
        """
        스캐너가 유효한지 확인

        Args:
            scanner_id: 스캐너 ID

        Returns:
            유효하면 True
        """
        scanner_class = self.get_scanner_class(scanner_id)
        if not scanner_class:
            return False

        # 필수 메타데이터 확인
        required_fields = ['id', 'name', 'field']
        metadata = scanner_class.metadata

        for field in required_fields:
            if field not in metadata:
                self.logger.warning(f"Scanner {scanner_id} missing required field: {field}")
                return False

        # _execute_scan 메서드 확인
        if not hasattr(scanner_class, '_execute_scan'):
            self.logger.warning(f"Scanner {scanner_id} missing _execute_scan method")
            return False

        return True


# 싱글톤 인스턴스 생성
scanner_registry = ScannerRegistry()
# 전역 레지스트리 인스턴스
registry = ScannerRegistry()