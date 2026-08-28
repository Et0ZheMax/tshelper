"""Пути к поставляемым ресурсам и пользовательским данным TSHelper."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parents[1]
FROZEN = bool(getattr(sys, "frozen", False))
BUNDLE_ROOT = Path(getattr(sys, "_MEIPASS", PROJECT_ROOT)).resolve()
INSTALL_ROOT = Path(sys.executable).resolve().parent if FROZEN else PROJECT_ROOT


def _first_existing(relative_path: str) -> Path:
    for base in (INSTALL_ROOT, BUNDLE_ROOT, PROJECT_ROOT):
        candidate = base / relative_path
        if candidate.exists():
            return candidate
    return PROJECT_ROOT / relative_path


ASSETS_DIR = _first_existing("assets")
BUNDLED_CONFIG_DIR = _first_existing("config")
ADHELPER2_DIR = _first_existing("apps/adhelper2")

_data_override = os.environ.get("TSHELPER_DATA_DIR", "").strip()
if _data_override:
    DATA_DIR = Path(_data_override).expanduser().resolve()
else:
    DATA_DIR = Path(os.environ.get("APPDATA") or Path.home()) / "TSHelper"
DATA_DIR.mkdir(parents=True, exist_ok=True)

CONFIG_FILE = DATA_DIR / "config.json"
USERS_FILE = DATA_DIR / "users.json"
DOCK_ITEMS_FILE = DATA_DIR / "dock_items.json"
LOG_FILE = DATA_DIR / "app.log"
PBX_DUMP_DIR = DATA_DIR / "_pbx_debug"
GLPI_INVENTORY_STATE_FILE = DATA_DIR / "glpi_inventory_state.json"


def asset_path(*parts: str) -> str:
    return str(ASSETS_DIR.joinpath(*parts))


def bundled_config_path(filename: str) -> str:
    return str(BUNDLED_CONFIG_DIR / filename)


def ensure_user_catalog(filename: str) -> str:
    """Создать редактируемую копию поставляемого каталога в профиле пользователя."""
    target = DATA_DIR / filename
    source = BUNDLED_CONFIG_DIR / filename
    if not target.exists() and source.is_file():
        shutil.copy2(source, target)
    return str(target)


def migrate_legacy_user_data() -> None:
    """Однократно скопировать данные старой раскладки из корня установки."""
    legacy_roots = [Path.cwd(), INSTALL_ROOT, PROJECT_ROOT]
    filenames = ("config.json", "users.json", "dock_items.json", ".ts_help_ad_secrets.json")
    for filename in filenames:
        target = DATA_DIR / filename
        if target.exists():
            continue
        for root in legacy_roots:
            source = root / filename
            if source.is_file() and source.resolve() != target.resolve():
                shutil.copy2(source, target)
                break
