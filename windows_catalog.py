from __future__ import annotations

import json
import os
import re
import tempfile
import time
from dataclasses import asdict
from typing import Any

from windows_catalog_models import (
    Architecture,
    DetectionConfig,
    DetectionType,
    RebootBehavior,
    SourceConfig,
    SourceKind,
    WindowsInstallType,
    WindowsPackage,
)
from windows_silent_presets import guess_silent_preset_from_args, normalize_silent_preset


class WindowsCatalogError(Exception):
    pass


class WindowsCatalogValidationError(WindowsCatalogError):
    pass


_SUPPORTED_INSTALL_TYPES = {item.value for item in WindowsInstallType}
_SUPPORTED_SOURCE_KINDS = {item.value for item in SourceKind}
_SUPPORTED_ARCH = {item.value for item in Architecture}
_SUPPORTED_REBOOT = {item.value for item in RebootBehavior}
_SUPPORTED_DETECTION = {item.value for item in DetectionType}
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
_SUPPORTED_OPERATORS = {"==", "!=", ">", "<", ">=", "<="}
_MAX_BACKUPS = 10


def _rotate_backups(catalog_path: str, keep_last: int) -> None:
    if keep_last < 1:
        return
    prefix = f"{os.path.basename(catalog_path)}.bak."
    folder = os.path.dirname(os.path.abspath(catalog_path)) or "."
    try:
        candidates = []
        for name in os.listdir(folder):
            if not name.startswith(prefix):
                continue
            full_path = os.path.join(folder, name)
            if not os.path.isfile(full_path):
                continue
            candidates.append(full_path)
        candidates.sort(key=lambda item: os.path.getmtime(item), reverse=True)
        for stale_backup in candidates[keep_last:]:
            try:
                os.remove(stale_backup)
            except Exception:
                continue
    except Exception:
        return


def _normalize_tags(tags: Any) -> list[str]:
    if isinstance(tags, str):
        tags = [token.strip() for token in tags.split(",")]
    if not isinstance(tags, list):
        return []
    return [str(tag).strip() for tag in tags if str(tag).strip()]


def _validate_source(raw: Any) -> SourceConfig:
    if not isinstance(raw, dict):
        raise WindowsCatalogValidationError("source должен быть объектом")
    kind = str(raw.get("kind", "")).strip().lower()
    value = str(raw.get("value", "")).strip()
    checksum = str(raw.get("checksum_sha256", "")).strip().lower()
    if kind not in _SUPPORTED_SOURCE_KINDS:
        raise WindowsCatalogValidationError(f"source.kind не поддерживается: {kind}")
    if not value:
        raise WindowsCatalogValidationError("source.value обязателен")
    if checksum and not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise WindowsCatalogValidationError("checksum_sha256 должен быть hex-строкой длиной 64")
    return SourceConfig(kind=SourceKind(kind), value=value, checksum_sha256=checksum)


def _validate_detection(raw: Any) -> DetectionConfig:
    if not isinstance(raw, dict):
        raise WindowsCatalogValidationError("detection должен быть объектом")
    dtype = str(raw.get("type", "")).strip().lower()
    if dtype not in _SUPPORTED_DETECTION:
        raise WindowsCatalogValidationError(f"detection.type не поддерживается: {dtype}")
    config = DetectionConfig(
        type=DetectionType(dtype),
        path=str(raw.get("path", "")).strip(),
        value_name=str(raw.get("value_name", "")).strip(),
        operator=str(raw.get("operator", "==")).strip(),
        value=str(raw.get("value", "")).strip(),
        command=[str(x) for x in raw.get("command", [])] if isinstance(raw.get("command", []), list) else [],
        script=str(raw.get("script", "")).strip(),
    )
    if config.type in {DetectionType.FILE_EXISTS, DetectionType.REGISTRY_EXISTS, DetectionType.REGISTRY_VALUE} and not config.path:
        raise WindowsCatalogValidationError("Для detection требуется поле path")
    if config.type == DetectionType.REGISTRY_VALUE and not config.value_name:
        raise WindowsCatalogValidationError("Для registry_value требуется value_name")
    if config.type == DetectionType.REGISTRY_VALUE and config.operator not in _SUPPORTED_OPERATORS:
        raise WindowsCatalogValidationError(f"Для registry_value operator должен быть одним из: {sorted(_SUPPORTED_OPERATORS)}")
    if config.type in {DetectionType.UNINSTALL_DISPLAY_NAME, DetectionType.PRODUCT_CODE} and not config.value:
        raise WindowsCatalogValidationError("Для uninstall/product_code требуется value")
    if config.type == DetectionType.COMMAND_SUCCESS and not config.command:
        raise WindowsCatalogValidationError("Для command_success требуется непустой command")
    if config.type == DetectionType.POWERSHELL_SCRIPT and not config.script:
        raise WindowsCatalogValidationError("Для powershell_script требуется script")
    return config


def validate_windows_package(raw: dict[str, Any], existing_ids: set[str] | None = None, current_id: str = "") -> WindowsPackage:
    package_id = str(raw.get("id", "")).strip().lower()
    if not _ID_RE.fullmatch(package_id):
        raise WindowsCatalogValidationError("id должен быть в формате [a-z0-9][a-z0-9_-]{1,63}")
    ids = existing_ids or set()
    if package_id != current_id and package_id in ids:
        raise WindowsCatalogValidationError(f"id уже существует: {package_id}")

    install_type = str(raw.get("install_type", "")).strip().lower()
    if install_type not in _SUPPORTED_INSTALL_TYPES:
        raise WindowsCatalogValidationError(f"install_type не поддерживается: {install_type}")

    os_family = str(raw.get("os_family", "")).strip().lower()
    if os_family != "windows":
        raise WindowsCatalogValidationError("os_family должен быть windows")

    timeout_sec = int(raw.get("timeout_sec", 1200) or 1200)
    if timeout_sec < 30 or timeout_sec > 7200:
        raise WindowsCatalogValidationError("timeout_sec должен быть в диапазоне 30..7200")

    silent_args = raw.get("silent_args", [])
    if not isinstance(silent_args, list) or not all(isinstance(arg, str) for arg in silent_args):
        raise WindowsCatalogValidationError("silent_args должен быть списком строк")
    silent_preset_raw = str(raw.get("silent_preset", "")).strip().lower()
    if install_type == "exe":
        silent_preset = normalize_silent_preset(silent_preset_raw or guess_silent_preset_from_args(install_type, silent_args), install_type=install_type)
    else:
        silent_preset = "custom"

    architecture = str(raw.get("architecture", "any")).strip().lower()
    if architecture not in _SUPPORTED_ARCH:
        raise WindowsCatalogValidationError(f"architecture не поддерживается: {architecture}")

    reboot_behavior = str(raw.get("reboot_behavior", "auto_detect")).strip().lower()
    if reboot_behavior not in _SUPPORTED_REBOOT:
        raise WindowsCatalogValidationError(f"reboot_behavior не поддерживается: {reboot_behavior}")

    title = str(raw.get("title", "")).strip()
    if not title:
        raise WindowsCatalogValidationError("title обязателен")

    return WindowsPackage(
        package_id=package_id,
        title=title,
        os_family="windows",
        install_type=WindowsInstallType(install_type),
        description=str(raw.get("description", "")).strip(),
        tags=_normalize_tags(raw.get("tags", [])),
        enabled=bool(raw.get("enabled", True)),
        requires_admin=bool(raw.get("requires_admin", True)),
        timeout_sec=timeout_sec,
        source=_validate_source(raw.get("source", {})),
        silent_args=[arg for arg in silent_args if arg.strip()],
        silent_preset=silent_preset,
        detection=_validate_detection(raw.get("detection", {})),
        execution_defaults=raw.get("execution_defaults", {}) if isinstance(raw.get("execution_defaults", {}), dict) else {},
        package_version=str(raw.get("package_version", raw.get("version", ""))).strip(),
        architecture=Architecture(architecture),
        reboot_behavior=RebootBehavior(reboot_behavior),
    )


class WindowsSoftwareCatalog:
    def __init__(self, items: list[WindowsPackage], source_path: str):
        self._items = {item.package_id: item for item in items}
        self.source_path = source_path

    @classmethod
    def load(cls, catalog_path: str) -> "WindowsSoftwareCatalog":
        payload = load_catalog_payload(catalog_path)
        items: list[WindowsPackage] = []
        seen_ids: set[str] = set()
        for raw in payload.get("software", []):
            item = validate_windows_package(raw, existing_ids=seen_ids)
            seen_ids.add(item.package_id)
            items.append(item)
        return cls(items=items, source_path=catalog_path)

    def all_items(self, enabled_only: bool = False) -> list[WindowsPackage]:
        values = list(self._items.values())
        if enabled_only:
            values = [item for item in values if item.enabled]
        return values

    def get(self, package_id: str) -> WindowsPackage:
        item = self._items.get(package_id)
        if not item:
            raise WindowsCatalogError(f"Пакет не найден: {package_id}")
        return item


def load_catalog_payload(catalog_path: str) -> dict[str, Any]:
    try:
        with open(catalog_path, "r", encoding="utf-8") as file_obj:
            payload = json.load(file_obj)
    except FileNotFoundError as exc:
        raise WindowsCatalogError(f"Файл Windows-каталога не найден: {catalog_path}") from exc
    except json.JSONDecodeError as exc:
        raise WindowsCatalogError(f"Windows-каталог содержит невалидный JSON: {exc}") from exc
    software = payload.get("software")
    if not isinstance(software, list):
        raise WindowsCatalogError("Корневой ключ software должен быть списком")
    return payload


def save_catalog_payload(catalog_path: str, payload: dict[str, Any]) -> None:
    folder = os.path.dirname(os.path.abspath(catalog_path)) or "."
    os.makedirs(folder, exist_ok=True)
    backup_path = f"{catalog_path}.bak.{int(time.time())}"
    if os.path.exists(catalog_path):
        with open(catalog_path, "rb") as source, open(backup_path, "wb") as backup:
            backup.write(source.read())
        _rotate_backups(catalog_path, keep_last=_MAX_BACKUPS)
    fd, temp_path = tempfile.mkstemp(prefix="software_catalog_windows_", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file_obj:
            json.dump(payload, file_obj, ensure_ascii=False, indent=2)
            file_obj.flush()
            os.fsync(file_obj.fileno())
        os.replace(temp_path, catalog_path)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def package_to_payload(item: WindowsPackage) -> dict[str, Any]:
    payload = asdict(item)
    payload["id"] = payload.pop("package_id")
    return payload


def upsert_windows_package(catalog_path: str, raw_entry: dict[str, Any], current_id: str = "") -> dict[str, Any]:
    payload = load_catalog_payload(catalog_path)
    software = payload.get("software", [])
    existing_ids = {str(item.get("id", "")).strip().lower() for item in software if isinstance(item, dict)}
    package = validate_windows_package(raw_entry, existing_ids=existing_ids, current_id=current_id)
    normalized = package_to_payload(package)

    replaced = False
    target_id = (current_id or package.package_id).strip().lower()
    for index, row in enumerate(software):
        if isinstance(row, dict) and str(row.get("id", "")).strip().lower() == target_id:
            software[index] = normalized
            replaced = True
            break
    if not replaced:
        software.append(normalized)
    save_catalog_payload(catalog_path, payload)
    return normalized


def disable_windows_package(catalog_path: str, package_id: str) -> None:
    payload = load_catalog_payload(catalog_path)
    found = False
    for row in payload.get("software", []):
        if isinstance(row, dict) and str(row.get("id", "")).strip().lower() == package_id.lower():
            row["enabled"] = False
            found = True
            break
    if not found:
        raise WindowsCatalogError(f"Пакет не найден: {package_id}")
    save_catalog_payload(catalog_path, payload)


def delete_windows_package(catalog_path: str, package_id: str) -> None:
    payload = load_catalog_payload(catalog_path)
    software = payload.get("software", [])
    filtered = [row for row in software if not (isinstance(row, dict) and str(row.get("id", "")).strip().lower() == package_id.lower())]
    if len(filtered) == len(software):
        raise WindowsCatalogError(f"Пакет не найден: {package_id}")
    payload["software"] = filtered
    save_catalog_payload(catalog_path, payload)
