from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any


_INSTALL_BY_EXT = {
    ".msi": "msi",
    ".msix": "msix",
    ".ps1": "powershell",
    ".cmd": "cmd",
    ".bat": "cmd",
    ".exe": "exe",
}

_ARCH_HINTS = {
    "x64": "x64",
    "amd64": "x64",
    "64": "x64",
    "x86": "x86",
    "win32": "x86",
    "32": "x86",
}


@dataclass(slots=True)
class DetectionSuggestion:
    title: str
    detection: dict[str, Any]
    confidence: str
    reason: str


@dataclass(slots=True)
class AutofillResult:
    fields: dict[str, Any] = field(default_factory=dict)
    detection_suggestions: list[DetectionSuggestion] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class InstallerInsight:
    path: str
    file_name: str
    stem: str
    install_type: str
    source_kind: str
    title: str
    package_version: str
    architecture: str
    normalized_id: str
    msi_metadata: dict[str, str] = field(default_factory=dict)


def normalize_package_id(raw_title: str) -> str:
    text = raw_title.strip().lower()
    replacements = {
        "vc++": "vc",
        "c++": "cpp",
        "7-zip": "7zip",
        "7 zip": "7zip",
        "visual c": "vc",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = re.sub(r"_{2,}", "_", text).strip("_")
    if not text:
        return "windows_package"
    if not re.match(r"^[a-z0-9]", text):
        text = f"pkg_{text}"
    return text[:64]


def analyze_installer(path: str) -> AutofillResult:
    insight = _build_insight(path)
    fields: dict[str, Any] = {
        "id": insight.normalized_id,
        "title": insight.title,
        "install_type": insight.install_type,
        "package_version": insight.package_version,
        "architecture": insight.architecture,
        "source": {
            "kind": insight.source_kind,
            "value": insight.path,
        },
        "silent_args": _default_silent_args(insight.install_type),
        "reboot_behavior": "auto_detect",
        "requires_admin": True,
    }

    suggestions = _build_detection_suggestions(insight)
    if suggestions:
        fields["detection"] = suggestions[0].detection

    notes: list[str] = [f"Тип установщика определён по расширению: {insight.install_type}."]
    if insight.msi_metadata:
        notes.append("MSI-метаданные извлечены из таблицы Property.")
    else:
        notes.append("Часть полей заполнена эвристически по имени файла.")
    if insight.install_type == "exe":
        notes.append("Для EXE silent_args оставлены пустыми: уточните параметры у вендора.")

    return AutofillResult(fields=fields, detection_suggestions=suggestions, notes=notes)


def suggest_detection_from_payload(payload: dict[str, Any]) -> list[DetectionSuggestion]:
    source = payload.get("source", {}) if isinstance(payload.get("source", {}), dict) else {}
    source_path = str(source.get("value", "")).strip()
    install_type = str(payload.get("install_type", "")).strip().lower()
    title = str(payload.get("title", "")).strip()
    package_version = str(payload.get("package_version", payload.get("version", ""))).strip()
    architecture = str(payload.get("architecture", "any")).strip().lower()

    insight = _build_insight(source_path)
    insight.install_type = install_type or insight.install_type
    insight.title = title or insight.title
    insight.package_version = package_version or insight.package_version
    insight.architecture = architecture or insight.architecture

    raw_detection = payload.get("detection", {}) if isinstance(payload.get("detection", {}), dict) else {}
    if "value" in raw_detection and str(raw_detection.get("value", "")).strip() and not insight.msi_metadata.get("ProductCode"):
        insight.msi_metadata["ProductCode"] = str(raw_detection.get("value", "")).strip()

    return _build_detection_suggestions(insight)


def _build_insight(path: str) -> InstallerInsight:
    normalized_path = path.strip()
    file_name = os.path.basename(normalized_path)
    stem, ext = os.path.splitext(file_name)
    install_type = _INSTALL_BY_EXT.get(ext.lower(), "exe")
    source_kind = "unc_path" if normalized_path.startswith("\\\\") else "file_path"

    title, version, architecture = _parse_name_hints(stem)
    metadata: dict[str, str] = {}
    if install_type == "msi" and normalized_path:
        metadata = _extract_msi_metadata(normalized_path)
        if metadata.get("ProductName"):
            title = metadata["ProductName"]
        if metadata.get("ProductVersion"):
            version = metadata["ProductVersion"]
        if metadata.get("Template"):
            architecture = _architecture_from_template(metadata["Template"]) or architecture

    normalized_id = normalize_package_id(title or stem)
    if not title:
        title = stem or "Новый пакет Windows"

    return InstallerInsight(
        path=normalized_path,
        file_name=file_name,
        stem=stem,
        install_type=install_type,
        source_kind=source_kind,
        title=title,
        package_version=version,
        architecture=architecture,
        normalized_id=normalized_id,
        msi_metadata=metadata,
    )


def _parse_name_hints(stem: str) -> tuple[str, str, str]:
    clean = stem.replace("_", " ").replace("-", " ")
    version_match = re.search(r"\b\d+(?:\.\d+){1,3}\b", clean)
    version = version_match.group(0) if version_match else ""
    architecture = "any"
    lower = clean.lower()
    for token, arch in _ARCH_HINTS.items():
        if re.search(rf"\b{re.escape(token)}\b", lower):
            architecture = arch
            break

    title = clean
    if version:
        title = title.replace(version, " ")
    title = re.sub(r"\b(setup|installer|install|win|windows|release)\b", " ", title, flags=re.IGNORECASE)
    title = re.sub(r"\s+", " ", title).strip(" _-")
    return (title or stem), version, architecture


def _extract_msi_metadata(path: str) -> dict[str, str]:
    if not os.path.exists(path):
        return {}
    ps_script = r'''
param([string]$MsiPath)
$ErrorActionPreference = 'Stop'
$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$installer,@($MsiPath,0))
function Get-MsiProperty([object]$Database,[string]$Name) {
  $view = $Database.OpenView("SELECT `Value` FROM `Property` WHERE `Property`='$Name'")
  $view.Execute()
  $record = $view.Fetch()
  if ($record -ne $null) { return $record.StringData(1) }
  return ''
}
$result = @{
  ProductName = Get-MsiProperty -Database $db -Name 'ProductName'
  ProductVersion = Get-MsiProperty -Database $db -Name 'ProductVersion'
  ProductCode = Get-MsiProperty -Database $db -Name 'ProductCode'
  Manufacturer = Get-MsiProperty -Database $db -Name 'Manufacturer'
  Template = Get-MsiProperty -Database $db -Name 'Template'
}
$result | ConvertTo-Json -Compress
'''.strip()
    command = ["powershell", "-NoProfile", "-Command", ps_script, "-MsiPath", path]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return {}
    if completed.returncode != 0 or not (completed.stdout or "").strip():
        return {}
    try:
        data = json.loads((completed.stdout or "").strip())
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): str(value).strip() for key, value in data.items() if str(value).strip()}


def _architecture_from_template(template: str) -> str:
    text = template.lower()
    if "x64" in text or "amd64" in text:
        return "x64"
    if ";1033" in text or "intel" in text:
        return "x86"
    return "any"


def _default_silent_args(install_type: str) -> list[str]:
    if install_type == "msi":
        return []
    return []


def _build_detection_suggestions(insight: InstallerInsight) -> list[DetectionSuggestion]:
    suggestions: list[DetectionSuggestion] = []

    if insight.install_type == "msi":
        product_code = insight.msi_metadata.get("ProductCode", "")
        if product_code:
            suggestions.append(
                DetectionSuggestion(
                    title="MSI ProductCode",
                    detection={"type": "product_code", "value": product_code},
                    confidence="high",
                    reason="Надёжно для MSI-пакетов с известным ProductCode.",
                )
            )
        if insight.title:
            suggestions.append(
                DetectionSuggestion(
                    title="Uninstall DisplayName",
                    detection={"type": "uninstall_display_name", "value": insight.title},
                    confidence="medium",
                    reason="Поиск по DisplayName в uninstall-ветках реестра.",
                )
            )

    if insight.install_type == "exe":
        if insight.title:
            suggestions.append(
                DetectionSuggestion(
                    title="Uninstall DisplayName",
                    detection={"type": "uninstall_display_name", "value": insight.title},
                    confidence="medium",
                    reason="Типовой вариант для EXE, если вендор регистрирует uninstall key.",
                )
            )
        exe_name = insight.file_name or f"{insight.normalized_id}.exe"
        program_files = "%ProgramFiles%"
        suggestions.append(
            DetectionSuggestion(
                title="File Exists (Program Files)",
                detection={"type": "file_exists", "path": f"{program_files}\\{insight.title}\\{exe_name}"},
                confidence="low",
                reason="Эвристика по типичному пути установки, требует проверки оператором.",
            )
        )

    if not suggestions:
        suggestions.append(
            DetectionSuggestion(
                title="Черновик file_exists",
                detection={"type": "file_exists", "path": ""},
                confidence="low",
                reason="Автоопределение неуверенное: заполните путь вручную.",
            )
        )
    return suggestions
