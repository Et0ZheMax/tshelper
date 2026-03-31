from __future__ import annotations

import os
import subprocess
from typing import Sequence

from windows_catalog_models import DetectionConfig, DetectionResult, DetectionType


def _run(command: Sequence[str], timeout_sec: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def run_detection(config: DetectionConfig, timeout_sec: int = 30) -> DetectionResult:
    try:
        if config.type == DetectionType.FILE_EXISTS:
            exists = os.path.exists(config.path)
            return DetectionResult(detected=exists, details=f"file_exists: {config.path}")

        if config.type == DetectionType.REGISTRY_EXISTS:
            cp = _run(["reg", "query", config.path], timeout_sec)
            return DetectionResult(
                detected=cp.returncode == 0,
                details=f"registry_exists: {config.path}",
                raw_output=(cp.stdout or "") + (cp.stderr or ""),
                error=None if cp.returncode == 0 else "Ключ не найден",
            )

        if config.type == DetectionType.REGISTRY_VALUE:
            cp = _run(["reg", "query", config.path, "/v", config.value_name], timeout_sec)
            raw = (cp.stdout or "") + (cp.stderr or "")
            if cp.returncode != 0:
                return DetectionResult(False, f"registry_value: {config.path}", raw_output=raw, error="Значение не найдено")
            detected = str(config.value).lower() in raw.lower()
            return DetectionResult(detected, f"registry_value: {config.path}/{config.value_name}", raw_output=raw)

        if config.type == DetectionType.UNINSTALL_DISPLAY_NAME:
            script = (
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* ,"
                "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
                "| Select-Object -ExpandProperty DisplayName"
            )
            cp = _run(["powershell", "-NoProfile", "-Command", script], timeout_sec)
            text = (cp.stdout or "") + (cp.stderr or "")
            detected = config.value.lower() in text.lower()
            return DetectionResult(detected, "uninstall_display_name", raw_output=text)

        if config.type == DetectionType.PRODUCT_CODE:
            script = (
                "Get-ChildItem HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall,"
                "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall "
                "| Select-Object -ExpandProperty PSChildName"
            )
            cp = _run(["powershell", "-NoProfile", "-Command", script], timeout_sec)
            text = (cp.stdout or "") + (cp.stderr or "")
            detected = config.value.lower() in text.lower()
            return DetectionResult(detected, "product_code", raw_output=text)

        if config.type == DetectionType.COMMAND_SUCCESS:
            cp = _run(config.command, timeout_sec)
            return DetectionResult(
                detected=cp.returncode == 0,
                details="command_success",
                raw_output=(cp.stdout or "") + (cp.stderr or ""),
                error=None if cp.returncode == 0 else f"Код выхода {cp.returncode}",
            )

        if config.type == DetectionType.POWERSHELL_SCRIPT:
            cp = _run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", config.script], timeout_sec)
            text = ((cp.stdout or "") + (cp.stderr or "")).strip().lower()
            detected = cp.returncode == 0 and text not in {"false", "0", ""}
            return DetectionResult(detected, "powershell_script", raw_output=text, error=None if cp.returncode == 0 else f"Код {cp.returncode}")

        return DetectionResult(False, "unsupported_detection", error=f"Неподдерживаемый detection: {config.type}")
    except subprocess.TimeoutExpired:
        return DetectionResult(False, "timeout", error=f"Timeout при detection: {config.type.value}")
    except Exception as exc:
        return DetectionResult(False, "error", error=str(exc))
