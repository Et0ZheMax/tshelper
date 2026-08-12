from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..constants import SCRIPTS_DIR


class PowerShellError(RuntimeError):
    def __init__(self, message: str, *, returncode: int = -1, stdout: str = "", stderr: str = "") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class PowerShellTimeoutError(PowerShellError):
    pass


@dataclass(slots=True)
class PowerShellResponse:
    ok: bool
    data: Any
    message: str = ""
    warnings: list[str] | None = None
    raw_stdout: str = ""
    raw_stderr: str = ""


class PowerShellClient:
    """Runs immutable PowerShell scripts and sends all user data through UTF-8 JSON stdin."""

    def __init__(self, scripts_dir: Path | None = None, logger: Callable[[str], None] | None = None) -> None:
        self.scripts_dir = scripts_dir or SCRIPTS_DIR
        self.logger = logger or (lambda _message: None)
        self.executable = self._find_executable()

    @staticmethod
    def _find_executable() -> str:
        for name in ("powershell.exe", "powershell", "pwsh.exe", "pwsh"):
            path = shutil.which(name)
            if path:
                return path
        return "powershell.exe" if os.name == "nt" else "pwsh"

    def invoke(self, action: str, payload: dict[str, Any] | None = None, timeout: int = 120) -> PowerShellResponse:
        script_path = (self.scripts_dir / f"{action}.ps1").resolve()
        if not script_path.exists():
            raise PowerShellError(f"PowerShell-операция не найдена: {script_path}")
        body = json.dumps(payload or {}, ensure_ascii=False)
        command = [
            self.executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-File", str(script_path),
        ]
        self.logger(f"[ps] {action}: запуск {script_path.name}")
        try:
            proc = subprocess.run(
                command,
                input=body,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            raise PowerShellTimeoutError(f"Операция '{action}' превысила тайм-аут {timeout} сек.") from exc
        except OSError as exc:
            raise PowerShellError(f"Не удалось запустить PowerShell: {exc}") from exc

        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        if stderr:
            self.logger(f"[ps:{action}:stderr] {stderr[:1200]}")

        # Скрипты возвращают структурированный JSON даже при exit 1. Сначала
        # разбираем его, чтобы пользователь видел нормальный текст ошибки, а не
        # целиком экранированный JSON из окна PowerShell.
        decoded: Any = None
        decode_error: json.JSONDecodeError | None = None
        if stdout:
            try:
                decoded = json.loads(stdout.lstrip("\ufeff"))
            except json.JSONDecodeError as exc:
                decode_error = exc

        if isinstance(decoded, dict):
            ok = bool(decoded.get("ok", True))
            response = PowerShellResponse(
                ok=ok,
                data=decoded.get("data"),
                message=str(decoded.get("message") or ""),
                warnings=[str(x) for x in (decoded.get("warnings") or [])],
                raw_stdout=stdout,
                raw_stderr=stderr,
            )
            if not ok:
                raise PowerShellError(
                    response.message or f"Операция '{action}' завершилась ошибкой",
                    returncode=proc.returncode,
                    stdout=stdout,
                    stderr=stderr,
                )
            if proc.returncode != 0:
                message = stderr or response.message or f"PowerShell завершился с кодом {proc.returncode}"
                raise PowerShellError(message, returncode=proc.returncode, stdout=stdout, stderr=stderr)
            return response

        if proc.returncode != 0:
            message = stderr or stdout or f"PowerShell завершился с кодом {proc.returncode}"
            raise PowerShellError(message, returncode=proc.returncode, stdout=stdout, stderr=stderr)
        if not stdout:
            return PowerShellResponse(ok=True, data=None, raw_stdout=stdout, raw_stderr=stderr)
        if decode_error is not None:
            raise PowerShellError(
                f"Операция '{action}' вернула некорректный JSON: {stdout[:500]}",
                returncode=proc.returncode,
                stdout=stdout,
                stderr=stderr,
            ) from decode_error
        return PowerShellResponse(ok=True, data=decoded, raw_stdout=stdout, raw_stderr=stderr)
