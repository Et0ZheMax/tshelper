from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from typing import Callable

from windows_catalog_models import BackendContext, ExecutionResult, SourceKind, WindowsInstallType, WindowsPackage


class WindowsExecutionBackend(ABC):
    def __init__(self, logger: Callable[[str], None] | None = None):
        self.logger = logger or (lambda _msg: None)

    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def prepare_payload(self, package: WindowsPackage, context: BackendContext) -> str:
        raise NotImplementedError

    @abstractmethod
    def run_install(self, package: WindowsPackage, context: BackendContext, payload_path: str) -> ExecutionResult:
        raise NotImplementedError

    @abstractmethod
    def cleanup(self, payload_path: str, context: BackendContext) -> None:
        raise NotImplementedError


class LocalSubprocessBackend(WindowsExecutionBackend):
    @property
    def name(self) -> str:
        return "local_subprocess"

    def prepare_payload(self, package: WindowsPackage, context: BackendContext) -> str:
        source = package.source
        if source.kind == SourceKind.WINGET_ID:
            return source.value
        if source.kind not in {SourceKind.FILE_PATH, SourceKind.UNC_PATH}:
            raise RuntimeError(f"Локальный backend не поддерживает source.kind={source.kind.value}")
        if not os.path.exists(source.value):
            raise FileNotFoundError(f"Источник не найден: {source.value}")
        return source.value

    def _build_command(self, package: WindowsPackage, payload_path: str) -> list[str]:
        if package.install_type == WindowsInstallType.EXE:
            return [payload_path, *package.silent_args]
        if package.install_type == WindowsInstallType.MSI:
            return ["msiexec.exe", "/i", payload_path, "/qn", "/norestart", *package.silent_args]
        if package.install_type == WindowsInstallType.MSIX:
            return [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                f"Add-AppxPackage -Path '{payload_path}'",
            ]
        if package.install_type == WindowsInstallType.POWERSHELL:
            return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", payload_path, *package.silent_args]
        if package.install_type == WindowsInstallType.CMD:
            return ["cmd.exe", "/c", payload_path, *package.silent_args]
        if package.install_type == WindowsInstallType.WINGET:
            return [
                "winget",
                "install",
                "--id",
                payload_path,
                "--silent",
                "--accept-package-agreements",
                "--accept-source-agreements",
                *package.silent_args,
            ]
        raise RuntimeError(f"Неподдерживаемый install_type: {package.install_type.value}")

    def run_install(self, package: WindowsPackage, context: BackendContext, payload_path: str) -> ExecutionResult:
        command = self._build_command(package, payload_path)
        self.logger(f"[deploy] cmd={command}")
        try:
            cp = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=context.timeout_sec,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return ExecutionResult(
                exit_code=cp.returncode,
                stdout=cp.stdout or "",
                stderr=cp.stderr or "",
                payload_path_used=payload_path,
                command_preview=" ".join(command[:4]) + (" ..." if len(command) > 4 else ""),
            )
        except subprocess.TimeoutExpired as exc:
            return ExecutionResult(
                exit_code=-1,
                stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
                stderr=(exc.stderr or "") if isinstance(exc.stderr, str) else "",
                timed_out=True,
                payload_path_used=payload_path,
                command_preview=" ".join(command[:4]) + (" ..." if len(command) > 4 else ""),
            )
        except FileNotFoundError as exc:
            return ExecutionResult(exit_code=-2, stdout="", stderr=str(exc), transport_error="Команда не найдена", payload_path_used=payload_path)
        except Exception as exc:
            return ExecutionResult(exit_code=-3, stdout="", stderr=str(exc), transport_error=str(exc), payload_path_used=payload_path)

    def cleanup(self, payload_path: str, context: BackendContext) -> None:
        return


class PsExecBackend(LocalSubprocessBackend):
    def __init__(self, psexec_path: str, logger: Callable[[str], None] | None = None):
        super().__init__(logger=logger)
        self.psexec_path = psexec_path

    @property
    def name(self) -> str:
        return "psexec"

    def prepare_payload(self, package: WindowsPackage, context: BackendContext) -> str:
        src = super().prepare_payload(package, context)
        if package.source.kind == SourceKind.WINGET_ID:
            return src
        if src.startswith("\\\\"):
            return src
        remote_admin_root = f"\\\\{context.target_host}\\ADMIN$"
        if not os.path.isdir(remote_admin_root):
            raise RuntimeError(f"ADMIN$ недоступен на {context.target_host}")
        rel_remote = context.remote_temp_dir.replace("C:\\Windows", "")
        remote_dir = os.path.join(remote_admin_root, rel_remote.lstrip("\\/"))
        os.makedirs(remote_dir, exist_ok=True)
        target = os.path.join(remote_dir, os.path.basename(src))
        shutil.copy2(src, target)
        return os.path.join(context.remote_temp_dir, os.path.basename(src))

    def run_install(self, package: WindowsPackage, context: BackendContext, payload_path: str) -> ExecutionResult:
        local_cmd = self._build_command(package, payload_path)
        remote_cmd = subprocess.list2cmdline(local_cmd)
        psexec_cmd = [
            self.psexec_path,
            f"\\\\{context.target_host}",
            "-accepteula",
            "-nobanner",
        ]
        if package.requires_admin:
            psexec_cmd.append("-h")
        if context.prefer_system_context:
            psexec_cmd.append("-s")
        psexec_cmd.extend(["cmd", "/c", remote_cmd])
        self.logger(f"[psexec] {' '.join(psexec_cmd[:6])} ...")
        try:
            cp = subprocess.run(
                psexec_cmd,
                capture_output=True,
                text=True,
                timeout=context.timeout_sec,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return ExecutionResult(
                exit_code=cp.returncode,
                stdout=cp.stdout or "",
                stderr=cp.stderr or "",
                payload_path_used=payload_path,
                command_preview=" ".join(psexec_cmd[:6]) + " ...",
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(exit_code=-1, stdout="", stderr="Таймаут выполнения psexec", timed_out=True, payload_path_used=payload_path)
        except Exception as exc:
            return ExecutionResult(exit_code=-2, stdout="", stderr=str(exc), transport_error=str(exc), payload_path_used=payload_path)

    def cleanup(self, payload_path: str, context: BackendContext) -> None:
        if not payload_path or payload_path.startswith("\\\\"):
            return
        remote_admin_root = f"\\\\{context.target_host}\\ADMIN$"
        rel_remote = context.remote_temp_dir.replace("C:\\Windows", "")
        remote_file = os.path.join(remote_admin_root, rel_remote.lstrip("\\/"), os.path.basename(payload_path))
        try:
            if os.path.exists(remote_file):
                os.remove(remote_file)
        except Exception as exc:
            self.logger(f"[cleanup] Не удалось удалить {remote_file}: {exc}")
