from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, Sequence

from windows_catalog_models import BackendContext, DetectionResult, ExecutionResult, SourceKind, WindowsInstallType, WindowsPackage
from windows_detection import run_detection_with_executor


class BackendError(RuntimeError):
    def __init__(self, message: str, error_kind: str):
        super().__init__(message)
        self.error_kind = error_kind


class InvalidTargetError(BackendError):
    def __init__(self, message: str):
        super().__init__(message, error_kind="invalid_target")


@dataclass(slots=True)
class _StagedPayload:
    local_source: str
    remote_file_path: str
    admin_share_path: str


@dataclass(slots=True)
class UserSessionInfo:
    username: str
    session_id: str
    state: str


class WindowsExecutionBackend(ABC):
    def __init__(self, logger: Callable[[str], None] | None = None):
        self.logger = logger or (lambda _msg: None)

    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def validate_context(self, context: BackendContext) -> None:
        raise NotImplementedError

    @abstractmethod
    def prepare_payload(self, package: WindowsPackage, context: BackendContext) -> str:
        raise NotImplementedError

    @abstractmethod
    def run_detection(self, package: WindowsPackage, context: BackendContext) -> DetectionResult:
        raise NotImplementedError

    @abstractmethod
    def run_install(self, package: WindowsPackage, context: BackendContext, payload_path: str) -> ExecutionResult:
        raise NotImplementedError

    @abstractmethod
    def cleanup(self, payload_path: str, context: BackendContext) -> None:
        raise NotImplementedError

    def find_user_session(self, context: BackendContext) -> UserSessionInfo:
        raise BackendError("Интерактивный режим поддерживается только для backend psexec", error_kind="unsupported_mode")

    def run_install_in_user_session(
        self,
        package: WindowsPackage,
        context: BackendContext,
        payload_path: str,
        session: UserSessionInfo,
    ) -> ExecutionResult:
        raise BackendError("Интерактивный запуск доступен только для backend psexec", error_kind="unsupported_mode")

    def verify_payload_delivery(self, package: WindowsPackage, context: BackendContext, payload_path: str) -> tuple[bool, str]:
        return True, "verification_not_required"


class LocalSubprocessBackend(WindowsExecutionBackend):
    @property
    def name(self) -> str:
        return "local_subprocess"

    def validate_context(self, context: BackendContext) -> None:
        if context.target_host.lower() not in {"", "localhost", ".", "127.0.0.1"}:
            raise InvalidTargetError("Локальный backend поддерживает только localhost")

    def prepare_payload(self, package: WindowsPackage, context: BackendContext) -> str:
        source = package.source
        if source.kind == SourceKind.WINGET_ID:
            return source.value
        if source.kind not in {SourceKind.FILE_PATH, SourceKind.UNC_PATH}:
            raise RuntimeError(f"Локальный backend не поддерживает source.kind={source.kind.value}")
        if not os.path.exists(source.value):
            raise FileNotFoundError(f"Источник не найден: {source.value}")
        return source.value

    def run_detection(self, package: WindowsPackage, context: BackendContext) -> DetectionResult:
        self.validate_context(context)
        return run_detection_with_executor(
            config=package.detection,
            executor=self._execute,
            timeout_sec=context.timeout_sec,
        )

    def _build_install_command(self, package: WindowsPackage, payload_path: str) -> list[str]:
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

    def _execute(self, command: Sequence[str], timeout_sec: int) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

    def run_install(self, package: WindowsPackage, context: BackendContext, payload_path: str) -> ExecutionResult:
        self.validate_context(context)
        if package.requires_admin and not _is_running_as_admin():
            return ExecutionResult(
                exit_code=-5,
                stdout="",
                stderr="Для локальной установки требуется elevated запуск TS HELPER",
                error_kind="elevation_required",
                payload_path_used=payload_path,
            )
        command = self._build_install_command(package, payload_path)
        self.logger(f"[deploy] cmd={command}")
        try:
            cp, timed_out = _run_command_with_heartbeat(
                command=command,
                timeout_sec=context.timeout_sec,
                host_label=context.target_host or "localhost",
                logger=self.logger,
            )
            if timed_out:
                return ExecutionResult(
                    exit_code=-1,
                    stdout=cp.stdout or "",
                    stderr=cp.stderr or "",
                    timed_out=True,
                    payload_path_used=payload_path,
                    command_preview=_command_preview(command),
                    error_kind="timeout",
                )
            return ExecutionResult(
                exit_code=cp.returncode,
                stdout=cp.stdout or "",
                stderr=cp.stderr or "",
                payload_path_used=payload_path,
                command_preview=_command_preview(command),
            )
        except FileNotFoundError as exc:
            return ExecutionResult(
                exit_code=-2,
                stdout="",
                stderr=str(exc),
                transport_error="Команда не найдена",
                payload_path_used=payload_path,
                error_kind="transport_failed",
            )
        except PermissionError as exc:
            return ExecutionResult(
                exit_code=-6,
                stdout="",
                stderr=str(exc),
                transport_error="Недостаточно прав",
                payload_path_used=payload_path,
                error_kind="access_denied",
            )
        except Exception as exc:
            return ExecutionResult(
                exit_code=-3,
                stdout="",
                stderr=str(exc),
                transport_error=str(exc),
                payload_path_used=payload_path,
                error_kind="transport_failed",
            )

    def cleanup(self, payload_path: str, context: BackendContext) -> None:
        return


class PsExecBackend(LocalSubprocessBackend):
    def __init__(self, psexec_path: str, logger: Callable[[str], None] | None = None):
        super().__init__(logger=logger)
        self.psexec_path = psexec_path
        self._staged_payloads: dict[str, _StagedPayload] = {}

    @property
    def name(self) -> str:
        return "psexec"

    def validate_context(self, context: BackendContext) -> None:
        host = (context.target_host or "").strip()
        if not host or host.lower() in {"localhost", ".", "127.0.0.1"}:
            raise InvalidTargetError("Для psexec требуется явный удалённый target host")
        if not os.path.isfile(self.psexec_path):
            raise BackendError(f"Не найден PsExec64.exe: {self.psexec_path}", error_kind="transport_failed")

    def prepare_payload(self, package: WindowsPackage, context: BackendContext) -> str:
        self.validate_context(context)
        src = super().prepare_payload(package, context)
        if package.source.kind == SourceKind.WINGET_ID:
            return src

        staging = _build_remote_staging_paths(context.target_host, context.remote_temp_dir, os.path.basename(src))
        _ensure_admin_share_available(staging.admin_share_root)
        os.makedirs(staging.admin_share_dir, exist_ok=True)
        shutil.copy2(src, staging.admin_share_file)
        self._staged_payloads[staging.remote_file_path.lower()] = _StagedPayload(
            local_source=src,
            remote_file_path=staging.remote_file_path,
            admin_share_path=staging.admin_share_file,
        )
        return staging.remote_file_path

    def _execute_remote(self, command: Sequence[str], context: BackendContext, requires_admin: bool) -> subprocess.CompletedProcess[str]:
        psexec_cmd = [
            self.psexec_path,
            f"\\\\{context.target_host}",
            "-accepteula",
            "-nobanner",
        ]
        if requires_admin:
            psexec_cmd.append("-h")
        if context.prefer_system_context:
            psexec_cmd.append("-s")
        remote_cmd = subprocess.list2cmdline(list(command))
        psexec_cmd.extend(["cmd", "/c", remote_cmd])
        return subprocess.run(
            psexec_cmd,
            capture_output=True,
            text=True,
            timeout=context.timeout_sec,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

    def run_detection(self, package: WindowsPackage, context: BackendContext) -> DetectionResult:
        self.validate_context(context)

        def remote_executor(command: Sequence[str], timeout_sec: int) -> subprocess.CompletedProcess[str]:
            local_context = BackendContext(
                target_host=context.target_host,
                timeout_sec=timeout_sec,
                requires_admin=context.requires_admin,
                prefer_system_context=context.prefer_system_context,
                remote_temp_dir=context.remote_temp_dir,
            )
            return self._execute_remote(command, local_context, requires_admin=context.requires_admin)

        result = run_detection_with_executor(config=package.detection, executor=remote_executor, timeout_sec=context.timeout_sec)
        if result.error_kind == "execution_failed" and result.error is None:
            result.error = "Ошибка выполнения detection на удалённом хосте"
        return result

    def run_install(self, package: WindowsPackage, context: BackendContext, payload_path: str) -> ExecutionResult:
        self.validate_context(context)
        command = self._build_install_command(package, payload_path)
        self.logger(f"[psexec] target={context.target_host} cmd={_command_preview(command)}")
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
        remote_cmd = subprocess.list2cmdline(list(command))
        psexec_cmd.extend(["cmd", "/c", remote_cmd])
        try:
            cp, timed_out = _run_command_with_heartbeat(
                command=psexec_cmd,
                timeout_sec=context.timeout_sec,
                host_label=context.target_host,
                logger=self.logger,
            )
            if timed_out:
                return ExecutionResult(
                    exit_code=-1,
                    stdout=cp.stdout or "",
                    stderr=(cp.stderr or "") or "Таймаут выполнения psexec",
                    timed_out=True,
                    payload_path_used=payload_path,
                    error_kind="timeout",
                )
            stderr_text = cp.stderr or ""
            if cp.returncode != 0 and "access is denied" in (stderr_text.lower() + (cp.stdout or "").lower()):
                return ExecutionResult(
                    exit_code=cp.returncode,
                    stdout=cp.stdout or "",
                    stderr=stderr_text,
                    payload_path_used=payload_path,
                    command_preview=_command_preview(command),
                    error_kind="access_denied",
                )
            return ExecutionResult(
                exit_code=cp.returncode,
                stdout=cp.stdout or "",
                stderr=stderr_text,
                payload_path_used=payload_path,
                command_preview=_command_preview(command),
            )
        except Exception as exc:
            return ExecutionResult(
                exit_code=-2,
                stdout="",
                stderr=str(exc),
                transport_error=str(exc),
                payload_path_used=payload_path,
                error_kind="transport_failed",
            )

    def find_user_session(self, context: BackendContext) -> UserSessionInfo:
        self.validate_context(context)
        command = ["quser", f"/server:{context.target_host}"]
        try:
            cp = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=max(20, min(context.timeout_sec, 120)),
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as exc:
            raise BackendError(f"Не удалось выполнить quser: {exc}", error_kind="session_query_failed") from exc
        output = f"{cp.stdout or ''}\n{cp.stderr or ''}".strip()
        if cp.returncode != 0:
            raise BackendError(
                f"Команда quser завершилась с кодом {cp.returncode}: {output or 'нет вывода'}",
                error_kind="session_query_failed",
            )
        parsed_sessions = _parse_quser_output(output)
        if not parsed_sessions:
            raise BackendError("На целевом хосте не найдены пользовательские сессии", error_kind="interactive_session_not_found")
        for session in parsed_sessions:
            if session.state.upper() == "ACTIVE":
                return session
        return parsed_sessions[0]

    def run_install_in_user_session(
        self,
        package: WindowsPackage,
        context: BackendContext,
        payload_path: str,
        session: UserSessionInfo,
    ) -> ExecutionResult:
        self.validate_context(context)
        command = self._build_install_command(package, payload_path)
        psexec_cmd = [
            self.psexec_path,
            f"\\\\{context.target_host}",
            "-accepteula",
            "-nobanner",
            "-i",
            str(session.session_id),
        ]
        if package.requires_admin:
            psexec_cmd.append("-h")
        if context.prefer_system_context:
            psexec_cmd.append("-s")
        psexec_cmd.extend(["cmd", "/c", subprocess.list2cmdline(list(command))])
        self.logger(f"[interactive] target={context.target_host}, session_id={session.session_id}, user={session.username}")
        try:
            cp, timed_out = _run_command_with_heartbeat(
                command=psexec_cmd,
                timeout_sec=context.timeout_sec,
                host_label=context.target_host,
                logger=self.logger,
            )
            if timed_out:
                return ExecutionResult(
                    exit_code=-1,
                    stdout=cp.stdout or "",
                    stderr=(cp.stderr or "") or "Таймаут интерактивного запуска через psexec",
                    timed_out=True,
                    payload_path_used=payload_path,
                    command_preview=_command_preview(command),
                    error_kind="timeout",
                )
            return ExecutionResult(
                exit_code=cp.returncode,
                stdout=cp.stdout or "",
                stderr=cp.stderr or "",
                payload_path_used=payload_path,
                command_preview=_command_preview(command),
            )
        except Exception as exc:
            return ExecutionResult(
                exit_code=-2,
                stdout="",
                stderr=str(exc),
                transport_error=str(exc),
                payload_path_used=payload_path,
                error_kind="transport_failed",
            )

    def verify_payload_delivery(self, package: WindowsPackage, context: BackendContext, payload_path: str) -> tuple[bool, str]:
        self.validate_context(context)
        staged = self._staged_payloads.get((payload_path or "").lower())
        expected_size = os.path.getsize(staged.local_source) if staged and os.path.exists(staged.local_source) else -1
        if staged and staged.admin_share_path:
            if not os.path.exists(staged.admin_share_path):
                return False, f"Файл не найден по admin-share пути: {staged.admin_share_path}"
            remote_size = os.path.getsize(staged.admin_share_path)
            if remote_size <= 0:
                return False, "Файл найден по admin-share, но размер некорректный (<= 0)"
            if expected_size > 0 and remote_size != expected_size:
                return False, f"Размер не совпадает: local={expected_size}, remote={remote_size}"
            return True, f"Доставка подтверждена через admin-share (размер {remote_size} байт)"
        ps_script = (
            "$p = '{path}';"
            "if (-not (Test-Path -LiteralPath $p)) {{ Write-Output 'missing'; exit 2 }};"
            "$i = Get-Item -LiteralPath $p;"
            "Write-Output ('size=' + $i.Length);"
            "if ($i.Length -le 0) {{ exit 3 }};"
            "exit 0"
        ).format(path=payload_path.replace("'", "''"))
        command = [
            self.psexec_path,
            f"\\\\{context.target_host}",
            "-accepteula",
            "-nobanner",
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            ps_script,
        ]
        cp = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(20, min(context.timeout_sec, 180)),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = f"{cp.stdout or ''}\n{cp.stderr or ''}".strip()
        if cp.returncode != 0:
            return False, output or "Не удалось подтвердить доставку файла"
        remote_size = _extract_remote_size(output)
        if remote_size <= 0:
            return False, "Файл найден, но размер некорректный (<= 0)"
        if expected_size > 0 and remote_size != expected_size:
            return False, f"Размер не совпадает: local={expected_size}, remote={remote_size}"
        return True, f"Доставка подтверждена (размер {remote_size} байт)"

    def cleanup(self, payload_path: str, context: BackendContext) -> None:
        staged = self._staged_payloads.pop((payload_path or "").lower(), None)
        if not staged:
            return
        try:
            if os.path.exists(staged.admin_share_path):
                os.remove(staged.admin_share_path)
        except Exception as exc:
            self.logger(f"[cleanup] Не удалось удалить {staged.admin_share_path}: {exc}")


@dataclass(slots=True)
class _RemotePathInfo:
    admin_share_root: str
    admin_share_dir: str
    admin_share_file: str
    remote_file_path: str


def _build_remote_staging_paths(target_host: str, remote_temp_dir: str, file_name: str) -> _RemotePathInfo:
    drive, remainder = os.path.splitdrive(remote_temp_dir)
    if not drive or len(drive) < 2:
        raise RuntimeError(f"Некорректный remote_temp_dir: {remote_temp_dir}")
    drive_letter = drive[0].upper()
    cleaned = remainder.strip("\\/")
    admin_share_root = f"\\\\{target_host}\\{drive_letter}$"
    admin_share_dir = os.path.join(admin_share_root, cleaned) if cleaned else admin_share_root
    remote_file_path = f"{drive_letter}:\\{cleaned}\\{file_name}" if cleaned else f"{drive_letter}:\\{file_name}"
    admin_share_file = os.path.join(admin_share_dir, file_name)
    return _RemotePathInfo(
        admin_share_root=admin_share_root,
        admin_share_dir=admin_share_dir,
        admin_share_file=admin_share_file,
        remote_file_path=remote_file_path,
    )


def _ensure_admin_share_available(admin_share_root: str) -> None:
    if not os.path.isdir(admin_share_root):
        raise RuntimeError(f"ADMIN$/{admin_share_root[-2:]} недоступен: {admin_share_root}")


def _is_running_as_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _command_preview(command: Sequence[str]) -> str:
    quoted = [subprocess.list2cmdline([part]) for part in command[:8]]
    preview = " ".join(quoted)
    return f"{preview} ..." if len(command) > 8 else preview


def _run_command_with_heartbeat(
    command: Sequence[str],
    timeout_sec: int,
    host_label: str,
    logger: Callable[[str], None],
    heartbeat_sec: int = 7,
) -> tuple[subprocess.CompletedProcess[str], bool]:
    process = subprocess.Popen(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    started_at = time.monotonic()
    while True:
        elapsed = time.monotonic() - started_at
        remaining = timeout_sec - elapsed
        if remaining <= 0:
            process.kill()
            stdout_text, stderr_text = process.communicate()
            return subprocess.CompletedProcess(list(command), -1, stdout_text or "", stderr_text or ""), True
        try:
            stdout_text, stderr_text = process.communicate(timeout=min(heartbeat_sec, max(1, int(remaining))))
            return subprocess.CompletedProcess(list(command), process.returncode, stdout_text or "", stderr_text or ""), False
        except subprocess.TimeoutExpired:
            logger(f"[deploy] Ожидание завершения установщика на хосте {host_label}...")


def _parse_quser_output(output: str) -> list[UserSessionInfo]:
    sessions: list[UserSessionInfo] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "USERNAME" in line.upper() and "SESSIONNAME" in line.upper():
            continue
        line = line.lstrip(">")
        parts = line.split()
        if len(parts) < 4:
            continue
        username = parts[0]
        state_index = None
        for idx, token in enumerate(parts):
            if token.upper() in {"ACTIVE", "DISC", "DISCONNECTED", "IDLE"} and idx > 0:
                state_index = idx
                break
        if state_index is None or state_index < 2:
            continue
        session_id = parts[state_index - 1]
        if not session_id.isdigit():
            continue
        sessions.append(UserSessionInfo(username=username, session_id=session_id, state=parts[state_index]))
    return sessions


def _extract_remote_size(text: str) -> int:
    for line in text.splitlines():
        normalized = line.strip().lower()
        if normalized.startswith("size="):
            value = normalized.split("=", 1)[1].strip()
            if value.isdigit():
                return int(value)
    return -1
