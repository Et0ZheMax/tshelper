from __future__ import annotations

import json
import os
import posixpath
import shlex
import socket
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


class RemoteOpsError(Exception):
    """Базовая ошибка remote automation."""


class DependencyError(RemoteOpsError):
    """Ошибка отсутствующей зависимости."""


class SSHConnectionError(RemoteOpsError):
    """Ошибка SSH-подключения."""


class CatalogError(RemoteOpsError):
    """Ошибка каталога ПО."""


@dataclass(slots=True)
class SSHKeySettings:
    enabled: bool = False
    private_key_path: str = ""
    public_key_path: str = ""
    auto_bootstrap: bool = False


@dataclass(slots=True)
class SSHAuthSettings:
    username: str
    password: str = ""
    key_settings: SSHKeySettings = field(default_factory=SSHKeySettings)
    connect_timeout_sec: int = 8
    command_timeout_sec: int = 1800


@dataclass(slots=True)
class RemoteHost:
    candidates: list[str]
    port: int = 22
    os_family: str = "ubuntu"


@dataclass(slots=True)
class StepResult:
    name: str
    success: bool
    return_code: int
    stdout: str = ""
    stderr: str = ""
    command: str = ""
    duration_sec: float = 0.0
    host: str = ""


@dataclass(slots=True)
class ActionResult:
    action_name: str
    success: bool
    host_used: str = ""
    steps: list[StepResult] = field(default_factory=list)
    error_message: str = ""
    used_key_auth: bool = False
    key_bootstrapped: bool = False

    @property
    def summary(self) -> str:
        parts = [f"Действие: {self.action_name}"]
        if self.host_used:
            parts.append(f"Хост: {self.host_used}")
        parts.append("Статус: успешно" if self.success else "Статус: ошибка")
        if self.used_key_auth:
            parts.append("Авторизация: SSH-ключ")
        else:
            parts.append("Авторизация: пароль")
        if self.key_bootstrapped:
            parts.append("SSH-ключ был автоматически проброшен")
        if self.error_message:
            parts.append(f"Ошибка: {self.error_message}")
        return "\n".join(parts)


@dataclass(slots=True)
class SoftwareItem:
    item_id: str
    title: str
    os_family: str
    install_type: str
    enabled: bool = True
    description: str = ""
    package_name: str = ""
    url: str = ""
    local_path: str = ""
    install_cmd: str = ""
    check_cmd: str = ""
    post_install_cmd: str = ""
    requires_sudo: bool = False
    timeout_sec: int = 1800
    tags: list[str] = field(default_factory=list)


class SoftwareCatalog:
    def __init__(self, items: list[SoftwareItem], source_path: str):
        self._items = {item.item_id: item for item in items}
        self.source_path = source_path

    @classmethod
    def load(cls, json_path: str) -> "SoftwareCatalog":
        try:
            with open(json_path, "r", encoding="utf-8") as file_obj:
                payload = json.load(file_obj)
        except FileNotFoundError as exc:
            raise CatalogError(f"Файл каталога не найден: {json_path}") from exc
        except json.JSONDecodeError as exc:
            raise CatalogError(f"Каталог ПО содержит невалидный JSON: {exc}") from exc
        except OSError as exc:
            raise CatalogError(f"Не удалось прочитать каталог ПО: {exc}") from exc

        software = payload.get("software")
        if not isinstance(software, list):
            raise CatalogError("Каталог ПО должен содержать список software")

        items: list[SoftwareItem] = []
        seen_ids: set[str] = set()
        for index, raw_item in enumerate(software, start=1):
            if not isinstance(raw_item, dict):
                raise CatalogError(f"Элемент каталога #{index} должен быть объектом")
            item_id = str(raw_item.get("id", "")).strip()
            title = str(raw_item.get("title", "")).strip()
            os_family = str(raw_item.get("os_family", "")).strip().lower()
            install_type = str(raw_item.get("install_type", "")).strip().lower()
            if not item_id or not title or not os_family or not install_type:
                raise CatalogError(f"Элемент каталога #{index} содержит пустые обязательные поля")
            if item_id in seen_ids:
                raise CatalogError(f"Дублирующийся id в каталоге ПО: {item_id}")
            seen_ids.add(item_id)
            items.append(
                SoftwareItem(
                    item_id=item_id,
                    title=title,
                    os_family=os_family,
                    install_type=install_type,
                    enabled=bool(raw_item.get("enabled", True)),
                    description=str(raw_item.get("description", "")).strip(),
                    package_name=str(raw_item.get("package_name", "")).strip(),
                    url=str(raw_item.get("url", "")).strip(),
                    local_path=str(raw_item.get("local_path", "")).strip(),
                    install_cmd=str(raw_item.get("install_cmd", "")).strip(),
                    check_cmd=str(raw_item.get("check_cmd", "")).strip(),
                    post_install_cmd=str(raw_item.get("post_install_cmd", "")).strip(),
                    requires_sudo=bool(raw_item.get("requires_sudo", False)),
                    timeout_sec=max(1, int(raw_item.get("timeout_sec", 1800))),
                    tags=[str(tag).strip() for tag in raw_item.get("tags", []) if str(tag).strip()],
                )
            )
        return cls(items, json_path)

    def all_enabled(self, os_family: str = "ubuntu") -> list[SoftwareItem]:
        os_family_norm = (os_family or "").strip().lower()
        return [
            item for item in self._items.values()
            if item.enabled and item.os_family == os_family_norm
        ]

    def get(self, item_id: str) -> SoftwareItem:
        item = self._items.get(item_id)
        if not item:
            raise CatalogError(f"Элемент ПО не найден: {item_id}")
        return item


class SSHExecutor:
    def __init__(self, auth: SSHAuthSettings, logger: Optional[Callable[[str], None]] = None):
        self.auth = auth
        self.logger = logger or (lambda _msg: None)
        try:
            import paramiko  # type: ignore
        except ImportError as exc:
            raise DependencyError("Не найден модуль paramiko. Установите зависимость: pip install paramiko") from exc
        self.paramiko = paramiko

    def _log(self, message: str) -> None:
        self.logger(message)

    def resolve_first_reachable(self, host: RemoteHost) -> tuple[str, str]:
        last_error = ""
        for candidate in host.candidates:
            candidate = (candidate or "").strip()
            if not candidate:
                continue
            connect_target = candidate
            try:
                resolved_ip = socket.gethostbyname(candidate)
                connect_target = resolved_ip
                self._log(f"Хост {candidate} резолвится в {resolved_ip}")
            except Exception as exc:
                last_error = f"{candidate}: ошибка DNS ({exc})"
                self._log(f"Не удалось разрешить {candidate}: {exc}. Проверяю прямое TCP-подключение.")
            try:
                with socket.create_connection((connect_target, host.port), timeout=self.auth.connect_timeout_sec):
                    self._log(f"Порт SSH доступен: {candidate} -> {connect_target}:{host.port}")
                    return candidate, connect_target
            except Exception as exc:
                last_error = f"{candidate}: SSH {connect_target}:{host.port} недоступен ({exc})"
                self._log(f"Кандидат {candidate} недоступен по SSH: {exc}")
        raise SSHConnectionError(f"Не удалось определить хост для подключения: {last_error or 'пустой список кандидатов'}")

    def _new_client(self):
        client = self.paramiko.SSHClient()
        client.set_missing_host_key_policy(self.paramiko.AutoAddPolicy())
        return client

    def _connect_with_key(self, hostname: str, port: int):
        key_path = self.auth.key_settings.private_key_path
        if not self.auth.key_settings.enabled or not key_path:
            raise SSHConnectionError("SSH-ключ для automation не настроен")
        if not os.path.isfile(key_path):
            raise SSHConnectionError(f"Приватный ключ не найден: {key_path}")
        client = self._new_client()
        try:
            client.connect(
                hostname=hostname,
                port=port,
                username=self.auth.username,
                key_filename=key_path,
                timeout=self.auth.connect_timeout_sec,
                banner_timeout=self.auth.connect_timeout_sec,
                auth_timeout=self.auth.connect_timeout_sec,
                look_for_keys=False,
                allow_agent=False,
            )
            self._log(f"Подключение по ключу успешно: {hostname}:{port}")
            return client
        except Exception as exc:
            client.close()
            raise SSHConnectionError(f"Подключение по ключу не удалось: {exc}") from exc

    def _connect_with_password(self, hostname: str, port: int):
        if not self.auth.password:
            raise SSHConnectionError("Пароль SSH не задан")
        client = self._new_client()
        try:
            client.connect(
                hostname=hostname,
                port=port,
                username=self.auth.username,
                password=self.auth.password,
                timeout=self.auth.connect_timeout_sec,
                banner_timeout=self.auth.connect_timeout_sec,
                auth_timeout=self.auth.connect_timeout_sec,
                look_for_keys=False,
                allow_agent=False,
            )
            self._log(f"Подключение по паролю успешно: {hostname}:{port}")
            return client
        except Exception as exc:
            client.close()
            raise SSHConnectionError(f"Подключение по паролю не удалось: {exc}") from exc

    def connect_with_fallback(self, host: RemoteHost):
        resolved_host, _resolved_ip = self.resolve_first_reachable(host)
        key_bootstrapped = False
        if self.auth.key_settings.enabled and self.auth.key_settings.private_key_path:
            try:
                client = self._connect_with_key(resolved_host, host.port)
                return client, True, False, resolved_host
            except SSHConnectionError as key_error:
                self._log(str(key_error))
                if self.auth.key_settings.auto_bootstrap:
                    self._log("Пробую автоматически пробросить публичный ключ через пароль")
                    self.bootstrap_public_key(resolved_host, host.port)
                    key_bootstrapped = True
                    client = self._connect_with_key(resolved_host, host.port)
                    return client, True, key_bootstrapped, resolved_host
                self._log("Fallback на пароль после ошибки ключа")
                client = self._connect_with_password(resolved_host, host.port)
                return client, False, False, resolved_host
        client = self._connect_with_password(resolved_host, host.port)
        return client, False, False, resolved_host

    def bootstrap_public_key(self, hostname: str, port: int) -> None:
        public_key_path = self.auth.key_settings.public_key_path
        if not public_key_path:
            raise SSHConnectionError("Не указан путь к публичному ключу для bootstrap")
        if not os.path.isfile(public_key_path):
            raise SSHConnectionError(f"Публичный ключ не найден: {public_key_path}")
        with open(public_key_path, "r", encoding="utf-8") as file_obj:
            public_key = file_obj.read().strip()
        if not public_key:
            raise SSHConnectionError("Публичный ключ пуст")

        client = self._connect_with_password(hostname, port)
        escaped_key = public_key.replace("'", "'\"'\"'")
        command = (
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
            "touch ~/.ssh/authorized_keys && "
            f"grep -Fqx '{escaped_key}' ~/.ssh/authorized_keys || echo '{escaped_key}' >> ~/.ssh/authorized_keys && "
            "chmod 600 ~/.ssh/authorized_keys"
        )
        try:
            result = self.run_command(
                client,
                command,
                timeout_sec=self.auth.command_timeout_sec,
                step_name="Проброс SSH-ключа",
                get_pty=False,
            )
            if not result.success:
                raise SSHConnectionError(result.stderr or result.stdout or "Не удалось пробросить SSH-ключ")
            self._log(f"Публичный ключ успешно добавлен на {hostname}")
        finally:
            self.close_client(client)

    def _emit_output_lines(self, step_name: str, stream_name: str, buffer: bytearray) -> None:
        while True:
            newline_index = buffer.find(b"\n")
            if newline_index < 0:
                break
            raw_line = bytes(buffer[:newline_index])
            del buffer[:newline_index + 1]
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r")
            if line:
                self._log(f"[{step_name}] {stream_name}: {line}")

    def _flush_output_buffer(self, step_name: str, stream_name: str, buffer: bytearray) -> None:
        if not buffer:
            return
        line = bytes(buffer).decode("utf-8", errors="replace").rstrip("\r")
        buffer.clear()
        if line:
            self._log(f"[{step_name}] {stream_name}: {line}")

    def run_command(self, client, command: str, timeout_sec: int, step_name: str, get_pty: bool = False) -> StepResult:
        started = time.time()
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout_sec, get_pty=get_pty)
        channel = stdout.channel
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        deadline = started + max(1, timeout_sec)
        timed_out = False

        while True:
            while channel.recv_ready():
                chunk = channel.recv(65536)
                stdout_chunks.append(chunk)
                stdout_buffer.extend(chunk)
                self._emit_output_lines(step_name, "stdout", stdout_buffer)
            while channel.recv_stderr_ready():
                chunk = channel.recv_stderr(65536)
                stderr_chunks.append(chunk)
                stderr_buffer.extend(chunk)
                self._emit_output_lines(step_name, "stderr", stderr_buffer)

            if channel.exit_status_ready():
                if not channel.recv_ready() and not channel.recv_stderr_ready():
                    break

            if time.time() >= deadline:
                timed_out = True
                try:
                    channel.close()
                except Exception:
                    pass
                break

            time.sleep(0.05)

        while channel.recv_ready():
            chunk = channel.recv(65536)
            stdout_chunks.append(chunk)
            stdout_buffer.extend(chunk)
            self._emit_output_lines(step_name, "stdout", stdout_buffer)
        while channel.recv_stderr_ready():
            chunk = channel.recv_stderr(65536)
            stderr_chunks.append(chunk)
            stderr_buffer.extend(chunk)
            self._emit_output_lines(step_name, "stderr", stderr_buffer)

        self._flush_output_buffer(step_name, "stdout", stdout_buffer)
        self._flush_output_buffer(step_name, "stderr", stderr_buffer)

        if timed_out:
            return StepResult(
                name=step_name,
                success=False,
                return_code=-1,
                stdout=b"".join(stdout_chunks).decode("utf-8", errors="replace").strip(),
                stderr=(b"".join(stderr_chunks).decode("utf-8", errors="replace").strip() or f"Команда превысила таймаут {timeout_sec} сек."),
                command=command,
                duration_sec=time.time() - started,
            )

        exit_status = channel.recv_exit_status()
        out_text = b"".join(stdout_chunks).decode("utf-8", errors="replace")
        err_text = b"".join(stderr_chunks).decode("utf-8", errors="replace")
        return StepResult(
            name=step_name,
            success=(exit_status == 0),
            return_code=exit_status,
            stdout=out_text.strip(),
            stderr=err_text.strip(),
            command=command,
            duration_sec=time.time() - started,
        )

    def upload_file(self, client, local_path: str, remote_path: str) -> None:
        if not os.path.isfile(local_path):
            raise RemoteOpsError(f"Локальный файл не найден: {local_path}")
        sftp = client.open_sftp()
        try:
            sftp.put(local_path, remote_path)
        finally:
            sftp.close()

    def close_client(self, client) -> None:
        try:
            client.close()
        except Exception:
            pass


class UbuntuSoftwareInstaller:
    def __init__(self, executor: SSHExecutor, catalog: SoftwareCatalog, logger: Optional[Callable[[str], None]] = None):
        self.executor = executor
        self.catalog = catalog
        self.logger = logger or (lambda _msg: None)

    def _log(self, message: str) -> None:
        self.logger(message)

    def _passwordless_sudo_message(self) -> str:
        return "На хосте не настроен passwordless sudo для пользователя support"

    def _run_sudo_preflight(self, result: ActionResult, client, timeout_sec: int) -> StepResult:
        step_result = self._run_step(
            result,
            client,
            "sudo -n true",
            "Проверка passwordless sudo",
            timeout_sec,
            get_pty=False,
        )
        if not step_result.success:
            step_result.stderr = self._passwordless_sudo_message()
        return step_result

    def _ensure_passwordless_sudo(self, result: ActionResult, client, timeout_sec: int) -> Optional[StepResult]:
        step_result = self._run_sudo_preflight(result, client, timeout_sec)
        if step_result.success:
            return None
        result.error_message = self._passwordless_sudo_message()
        return step_result

    def _run_step(self, result: ActionResult, client, command: str, step_name: str, timeout_sec: int, get_pty: bool = False) -> StepResult:
        self._log(f"[{step_name}] Выполняю: {command}")
        step_result = self.executor.run_command(client, command, timeout_sec=timeout_sec, step_name=step_name, get_pty=get_pty)
        result.steps.append(step_result)
        if step_result.success:
            self._log(f"[{step_name}] OK")
        else:
            self._log(f"[{step_name}] ERROR rc={step_result.return_code}: {step_result.stderr or step_result.stdout}")
        return step_result

    def install_software(self, host: RemoteHost, item_id: str, force_reinstall: bool = False) -> ActionResult:
        item = self.catalog.get(item_id)
        action_result = ActionResult(action_name=f"Установка ПО: {item.title}", success=False)
        client = None
        cleanup_remote_paths: list[str] = []
        try:
            client, used_key_auth, key_bootstrapped, used_host = self.executor.connect_with_fallback(host)
            action_result.used_key_auth = used_key_auth
            action_result.key_bootstrapped = key_bootstrapped
            action_result.host_used = used_host
            self._log(f"Подключение к {used_host} установлено")

            if item.check_cmd and not force_reinstall:
                check_result = self._run_step(action_result, client, item.check_cmd, "Проверка установки", timeout_sec=min(item.timeout_sec, self.executor.auth.command_timeout_sec))
                if check_result.success:
                    action_result.success = True
                    action_result.error_message = ""
                    self._log("ПО уже установлено, повторная установка не требуется")
                    return action_result

            timeout_sec = min(item.timeout_sec, self.executor.auth.command_timeout_sec)
            install_type = item.install_type.lower()
            install_result: Optional[StepResult] = None

            if install_type == "apt":
                if not item.package_name:
                    raise CatalogError(f"Для apt-пакета не указано package_name: {item.item_id}")
                preflight_result = self._ensure_passwordless_sudo(action_result, client, timeout_sec)
                if preflight_result is not None:
                    return action_result
                update_result = self._run_step(action_result, client, "sudo -n apt-get update", "apt-get update", timeout_sec)
                if not update_result.success:
                    action_result.error_message = update_result.stderr or update_result.stdout or "Ошибка apt-get update"
                    return action_result
                install_command = (
                    "sudo -n apt-get -o DPkg::Lock::Timeout=60 install -y "
                    f"{shlex.quote(item.package_name)}"
                )
                install_result = self._run_step(action_result, client, install_command, "Установка apt-пакета", timeout_sec)
            elif install_type == "deb_url":
                if not item.url:
                    raise CatalogError(f"Для deb_url не указан url: {item.item_id}")
                remote_deb = f"/tmp/tshelper_{item.item_id}_{int(time.time())}.deb"
                cleanup_remote_paths.append(remote_deb)
                download_command = f"wget -O {shlex.quote(remote_deb)} {shlex.quote(item.url)}"
                download_result = self._run_step(action_result, client, download_command, "Скачивание deb-пакета", timeout_sec)
                if not download_result.success:
                    action_result.error_message = download_result.stderr or download_result.stdout or "Ошибка скачивания deb-пакета"
                    return action_result
                preflight_result = self._ensure_passwordless_sudo(action_result, client, timeout_sec)
                if preflight_result is not None:
                    return action_result
                install_command = (
                    "sudo -n apt-get -o DPkg::Lock::Timeout=60 install -y "
                    f"{shlex.quote(remote_deb)}"
                )
                install_result = self._run_step(action_result, client, install_command, "Установка deb-пакета", timeout_sec)
            elif install_type == "local_script":
                local_path = item.local_path
                if not local_path:
                    raise CatalogError(f"Для local_script не указан local_path: {item.item_id}")
                if not os.path.isabs(local_path):
                    local_path = os.path.join(os.path.dirname(os.path.abspath(self.catalog.source_path)), local_path)
                if not os.path.isfile(local_path):
                    raise CatalogError(f"Скрипт для установки не найден: {local_path}")
                temp_remote_path = posixpath.join("/tmp", f"tshelper_{item.item_id}.sh")
                cleanup_remote_paths.append(temp_remote_path)
                self._log(f"Загружаю скрипт {local_path} -> {temp_remote_path}")
                self.executor.upload_file(client, local_path, temp_remote_path)
                upload_step = StepResult(name="Загрузка скрипта", success=True, return_code=0, stdout=f"Загружен {temp_remote_path}", command=local_path)
                action_result.steps.append(upload_step)
                chmod_step = self._run_step(action_result, client, f"chmod +x {shlex.quote(temp_remote_path)}", "Подготовка скрипта", timeout_sec)
                if chmod_step.success:
                    if item.requires_sudo:
                        preflight_result = self._ensure_passwordless_sudo(action_result, client, timeout_sec)
                        if preflight_result is not None:
                            return action_result
                    script_command = shlex.quote(temp_remote_path)
                    if item.requires_sudo:
                        script_command = f"sudo -n {script_command}"
                    install_result = self._run_step(
                        action_result,
                        client,
                        script_command,
                        "Выполнение скрипта",
                        timeout_sec,
                        get_pty=False,
                    )
                else:
                    install_result = chmod_step
            elif install_type == "custom_cmd":
                if not item.install_cmd:
                    raise CatalogError(f"Для custom_cmd не указан install_cmd: {item.item_id}")
                # В custom_cmd ответственность за добавление sudo остаётся на install_cmd.
                # requires_sudo здесь влияет только на режим выполнения (PTY), чтобы команда,
                # уже содержащая sudo, могла корректно запросить tty на удалённой стороне.
                install_result = self._run_step(action_result, client, item.install_cmd, "Выполнение команды", timeout_sec, get_pty=item.requires_sudo)
            else:
                raise CatalogError(f"Неподдерживаемый install_type: {item.install_type}")

            if not install_result or not install_result.success:
                action_result.error_message = (install_result.stderr or install_result.stdout or "Ошибка установки") if install_result else "Ошибка установки"
                return action_result

            if item.post_install_cmd:
                post_result = self._run_step(action_result, client, item.post_install_cmd, "Post-install", timeout_sec, get_pty=item.requires_sudo)
                if not post_result.success:
                    action_result.error_message = post_result.stderr or post_result.stdout or "Ошибка post-install"
                    return action_result

            action_result.success = True
            return action_result
        except RemoteOpsError as exc:
            action_result.error_message = str(exc)
            self._log(f"Remote automation error: {exc}")
            return action_result
        except Exception as exc:
            action_result.error_message = str(exc)
            self._log(f"Непредвиденная ошибка automation: {exc}")
            return action_result
        finally:
            if client is not None:
                if cleanup_remote_paths:
                    try:
                        cleanup_command = "rm -f " + " ".join(shlex.quote(path) for path in cleanup_remote_paths)
                        cleanup_result = self.executor.run_command(client, cleanup_command, timeout_sec=30, step_name="Очистка временного файла")
                        action_result.steps.append(cleanup_result)
                    except Exception as cleanup_error:
                        self._log(f"Не удалось удалить временный файл: {cleanup_error}")
                self.executor.close_client(client)
