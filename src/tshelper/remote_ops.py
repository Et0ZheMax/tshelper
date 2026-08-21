from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
import socket
import tempfile
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


TSHELPER_SUDOERS_PATH = "/etc/sudoers.d/90-support-tshelper"
TSHELPER_SUDOERS_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]*[$]?$")


def validate_tshelper_username(username: str) -> str:
    normalized = (username or "").strip()
    if not TSHELPER_SUDOERS_USERNAME_RE.fullmatch(normalized):
        raise RemoteOpsError(
            "Логин SSH содержит недопустимые символы для sudoers. "
            "Разрешены только строчные латинские буквы, цифры, '_', '-' и необязательный '$' в конце."
        )
    return normalized


def build_tshelper_sudoers_content(username: str) -> str:
    safe_username = validate_tshelper_username(username)
    lines = [
        "# Managed by TSHelper",
        f"{safe_username} ALL=(root) NOPASSWD: /usr/bin/apt",
        f"{safe_username} ALL=(root) NOPASSWD: /usr/bin/apt-get",
        f"{safe_username} ALL=(root) NOPASSWD: /usr/bin/dpkg",
        f"{safe_username} ALL=(root) NOPASSWD: /usr/bin/systemctl",
        f"{safe_username} ALL=(root) NOPASSWD: /usr/bin/bash",
        f"{safe_username} ALL=(root) NOPASSWD: /bin/bash",
        f"{safe_username} ALL=(root) NOPASSWD: /usr/sbin/reboot",
        f"{safe_username} ALL=(root) NOPASSWD: /sbin/reboot",
        f"{safe_username} ALL=(root) NOPASSWD: /usr/bin/bash /usr/local/tshelper-scripts/*",
        f"{safe_username} ALL=(root) NOPASSWD: /bin/bash /usr/local/tshelper-scripts/*",
    ]
    return "\n".join(lines) + "\n"


class RemoteOpsError(Exception):
    """Базовая ошибка remote automation."""


class DependencyError(RemoteOpsError):
    """Ошибка отсутствующей зависимости."""


class SSHConnectionError(RemoteOpsError):
    """Ошибка SSH-подключения."""


class CatalogError(RemoteOpsError):
    """Ошибка каталога ПО."""


class CatalogValidationError(CatalogError):
    """Ошибка валидации записи каталога ПО."""


class InteractivePromptTimeout(RemoteOpsError):
    """Не получен ответ оператора на интерактивный запрос."""


class InteractivePromptCancelled(RemoteOpsError):
    """Оператор отменил интерактивный запрос."""


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
    needs_sudo_repair: bool = False
    sudo_repair_message: str = ""

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
        if self.needs_sudo_repair and self.sudo_repair_message:
            parts.append(f"Требуется исправление sudoers: {self.sudo_repair_message}")
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
    packages: list[str] = field(default_factory=list)
    url: str = ""
    local_path: str = ""
    install_cmd: str = ""
    check_cmd: str = ""
    post_install_cmd: str = ""
    requires_sudo: bool = False
    timeout_sec: int = 1800
    tags: list[str] = field(default_factory=list)
    interactive_responses: list[dict[str, str]] = field(default_factory=list)


class SoftwareCatalog:
    def __init__(self, items: list[SoftwareItem], source_path: str):
        self._items = {item.item_id: item for item in items}
        self.source_path = source_path

    @classmethod
    def load(cls, json_path: str) -> "SoftwareCatalog":
        payload = load_software_catalog(json_path)
        software = payload["software"]
        items: list[SoftwareItem] = []
        for raw_item in software:
            packages = _extract_packages_from_entry(raw_item)
            items.append(
                SoftwareItem(
                    item_id=str(raw_item.get("id", "")).strip(),
                    title=str(raw_item.get("title", "")).strip(),
                    os_family=str(raw_item.get("os_family", "")).strip().lower(),
                    install_type=str(raw_item.get("install_type", "")).strip().lower(),
                    enabled=bool(raw_item.get("enabled", True)),
                    description=str(raw_item.get("description", "")).strip(),
                    package_name=str(raw_item.get("package_name", "")).strip(),
                    packages=packages,
                    url=str(raw_item.get("url", "")).strip(),
                    local_path=str(raw_item.get("local_path", "")).strip(),
                    install_cmd=str(raw_item.get("install_cmd", "")).strip(),
                    check_cmd=str(raw_item.get("check_cmd", "")).strip(),
                    post_install_cmd=str(raw_item.get("post_install_cmd", "")).strip(),
                    requires_sudo=bool(raw_item.get("requires_sudo", False)),
                    timeout_sec=max(1, int(raw_item.get("timeout_sec", 1800))),
                    tags=[str(tag).strip() for tag in raw_item.get("tags", []) if str(tag).strip()],
                    interactive_responses=[
                        {
                            "pattern": str(entry.get("pattern", "")).strip(),
                            "response": str(entry.get("response", "")),
                        }
                        for entry in raw_item.get("interactive_responses", [])
                        if isinstance(entry, dict) and str(entry.get("pattern", "")).strip()
                    ],
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

    def all_items(self) -> list[SoftwareItem]:
        return list(self._items.values())


APT_DANGEROUS_PATTERNS = (";", "&&", "||", "|", "`", "$(")
APT_INSTALL_TYPES = {"apt", "deb_file", "deb_url"}
APT_PACKAGE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:-]*(=[A-Za-z0-9+._:~\\-]+)?$")


def slugify_software_id(value: str) -> str:
    text = (value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return text or f"software-{int(time.time())}"


def _extract_packages_from_entry(raw_item: dict) -> list[str]:
    raw_packages = raw_item.get("packages")
    if isinstance(raw_packages, list):
        return [str(package).strip() for package in raw_packages if str(package).strip()]
    package_name = str(raw_item.get("package_name", "")).strip()
    return [package_name] if package_name else []


def normalize_apt_input(user_input: str) -> list[str]:
    source = (user_input or "").strip()
    if not source:
        return []
    for pattern in APT_DANGEROUS_PATTERNS:
        if pattern in source:
            raise CatalogValidationError(
                f"Обнаружена потенциально опасная конструкция в apt-вводе: {pattern}"
            )
    try:
        tokens = shlex.split(source, posix=True)
    except ValueError as exc:
        raise CatalogValidationError(f"Не удалось разобрать apt-ввод: {exc}") from exc
    if not tokens:
        return []

    lowered = [token.lower() for token in tokens]
    start_index = 0
    if lowered and lowered[0] == "sudo":
        start_index = 1
    if len(tokens) > start_index and lowered[start_index] in {"apt", "apt-get"}:
        start_index += 1
        if len(tokens) > start_index and lowered[start_index] == "install":
            start_index += 1

    packages: list[str] = []
    for token in tokens[start_index:]:
        if token.startswith("-"):
            continue
        if token == "--":
            continue
        if not APT_PACKAGE_TOKEN_RE.fullmatch(token):
            raise CatalogValidationError(f"Некорректное имя apt-пакета: {token}")
        packages.append(token)
    return packages


def load_software_catalog(json_path: str) -> dict:
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

    seen_ids: set[str] = set()
    for index, raw_item in enumerate(software, start=1):
        if not isinstance(raw_item, dict):
            raise CatalogError(f"Элемент каталога #{index} должен быть объектом")
        entry_id = str(raw_item.get("id", "")).strip()
        title = str(raw_item.get("title", "")).strip()
        os_family = str(raw_item.get("os_family", "")).strip().lower()
        install_type = str(raw_item.get("install_type", "")).strip().lower()
        if not entry_id or not title or not os_family or not install_type:
            raise CatalogError(f"Элемент каталога #{index} содержит пустые обязательные поля")
        if entry_id in seen_ids:
            raise CatalogError(f"Дублирующийся id в каталоге ПО: {entry_id}")
        seen_ids.add(entry_id)
    return payload


def validate_software_entry(entry: dict, existing_ids: set[str] | None = None, current_id: str = "") -> dict:
    candidate = dict(entry)
    candidate["title"] = str(candidate.get("title", "")).strip()
    candidate["id"] = str(candidate.get("id", "")).strip() or slugify_software_id(candidate["title"])
    candidate["os_family"] = str(candidate.get("os_family", "")).strip().lower()
    candidate["install_type"] = str(candidate.get("install_type", "")).strip().lower()
    candidate["description"] = str(candidate.get("description", "")).strip()
    candidate["timeout_sec"] = max(1, int(candidate.get("timeout_sec", 1800)))
    candidate["requires_sudo"] = bool(candidate.get("requires_sudo", False))
    candidate["enabled"] = bool(candidate.get("enabled", True))

    tags = candidate.get("tags", [])
    if isinstance(tags, str):
        tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
    elif isinstance(tags, list):
        tags = [str(tag).strip() for tag in tags if str(tag).strip()]
    else:
        tags = []
    candidate["tags"] = tags

    if not candidate["id"] or not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", candidate["id"]):
        raise CatalogValidationError("Поле id должно содержать только a-z, 0-9, '_' и '-'")
    if not candidate["title"] or not candidate["os_family"] or not candidate["install_type"]:
        raise CatalogValidationError("Поля title, os_family и install_type обязательны")
    if candidate["install_type"] not in APT_INSTALL_TYPES:
        raise CatalogValidationError("Поддерживаются install_type: apt, deb_file, deb_url")

    ids_pool = existing_ids or set()
    if candidate["id"] != current_id and candidate["id"] in ids_pool:
        raise CatalogValidationError(f"id уже существует: {candidate['id']}")

    if candidate["install_type"] == "apt":
        apt_input = str(candidate.get("apt_input", "")).strip()
        if not apt_input:
            apt_input = " ".join(candidate.get("packages") or []) or str(candidate.get("package_name", "")).strip()
        packages = normalize_apt_input(apt_input)
        if not packages:
            raise CatalogValidationError("Для apt требуется минимум один пакет")
        candidate["packages"] = packages
        candidate["package_name"] = packages[0]
        candidate["url"] = ""
        candidate["local_path"] = ""
    elif candidate["install_type"] == "deb_file":
        local_path = str(candidate.get("local_path", "")).strip()
        if not local_path:
            raise CatalogValidationError("Для deb_file укажите путь к локальному файлу")
        if not os.path.isfile(local_path):
            raise CatalogValidationError(f"Файл .deb не найден: {local_path}")
        candidate["local_path"] = local_path
        candidate["url"] = ""
        candidate["packages"] = []
        candidate["package_name"] = ""
    elif candidate["install_type"] == "deb_url":
        url = str(candidate.get("url", "")).strip()
        if not url:
            raise CatalogValidationError("Для deb_url укажите URL")
        candidate["url"] = url
        candidate["local_path"] = ""
        candidate["packages"] = []
        candidate["package_name"] = ""
    return candidate


def save_software_catalog(json_path: str, payload: dict) -> None:
    backup_path = f"{json_path}.bak"
    if os.path.exists(json_path):
        with open(json_path, "rb") as src, open(backup_path, "wb") as dst:
            dst.write(src.read())
    folder = os.path.dirname(os.path.abspath(json_path)) or "."
    fd, temp_path = tempfile.mkstemp(prefix="software_catalog_", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file_obj:
            json.dump(payload, file_obj, ensure_ascii=False, indent=2)
            file_obj.flush()
            os.fsync(file_obj.fileno())
        os.replace(temp_path, json_path)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def upsert_software_entry(json_path: str, entry: dict, current_id: str = "") -> dict:
    payload = load_software_catalog(json_path)
    software = payload.get("software", [])
    existing_ids = {str(item.get("id", "")).strip() for item in software if isinstance(item, dict)}
    validated = validate_software_entry(entry, existing_ids=existing_ids, current_id=current_id)

    target_id = current_id or validated["id"]
    updated = False
    for index, item in enumerate(software):
        if isinstance(item, dict) and str(item.get("id", "")).strip() == target_id:
            software[index] = {**item, **validated}
            updated = True
            break
    if not updated:
        software.append(validated)

    save_software_catalog(json_path, payload)
    return validated


def disable_software_entry(json_path: str, entry_id: str) -> None:
    payload = load_software_catalog(json_path)
    software = payload.get("software", [])
    for item in software:
        if isinstance(item, dict) and str(item.get("id", "")).strip() == entry_id:
            item["enabled"] = False
            save_software_catalog(json_path, payload)
            return
    raise CatalogError(f"Элемент ПО не найден: {entry_id}")


def delete_software_entry(json_path: str, entry_id: str) -> None:
    payload = load_software_catalog(json_path)
    software = payload.get("software", [])
    filtered = [item for item in software if not (isinstance(item, dict) and str(item.get("id", "")).strip() == entry_id)]
    if len(filtered) == len(software):
        raise CatalogError(f"Элемент ПО не найден: {entry_id}")
    payload["software"] = filtered
    save_software_catalog(json_path, payload)


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

    def _extract_tail_lines(self, text: str, max_lines: int = 6) -> str:
        lines = [line.rstrip() for line in text.splitlines() if line.strip()]
        if not lines:
            return text.strip()[-400:]
        return "\n".join(lines[-max_lines:])[-1200:]

    def _looks_like_prompt(self, text: str) -> bool:
        probe = (text or "").strip()
        if not probe:
            return False
        prompt_patterns = (
            r"\[[Yy]/[Nn]\]",
            r"\([Yy]/[Nn]\)",
            r"\[[Nn]/[Yy]\]",
            r"do you want",
            r"continue\?",
            r"press enter",
            r"yes/no",
            r"enter choice",
            r"введите",
            r"продолжить",
            r"подтверд",
        )
        if any(re.search(pattern, probe, re.IGNORECASE) for pattern in prompt_patterns):
            return True
        return probe.endswith(":") or probe.endswith("?")

    def _match_auto_response(
        self,
        prompt_text: str,
        interactive_responses: list[dict[str, str]],
    ) -> Optional[tuple[str, str]]:
        for entry in interactive_responses:
            pattern = str(entry.get("pattern", "")).strip()
            if not pattern:
                continue
            if re.search(pattern, prompt_text, re.IGNORECASE | re.MULTILINE):
                return pattern, str(entry.get("response", ""))
        return None

    def run_command_interactive(
        self,
        client,
        command: str,
        timeout_sec: int,
        step_name: str,
        stdin_data: str = "",
        interactive_responses: Optional[list[dict[str, str]]] = None,
        prompt_callback: Optional[Callable[[str], Optional[str]]] = None,
        prompt_idle_sec: int = 2,
    ) -> StepResult:
        started = time.time()
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout_sec, get_pty=True)
        if stdin_data:
            stdin.write(stdin_data)
            stdin.flush()

        channel = stdout.channel
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        combined_tail = ""
        last_output_at = time.time()
        last_prompt_text = ""
        timed_out = False
        deadline = started + max(1, timeout_sec)
        interactive_responses = interactive_responses or []

        while True:
            activity = False
            while channel.recv_ready():
                chunk = channel.recv(65536)
                stdout_chunks.append(chunk)
                stdout_buffer.extend(chunk)
                self._emit_output_lines(step_name, "stdout", stdout_buffer)
                combined_tail = (combined_tail + chunk.decode("utf-8", errors="replace"))[-4000:]
                last_output_at = time.time()
                activity = True
            while channel.recv_stderr_ready():
                chunk = channel.recv_stderr(65536)
                stderr_chunks.append(chunk)
                stderr_buffer.extend(chunk)
                self._emit_output_lines(step_name, "stderr", stderr_buffer)
                combined_tail = (combined_tail + chunk.decode("utf-8", errors="replace"))[-4000:]
                last_output_at = time.time()
                activity = True

            if channel.exit_status_ready():
                if not channel.recv_ready() and not channel.recv_stderr_ready():
                    break

            prompt_text = self._extract_tail_lines(combined_tail)
            idle_for = time.time() - last_output_at
            if (
                not activity
                and prompt_text
                and prompt_text != last_prompt_text
                and idle_for >= prompt_idle_sec
                and self._looks_like_prompt(prompt_text)
            ):
                last_prompt_text = prompt_text
                self._log("[interactive] detected possible prompt")
                auto_response = self._match_auto_response(prompt_text, interactive_responses)
                if auto_response is not None:
                    pattern, response = auto_response
                    stdin.write(response if response.endswith("\n") else f"{response}\n")
                    stdin.flush()
                    self._log(f"[auto-response] matched '{pattern}' -> sent response")
                    last_output_at = time.time()
                elif prompt_callback is not None:
                    self._log("[interactive] waiting for operator response")
                    operator_response = prompt_callback(prompt_text)
                    if operator_response is None:
                        raise InteractivePromptCancelled("Операция отменена оператором во время интерактивного запроса")
                    if operator_response == "__TIMEOUT__":
                        raise InteractivePromptTimeout("Не получен ответ оператора на интерактивный запрос установщика")
                    stdin.write(operator_response if operator_response.endswith("\n") else f"{operator_response}\n")
                    stdin.flush()
                    self._log("[interactive] operator response sent")
                    last_output_at = time.time()

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
            success=exit_status == 0,
            return_code=exit_status,
            stdout=out_text.strip(),
            stderr=err_text.strip(),
            command=command,
            duration_sec=time.time() - started,
        )

    def run_command(self, client, command: str, timeout_sec: int, step_name: str, get_pty: bool = False, stdin_data: str = "") -> StepResult:
        started = time.time()
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout_sec, get_pty=get_pty)
        if stdin_data:
            stdin.write(stdin_data)
            stdin.flush()
            try:
                stdin.channel.shutdown_write()
            except Exception:
                try:
                    stdin.close()
                except Exception:
                    pass
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

    def check_sudo_nopasswd(self, client, timeout_sec: int) -> StepResult:
        return self.run_command(
            client,
            "sudo -n true",
            timeout_sec=timeout_sec,
            step_name="Проверка sudo -n true",
            get_pty=False,
        )

    def run_remote_sudo_command(
        self,
        client,
        remote_command: str,
        timeout_sec: int,
        step_name: str,
        sudo_password: Optional[str] = None,
    ) -> StepResult:
        sudo_prefix = "sudo -n" if sudo_password is None else "sudo -S -p '' -k"
        wrapped_command = f"{sudo_prefix} /bin/sh -c {shlex.quote(remote_command)}"
        stdin_data = "" if sudo_password is None else f"{sudo_password}\n"
        return self.run_command(
            client,
            wrapped_command,
            timeout_sec=timeout_sec,
            step_name=step_name,
            get_pty=False,
            stdin_data=stdin_data,
        )

    def close_client(self, client) -> None:
        try:
            client.close()
        except Exception:
            pass


class UbuntuSoftwareInstaller:
    def __init__(self, executor: SSHExecutor, catalog: Optional[SoftwareCatalog], logger: Optional[Callable[[str], None]] = None):
        self.executor = executor
        self.catalog = catalog
        self.logger = logger or (lambda _msg: None)

    def _log(self, message: str) -> None:
        self.logger(message)

    def _passwordless_sudo_message(self) -> str:
        return "На хосте не настроен passwordless sudo для пользователя support"

    def _passwordless_sudo_message_for_user(self, username: str) -> str:
        return f"На хосте не настроен passwordless sudo для пользователя {username}"

    def _sudo_password_required(self, step_result: StepResult) -> bool:
        combined_output = f"{step_result.stdout}\n{step_result.stderr}".lower()
        password_required_markers = (
            "a password is required",
            "password is required",
            "требуется указать пароль",
            "необходимо указать пароль",
        )
        if any(marker in combined_output for marker in password_required_markers):
            return True
        return "sudo:" in combined_output and ("password" in combined_output or "парол" in combined_output)

    def _get_sudo_preflight_command(self, item: Optional[SoftwareItem] = None, command_hint: str = "") -> str:
        install_type = (item.install_type.lower() if item else "")
        command_hint = (command_hint or "").lower()
        if install_type in {"apt", "deb_url", "deb_file"}:
            return "sudo -n /usr/bin/apt-get --version"
        if "systemctl" in command_hint:
            return "sudo -n /usr/bin/systemctl --version"
        return "sudo -n true"

    def _run_sudo_preflight(
        self,
        result: ActionResult,
        client,
        timeout_sec: int,
        item: Optional[SoftwareItem] = None,
        command_hint: str = "",
    ) -> StepResult:
        preflight_command = self._get_sudo_preflight_command(item=item, command_hint=command_hint)
        step_result = self._run_step(
            result,
            client,
            preflight_command,
            "Проверка passwordless sudo",
            timeout_sec,
            get_pty=False,
        )
        return step_result

    def _mark_sudo_repair_needed(self, result: ActionResult) -> None:
        result.needs_sudo_repair = True
        result.sudo_repair_message = self._passwordless_sudo_message()
        result.error_message = self._passwordless_sudo_message()
        self._log("Требуется донастройка sudoers")

    def _ensure_passwordless_sudo(
        self,
        result: ActionResult,
        client,
        timeout_sec: int,
        item: Optional[SoftwareItem] = None,
        command_hint: str = "",
    ) -> Optional[StepResult]:
        step_result = self._run_sudo_preflight(result, client, timeout_sec, item=item, command_hint=command_hint)
        if step_result.success:
            return None
        if self._sudo_password_required(step_result):
            self._mark_sudo_repair_needed(result)
            return step_result
        result.error_message = step_result.stderr or step_result.stdout or self._passwordless_sudo_message()
        return step_result

    def _run_step(
        self,
        result: ActionResult,
        client,
        command: str,
        step_name: str,
        timeout_sec: int,
        get_pty: bool = False,
        stdin_data: str = "",
        interactive_responses: Optional[list[dict[str, str]]] = None,
        prompt_callback: Optional[Callable[[str], Optional[str]]] = None,
    ) -> StepResult:
        self._log(f"[{step_name}] Выполняю: {command}")
        if get_pty and (interactive_responses or prompt_callback):
            step_result = self.executor.run_command_interactive(
                client,
                command,
                timeout_sec=timeout_sec,
                step_name=step_name,
                stdin_data=stdin_data,
                interactive_responses=interactive_responses,
                prompt_callback=prompt_callback,
            )
        else:
            step_result = self.executor.run_command(
                client,
                command,
                timeout_sec=timeout_sec,
                step_name=step_name,
                get_pty=get_pty,
                stdin_data=stdin_data,
            )
        result.steps.append(step_result)
        if step_result.success:
            self._log(f"[{step_name}] OK")
        else:
            self._log(f"[{step_name}] ERROR rc={step_result.return_code}: {step_result.stderr or step_result.stdout}")
        return step_result

    def _resolve_sudo_password(
        self,
        action_result: ActionResult,
        client,
        username: str,
        host_name: str,
        timeout_sec: int,
        ssh_password_candidate: str = "",
        sudo_password_prompt: Optional[Callable[[str, str], Optional[str]]] = None,
    ) -> tuple[bool, Optional[str]]:
        preflight_step = self.executor.check_sudo_nopasswd(client, timeout_sec)
        action_result.steps.append(preflight_step)
        if preflight_step.success:
            self._log(f"sudo -n true успешно для {username}@{host_name}")
            return True, None

        if not self._sudo_password_required(preflight_step):
            action_result.error_message = (
                preflight_step.stderr
                or preflight_step.stdout
                or f"Не удалось проверить sudo для пользователя {username}"
            )
            return False, None

        self._log(f"sudo -n true требует пароль для {username}@{host_name}")
        if ssh_password_candidate:
            self._log(f"Пробую SSH Password как кандидат sudo для {username}@{host_name}")
            ssh_password_step = self.executor.run_remote_sudo_command(
                client,
                "true",
                timeout_sec=timeout_sec,
                step_name="Проверка sudo с SSH Password",
                sudo_password=ssh_password_candidate,
            )
            action_result.steps.append(ssh_password_step)
            if ssh_password_step.success:
                self._log(f"SSH Password подошёл для sudo у {username}@{host_name}")
                return True, ssh_password_candidate
            self._log(f"SSH Password не подошёл для sudo у {username}@{host_name}")

        if sudo_password_prompt is None:
            action_result.error_message = f"Для {username}@{host_name} требуется sudo-пароль, но ввод недоступен."
            return False, None

        manual_password = sudo_password_prompt(host_name, username)
        if manual_password is None:
            action_result.error_message = f"Операция отменена: sudo-пароль для {username}@{host_name} не введён."
            self._log(f"Оператор отменил ввод sudo-пароля для {username}@{host_name}")
            return False, None

        manual_step = self.executor.run_remote_sudo_command(
            client,
            "true",
            timeout_sec=timeout_sec,
            step_name="Проверка sudo с введённым паролем",
            sudo_password=manual_password,
        )
        action_result.steps.append(manual_step)
        if manual_step.success:
            self._log(f"Ручной sudo-пароль подтверждён для {username}@{host_name}")
            return True, manual_password

        action_result.error_message = (
            manual_step.stderr
            or manual_step.stdout
            or f"Не удалось аутентифицироваться через sudo для {username}@{host_name}"
        )
        self._log(f"Ручной sudo-пароль не подошёл для {username}@{host_name}")
        return False, None

    def apply_tshelper_sudoers(
        self,
        host: RemoteHost,
        username: str,
        ssh_password_candidate: str = "",
        sudo_password_prompt: Optional[Callable[[str, str], Optional[str]]] = None,
    ) -> ActionResult:
        safe_username = validate_tshelper_username(username)
        action_result = ActionResult(action_name="Настройка TSHelper sudoers", success=False)
        client = None
        remote_temp_path = ""
        timeout_sec = min(300, self.executor.auth.command_timeout_sec)
        self._log(f"Старт настройки TSHelper sudoers: host={','.join(host.candidates)} login={safe_username}")
        try:
            client, used_key_auth, key_bootstrapped, used_host = self.executor.connect_with_fallback(host)
            action_result.used_key_auth = used_key_auth
            action_result.key_bootstrapped = key_bootstrapped
            action_result.host_used = used_host
            self._log(f"Подключение к {used_host} установлено для настройки sudoers пользователя {safe_username}")

            auth_ok, sudo_password = self._resolve_sudo_password(
                action_result,
                client,
                username=safe_username,
                host_name=used_host,
                timeout_sec=timeout_sec,
                ssh_password_candidate=ssh_password_candidate,
                sudo_password_prompt=sudo_password_prompt,
            )
            if not auth_ok:
                if not action_result.error_message:
                    action_result.error_message = self._passwordless_sudo_message_for_user(safe_username)
                return action_result

            mktemp_step = self._run_step(
                action_result,
                client,
                "mktemp /tmp/tshelper-sudoers.XXXXXX",
                "Создание временного sudoers-файла",
                timeout_sec,
            )
            if not mktemp_step.success:
                action_result.error_message = mktemp_step.stderr or mktemp_step.stdout or "Не удалось создать временный sudoers-файл"
                return action_result
            remote_temp_path = (mktemp_step.stdout or "").strip().splitlines()[-1].strip()
            if not remote_temp_path.startswith("/tmp/"):
                action_result.error_message = "Удалённая сторона вернула неожиданный путь временного sudoers-файла"
                return action_result

            sudoers_content = build_tshelper_sudoers_content(safe_username)
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", delete=False) as temp_file:
                temp_file.write(sudoers_content)
                local_temp_path = temp_file.name
            try:
                self.executor.upload_file(client, local_temp_path, remote_temp_path)
            finally:
                try:
                    os.remove(local_temp_path)
                except OSError:
                    pass
            action_result.steps.append(
                StepResult(
                    name="Загрузка временного sudoers-файла",
                    success=True,
                    return_code=0,
                    stdout=f"Загружен {remote_temp_path}",
                    command=remote_temp_path,
                    host=used_host,
                )
            )

            visudo_step = self.executor.run_remote_sudo_command(
                client,
                f"visudo -cf {shlex.quote(remote_temp_path)}",
                timeout_sec=timeout_sec,
                step_name="Проверка visudo",
                sudo_password=sudo_password,
            )
            action_result.steps.append(visudo_step)
            if visudo_step.success:
                self._log(f"visudo -cf успешно для {used_host} ({safe_username})")
            else:
                self._log(f"visudo -cf завершился ошибкой для {used_host} ({safe_username})")
                action_result.error_message = visudo_step.stderr or visudo_step.stdout or "Проверка visudo завершилась ошибкой"
                return action_result

            move_step = self.executor.run_remote_sudo_command(
                client,
                f"mv {shlex.quote(remote_temp_path)} {shlex.quote(TSHELPER_SUDOERS_PATH)}",
                timeout_sec=timeout_sec,
                step_name="Установка managed sudoers-файла",
                sudo_password=sudo_password,
            )
            action_result.steps.append(move_step)
            if not move_step.success:
                action_result.error_message = move_step.stderr or move_step.stdout or "Не удалось установить managed sudoers-файл"
                return action_result
            remote_temp_path = ""

            chown_step = self.executor.run_remote_sudo_command(
                client,
                f"chown root:root {shlex.quote(TSHELPER_SUDOERS_PATH)}",
                timeout_sec=timeout_sec,
                step_name="Назначение владельца sudoers-файла",
                sudo_password=sudo_password,
            )
            action_result.steps.append(chown_step)
            if not chown_step.success:
                action_result.error_message = chown_step.stderr or chown_step.stdout or "Не удалось назначить владельца sudoers-файла"
                return action_result

            chmod_step = self.executor.run_remote_sudo_command(
                client,
                f"chmod 0440 {shlex.quote(TSHELPER_SUDOERS_PATH)}",
                timeout_sec=timeout_sec,
                step_name="Назначение прав sudoers-файла",
                sudo_password=sudo_password,
            )
            action_result.steps.append(chmod_step)
            if not chmod_step.success:
                action_result.error_message = chmod_step.stderr or chmod_step.stdout or "Не удалось назначить права sudoers-файла"
                return action_result

            action_result.success = True
            action_result.error_message = ""
            self._log(f"TSHelper sudoers успешно обновлён на {used_host} для {safe_username}")
            return action_result
        except RemoteOpsError as exc:
            action_result.error_message = str(exc)
            self._log(f"Ошибка настройки TSHelper sudoers: {exc}")
            return action_result
        except Exception as exc:
            action_result.error_message = str(exc)
            self._log(f"Непредвиденная ошибка настройки TSHelper sudoers: {exc}")
            return action_result
        finally:
            if client is not None and remote_temp_path:
                try:
                    cleanup_step = self.executor.run_command(
                        client,
                        f"rm -f {shlex.quote(remote_temp_path)}",
                        timeout_sec=30,
                        step_name="Очистка временного sudoers-файла",
                    )
                    action_result.steps.append(cleanup_step)
                except Exception as cleanup_error:
                    self._log(f"Не удалось удалить временный sudoers-файл: {cleanup_error}")
            if client is not None:
                self.executor.close_client(client)

    def repair_passwordless_sudo(self, host: RemoteHost, sudo_password: str) -> ActionResult:
        return self.apply_tshelper_sudoers(host, username="support", ssh_password_candidate=sudo_password)

    def install_software(
        self,
        host: RemoteHost,
        item_id: str,
        force_reinstall: bool = False,
        prompt_callback: Optional[Callable[[str, str, str], Optional[str]]] = None,
    ) -> ActionResult:
        if self.catalog is None:
            raise CatalogError("Каталог ПО не загружен")
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

            def item_prompt_callback(prompt_text: str) -> Optional[str]:
                if prompt_callback is None:
                    return None
                return prompt_callback(action_result.host_used or "", item.title, prompt_text)

            if install_type == "apt":
                apt_packages = item.packages or ([item.package_name] if item.package_name else [])
                if not apt_packages:
                    raise CatalogError(f"Для apt-пакета не указано package_name/packages: {item.item_id}")
                sudo_prefix = "sudo -n " if item.requires_sudo else ""
                if item.requires_sudo:
                    preflight_result = self._ensure_passwordless_sudo(action_result, client, timeout_sec, item=item)
                    if preflight_result is not None:
                        return action_result
                update_result = self._run_step(action_result, client, f"{sudo_prefix}apt-get update", "apt-get update", timeout_sec)
                if not update_result.success:
                    action_result.error_message = update_result.stderr or update_result.stdout or "Ошибка apt-get update"
                    return action_result
                quoted_packages = " ".join(shlex.quote(package) for package in apt_packages)
                install_command = (
                    f"{sudo_prefix}apt-get -o DPkg::Lock::Timeout=60 install -y "
                    f"{quoted_packages}"
                )
                install_result = self._run_step(action_result, client, install_command, "Установка apt-пакета", timeout_sec)
            elif install_type == "deb_file":
                local_path = item.local_path
                if not local_path:
                    raise CatalogError(f"Для deb_file не указан local_path: {item.item_id}")
                if not os.path.isabs(local_path):
                    local_path = os.path.join(os.path.dirname(os.path.abspath(self.catalog.source_path)), local_path)
                if not os.path.isfile(local_path):
                    raise CatalogError(f"Файл .deb не найден: {local_path}")
                remote_deb = f"/tmp/tshelper_{item.item_id}_{int(time.time())}.deb"
                cleanup_remote_paths.append(remote_deb)
                self._log(f"Загружаю deb-файл {local_path} -> {remote_deb}")
                self.executor.upload_file(client, local_path, remote_deb)
                upload_step = StepResult(name="Загрузка deb-файла", success=True, return_code=0, stdout=f"Загружен {remote_deb}", command=local_path)
                action_result.steps.append(upload_step)
                sudo_prefix = "sudo -n " if item.requires_sudo else ""
                if item.requires_sudo:
                    preflight_result = self._ensure_passwordless_sudo(action_result, client, timeout_sec, item=item)
                    if preflight_result is not None:
                        return action_result
                install_command = (
                    f"{sudo_prefix}apt-get -o DPkg::Lock::Timeout=60 install -y "
                    f"{shlex.quote(remote_deb)}"
                )
                install_result = self._run_step(
                    action_result,
                    client,
                    install_command,
                    "Установка локального deb-пакета",
                    timeout_sec,
                    get_pty=item.requires_sudo,
                    interactive_responses=item.interactive_responses,
                    prompt_callback=item_prompt_callback,
                )
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
                sudo_prefix = "sudo -n " if item.requires_sudo else ""
                if item.requires_sudo:
                    preflight_result = self._ensure_passwordless_sudo(action_result, client, timeout_sec, item=item)
                    if preflight_result is not None:
                        return action_result
                install_command = (
                    f"{sudo_prefix}apt-get -o DPkg::Lock::Timeout=60 install -y "
                    f"{shlex.quote(remote_deb)}"
                )
                install_result = self._run_step(
                    action_result,
                    client,
                    install_command,
                    "Установка deb-пакета",
                    timeout_sec,
                    get_pty=item.requires_sudo,
                    interactive_responses=item.interactive_responses,
                    prompt_callback=item_prompt_callback,
                )
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
                install_result = self._run_step(
                    action_result,
                    client,
                    item.install_cmd,
                    "Выполнение команды",
                    timeout_sec,
                    get_pty=(item.requires_sudo or bool(item.interactive_responses)),
                    interactive_responses=item.interactive_responses,
                    prompt_callback=item_prompt_callback,
                )
            else:
                raise CatalogError(f"Неподдерживаемый install_type: {item.install_type}")

            if not install_result or not install_result.success:
                action_result.error_message = (install_result.stderr or install_result.stdout or "Ошибка установки") if install_result else "Ошибка установки"
                return action_result

            if item.post_install_cmd:
                post_result = self._run_step(
                    action_result,
                    client,
                    item.post_install_cmd,
                    "Post-install",
                    timeout_sec,
                    get_pty=(item.requires_sudo or install_type in {"deb_url", "custom_cmd"} or bool(item.interactive_responses)),
                    interactive_responses=item.interactive_responses,
                    prompt_callback=item_prompt_callback,
                )
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
