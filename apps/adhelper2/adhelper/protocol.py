from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .constants import APP_NAME, PROJECT_ROOT

PROTOCOL_SCHEME = "adhelper"
PROTOCOL_ACTION = "onboard"


class ProtocolError(ValueError):
    """Некорректная или неподдерживаемая ссылка ADHelper."""


def _decode_base64url(value: str) -> bytes:
    value = (value or "").strip()
    if not value:
        raise ProtocolError("В ссылке отсутствуют данные заявки")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except Exception as exc:  # pragma: no cover - конкретный тип зависит от Python
        raise ProtocolError("Не удалось декодировать данные заявки") from exc


def decode_onboarding_uri(uri: str) -> dict[str, Any]:
    """Разбирает ``adhelper://onboard?data=...`` и валидирует безопасный минимум."""
    try:
        parsed = urlparse((uri or "").strip())
    except Exception as exc:  # pragma: no cover
        raise ProtocolError("Некорректная ссылка ADHelper") from exc

    if parsed.scheme.lower() != PROTOCOL_SCHEME:
        raise ProtocolError("Ссылка имеет неподдерживаемую схему")
    if parsed.netloc.lower() != PROTOCOL_ACTION:
        raise ProtocolError("Неизвестное действие ADHelper")

    params = parse_qs(parsed.query, keep_blank_values=True)
    encoded = (params.get("data") or [""])[0]
    try:
        payload = json.loads(_decode_base64url(encoded).decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ProtocolError("Данные заявки имеют неверную кодировку") from exc
    except json.JSONDecodeError as exc:
        raise ProtocolError("Данные заявки повреждены") from exc

    if not isinstance(payload, dict):
        raise ProtocolError("Ожидался объект с данными заявки")

    request_text = str(payload.get("request_text") or "").strip()
    callback_url = str(payload.get("callback_url") or "").strip()
    source_url = str(payload.get("source_url") or "").strip()
    ticket_id = payload.get("ticket_id")

    if not request_text:
        raise ProtocolError("GLPI не передал текст заявки")
    try:
        ticket_id = int(ticket_id)
    except (TypeError, ValueError) as exc:
        raise ProtocolError("GLPI не передал корректный ID заявки") from exc
    if ticket_id <= 0:
        raise ProtocolError("GLPI не передал корректный ID заявки")

    # Callback не должен уводить приложение на посторонний сайт. Сервер GLPI
    # передаёт source_url и callback_url с одного HTTPS-хоста.
    callback = urlparse(callback_url)
    source = urlparse(source_url)
    if callback.scheme.lower() != "https" or not callback.netloc:
        raise ProtocolError("Callback GLPI должен использовать HTTPS")
    if source.scheme.lower() != "https" or not source.netloc:
        raise ProtocolError("Адрес исходной заявки GLPI должен использовать HTTPS")
    if callback.netloc.lower() != source.netloc.lower():
        raise ProtocolError("Callback GLPI ведёт на другой сервер")

    payload["ticket_id"] = ticket_id
    payload["request_text"] = request_text
    payload["callback_url"] = callback_url
    payload["source_url"] = source_url
    return payload


def is_onboarding_uri(value: str) -> bool:
    try:
        parsed = urlparse((value or "").strip())
    except Exception:
        return False
    return parsed.scheme.lower() == PROTOCOL_SCHEME and parsed.netloc.lower() == PROTOCOL_ACTION


def _protocol_command() -> str:
    """Команда запуска для HKCU\\Software\\Classes\\adhelper."""
    if getattr(sys, "frozen", False):
        executable = Path(sys.executable).resolve()
        return f'"{executable}" "%1"'

    executable = Path(sys.executable).resolve()
    main_py = (PROJECT_ROOT / "main.py").resolve()
    return f'"{executable}" "{main_py}" "%1"'


def register_protocol_handler() -> bool:
    """Регистрирует adhelper:// для текущего пользователя Windows без прав администратора."""
    if os.name != "nt":
        return False

    try:
        import winreg

        base = rf"Software\Classes\{PROTOCOL_SCHEME}"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, f"URL:{APP_NAME} Protocol")
            winreg.SetValueEx(key, "URL Protocol", 0, winreg.REG_SZ, "")

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r"\DefaultIcon") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(Path(sys.executable).resolve()))

        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r"\shell\open\command") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, _protocol_command())
        return True
    except OSError:
        return False
