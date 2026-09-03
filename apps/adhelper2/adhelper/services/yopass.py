from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote

from pgpy import PGPMessage
from pgpy.constants import CompressionAlgorithm, HashAlgorithm, SymmetricKeyAlgorithm


class YopassError(RuntimeError):
    pass


@dataclass(slots=True)
class YopassResult:
    url: str
    secret_id: str


class YopassClient:
    """Клиент совместимого с YoPass API с локальным OpenPGP-шифрованием."""

    def __init__(
        self,
        base_url: str,
        opener: Callable[..., object] | None = None,
    ) -> None:
        self.base_url = str(base_url or "").strip().rstrip("/")
        self._opener = opener or urllib.request.urlopen

    def create_secret(
        self,
        secret_text: str,
        *,
        expiration: int = 604800,
        one_time: bool = True,
        timeout: int = 15,
    ) -> YopassResult:
        if not self.base_url.startswith("https://"):
            raise YopassError("Адрес YoPass должен использовать HTTPS")
        if expiration not in {3600, 86400, 604800}:
            raise YopassError("YoPass поддерживает срок 1 час, 1 день или 1 неделю")
        if not secret_text.strip():
            raise YopassError("Нельзя создать пустой секрет")

        decryption_key = secrets.token_urlsafe(24)
        message = PGPMessage.new(secret_text, compression=CompressionAlgorithm.ZLIB)
        encrypted = message.encrypt(
            decryption_key,
            cipher=SymmetricKeyAlgorithm.AES256,
            hash=HashAlgorithm.SHA256,
        )
        payload = json.dumps({
            "expiration": expiration,
            "message": str(encrypted),
            "one_time": one_time,
        }).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/secret",
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with self._opener(request, timeout=timeout) as response:  # type: ignore[attr-defined]
                response_data = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise YopassError(f"Не удалось создать защищённую ссылку: {exc}") from exc

        secret_id = str(response_data.get("message") or "").strip()
        if not secret_id or any(character in secret_id for character in "/?#"):
            raise YopassError("YoPass вернул некорректный идентификатор секрета")
        url = f"{self.base_url}/#/{quote(secret_id, safe='')}/{quote(decryption_key, safe='')}"
        return YopassResult(url=url, secret_id=secret_id)
