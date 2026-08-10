"""Локальный HTTP-мост между браузерным расширением GLPI и TSHelper.

Сервер слушает только loopback-адрес, принимает JSON и никогда не выполняет
переданные браузером команды. Браузер может лишь попросить TSHelper найти
пользователя и открыть его уже существующее меню действий.
"""

from __future__ import annotations

import hmac
import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional
from urllib.parse import urlsplit


MAX_BODY_BYTES = 16 * 1024
ALLOWED_EXTENSION_SCHEMES = {"chrome-extension", "moz-extension", "edge-extension"}


@dataclass(frozen=True)
class BrowserIntegrationAddress:
    host: str
    port: int

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


class BrowserIntegrationServer:
    """Неблокирующий локальный сервер для запросов из WebExtension."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        token: str,
        open_user_callback: Callable[[dict], dict],
        log_callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Браузерная интеграция может слушать только loopback-адрес")
        if not token:
            raise ValueError("Не задан токен браузерной интеграции")

        self.address = BrowserIntegrationAddress(host=host, port=int(port))
        self.token = str(token)
        self.open_user_callback = open_user_callback
        self.log_callback = log_callback or (lambda _message: None)
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def is_running(self) -> bool:
        return bool(self._httpd and self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.is_running:
            return

        integration = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "TSHelperBrowserBridge/1.0"
            sys_version = ""

            def log_message(self, fmt: str, *args) -> None:  # noqa: A003
                integration.log_callback(f"Browser bridge: {fmt % args}")

            def _origin_is_allowed(self) -> bool:
                origin = (self.headers.get("Origin") or "").strip()
                if not origin:
                    return True
                try:
                    return urlsplit(origin).scheme.lower() in ALLOWED_EXTENSION_SCHEMES
                except Exception:
                    return False

            def _cors_headers(self) -> dict[str, str]:
                origin = (self.headers.get("Origin") or "").strip()
                headers = {
                    "Access-Control-Allow-Headers": "Content-Type, X-TSHelper-Token",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Max-Age": "600",
                    "Access-Control-Allow-Private-Network": "true",
                    "Cache-Control": "no-store",
                }
                if origin and self._origin_is_allowed():
                    headers["Access-Control-Allow-Origin"] = origin
                    headers["Vary"] = "Origin"
                return headers

            def _send_json(self, status: int, payload: dict) -> None:
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                for key, value in self._cors_headers().items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

            def _authorized(self) -> bool:
                provided = self.headers.get("X-TSHelper-Token") or ""
                return hmac.compare_digest(str(provided), integration.token)

            def do_OPTIONS(self) -> None:  # noqa: N802
                if not self._origin_is_allowed():
                    self._send_json(403, {"ok": False, "error": "Недопустимый источник запроса"})
                    return
                self.send_response(204)
                for key, value in self._cors_headers().items():
                    self.send_header(key, value)
                self.end_headers()

            def do_GET(self) -> None:  # noqa: N802
                if self.path.rstrip("/") != "/health":
                    self._send_json(404, {"ok": False, "error": "Маршрут не найден"})
                    return
                if not self._origin_is_allowed():
                    self._send_json(403, {"ok": False, "error": "Недопустимый источник запроса"})
                    return
                if not self._authorized():
                    self._send_json(401, {"ok": False, "error": "Неверный токен TSHelper"})
                    return
                self._send_json(200, {"ok": True, "service": "TSHelper", "bridge": "1.0"})

            def do_POST(self) -> None:  # noqa: N802
                if self.path.rstrip("/") != "/open-user":
                    self._send_json(404, {"ok": False, "error": "Маршрут не найден"})
                    return
                if not self._origin_is_allowed():
                    self._send_json(403, {"ok": False, "error": "Недопустимый источник запроса"})
                    return
                if not self._authorized():
                    self._send_json(401, {"ok": False, "error": "Неверный токен TSHelper"})
                    return

                try:
                    content_length = int(self.headers.get("Content-Length") or "0")
                except ValueError:
                    content_length = 0
                if content_length <= 0 or content_length > MAX_BODY_BYTES:
                    self._send_json(413, {"ok": False, "error": "Некорректный размер запроса"})
                    return

                try:
                    raw = self.rfile.read(content_length)
                    payload = json.loads(raw.decode("utf-8"))
                except Exception:
                    self._send_json(400, {"ok": False, "error": "Ожидался корректный JSON"})
                    return

                if not isinstance(payload, dict):
                    self._send_json(400, {"ok": False, "error": "Ожидался JSON-объект"})
                    return

                allowed_fields = {"glpi_user_id", "name", "login", "email", "extension", "location", "source_url"}
                sanitized = {}
                for key in allowed_fields:
                    value = payload.get(key)
                    if value is None:
                        continue
                    text = str(value).strip()
                    if len(text) > 500:
                        text = text[:500]
                    sanitized[key] = text

                if not any(sanitized.get(key) for key in ("name", "login", "email", "extension")):
                    self._send_json(400, {"ok": False, "error": "Недостаточно данных о пользователе"})
                    return

                try:
                    result = integration.open_user_callback(sanitized)
                except Exception as exc:  # callback обязан сам логировать детали
                    integration.log_callback(f"Browser bridge callback error: {exc}")
                    self._send_json(500, {"ok": False, "error": "TSHelper не смог обработать запрос"})
                    return

                if not isinstance(result, dict):
                    result = {"ok": bool(result)}
                self._send_json(200 if result.get("ok") else 404, result)

        httpd = ThreadingHTTPServer((self.address.host, self.address.port), Handler)
        httpd.daemon_threads = True
        self._httpd = httpd
        self._thread = threading.Thread(
            target=httpd.serve_forever,
            name="TSHelperBrowserBridge",
            daemon=True,
        )
        self._thread.start()
        self.log_callback(f"Browser bridge запущен: {self.address.base_url}")

    def stop(self) -> None:
        httpd = self._httpd
        thread = self._thread
        self._httpd = None
        self._thread = None
        if httpd is not None:
            try:
                httpd.shutdown()
            finally:
                httpd.server_close()
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        self.log_callback("Browser bridge остановлен")
