from __future__ import annotations

import base64
import json

import pytest

from adhelper.protocol import ProtocolError, decode_onboarding_uri, is_onboarding_uri


def _uri(payload: dict) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"adhelper://onboard?data={encoded}"


def test_decode_glpi_onboarding_uri() -> None:
    uri = _uri({
        "ticket_id": 35416,
        "ticket_title": "Организация рабочего места для сотрудника Исакова Елена Борисовна",
        "request_text": "1) Фамилия: Исакова\n2) Имя: Елена",
        "source_url": "https://inv.pak-cspmz.ru/front/ticket.form.php?id=35416",
        "callback_url": "https://inv.pak-cspmz.ru/plugins/workplace/Complete?token=abc",
    })
    payload = decode_onboarding_uri(uri)
    assert payload["ticket_id"] == 35416
    assert "Исакова" in payload["request_text"]
    assert is_onboarding_uri(uri)


def test_callback_must_stay_on_same_glpi_host() -> None:
    uri = _uri({
        "ticket_id": 35416,
        "request_text": "1) Фамилия: Исакова\n2) Имя: Елена",
        "source_url": "https://inv.pak-cspmz.ru/front/ticket.form.php?id=35416",
        "callback_url": "https://example.org/callback",
    })
    with pytest.raises(ProtocolError):
        decode_onboarding_uri(uri)
