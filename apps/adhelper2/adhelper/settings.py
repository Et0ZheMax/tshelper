from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

from .constants import APP_NAME, DOMAIN_CONFIGS, OFFICE_ADDRESSES
from .security import protect_text, unprotect_text


class SettingsStore:
    def __init__(self) -> None:
        appdata = os.environ.get("APPDATA") or str(Path.home())
        self.base_dir = Path(appdata) / APP_NAME
        self.path = self.base_dir / "config_v2.json"
        self.audit_dir = self.base_dir / "audit"
        self.recovery_dir = self.base_dir / "recovery"
        self.generated_dir = self.base_dir / "generated"
        self.log_dir = self.base_dir / "logs"
        for path in (self.base_dir, self.audit_dir, self.recovery_dir, self.generated_dir, self.log_dir):
            path.mkdir(parents=True, exist_ok=True)
        self._data = self._load()
        self._migrate_legacy_if_needed()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}


    def _migrate_legacy_if_needed(self) -> None:
        if self.path.exists():
            return
        legacy_path = self.base_dir / "config.json"
        if not legacy_path.exists():
            return
        try:
            legacy = json.loads(legacy_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(legacy, dict):
            return
        if legacy.get("password_token"):
            self._data["password_token"] = legacy["password_token"]
        if legacy.get("window_geometry"):
            self._data["legacy_window_geometry"] = legacy["window_geometry"]
        self._data["migrated_from_v1"] = True
        self.save()

    def save(self) -> None:
        temp = self.path.with_suffix(".tmp")
        temp.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(self.path)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value
        self.save()

    @staticmethod
    def _normalize_office_address(item: Any) -> dict[str, str] | None:
        if isinstance(item, str):
            item = {"address": item}
        if not isinstance(item, dict):
            return None
        address = str(item.get("address") or item.get("street_address") or "").strip()
        if not address:
            return None
        return {
            "address": address,
            "pobox": str(item.get("pobox") or "").strip(),
            "city": str(item.get("city") or "").strip(),
            "state": str(item.get("state") or "").strip(),
            "postal_code": str(item.get("postal_code") or item.get("postalCode") or "").strip(),
            "country": str(item.get("country") or "").strip().upper(),
        }

    def office_addresses(self) -> list[dict[str, str]]:
        raw = self.get("office_addresses")
        source = raw if isinstance(raw, list) and raw else OFFICE_ADDRESSES
        result: list[dict[str, str]] = []
        seen: set[str] = set()
        for source_item in source:
            item = self._normalize_office_address(source_item)
            if item is None:
                continue
            key = item["address"].casefold()
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        if not result:
            result = deepcopy(OFFICE_ADDRESSES)
        if raw != result:
            self._data["office_addresses"] = deepcopy(result)
            self.save()
        return deepcopy(result)

    def set_office_addresses(self, values: list[dict[str, str]]) -> None:
        if not isinstance(values, list) or not values:
            raise ValueError("Должен быть настроен хотя бы один адрес офиса")
        normalized: list[dict[str, str]] = []
        seen: set[str] = set()
        for source_item in values:
            item = self._normalize_office_address(source_item)
            if item is None:
                raise ValueError("У каждого адреса офиса должно быть заполнено поле «Адрес»")
            key = item["address"].casefold()
            if key in seen:
                raise ValueError(f"Адрес «{item['address']}» указан несколько раз")
            if item["country"] and (len(item["country"]) != 2 or not item["country"].isalpha()):
                raise ValueError(f"{item['address']}: код страны должен состоять из двух букв, например RU")
            seen.add(key)
            normalized.append(item)
        self._data["office_addresses"] = deepcopy(normalized)
        current_default = str(self._data.get("default_address") or "").strip()
        if current_default.casefold() not in seen:
            self._data["default_address"] = normalized[0]["address"]
        self.save()

    def reset_office_addresses(self) -> list[dict[str, str]]:
        values = deepcopy(OFFICE_ADDRESSES)
        self.set_office_addresses(values)
        return values

    def default_address(self) -> str:
        addresses = self.office_addresses()
        choices = [item["address"] for item in addresses]
        value = str(self.get("default_address", choices[0])).strip()
        match = next((item for item in choices if item.casefold() == value.casefold()), "")
        return match or choices[0]

    def set_default_address(self, value: str) -> None:
        clean = str(value or "").strip()
        choices = [item["address"] for item in self.office_addresses()]
        match = next((item for item in choices if item.casefold() == clean.casefold()), "")
        if not match:
            raise ValueError("Адрес по умолчанию должен быть выбран из сохранённых адресов офиса")
        self.set("default_address", match)

    def address_details(self, address: str) -> dict[str, str]:
        clean = str(address or "").strip().casefold()
        for item in self.office_addresses():
            if item["address"].casefold() == clean:
                return {key: value for key, value in item.items() if key != "address" and value}
        return {}

    def set_default_password(self, value: str) -> None:
        self.set("password_token", protect_text(value))

    def get_default_password(self) -> str:
        token = str(self.get("password_token", ""))
        return unprotect_text(token) if token else ""

    def has_default_password(self) -> bool:
        return bool(self.get("password_token", ""))

    def domain_configs(self) -> list[dict[str, str]]:
        raw = self.get("domain_configs")
        source = raw if isinstance(raw, list) and raw else DOMAIN_CONFIGS
        result: list[dict[str, str]] = []
        for item in source:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            profile = str(item.get("profile") or ("omg" if name == "omg-cspfmba" else "standard")).strip().lower()
            if profile not in {"standard", "omg"}:
                profile = "standard"
            result.append({
                "name": name,
                "label": str(item.get("label") or name).strip(),
                "netbios": str(item.get("netbios") or "").strip(),
                "server": str(item.get("server") or "").strip(),
                "search_base": str(item.get("search_base") or "").strip(),
                "ou_dn": str(item.get("ou_dn") or "").strip(),
                "upn_suffix": str(item.get("upn_suffix") or "").strip(),
                "email_suffix": str(item.get("email_suffix") or "").strip(),
                "fired_ou_dn": str(item.get("fired_ou_dn") or "").strip(),
                "profile": profile,
            })
        if not result:
            result = deepcopy(DOMAIN_CONFIGS)
        if raw != result:
            self._data["domain_configs"] = deepcopy(result)
            self.save()
        return deepcopy(result)

    def set_domain_configs(self, values: list[dict[str, str]]) -> None:
        if not isinstance(values, list) or not values:
            raise ValueError("Должен быть настроен хотя бы один домен")
        self._data["domain_configs"] = deepcopy(values)
        self.save()

    def reset_domain_configs(self) -> list[dict[str, str]]:
        values = deepcopy(DOMAIN_CONFIGS)
        self.set_domain_configs(values)
        return values
