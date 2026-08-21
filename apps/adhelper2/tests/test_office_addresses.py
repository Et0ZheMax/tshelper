from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adhelper.models import DomainConfig, ParsedRequest
from adhelper.services.onboarding import DomainPlan, OnboardingPlan, OnboardingService
from adhelper.settings import SettingsStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ONBOARDING_SOURCE = (PROJECT_ROOT / "adhelper" / "ui" / "pages" / "onboarding.py").read_text(encoding="utf-8")
SETTINGS_SOURCE = (PROJECT_ROOT / "adhelper" / "ui" / "pages" / "settings_page.py").read_text(encoding="utf-8")


class OfficeAddressSettingsTests(unittest.TestCase):
    def test_addresses_are_persisted_with_ad_metadata_and_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {"APPDATA": temp_dir}):
            store = SettingsStore()
            values = [
                {
                    "address": "ул. Тестовая, д. 1",
                    "pobox": "Москва",
                    "city": "Москва",
                    "state": "Москва",
                    "postal_code": "101000",
                    "country": "RU",
                },
                {
                    "address": "ул. Вторая, д. 2",
                    "pobox": "",
                    "city": "Москва",
                    "state": "Москва",
                    "postal_code": "101001",
                    "country": "RU",
                },
            ]
            store.set_office_addresses(values)
            store.set_default_address("ул. Вторая, д. 2")

            reloaded = SettingsStore()
            self.assertEqual(reloaded.default_address(), "ул. Вторая, д. 2")
            self.assertEqual(reloaded.address_details("УЛ. ТЕСТОВАЯ, Д. 1")["postal_code"], "101000")
            config = json.loads((Path(temp_dir) / "ADHelper" / "config_v2.json").read_text(encoding="utf-8"))
            self.assertEqual(len(config["office_addresses"]), 2)

    def test_removing_default_address_selects_first_remaining_address(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {"APPDATA": temp_dir}):
            store = SettingsStore()
            original = store.office_addresses()
            store.set_default_address(original[-1]["address"])
            store.set_office_addresses([original[0]])
            self.assertEqual(store.default_address(), original[0]["address"])

    def test_duplicate_addresses_are_rejected_case_insensitively(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {"APPDATA": temp_dir}):
            store = SettingsStore()
            with self.assertRaises(ValueError):
                store.set_office_addresses([
                    {"address": "Москва, дом 1"},
                    {"address": "МОСКВА, ДОМ 1"},
                ])


class OfficeAddressUISourceTests(unittest.TestCase):
    def test_onboarding_address_combo_is_editable_and_uses_saved_addresses(self) -> None:
        self.assertIn("self.address_combo.setEditable(True)", ONBOARDING_SOURCE)
        self.assertIn("self.context.settings.office_addresses()", ONBOARDING_SOURCE)
        self.assertIn("self.context.settings.address_details(address)", ONBOARDING_SOURCE)
        self.assertIn("self.context.events.addresses_changed.connect(self._addresses_changed)", ONBOARDING_SOURCE)

    def test_settings_can_add_delete_restore_and_save_office_addresses(self) -> None:
        for fragment in (
            "def _build_addresses_card",
            "def _add_address",
            "def _delete_address",
            "def _restore_addresses",
            "def _save_addresses",
            "Сохранить адреса",
        ):
            self.assertIn(fragment, SETTINGS_SOURCE)


class OnboardingAddressPayloadTests(unittest.TestCase):
    def test_payload_uses_address_and_metadata_captured_in_plan(self) -> None:
        domain = DomainConfig(
            name="pak",
            label="pak",
            netbios="PAK",
            server="dc.example.test",
            search_base="DC=example,DC=test",
            ou_dn="OU=Users,DC=example,DC=test",
            upn_suffix="@example.test",
            email_suffix="@example.test",
            fired_ou_dn="OU=Fired,DC=example,DC=test",
        )
        request = ParsedRequest(last_name="Иванов", first_name="Иван", title="Инженер")
        domain_plan = DomainPlan(domain=domain, target_ou=domain.ou_dn, department="ИТ")
        plan = OnboardingPlan(
            request=request,
            sam="iivanov",
            address="ул. Тестовая, д. 1",
            address_meta={"city": "Москва", "postal_code": "101000", "country": "RU"},
            password="Password1!",
            domains=[domain_plan],
        )

        payload = OnboardingService._build_payload(plan, domain_plan)

        self.assertEqual(payload["street_address"], "ул. Тестовая, д. 1")
        self.assertEqual(payload["address_meta"]["postal_code"], "101000")
        plan.address_meta["postal_code"] = "999999"
        self.assertEqual(payload["address_meta"]["postal_code"], "101000")


if __name__ == "__main__":
    unittest.main()
