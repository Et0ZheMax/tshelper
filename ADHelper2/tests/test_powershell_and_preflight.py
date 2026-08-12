from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adhelper.services.ad_service import ADService
from adhelper.services.powershell import (
    PowerShellClient,
    PowerShellError,
    PowerShellResponse,
    PowerShellTimeoutError,
)


class PowerShellClientTests(unittest.TestCase):
    def test_structured_error_is_shown_without_raw_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            scripts = Path(temp_dir)
            (scripts / "dummy.ps1").write_text("", encoding="utf-8")
            client = PowerShellClient(scripts_dir=scripts)
            completed = subprocess.CompletedProcess(
                args=["powershell"],
                returncode=1,
                stdout='{"ok":false,"data":null,"message":"Понятная ошибка LDAP","warnings":[]}',
                stderr="",
            )
            with patch("subprocess.run", return_value=completed):
                with self.assertRaises(PowerShellError) as raised:
                    client.invoke("dummy")
            self.assertEqual(str(raised.exception), "Понятная ошибка LDAP")
            self.assertNotIn('"ok":false', str(raised.exception))

    def test_utf8_bom_before_json_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            scripts = Path(temp_dir)
            (scripts / "dummy.ps1").write_text("", encoding="utf-8")
            client = PowerShellClient(scripts_dir=scripts)
            completed = subprocess.CompletedProcess(
                args=["powershell"],
                returncode=0,
                stdout='\ufeff{"ok":true,"data":{"value":42},"message":"","warnings":[]}',
                stderr="",
            )
            with patch("subprocess.run", return_value=completed):
                response = client.invoke("dummy")
            self.assertEqual(response.data, {"value": 42})


class FakePowerShell:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def invoke(self, action: str, payload: dict, timeout: int = 120) -> PowerShellResponse:
        self.calls.append((action, timeout))
        if action == "preflight_environment":
            return PowerShellResponse(
                ok=True,
                data={
                    "powershell_version": "5.1",
                    "module_available": True,
                    "ad_module": True,
                    "message": "",
                },
            )
        if action == "preflight_domain":
            domain = payload["domain"]
            if domain["name"] == "second":
                raise PowerShellTimeoutError("timeout")
            return PowerShellResponse(
                ok=True,
                data={
                    "name": domain["name"],
                    "label": domain["label"],
                    "server": domain["server"],
                    "configured_server": domain["server"],
                    "server_ok": True,
                    "ou_ok": True,
                    "message": "",
                },
            )
        raise AssertionError(action)


class PreflightTests(unittest.TestCase):
    def test_preflight_reports_steps_and_converts_domain_timeout_to_result(self) -> None:
        domains = [
            {
                "name": "first", "label": "Первый", "netbios": "FIRST",
                "server": "dc1.example.ru", "search_base": "DC=example,DC=ru",
                "ou_dn": "OU=Users,DC=example,DC=ru", "upn_suffix": "@example.ru",
                "email_suffix": "@example.ru", "fired_ou_dn": "", "profile": "standard",
            },
            {
                "name": "second", "label": "Второй", "netbios": "SECOND",
                "server": "dc2.example.ru", "search_base": "DC=example,DC=ru",
                "ou_dn": "OU=Users,DC=example,DC=ru", "upn_suffix": "@example.ru",
                "email_suffix": "@example.ru", "fired_ou_dn": "", "profile": "standard",
            },
        ]
        fake = FakePowerShell()
        service = ADService(fake, domains)
        updates: list[tuple[str, str]] = []

        result = service.preflight(progress=lambda key, message: updates.append((key, message)))

        self.assertEqual(result["powershell_version"], "5.1")
        self.assertTrue(result["domains"][0]["server_ok"])
        self.assertFalse(result["domains"][1]["server_ok"])
        self.assertIn("Тайм-аут 15 сек", result["domains"][1]["message"])
        self.assertEqual(updates[0][0], "0/3")
        self.assertEqual(updates[-1][0], "3/3")
        self.assertEqual(fake.calls[0], ("preflight_environment", 12))
        self.assertEqual(fake.calls[-1], ("preflight_domain", 15))


class ScriptRegressionTests(unittest.TestCase):
    def test_ldap_escape_does_not_use_ambiguous_char_replace(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "adhelper" / "scripts" / "common.ps1").read_text(
            encoding="utf-8-sig"
        )
        self.assertNotIn(".Replace([char]0", script)
        self.assertIn("[System.Text.StringBuilder]", script)
        self.assertIn("Append('\\00')", script)


if __name__ == "__main__":
    unittest.main()
