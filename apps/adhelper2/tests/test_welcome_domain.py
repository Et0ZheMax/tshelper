from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from adhelper.models import DomainConfig
from adhelper.services.welcome import WelcomeDocumentService, select_welcome_domain


class WelcomeDomainTests(unittest.TestCase):
    @staticmethod
    def _domain(name: str, profile: str, netbios: str) -> DomainConfig:
        return DomainConfig(
            name=name,
            label=name,
            netbios=netbios,
            server="dc.example.test",
            search_base="DC=example,DC=test",
            ou_dn="OU=Users,DC=example,DC=test",
            upn_suffix="@example.test",
            email_suffix="@example.test",
            fired_ou_dn="OU=Fired,DC=example,DC=test",
            profile=profile,
        )

    def test_omg_domain_is_selected_even_when_pak_is_first(self) -> None:
        pak = self._domain("pak-cspmz", "standard", "PAK-CSPMZ")
        omg = self._domain("omg-cspfmba", "omg", "OMG")
        self.assertIs(select_welcome_domain([pak, omg]), omg)

    def test_missing_omg_profile_does_not_fall_back_to_pak(self) -> None:
        pak = self._domain("pak-cspmz", "standard", "PAK-CSPMZ")
        with self.assertRaisesRegex(RuntimeError, "профилем OMG"):
            select_welcome_domain([pak])

    def test_omg_domain_requires_netbios(self) -> None:
        omg = self._domain("omg-cspfmba", "omg", "")
        with self.assertRaisesRegex(RuntimeError, "NetBIOS"):
            select_welcome_domain([omg])

    def test_contractor_response_contains_only_created_domains(self) -> None:
        pak = self._domain("pak-cspmz", "standard", "PAK-CSPMZ")
        omg = self._domain("omg-cspfmba", "omg", "OMG")
        with TemporaryDirectory() as directory:
            settings = type("Settings", (), {"generated_dir": Path(directory)})()
            service = WelcomeDocumentService(settings)
            path = service.generate_contractor_response(
                login="i.ivanov",
                password="Test-password!",
                domains=[pak, omg],
            )
            content = path.read_text(encoding="utf-8")

        self.assertIn("PAK-CSPMZ\\i.ivanov", content)
        self.assertIn("OMG\\i.ivanov", content)
        self.assertIn("mail.cspfmba.ru", content)
        self.assertIn("Test-password!", content)
        self.assertEqual(content.count("Добрый день!"), 1)

    def test_contractor_response_hides_password_when_yopass_link_exists(self) -> None:
        pak = self._domain("pak-cspmz", "standard", "PAK-CSPMZ")
        with TemporaryDirectory() as directory:
            settings = type("Settings", (), {"generated_dir": Path(directory)})()
            path = WelcomeDocumentService(settings).generate_contractor_response(
                login="i.ivanov",
                password="Do-not-put-this-password-in-html!",
                domains=[pak],
                secret_url="https://yopass.example.test/#/secret/key",
            )
            content = path.read_text(encoding="utf-8")

        self.assertNotIn("Do-not-put-this-password-in-html!", content)
        self.assertNotIn("PAK-CSPMZ\\i.ivanov", content)
        self.assertIn("https://yopass.example.test/#/secret/key", content)
        self.assertIn("только один раз", content)


if __name__ == "__main__":
    unittest.main()
