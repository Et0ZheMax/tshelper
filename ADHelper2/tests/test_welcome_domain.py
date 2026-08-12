from __future__ import annotations

import unittest

from adhelper.models import DomainConfig
from adhelper.services.welcome import select_welcome_domain


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


if __name__ == "__main__":
    unittest.main()
