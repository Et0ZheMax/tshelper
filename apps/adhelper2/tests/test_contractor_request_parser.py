from __future__ import annotations

import unittest

from adhelper.models import DomainConfig
from adhelper.parsers.contractor_request_parser import (
    contractor_target_ous,
    parse_contractor_request,
    requested_domain_names,
)


class ContractorRequestParserTests(unittest.TestCase):
    def test_bars_group_request(self) -> None:
        request = parse_contractor_request(
            '''Создать УЗ для нового сотрудника контрагента АО "БАРС Груп" в OMG и PAK-CSPMZ.RU
Просим создать УЗ для нового сотрудника контрагента АО "БАРС Груп" в домене OMG и PAK-CSPMZ.RU:
Иванов Иван Иванович (разработчик 1 категории)
Мобильный телефон сотрудника: +79990000000
Почта сотрудника: test.user\\@example.test'''
        )
        self.assertEqual(request.display_name, "Иванов Иван Иванович")
        self.assertEqual(request.title, "разработчик 1 категории")
        self.assertEqual(request.mobile_phone, "+79990000000")
        self.assertEqual(request.email, "test.user@example.test")
        self.assertEqual(request.company, "АО «БАРС Груп»")
        self.assertEqual(request.department, "outsource")
        self.assertTrue(request.need_mail)

    def test_requested_domains(self) -> None:
        selected = requested_domain_names(
            "в домене OMG и PAK-CSPMZ.RU",
            ["pak-cspmz", "omg-cspfmba", "other"],
        )
        self.assertEqual(selected, {"pak-cspmz", "omg-cspfmba"})

    def test_pak_uses_outsource_ou_by_default(self) -> None:
        domains = [
            DomainConfig(
                name="pak-cspmz", label="PAK", netbios="PAK-CSPMZ", server="dc",
                search_base="DC=example,DC=test",
                ou_dn="OU=omg,OU=csp,OU=Users,OU=csp,DC=example,DC=test",
                upn_suffix="@example.test", email_suffix="@example.test", fired_ou_dn="",
                profile="standard",
            ),
            DomainConfig(
                name="omg-cspfmba", label="OMG", netbios="OMG", server="dc",
                search_base="DC=example,DC=test", ou_dn="OU=Institute,DC=example,DC=test",
                upn_suffix="@example.test", email_suffix="@example.test", fired_ou_dn="",
                profile="omg",
            ),
        ]
        self.assertEqual(
            contractor_target_ous(domains),
            {"pak-cspmz": "OU=outsource,OU=Users,OU=csp,DC=example,DC=test"},
        )


if __name__ == "__main__":
    unittest.main()
