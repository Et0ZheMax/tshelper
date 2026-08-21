from __future__ import annotations

import unittest

from adhelper.models import DomainConfig, UserRecord
from adhelper.services.ou_alignment import analyze_ou_alignment, name_similarity, parent_dn


class OUAlignmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.domain = DomainConfig(
            name="omg-cspfmba",
            label="omg.cspfmba",
            netbios="OMG",
            server="dc24.omg.cspfmba.ru",
            search_base="DC=omg,DC=cspfmba,DC=ru",
            ou_dn="OU=Institute of Synthetic Biology and Genetic Engineering,DC=omg,DC=cspfmba,DC=ru",
            upn_suffix="@omg.cspfmba.ru",
            email_suffix="@cspfmba.ru",
            fired_ou_dn="OU=Уволенные,DC=omg,DC=cspfmba,DC=ru",
            profile="omg",
        )
        self.department = "управление экспериментальной биотехнологии и генной инженерии"
        self.department_dn = f"OU={self.department},{self.domain.ou_dn}"

    def test_resource_lab_plural_attribute_matches_singular_ou(self) -> None:
        section_attribute = "отдел ресурсного сопровождения лабораторий"
        section_ou = "отдел ресурсного сопровождения лаборатории"
        self.assertGreaterEqual(name_similarity(section_attribute, section_ou), 0.99)

    def test_detects_realistic_mismatch_and_recommends_correct_ou(self) -> None:
        expected_name = "отдел ресурсного сопровождения лаборатории"
        expected_dn = f"OU={expected_name},{self.department_dn}"
        current_name = "лаборатория биобанкирования и мультиомиксных методов исследований"
        current_dn = f"OU={current_name},{self.department_dn}"
        user = UserRecord(
            domain=self.domain.name,
            display_name="Устинова Оксана Владимировна",
            sam="OUstinova",
            dn=f"CN=Устинова Оксана Владимировна,{current_dn}",
            division="институт синтетической биологии и генной инженерии",
            department=self.department,
            section="отдел ресурсного сопровождения лабораторий",
        )
        ous = [
            {"name": self.department, "dn": self.department_dn},
            {"name": current_name, "dn": current_dn},
            {"name": expected_name, "dn": expected_dn},
        ]

        result = analyze_ou_alignment(self.domain, user, ous)
        self.assertEqual(result.status, "mismatch")
        self.assertEqual(result.expected_dn, expected_dn)
        self.assertTrue(result.can_move)
        self.assertEqual(result.matched_attribute, "section")

    def test_correct_ou_is_reported_ok(self) -> None:
        section_name = "отдел ресурсного сопровождения лаборатории"
        section_dn = f"OU={section_name},{self.department_dn}"
        user = UserRecord(
            domain=self.domain.name,
            sam="user",
            dn=f"CN=User,{section_dn}",
            department=self.department,
            section="отдел ресурсного сопровождения лабораторий",
        )
        result = analyze_ou_alignment(
            self.domain,
            user,
            [
                {"name": self.department, "dn": self.department_dn},
                {"name": section_name, "dn": section_dn},
            ],
        )
        self.assertEqual(result.status, "ok")
        self.assertFalse(result.can_move)

    def test_duplicate_section_names_are_not_auto_selected_without_department_match(self) -> None:
        section = "отдел тестирования"
        branch_a = f"OU=управление A,{self.domain.ou_dn}"
        branch_b = f"OU=управление B,{self.domain.ou_dn}"
        user = UserRecord(
            domain=self.domain.name,
            sam="user",
            dn=f"CN=User,OU=Somewhere,{self.domain.ou_dn}",
            department="несуществующее управление",
            section=section,
        )
        result = analyze_ou_alignment(
            self.domain,
            user,
            [
                {"name": "управление A", "dn": branch_a},
                {"name": "управление B", "dn": branch_b},
                {"name": section, "dn": f"OU={section},{branch_a}"},
                {"name": section, "dn": f"OU={section},{branch_b}"},
            ],
        )
        self.assertEqual(result.status, "unresolved")
        self.assertFalse(result.expected_dn)

    def test_parent_dn_handles_escaped_comma(self) -> None:
        self.assertEqual(
            parent_dn(r"CN=Иванов\, Иван,OU=Отдел,DC=example,DC=ru"),
            "OU=Отдел,DC=example,DC=ru",
        )


if __name__ == "__main__":
    unittest.main()
