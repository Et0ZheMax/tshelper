from __future__ import annotations

import unittest

from adhelper.services.access_management import (
    ACCESS_READ,
    ACCESS_WRITE,
    GroupRecord,
    infer_group_access,
    parse_access_request,
    rank_groups,
)


class AccessRequestParserTests(unittest.TestCase):
    def test_realistic_readonly_request(self) -> None:
        request = parse_access_request(
            """
            Доступ для чтения к файлу

            Коллеги,
            просим предоставить доступ к файлу для чтения (без редактирования) для сотрудника ЛБиММИ Кикот Александры.

            Путь к файлу:
            U:\\Обмен лаборатория\\ЛГиКИ\\Штрих коды для центральной зоны

            Название файла: Образцы_для центр.зоны (5)
            """
        )
        self.assertEqual(request.access_mode, ACCESS_READ)
        self.assertEqual(request.path, r"U:\Обмен лаборатория\ЛГиКИ\Штрих коды для центральной зоны")
        self.assertEqual(request.file_name, "Образцы_для центр.зоны (5)")
        # В реальных заявках между словом «сотрудника» и ФИО может стоять подразделение.
        self.assertEqual(request.person_search, "Кикот")

    def test_rw_request(self) -> None:
        request = parse_access_request("Нужен доступ на запись и редактирование к U:\\Lab\\Reports")
        self.assertEqual(request.access_mode, ACCESS_WRITE)


class AccessRankingTests(unittest.TestCase):
    def test_resource_path_and_access_mode_rank_correct_group_first(self) -> None:
        groups = [
            GroupRecord(
                domain="pak-cspmz",
                name="ShtrihOMG_ro",
                sam="ShtrihOMG_ro",
                description=r"\\pak-cspmz.ru\common\project\ЛГиКИ\Штрих коды для центральной зоны ответственный Мухин В",
            ),
            GroupRecord(
                domain="pak-cspmz",
                name="ShtrihOMG_rw",
                sam="ShtrihOMG_rw",
                description=r"\\pak-cspmz.ru\common\project\ЛГиКИ\Штрих коды для центральной зоны",
            ),
            GroupRecord(
                domain="pak-cspmz",
                name="Obmen_lab_ro",
                sam="Obmen_lab_ro",
                description="Доступ на чтение U:\\Обмен лаборатория\\",
            ),
        ]
        path = r"U:\Обмен лаборатория\ЛГиКИ\Штрих коды для центральной зоны"
        matches = rank_groups(groups, path, ACCESS_READ, resource_path=path)
        self.assertGreaterEqual(len(matches), 2)
        self.assertEqual(matches[0].group.sam, "ShtrihOMG_ro")
        self.assertGreater(matches[0].score, matches[1].score)

    def test_suffix_is_stronger_than_wrong_description(self) -> None:
        group = GroupRecord(
            domain="pak-cspmz",
            name="lgiki_Shestovskaya_rw",
            sam="lgiki_Shestovskaya_rw",
            description=r"Доступ на чтение U:\Обмен лаборатория\ЛГиКИ\Shestovskaya MV",
        )
        self.assertEqual(infer_group_access(group), ACCESS_WRITE)


if __name__ == "__main__":
    unittest.main()

class AccessSourceRegressionTests(unittest.TestCase):
    def test_membership_script_is_guarded_and_verifies_result(self) -> None:
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        path = root / "adhelper" / "scripts" / "manage_group_membership.ps1"
        raw = path.read_bytes()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
        source = raw.decode("utf-8-sig")
        self.assertIn("group_search_base", source)
        self.assertIn("Add-ADGroupMember", source)
        self.assertIn("Get-ADUser", source)
        self.assertIn("verified", source)

    def test_access_page_is_wired_into_main_navigation(self) -> None:
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        source = (root / "adhelper" / "ui" / "main_window.py").read_text(encoding="utf-8")
        self.assertIn("AccessPage", source)
        self.assertIn("Доступы", source)
