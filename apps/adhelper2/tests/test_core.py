from __future__ import annotations

import unittest

from adhelper.models import ParsedRequest
from adhelper.organization import get_omg_department_section, get_pak_department
from adhelper.parsers.request_parser import format_request_text, parse_request, validation_errors
from adhelper.utils import normalize_phone, sam_base, sam_with_suffix, translit


class RequestParserTests(unittest.TestCase):
    def test_parse_request(self) -> None:
        request = parse_request(
            """
            1) Фамилия: Иванов
            2) Имя: Иван
            Отчество: Иванович
            Руководитель: Петров Пётр
            Отдел: управление цифровых систем и биоинформатики / отдел системной биологии и биоинформатики
            Должность сотрудника: Научный сотрудник
            Предоставить электронный почтовый ящик для сотрудника: Да
            Номер сотового телефона для переадресации: +7 (917) 561-44-55
            """
        )
        self.assertEqual(request.last_name, "Иванов")
        self.assertEqual(request.first_name, "Иван")
        self.assertTrue(request.need_mail)
        self.assertEqual(request.display_name, "Иванов Иван Иванович")
        self.assertEqual(validation_errors(request), [])

    def test_one_line_glpi_request_is_split_by_numbered_markers(self) -> None:
        text = (
            "1) Фамилия: БлоТест 2) Имя: Тестсей 3) Отчество: Тестович "
            "4) Есть ли у вас фотография сотрудника?: Нет 5) Руководитель: DZagrebiina "
            "6) Управление: отдел научно-технического и методического обеспечения "
            "7) Должность сотрудника: лаборант 8) Дата выхода сотрудника: 2026-07-27 "
            "9) Режим работы сотрудника: Офис 10) Номер кабинета: Щ-2-305 "
            "11) Предоставить электронный почтовый ящик для сотрудника: Да "
            "12) Предоставить внутренний телефонный номер для сотрудника: Да "
            "13) Номер сотового телефона для переадресации: +7(915)555-55-55 "
            "14) Оборудование необходимое сотруднику: Компьютер в офисе, 1-й Монитор, 2-й Монитор "
            "15) Операционная система для компьютера в офисе: Ubuntu 22.04 "
            "16) Предоставить локальные права sudo: Нет 17) Предоставить доступ к серверам: Нет "
            "18) Предоставить доступ к папкам: Да 19) Тип доступа к папкам: Запись/Чтение "
            "20) К каким папкам требуется доступ?: Диск O; L; U; 21) Доступ к R7-офис: Да "
            "22) Примечание: На рабочем месте будет наклейка с ФИО "
            "23) Таблица соответствия ПК и ОС (информация для техподдержки):"
        )
        request = parse_request(text)
        self.assertEqual(request.last_name, "БлоТест")
        self.assertEqual(request.first_name, "Тестсей")
        self.assertEqual(request.middle_name, "Тестович")
        self.assertEqual(request.manager_name, "DZagrebiina")
        self.assertEqual(request.management, "отдел научно-технического и методического обеспечения")
        self.assertEqual(request.title, "лаборант")
        self.assertEqual(request.office_room, "Щ-2-305")
        self.assertTrue(request.need_mail)
        self.assertTrue(request.need_internal_phone)
        self.assertEqual(request.mobile_phone, "+7(915)555-55-55")
        self.assertEqual(request.office_os, "Ubuntu 22.04")
        self.assertFalse(request.need_servers_access)
        self.assertTrue(request.need_folders_access)
        self.assertEqual(request.notes, "На рабочем месте будет наклейка с ФИО")
        self.assertEqual(validation_errors(request), [])

    def test_format_request_text_restores_visual_lines(self) -> None:
        formatted = format_request_text("1) Фамилия: Иванов 2) Имя: Иван 3) Отчество: Иванович")
        self.assertEqual(formatted.splitlines(), [
            "1) Фамилия: Иванов",
            "2) Имя: Иван",
            "3) Отчество: Иванович",
        ])

    def test_required_fields(self) -> None:
        errors = validation_errors(ParsedRequest())
        self.assertEqual(len(errors), 2)


class NormalizationTests(unittest.TestCase):
    def test_phone(self) -> None:
        self.assertEqual(normalize_phone("+7(917)561-44-55"), "89175614455")
        self.assertEqual(normalize_phone("9175614455"), "89175614455")

    def test_sam_length(self) -> None:
        base = sam_base("Александр", "Оченьдлиннаяфамилиясотрудника")
        self.assertLessEqual(len(base), 20)
        self.assertLessEqual(len(sam_with_suffix(base, 123)), 20)

    def test_translit(self) -> None:
        self.assertEqual(translit("Щукин"), "shchukin")


class OrganizationTests(unittest.TestCase):
    def test_omg_hierarchy(self) -> None:
        request = ParsedRequest(
            department="управление цифровых систем и биоинформатики / отдел системной биологии и биоинформатики"
        )
        department, section = get_omg_department_section(request)
        self.assertEqual(department, "управление цифровых систем и биоинформатики")
        self.assertEqual(section, "отдел системной биологии и биоинформатики")

    def test_pak_department(self) -> None:
        request = ParsedRequest(department="Управление / Отдел ИТ")
        self.assertEqual(get_pak_department(request), "отдел ит")


if __name__ == "__main__":
    unittest.main()
