from __future__ import annotations

import os
import unittest
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QComboBox  # noqa: E402

from adhelper.models import UserRecord  # noqa: E402
from adhelper.ui.pages.users import UsersPage  # noqa: E402


class LinkedOrganizationFieldsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    @staticmethod
    def make_page(department: str = "", section: str = "") -> UsersPage:
        domain = SimpleNamespace(profile="omg")
        context = SimpleNamespace(ad=SimpleNamespace(domain_by_name={"omg": domain}))
        page = UsersPage(context)
        user = UserRecord(domain="omg", display_name="Тест", department=department, section=section)
        values = page._values_from_user(user)
        page.selected = user
        page._loaded_values = values
        page._loading_record = True
        try:
            page._configure_organization_fields(user, values)
            page._set_field_text("department", department)
            page._set_field_text("section", section)
        finally:
            page._loading_record = False
        return page

    def test_section_selection_sets_unique_department(self) -> None:
        page = self.make_page()
        department = page.edits["department"]
        section = page.edits["section"]
        self.assertIsInstance(department, QComboBox)
        self.assertIsInstance(section, QComboBox)

        section.setEditText("лаборатория мРНК технологий")
        self.app.processEvents()

        self.assertEqual(
            department.currentText(),
            "управление экспериментальной биотехнологии и генной инженерии",
        )
        page.close()

    def test_standalone_department_clears_and_disables_section(self) -> None:
        page = self.make_page(
            "управление информационных технологий",
            "отдел эксплуатации вычислительной инфраструктуры",
        )
        department = page.edits["department"]
        section = page.edits["section"]

        department.setEditText("отдел менеджмента качества")
        self.app.processEvents()

        self.assertEqual(section.currentText(), "")
        self.assertFalse(section.isEnabled())
        page.close()

    def test_unknown_existing_values_are_preserved(self) -> None:
        page = self.make_page("аппарат управления", "старое значение section")
        self.assertEqual(page.edits["department"].currentText(), "аппарат управления")
        self.assertEqual(page.edits["section"].currentText(), "старое значение section")
        self.assertTrue(page.edits["section"].isEnabled())
        page.close()

    def test_details_panel_scrolls_instead_of_compressing_editors(self) -> None:
        page = self.make_page()
        page.resize(900, 500)
        page.show()
        self.app.processEvents()

        self.assertGreater(page.details_scroll.verticalScrollBar().maximum(), 0)
        self.assertTrue(all(editor.height() >= 36 for editor in page.edits.values()))
        page.close()

    def test_successful_save_refreshes_selected_card_and_table_immediately(self) -> None:
        events = SimpleNamespace(operations_changed=SimpleNamespace(emit=lambda: None))
        domain = SimpleNamespace(profile="standard")
        context = SimpleNamespace(ad=SimpleNamespace(domain_by_name={"test": domain}), events=events)
        page = UsersPage(context)
        page._start_ou_analysis = lambda _user: None
        original = UserRecord(
            domain="test",
            display_name="Иванов Иван",
            sam="iivanov",
            guid="guid-1",
            department="Старое управление",
        )
        page.records = [original]
        page.table.setRowCount(1)
        page._set_table_user_row(0, original)
        page.table.selectRow(0)
        page._show_selected_user(original)

        result = SimpleNamespace(data={"updated_user": {
            "domain": "test",
            "displayName": "Иванов Иван",
            "sam": "iivanov",
            "guid": "guid-1",
            "department": "Новое управление",
            "enabled": True,
        }})
        page._save_ready(result)
        self.app.processEvents()

        self.assertEqual(page.selected.department, "Новое управление")
        self.assertEqual(page._field_text("department"), "Новое управление")
        self.assertEqual(page.table.item(0, 3).text(), "Новое управление")
        self.assertEqual(page.window()._status_toast.objectName(), "StatusToastSuccess")
        page.close()


if __name__ == "__main__":
    unittest.main()
