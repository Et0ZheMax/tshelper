from __future__ import annotations

import unittest
from pathlib import Path


class UsersPageSourceRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (
            Path(__file__).resolve().parents[1] / "adhelper" / "ui" / "pages" / "users.py"
        ).read_text(encoding="utf-8")

    def test_only_dirty_fields_are_collected(self) -> None:
        self.assertIn("for key in self._dirty_fields", self.source)
        self.assertNotIn("for key, edit in self.edits.items():\n            value = edit.text().strip()\n            if value != current", self.source)

    def test_mail_is_changed_only_after_checkbox_toggle(self) -> None:
        self.assertIn("if self._mail_dirty:", self.source)
        self.assertIn("checked != self._mail_original_checked", self.source)

    def test_context_menu_contains_requested_actions(self) -> None:
        self.assertIn("Копировать логин", self.source)
        self.assertIn("Печать приветственного листа", self.source)
        self.assertIn("Удалить пользователя", self.source)
        self.assertIn("QApplication.clipboard().setText(user.sam)", self.source)

    def test_deletion_requires_domain_confirmation_and_defaults_to_no(self) -> None:
        self.assertIn('Вы уверены, что хотите удалить пользователя из домена', self.source)
        self.assertIn("domain = self.context.ad.domain_by_name.get(user.domain)", self.source)
        self.assertIn("QMessageBox.StandardButton.No", self.source)
        self.assertIn("self.context.user_management.delete, user", self.source)
        self.assertIn('data.get("recovery_path")', self.source)

    def test_welcome_sheet_uses_omg_profile_for_any_selected_account(self) -> None:
        self.assertIn("select_welcome_domain(self.context.ad.domains)", self.source)
        self.assertIn("print_domain.netbios", self.source)
        self.assertNotIn('domain_login=f"{domain.netbios}\\\\{user.sam}"', self.source)


    def test_org_attributes_have_russian_labels(self) -> None:
        self.assertIn('division (Подразделение)', self.source)
        self.assertIn('department (Управление)', self.source)
        self.assertIn('section (Отдел)', self.source)

    def test_users_page_has_ou_consistency_control_and_move_action(self) -> None:
        self.assertIn('Контроль OU по оргструктуре', self.source)
        self.assertIn('OU-контроль', self.source)
        self.assertIn('Переместить в правильный OU', self.source)
        self.assertIn('{"target_ou": target_dn}', self.source)


if __name__ == "__main__":
    unittest.main()
