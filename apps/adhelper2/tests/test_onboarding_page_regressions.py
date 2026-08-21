from __future__ import annotations

import unittest
from pathlib import Path


class OnboardingPageSourceRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (
            Path(__file__).resolve().parents[1] / "adhelper" / "ui" / "pages" / "onboarding.py"
        ).read_text(encoding="utf-8")

    def test_request_and_preview_are_shown_side_by_side(self) -> None:
        self.assertIn("QSplitter(Qt.Orientation.Horizontal)", self.source)
        self.assertIn("Распознанная карточка сотрудника", self.source)
        self.assertIn("Полное имя", self.source)

    def test_paste_is_normalized_before_insertion(self) -> None:
        self.assertIn("class RequestTextEdit(QTextEdit)", self.source)
        self.assertIn("self.insertPlainText(format_request_text(source.text()))", self.source)

    def test_edited_card_is_used_for_plan(self) -> None:
        self.assertIn("self.request = self._collect_request()", self.source)
        self.assertIn("Карточка справа является источником истины", self.source)

    def test_workflow_has_three_pages(self) -> None:
        self.assertNotIn("self.stack.addWidget(self._build_details_page())", self.source)
        self.assertIn('labels = ["1  Заявка и карточка", "2  План AD", "3  Выполнение"]', self.source)


if __name__ == "__main__":
    unittest.main()
