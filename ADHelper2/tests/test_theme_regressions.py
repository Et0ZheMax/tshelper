from __future__ import annotations

import re
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
UI_ROOT = PROJECT_ROOT / "adhelper" / "ui"
THEME_SOURCE = (UI_ROOT / "theme.py").read_text(encoding="utf-8")
MAIN_WINDOW_SOURCE = (UI_ROOT / "main_window.py").read_text(encoding="utf-8")
APP_SOURCE = (PROJECT_ROOT / "adhelper" / "app.py").read_text(encoding="utf-8")


class ThemeSourceRegressionTests(unittest.TestCase):
    def test_theme_is_applied_application_wide_with_palette_and_repolish(self) -> None:
        self.assertIn("app.setPalette(build_palette(normalized))", THEME_SOURCE)
        self.assertIn("app.setStyleSheet", THEME_SOURCE)
        self.assertIn("for widget in app.allWidgets()", THEME_SOURCE)
        self.assertIn("style.unpolish(widget)", THEME_SOURCE)
        self.assertIn("style.polish(widget)", THEME_SOURCE)

    def test_fusion_style_is_used_for_native_controls(self) -> None:
        self.assertIn('app.setStyle("Fusion")', APP_SOURCE)
        self.assertIn('app.setStyle("Fusion")', THEME_SOURCE)
        self.assertNotIn("QCheckBox::indicator", THEME_SOURCE)
        self.assertNotIn("QRadioButton::indicator", THEME_SOURCE)

    def test_popup_dialog_and_service_widgets_are_covered(self) -> None:
        for selector in (
            "QMenu {",
            "QComboBox QAbstractItemView",
            "QDockWidget::title",
            "QToolTip {",
            "QSplitter::handle",
            "QScrollBar:horizontal",
            "QStatusBar {",
            "QTableCornerButton::section",
            "QLineEdit:read-only",
            "QPushButton#Primary:disabled",
            "QPushButton#Danger:disabled",
        ):
            self.assertIn(selector, THEME_SOURCE)

    def test_no_inline_fixed_interface_colors_outside_theme_module(self) -> None:
        offenders: list[str] = []
        color_pattern = re.compile(r"#[0-9A-Fa-f]{6}")
        for path in UI_ROOT.rglob("*.py"):
            if path.name == "theme.py":
                continue
            source = path.read_text(encoding="utf-8")
            if color_pattern.search(source) or "setStyleSheet(" in source:
                offenders.append(str(path.relative_to(PROJECT_ROOT)))
        self.assertEqual(offenders, [])

    def test_logo_uses_theme_object_names_not_html_color(self) -> None:
        self.assertIn('setObjectName("LogoTitle")', MAIN_WINDOW_SOURCE)
        self.assertIn('setObjectName("LogoVersion")', MAIN_WINDOW_SOURCE)
        self.assertNotIn("style='color:", MAIN_WINDOW_SOURCE)

    def test_theme_switch_calls_application_theme_manager(self) -> None:
        self.assertIn("apply_application_theme(key)", MAIN_WINDOW_SOURCE)
        self.assertNotIn("self.setStyleSheet(", MAIN_WINDOW_SOURCE)


if __name__ == "__main__":
    unittest.main()
