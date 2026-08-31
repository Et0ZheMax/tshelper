from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication


@dataclass(frozen=True)
class ThemeColors:
    window: str
    window_alt: str
    sidebar: str
    card: str
    inset: str
    input_bg: str
    input_readonly: str
    popup: str
    header: str
    border: str
    border_strong: str
    text: str
    muted: str
    title: str
    disabled_text: str
    disabled_bg: str
    hover: str
    pressed: str
    selected: str
    selected_text: str
    primary: str
    primary_hover: str
    primary_pressed: str
    danger: str
    danger_hover: str
    danger_pressed: str
    success: str
    success_border: str
    scrollbar: str
    scrollbar_hover: str
    link: str
    visited_link: str
    tooltip_bg: str
    tooltip_text: str


THEMES: dict[str, ThemeColors] = {
    "dark": ThemeColors(
        window="#0F131A",
        window_alt="#111720",
        sidebar="#151B24",
        card="#181F2A",
        inset="#111720",
        input_bg="#111720",
        input_readonly="#151B24",
        popup="#171E28",
        header="#1A2330",
        border="#2A3545",
        border_strong="#3A475B",
        text="#E6EAF0",
        muted="#93A1B5",
        title="#FFFFFF",
        disabled_text="#687487",
        disabled_bg="#1A202A",
        hover="#2A3749",
        pressed="#1D2633",
        selected="#2D5D99",
        selected_text="#FFFFFF",
        primary="#3B82F6",
        primary_hover="#4C8DF7",
        primary_pressed="#2F6FD0",
        danger="#B4232F",
        danger_hover="#CA2D3B",
        danger_pressed="#951D28",
        success="#166534",
        success_border="#22C55E",
        scrollbar="#3B4658",
        scrollbar_hover="#526177",
        link="#7DB0FF",
        visited_link="#B69CFF",
        tooltip_bg="#202936",
        tooltip_text="#FFFFFF",
    ),
    "light": ThemeColors(
        window="#F4F7FB",
        window_alt="#FFFFFF",
        sidebar="#FFFFFF",
        card="#FFFFFF",
        inset="#F8FAFC",
        input_bg="#FFFFFF",
        input_readonly="#F3F6FA",
        popup="#FFFFFF",
        header="#EEF2F7",
        border="#DDE4EE",
        border_strong="#CDD5E1",
        text="#202938",
        muted="#667085",
        title="#111827",
        disabled_text="#98A2B3",
        disabled_bg="#EEF2F6",
        hover="#F1F5F9",
        pressed="#E6ECF3",
        selected="#DCEAFF",
        selected_text="#153E75",
        primary="#2563EB",
        primary_hover="#1D4ED8",
        primary_pressed="#1E40AF",
        danger="#C62835",
        danger_hover="#B4232F",
        danger_pressed="#92202A",
        success="#15803D",
        success_border="#16A34A",
        scrollbar="#C3CDD9",
        scrollbar_hover="#98A6B8",
        link="#1D4ED8",
        visited_link="#6D28D9",
        tooltip_bg="#172033",
        tooltip_text="#FFFFFF",
    ),
}


def normalize_theme(key: str) -> str:
    return "light" if str(key).strip().lower() == "light" else "dark"


def build_palette(key: str) -> QPalette:
    colors = THEMES[normalize_theme(key)]
    palette = QPalette()

    role_colors = {
        QPalette.ColorRole.Window: colors.window,
        QPalette.ColorRole.WindowText: colors.text,
        QPalette.ColorRole.Base: colors.input_bg,
        QPalette.ColorRole.AlternateBase: colors.inset,
        QPalette.ColorRole.ToolTipBase: colors.tooltip_bg,
        QPalette.ColorRole.ToolTipText: colors.tooltip_text,
        QPalette.ColorRole.Text: colors.text,
        QPalette.ColorRole.Button: colors.card,
        QPalette.ColorRole.ButtonText: colors.text,
        QPalette.ColorRole.BrightText: "#FFFFFF",
        QPalette.ColorRole.Highlight: colors.selected,
        QPalette.ColorRole.HighlightedText: colors.selected_text,
        QPalette.ColorRole.Link: colors.link,
        QPalette.ColorRole.LinkVisited: colors.visited_link,
        QPalette.ColorRole.Light: colors.hover,
        QPalette.ColorRole.Midlight: colors.border,
        QPalette.ColorRole.Mid: colors.border_strong,
        QPalette.ColorRole.Dark: colors.window_alt,
        QPalette.ColorRole.Shadow: colors.window,
        QPalette.ColorRole.PlaceholderText: colors.muted,
    }
    for role, value in role_colors.items():
        palette.setColor(role, QColor(value))

    disabled = QPalette.ColorGroup.Disabled
    for role in (
        QPalette.ColorRole.WindowText,
        QPalette.ColorRole.Text,
        QPalette.ColorRole.ButtonText,
        QPalette.ColorRole.PlaceholderText,
    ):
        palette.setColor(disabled, role, QColor(colors.disabled_text))
    palette.setColor(disabled, QPalette.ColorRole.Button, QColor(colors.disabled_bg))
    palette.setColor(disabled, QPalette.ColorRole.Base, QColor(colors.disabled_bg))
    palette.setColor(disabled, QPalette.ColorRole.Highlight, QColor(colors.border))
    palette.setColor(disabled, QPalette.ColorRole.HighlightedText, QColor(colors.disabled_text))
    return palette


def build_style_sheet(key: str) -> str:
    c = THEMES[normalize_theme(key)]
    return f"""
/* Base surfaces and typography */
QWidget {{
    font-family: 'Segoe UI';
    font-size: 10pt;
    color: {c.text};
}}
QMainWindow, QDialog {{ background-color: {c.window}; }}
QStackedWidget, QScrollArea, QScrollArea QWidget#qt_scrollarea_viewport {{
    background-color: {c.window};
    border: none;
}}
QFrame#Sidebar {{ background-color: {c.sidebar}; border-right: 1px solid {c.border}; }}
QFrame#Topbar {{ background-color: {c.window_alt}; border-bottom: 1px solid {c.border}; }}
QFrame#Card {{ background-color: {c.card}; border: 1px solid {c.border}; border-radius: 12px; }}
QFrame#InsetCard {{ background-color: {c.inset}; border: 1px solid {c.border_strong}; border-radius: 10px; }}
QFrame#StatusToastSuccess {{ background-color: {c.success}; border: 1px solid {c.success_border}; border-radius: 10px; }}
QFrame#StatusToastError {{ background-color: {c.danger}; border: 1px solid {c.danger_hover}; border-radius: 10px; }}
QLabel#StatusToastIcon {{ color: #FFFFFF; font-size: 16pt; font-weight: 700; }}
QLabel#StatusToastText {{ color: #FFFFFF; font-size: 10pt; font-weight: 600; }}
QLabel#LogoTitle {{ font-size: 14pt; font-weight: 700; color: {c.title}; padding: 0 6px; }}
QLabel#LogoVersion {{ color: {c.muted}; padding: 0 6px; }}
QLabel#PageTitle {{ font-size: 22pt; font-weight: 700; color: {c.title}; }}
QLabel#Muted {{ color: {c.muted}; }}
QLabel#CardTitle {{ font-size: 11pt; font-weight: 600; color: {c.muted}; }}
QLabel#Metric {{ font-size: 24pt; font-weight: 700; color: {c.title}; }}
QLabel#LinkLabel {{ color: {c.link}; font-weight: 600; }}
QLabel#OuStatus {{ font-weight: 600; }}
QLabel#OuStatus[state="problem"] {{ color: {c.danger}; }}
QLabel#OuStatus[state="ok"] {{ color: {c.primary}; }}
QLabel#OuStatus[state="neutral"] {{ color: {c.muted}; }}
QLabel:disabled {{ color: {c.disabled_text}; }}

/* Buttons */
QPushButton {{
    background-color: {c.card};
    color: {c.text};
    border: 1px solid {c.border_strong};
    border-radius: 8px;
    padding: 8px 14px;
}}
QPushButton:hover {{ background-color: {c.hover}; }}
QPushButton:pressed {{ background-color: {c.pressed}; }}
QPushButton:focus {{ border: 1px solid {c.primary}; }}
QPushButton:disabled {{ color: {c.disabled_text}; background-color: {c.disabled_bg}; border-color: {c.border}; }}
QPushButton#Primary {{ background-color: {c.primary}; color: #FFFFFF; border: none; font-weight: 600; }}
QPushButton#Primary:hover {{ background-color: {c.primary_hover}; }}
QPushButton#Primary:pressed {{ background-color: {c.primary_pressed}; }}
QPushButton#Primary:disabled {{ background-color: {c.disabled_bg}; color: {c.disabled_text}; border: 1px solid {c.border}; }}
QPushButton#Danger {{ background-color: {c.danger}; color: #FFFFFF; border: none; font-weight: 600; }}
QPushButton#Danger:hover {{ background-color: {c.danger_hover}; }}
QPushButton#Danger:pressed {{ background-color: {c.danger_pressed}; }}
QPushButton#Danger:disabled {{ background-color: {c.disabled_bg}; color: {c.disabled_text}; border: 1px solid {c.border}; }}
QPushButton#Nav {{ text-align: left; padding: 10px 14px; border: none; background: transparent; color: {c.muted}; }}
QPushButton#Nav:hover {{ background-color: {c.hover}; color: {c.title}; }}
QPushButton#Nav:checked {{ background-color: {c.selected}; color: {c.link}; border-left: 3px solid {c.primary}; }}

/* Inputs */
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox, QDateEdit, QDateTimeEdit, QTimeEdit {{
    background-color: {c.input_bg};
    color: {c.text};
    border: 1px solid {c.border_strong};
    border-radius: 8px;
    padding: 8px;
    selection-background-color: {c.primary};
    selection-color: #FFFFFF;
}}
QLineEdit:hover, QTextEdit:hover, QPlainTextEdit:hover, QComboBox:hover, QSpinBox:hover,
QDoubleSpinBox:hover, QDateEdit:hover, QDateTimeEdit:hover, QTimeEdit:hover {{ border-color: {c.muted}; }}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus,
QDoubleSpinBox:focus, QDateEdit:focus, QDateTimeEdit:focus, QTimeEdit:focus {{ border: 1px solid {c.primary}; }}
QLineEdit:read-only, QTextEdit:read-only, QPlainTextEdit:read-only {{ background-color: {c.input_readonly}; }}
QLineEdit:disabled, QTextEdit:disabled, QPlainTextEdit:disabled, QComboBox:disabled,
QSpinBox:disabled, QDoubleSpinBox:disabled, QDateEdit:disabled, QDateTimeEdit:disabled, QTimeEdit:disabled {{
    background-color: {c.disabled_bg}; color: {c.disabled_text}; border-color: {c.border};
}}
QComboBox {{ padding-right: 30px; }}
QComboBox::drop-down {{ border: none; width: 28px; }}
QComboBox QAbstractItemView {{
    background-color: {c.popup};
    color: {c.text};
    border: 1px solid {c.border_strong};
    outline: none;
    selection-background-color: {c.selected};
    selection-color: {c.selected_text};
}}

/* Tables and item views */
QTableWidget, QTreeWidget, QListWidget {{
    background-color: {c.input_bg};
    alternate-background-color: {c.inset};
    color: {c.text};
    border: 1px solid {c.border};
    border-radius: 8px;
    gridline-color: {c.border};
    selection-background-color: {c.selected};
    selection-color: {c.selected_text};
    outline: none;
}}
QTableWidget::item, QTreeWidget::item, QListWidget::item {{ padding: 4px; }}
QTableWidget::item:selected, QTreeWidget::item:selected, QListWidget::item:selected {{
    background-color: {c.selected}; color: {c.selected_text};
}}
QTableWidget::item:selected:!active, QTreeWidget::item:selected:!active, QListWidget::item:selected:!active {{
    background-color: {c.selected}; color: {c.selected_text};
}}
QHeaderView::section {{
    background-color: {c.header};
    color: {c.muted};
    border: none;
    border-right: 1px solid {c.border};
    border-bottom: 1px solid {c.border};
    padding: 8px;
    font-weight: 600;
}}
QTableCornerButton::section {{ background-color: {c.header}; border: 1px solid {c.border}; }}

/* Checkboxes, tabs and grouping */
QCheckBox, QRadioButton {{ spacing: 8px; color: {c.text}; }}
QCheckBox:hover, QRadioButton:hover {{ color: {c.title}; }}
QCheckBox:disabled, QRadioButton:disabled {{ color: {c.disabled_text}; }}
QTabWidget::pane {{ background-color: {c.card}; border: 1px solid {c.border}; border-radius: 8px; }}
QTabBar::tab {{ background-color: {c.popup}; color: {c.muted}; padding: 9px 16px; margin-right: 2px; border-top-left-radius: 7px; border-top-right-radius: 7px; }}
QTabBar::tab:hover {{ background-color: {c.hover}; color: {c.title}; }}
QTabBar::tab:selected {{ background-color: {c.selected}; color: {c.link}; }}
QGroupBox {{ border: 1px solid {c.border}; border-radius: 8px; margin-top: 12px; padding-top: 10px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 5px; color: {c.muted}; }}

/* Splitters, scrollbars and progress */
QSplitter::handle {{ background-color: {c.border}; }}
QSplitter::handle:horizontal {{ width: 5px; margin: 2px 0; }}
QSplitter::handle:vertical {{ height: 5px; margin: 0 2px; }}
QSplitter::handle:hover {{ background-color: {c.primary}; }}
QScrollBar:vertical {{ background: transparent; width: 12px; margin: 2px; }}
QScrollBar::handle:vertical {{ background-color: {c.scrollbar}; border-radius: 5px; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background-color: {c.scrollbar_hover}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
QScrollArea#UserDetailsScroll, QWidget#UserDetailsContent {{ background: transparent; border: none; }}
QScrollBar:horizontal {{ background: transparent; height: 12px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background-color: {c.scrollbar}; border-radius: 5px; min-width: 24px; }}
QScrollBar::handle:horizontal:hover {{ background-color: {c.scrollbar_hover}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: transparent; }}
QProgressBar {{ background-color: {c.disabled_bg}; color: {c.text}; border: none; border-radius: 6px; text-align: center; }}
QProgressBar::chunk {{ background-color: {c.primary}; border-radius: 6px; }}

/* Menus, dialogs, dock and status */
QMenu {{ background-color: {c.popup}; color: {c.text}; border: 1px solid {c.border_strong}; padding: 5px; }}
QMenu::item {{ padding: 7px 26px 7px 10px; border-radius: 5px; }}
QMenu::item:selected {{ background-color: {c.selected}; color: {c.selected_text}; }}
QMenu::item:disabled {{ color: {c.disabled_text}; }}
QMenu::separator {{ height: 1px; background-color: {c.border}; margin: 5px 8px; }}
QMenuBar {{ background-color: {c.window_alt}; color: {c.text}; }}
QMenuBar::item:selected {{ background-color: {c.hover}; }}
QDockWidget {{ color: {c.text}; }}
QDockWidget::title {{ background-color: {c.header}; color: {c.muted}; padding: 7px; border-bottom: 1px solid {c.border}; text-align: left; }}
QStatusBar {{ background-color: {c.window_alt}; color: {c.muted}; border-top: 1px solid {c.border}; }}
QStatusBar::item {{ border: none; }}
QToolTip {{ background-color: {c.tooltip_bg}; color: {c.tooltip_text}; border: 1px solid {c.border_strong}; padding: 5px; }}
"""


DARK_STYLE = build_style_sheet("dark")
LIGHT_STYLE = build_style_sheet("light")


def apply_application_theme(key: str) -> str:
    """Apply a complete theme to all current and future application widgets."""
    normalized = normalize_theme(key)
    app = QApplication.instance()
    if app is None:
        return normalized

    # Fusion is palette-aware and avoids Windows-native controls staying light
    # when the rest of the application switches to the dark theme.
    app.setStyle("Fusion")
    app.setPalette(build_palette(normalized))
    app.setStyleSheet(DARK_STYLE if normalized == "dark" else LIGHT_STYLE)
    app.setProperty("adhelperTheme", normalized)

    # Re-polish already-created widgets. This is important for popup views,
    # dialogs, dock widgets and controls that cache metrics/colors.
    for widget in app.allWidgets():
        widget.setProperty("adhelperTheme", normalized)
        style = widget.style()
        if style is not None:
            style.unpolish(widget)
            style.polish(widget)
        widget.update()
    return normalized
