from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QButtonGroup, QDockWidget, QFrame, QHBoxLayout, QLabel, QMainWindow,
    QPlainTextEdit, QPushButton, QStackedWidget, QStatusBar, QVBoxLayout, QWidget
)

from ..constants import APP_NAME, APP_VERSION
from ..context import AppContext
from .pages.dashboard import DashboardPage
from .pages.offboarding import OffboardingPage
from .pages.onboarding import OnboardingPage
from .pages.operations import OperationsPage
from .pages.recovery import RecoveryPage
from .pages.settings_page import SettingsPage
from .pages.users import UsersPage
from .theme import apply_application_theme


class MainWindow(QMainWindow):
    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.context = context
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.resize(1440, 900)
        self.setMinimumSize(1120, 720)

        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(14, 18, 14, 18)
        logo_title = QLabel(APP_NAME)
        logo_title.setObjectName("LogoTitle")
        sidebar_layout.addWidget(logo_title)
        logo_version = QLabel(f"версия {APP_VERSION}")
        logo_version.setObjectName("LogoVersion")
        sidebar_layout.addWidget(logo_version)
        sidebar_layout.addSpacing(18)

        self.stack = QStackedWidget()
        self.dashboard = DashboardPage(context)
        self.onboarding = OnboardingPage(context)
        self.users = UsersPage(context)
        self.offboarding = OffboardingPage(context)
        self.recovery = RecoveryPage(context)
        self.operations = OperationsPage(context)
        self.settings_page = SettingsPage(context)
        pages = [
            ("▦  Обзор", self.dashboard),
            ("＋  Создание", self.onboarding),
            ("⌕  Пользователи", self.users),
            ("⇥  Увольнение", self.offboarding),
            ("↶  Восстановление", self.recovery),
            ("≡  Операции", self.operations),
            ("⚙  Настройки", self.settings_page),
        ]
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        for index, (title, page) in enumerate(pages):
            self.stack.addWidget(page)
            button = QPushButton(title)
            button.setObjectName("Nav")
            button.setCheckable(True)
            button.clicked.connect(lambda checked=False, idx=index: self.stack.setCurrentIndex(idx))
            self.nav_group.addButton(button, index)
            sidebar_layout.addWidget(button)
            if index == 0:
                button.setChecked(True)
        sidebar_layout.addStretch(1)
        self.status_label = QLabel("● Готов")
        self.status_label.setObjectName("Muted")
        sidebar_layout.addWidget(self.status_label)

        root.addWidget(sidebar)
        root.addWidget(self.stack, 1)
        self.setCentralWidget(central)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(2000)
        log_dock = QDockWidget("Диагностика", self)
        log_dock.setObjectName("DiagnosticsDock")
        log_dock.setWidget(self.log_view)
        log_dock.setAllowedAreas(Qt.DockWidgetArea.BottomDockWidgetArea)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, log_dock)
        log_dock.hide()

        status = QStatusBar()
        self.setStatusBar(status)
        status.showMessage(f"{APP_NAME} {APP_VERSION} · данные операций хранятся локально")

        self.context.events.log_message.connect(self._append_log)
        self.settings_page.theme_changed.connect(self.apply_theme)
        self.apply_theme(str(self.context.settings.get("theme", "dark")))

    def apply_theme(self, key: str) -> None:
        apply_application_theme(key)

    def _append_log(self, message: str) -> None:
        self.log_view.appendPlainText(message)

    def open_search(self, query: str, autorun: bool = True) -> None:
        self.stack.setCurrentWidget(self.users)
        button = self.nav_group.button(2)
        if button:
            button.setChecked(True)
        self.users.query.setText(query)
        if autorun and query.strip():
            self.users.search()

    def open_onboarding_payload(self, payload: dict[str, object]) -> None:
        self.stack.setCurrentWidget(self.onboarding)
        button = self.nav_group.button(1)
        if button:
            button.setChecked(True)
        self.onboarding.load_external_payload(payload)
        self.raise_()
        self.activateWindow()
