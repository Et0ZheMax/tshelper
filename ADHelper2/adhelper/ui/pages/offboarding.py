from __future__ import annotations

import html

from PySide6.QtCore import QThreadPool, Qt
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ...context import AppContext
from ...models import UserRecord
from ...workers import FunctionWorker
from ..widgets import BusyBar, PageHeader


class LoginConfirmationDialog(QDialog):
    """Подтверждение опасной операции с копируемым логином."""

    def __init__(self, login: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.login = login
        self.setWindowTitle("Подтверждение логина")
        self.setModal(True)
        self.setMinimumWidth(390)

        layout = QVBoxLayout(self)
        instruction = QLabel("Введите точный логин. Нажмите на логин ниже, чтобы скопировать его:")
        instruction.setWordWrap(True)
        layout.addWidget(instruction)

        self.login_link = QLabel(f"<a href='copy'>{html.escape(login)}</a>")
        self.login_link.setObjectName("LinkLabel")
        self.login_link.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        self.login_link.setOpenExternalLinks(False)
        self.login_link.setCursor(Qt.CursorShape.PointingHandCursor)
        self.login_link.linkActivated.connect(self._copy_login)
        layout.addWidget(self.login_link)

        self.copy_state = QLabel("")
        self.copy_state.setObjectName("Muted")
        layout.addWidget(self.copy_state)

        self.edit = QLineEdit()
        self.edit.setPlaceholderText("Вставьте подтверждаемый логин")
        self.edit.textChanged.connect(self._validate)
        self.edit.returnPressed.connect(self._accept_if_valid)
        layout.addWidget(self.edit)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.accepted.connect(self._accept_if_valid)
        self.buttons.rejected.connect(self.reject)
        self.ok_button = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok_button.setEnabled(False)
        layout.addWidget(self.buttons)
        self.edit.setFocus()

    def _copy_login(self, _link: str = "") -> None:
        QApplication.clipboard().setText(self.login)
        self.copy_state.setText(f"Логин «{self.login}» скопирован в буфер обмена")

    def _validate(self, value: str) -> None:
        self.ok_button.setEnabled(value.strip().casefold() == self.login.casefold())

    def _accept_if_valid(self) -> None:
        if self.edit.text().strip().casefold() == self.login.casefold():
            self.accept()


class OffboardingPage(QWidget):
    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.context = context
        self.pool = QThreadPool.globalInstance()
        self.records: list[UserRecord] = []
        self.selected: UserRecord | None = None
        self._preview_valid = False
        self._busy_state = False
        self._active_workers: list[FunctionWorker] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.addWidget(PageHeader(
            "Увольнение сотрудника",
            "До первого изменения сохраняется полный recovery-снимок всех очищаемых атрибутов. "
            "Каждая операция и точная ошибка отображаются отдельно.",
        ))

        search_row = QHBoxLayout()
        self.query = QLineEdit()
        self.query.setPlaceholderText("ФИО или точный логин")
        self.query.returnPressed.connect(self.search)
        self.search_button = QPushButton("Найти")
        self.search_button.clicked.connect(self.search)
        search_row.addWidget(self.query, 1)
        search_row.addWidget(self.search_button)
        root.addLayout(search_row)

        self.progress_label = QLabel("")
        self.progress_label.setObjectName("Muted")
        self.progress_label.setWordWrap(True)
        self.progress_label.hide()
        root.addWidget(self.progress_label)
        self.busy = BusyBar()
        root.addWidget(self.busy)

        splitter = QSplitter()
        list_frame = QFrame()
        list_frame.setObjectName("Card")
        list_layout = QVBoxLayout(list_frame)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Сотрудник", "Логин", "Домен", "Статус", "OU"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._select)
        list_layout.addWidget(self.table)

        details_frame = QFrame()
        details_frame.setObjectName("Card")
        details_layout = QVBoxLayout(details_frame)
        self.name_label = QLabel("Сотрудник не выбран")
        self.name_label.setObjectName("CardTitle")
        details_layout.addWidget(self.name_label)
        self.details_label = QLabel()
        self.details_label.setObjectName("Muted")
        self.details_label.setWordWrap(True)
        details_layout.addWidget(self.details_label)
        self.plan_text = QTextEdit()
        self.plan_text.setReadOnly(True)
        self.plan_text.setPlaceholderText("Нажмите «Проверить план»: приложение проверит пользователя и OU уволенных в каждом домене.")
        details_layout.addWidget(self.plan_text, 1)
        buttons = QHBoxLayout()
        self.preview_button = QPushButton("Проверить план")
        self.preview_button.setEnabled(False)
        self.preview_button.clicked.connect(self.preview)
        self.execute_button = QPushButton("Выполнить увольнение")
        self.execute_button.setObjectName("Danger")
        self.execute_button.setEnabled(False)
        self.execute_button.clicked.connect(self.execute)
        buttons.addWidget(self.preview_button)
        buttons.addStretch(1)
        buttons.addWidget(self.execute_button)
        details_layout.addLayout(buttons)

        splitter.addWidget(list_frame)
        splitter.addWidget(details_frame)
        splitter.setSizes([700, 560])
        root.addWidget(splitter, 1)

        self.steps_table = QTableWidget(0, 3)
        self.steps_table.setHorizontalHeaderLabels(["Этап", "Статус", "Сообщение / точная ошибка"])
        self.steps_table.horizontalHeader().setStretchLastSection(True)
        self.steps_table.setMinimumHeight(190)
        root.addWidget(self.steps_table)

    def _track_worker(self, worker: FunctionWorker) -> FunctionWorker:
        self._active_workers.append(worker)
        worker.signals.finished.connect(lambda current=worker: self._worker_finished(current))
        return worker

    def _worker_finished(self, worker: FunctionWorker) -> None:
        if worker in self._active_workers:
            self._active_workers.remove(worker)
        self._finish_task()

    def _start_task(self, total: int, message: str) -> None:
        self._busy_state = True
        self.progress_label.setText(message)
        self.progress_label.show()
        self.busy.start_steps(max(1, total))
        self._update_buttons()

    def _progress(self, key: str, message: str) -> None:
        current, total = 0, max(1, self.busy.maximum())
        try:
            left, right = key.split("/", 1)
            current, total = int(left), max(1, int(right))
        except (ValueError, AttributeError):
            current = min(self.busy.value() + 1, total)
        if self.busy.maximum() != total or not self.busy.isVisible():
            self.busy.start_steps(total)
        self.busy.set_step(current, total)
        self.progress_label.setText(f"Шаг {current} из {total}: {message}")
        self.progress_label.show()

    def _finish_task(self) -> None:
        if not self._busy_state and not self.busy.isVisible():
            return
        self._busy_state = False
        self.busy.stop()
        self.progress_label.hide()
        self._update_buttons()

    def _update_buttons(self) -> None:
        enabled = not self._busy_state
        self.search_button.setEnabled(enabled)
        self.preview_button.setEnabled(enabled and self.selected is not None)
        self.execute_button.setEnabled(enabled and self.selected is not None and self._preview_valid)

    def search(self) -> None:
        query = self.query.text().strip()
        if not query:
            QMessageBox.warning(self, "Поиск", "Введите ФИО или логин")
            return
        self._preview_valid = False
        self._start_task(len(self.context.ad.domains), "Подготовка поиска пользователя…")
        worker = self._track_worker(FunctionWorker(self.context.ad.search_users, query, include_fired=False))
        worker.signals.progress.connect(self._progress)
        worker.signals.result.connect(self._search_ready)
        worker.signals.error.connect(self._error)
        self.pool.start(worker)

    def _search_ready(self, value: object) -> None:
        try:
            all_records = value if isinstance(value, list) else []
            self.records = [record for record in all_records if isinstance(record, UserRecord) and not record.is_fired]
            self.table.setRowCount(len(self.records))
            for row, user in enumerate(self.records):
                ou = user.dn.split(",", 1)[1] if "," in user.dn else user.dn
                values = [user.display_name, user.sam, user.domain, "Активен" if user.enabled else "Отключён", ou]
                for column, text in enumerate(values):
                    item = QTableWidgetItem(text)
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    self.table.setItem(row, column, item)
            if not self.records:
                QMessageBox.information(self, "Поиск", "Активные пользователи не найдены")
        finally:
            self._finish_task()

    def _select(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        self._preview_valid = False
        if not rows:
            self.selected = None
            self._update_buttons()
            return
        row = rows[0].row()
        if row >= len(self.records):
            return
        self.selected = self.records[row]
        self.name_label.setText(self.selected.display_name)
        self.details_label.setText(
            f"Логин: {self.selected.sam}\n"
            f"Выбрана запись домена: {self.selected.domain}\n"
            "Сначала выполните проверку плана: она проверит этот же логин, GUID и OU уволенных во всех доменах."
        )
        self.plan_text.clear()
        self.steps_table.setRowCount(0)
        self._update_buttons()

    def preview(self) -> None:
        if not self.selected:
            return
        self._preview_valid = False
        total = max(1, len(self.context.ad.domains) * 2)
        self._start_task(total, "Получаем recovery-снимки и проверяем OU уволенных…")
        worker = self._track_worker(FunctionWorker(self.context.offboarding.preview, self.selected.sam))
        worker.signals.progress.connect(self._progress)
        worker.signals.result.connect(self._preview_ready)
        worker.signals.error.connect(self._error)
        self.pool.start(worker)

    def _preview_ready(self, value: object) -> None:
        try:
            snapshots = value if isinstance(value, dict) else {}
            if not snapshots:
                self.plan_text.setPlainText("Пользователь не найден ни в одном домене.")
                self._preview_valid = False
                return

            lines = ["План увольнения:", ""]
            validation_errors: list[str] = []
            for domain, snapshot in snapshots.items():
                error = str(snapshot.get("validation_error") or "")
                clear_attributes = snapshot.get("clear_attributes") or []
                lines.extend([
                    f"• {domain}",
                    f"  DN: {snapshot.get('dn', '')}",
                    f"  Статус: {'Enabled' if snapshot.get('enabled') else 'Disabled'}",
                    f"  В recovery записано очищаемых атрибутов: {len(clear_attributes)}",
                ])
                if error:
                    validation_errors.append(f"[{domain}] {error}")
                    lines.append(f"  ПРОВЕРКА НЕ ПРОЙДЕНА: {error}")
                else:
                    validation = snapshot.get("offboarding_validation") or {}
                    raw_steps = validation.get("steps") or []
                    populated = []
                    if raw_steps and isinstance(raw_steps[0], dict):
                        populated = raw_steps[0].get("populated_attributes") or []
                    lines.append(f"  Будет очищено заполненных атрибутов: {len(populated)}")
                    lines.append("  Затем: отключение → проверка Enabled=False → перенос → проверка итогового DN")
                lines.append("")

            lines.append("Recovery JSON создаётся до первого изменения в AD.")
            if validation_errors:
                lines.extend(["", "Исправьте ошибки перед запуском:", *[f"• {item}" for item in validation_errors]])
                self._preview_valid = False
            else:
                lines.extend(["", "Все обязательные предварительные проверки пройдены."])
                self._preview_valid = True
            self.plan_text.setPlainText("\n".join(lines))
        finally:
            self._finish_task()

    def execute(self) -> None:
        user = self.selected
        if not user or not self._preview_valid:
            QMessageBox.warning(self, "Увольнение", "Сначала выполните успешную проверку плана.")
            return
        answer = QMessageBox.warning(
            self,
            "Необратимая операция",
            f"Будут изменены учётные записи '{user.sam}' во всех доменах, где они найдены.\n\n"
            "Перед изменениями будет записан recovery JSON со всеми очищаемыми полями.\n"
            "Затем рабочие атрибуты будут очищены, аккаунт отключён и перемещён в OU «Уволенные».\n\nПродолжить?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        confirmation = LoginConfirmationDialog(user.sam, self)
        if confirmation.exec() != QDialog.DialogCode.Accepted:
            return

        total = max(1, len(self.context.ad.domains) * 5 + 1)
        self._start_task(total, "Начинаем безопасное увольнение…")
        self.steps_table.setRowCount(0)
        self.plan_text.append("\n--- Выполнение ---")
        worker = self._track_worker(
            FunctionWorker(self.context.offboarding.execute, user.sam, user.display_name, dry_run=False)
        )
        worker.signals.progress.connect(self._execution_progress)
        worker.signals.result.connect(self._execute_ready)
        worker.signals.error.connect(self._error)
        self.pool.start(worker)

    def _execution_progress(self, key: str, message: str) -> None:
        self._progress(key, message)
        self.plan_text.append(message)

    def _execute_ready(self, operation: object) -> None:
        try:
            self.context.events.operations_changed.emit()
            steps = getattr(operation, "steps", [])
            self.steps_table.setRowCount(len(steps))
            for row, step in enumerate(steps):
                for column, value in enumerate((step.title, step.status, step.message)):
                    item = QTableWidgetItem(str(value))
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    self.steps_table.setItem(row, column, item)
            self.steps_table.resizeRowsToContents()

            data = getattr(operation, "data", {}) or {}
            recovery_path = data.get("recovery_path", "")
            status = getattr(operation, "status", "unknown")
            errors = [str(item) for item in (getattr(operation, "errors", []) or [])]
            warnings = [str(item) for item in (getattr(operation, "warnings", []) or [])]

            self.plan_text.append(f"\nИтог: {status}")
            if recovery_path:
                self.plan_text.append(f"Recovery-файл: {recovery_path}")
            if errors:
                self.plan_text.append("\nТочные ошибки:")
                for error in errors:
                    self.plan_text.append(f"• {error}")
            if warnings:
                self.plan_text.append("\nПредупреждения:")
                for warning in warnings:
                    self.plan_text.append(f"• {warning}")

            if status == "success":
                QMessageBox.information(
                    self,
                    "Готово",
                    f"Увольнение завершено.\nRecovery-файл: {recovery_path}",
                )
            else:
                exact = "\n".join(f"• {item}" for item in errors[:6]) or "Смотрите таблицу этапов и предупреждения."
                QMessageBox.warning(
                    self,
                    "Увольнение завершилось неуспешно",
                    f"Статус: {status}\n\n{exact}\n\nRecovery-файл сохранён:\n{recovery_path}",
                )
            self._preview_valid = False
        finally:
            self._finish_task()

    def _error(self, message: str, trace: str) -> None:
        self.context.events.log_message.emit(trace)
        self.plan_text.append(f"\nОШИБКА: {message}")
        self._finish_task()
        QMessageBox.critical(self, "Ошибка", message)
