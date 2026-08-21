from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import QThreadPool, QTimer, Qt
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QMenu, QMessageBox, QPushButton, QSplitter, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from ...context import AppContext
from ...models import UserRecord
from ...services.welcome import select_welcome_domain
from ...workers import FunctionWorker
from ..widgets import BusyBar, PageHeader


class UsersPage(QWidget):
    EDIT_FIELDS = [
        ("title", "Должность"),
        ("department", "Department"),
        ("section", "Section"),
        ("division", "Division"),
        ("description", "Description"),
        ("office", "Кабинет"),
        ("telephone", "Стационарный"),
        ("mobile", "Mobile"),
        ("otp_mobile", "OTP Mobile"),
        ("manager_name", "Руководитель"),
        ("street_address", "Адрес"),
        ("target_ou", "Целевой OU"),
    ]
    FIELD_LABELS = dict(EDIT_FIELDS) | {"mail": "Почта"}

    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.context = context
        self.pool = QThreadPool.globalInstance()
        self.records: list[UserRecord] = []
        self.selected: UserRecord | None = None
        self.edits: dict[str, QLineEdit] = {}
        self._loaded_values: dict[str, str] = {}
        self._dirty_fields: set[str] = set()
        self._mail_original_checked = False
        self._mail_dirty = False
        self._loading_record = False
        self._active_worker: FunctionWorker | None = None
        self._is_busy = False
        self._refresh_after_finish = False

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.addWidget(PageHeader("Пользователи", "Поиск, просмотр и безопасное изменение атрибутов в обоих доменах."))
        search_row = QHBoxLayout()
        self.query = QLineEdit()
        self.query.setPlaceholderText("ФИО, логин или телефон")
        self.query.returnPressed.connect(self.search)
        self.show_fired = QCheckBox("Показывать уволенных")
        self.search_button = QPushButton("Найти")
        self.search_button.setObjectName("Primary")
        self.search_button.clicked.connect(self.search)
        search_row.addWidget(self.query, 1)
        search_row.addWidget(self.show_fired)
        search_row.addWidget(self.search_button)
        root.addLayout(search_row)
        self.busy = BusyBar()
        root.addWidget(self.busy)
        self.busy_label = QLabel()
        self.busy_label.setObjectName("Muted")
        self.busy_label.hide()
        root.addWidget(self.busy_label)

        splitter = QSplitter()
        left = QFrame()
        left.setObjectName("Card")
        left_layout = QVBoxLayout(left)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Сотрудник", "Логин", "Домен", "Отдел", "Статус", "OU"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._select_record)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        left_layout.addWidget(self.table)

        right = QFrame()
        right.setObjectName("Card")
        right_layout = QVBoxLayout(right)
        self.selected_label = QLabel("Пользователь не выбран")
        self.selected_label.setObjectName("CardTitle")
        right_layout.addWidget(self.selected_label)
        self.identity_label = QLabel()
        self.identity_label.setObjectName("Muted")
        self.identity_label.setWordWrap(True)
        right_layout.addWidget(self.identity_label)
        form = QFormLayout()
        for key, label in self.EDIT_FIELDS:
            edit = QLineEdit()
            edit.textEdited.connect(lambda _text, field=key: self._mark_field_dirty(field))
            self.edits[key] = edit
            form.addRow(label, edit)
        self.mail_check = QCheckBox("Корпоративная почта назначена")
        self.mail_check.toggled.connect(self._mark_mail_dirty)
        form.addRow("Почта", self.mail_check)
        right_layout.addLayout(form)
        self.save_button = QPushButton("Сохранить изменения")
        self.save_button.setObjectName("Primary")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.save)
        right_layout.addWidget(self.save_button, 0, Qt.AlignmentFlag.AlignRight)
        right_layout.addStretch(1)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([760, 520])
        root.addWidget(splitter, 1)

    def search(self) -> None:
        if self._active_worker is not None:
            return
        query = self.query.text().strip()
        if not query:
            QMessageBox.warning(self, "Поиск", "Введите строку поиска")
            return
        self._busy(True, "Поиск пользователей в настроенных доменах…")
        worker = FunctionWorker(self.context.ad.search_users, query, include_fired=self.show_fired.isChecked())
        self._active_worker = worker
        worker.signals.result.connect(self._search_ready)
        worker.signals.error.connect(self._error)
        worker.signals.finished.connect(self._worker_finished)
        self.pool.start(worker)

    def _search_ready(self, result: object) -> None:
        self._clear_selected_user()
        self.records = result if isinstance(result, list) else []
        self.table.clearContents()
        self.table.setRowCount(len(self.records))
        for row, user in enumerate(self.records):
            if not isinstance(user, UserRecord):
                continue
            ou = user.dn.split(",", 1)[1] if "," in user.dn else user.dn
            values = [
                user.display_name,
                user.sam,
                user.domain,
                user.department,
                "Активен" if user.enabled else "Отключён",
                ou,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, column, item)
        if not self.records:
            QMessageBox.information(self, "Поиск", "Пользователи не найдены")

    def _select_record(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            self._clear_selected_user()
            return
        index = rows[0].row()
        if index >= len(self.records):
            self._clear_selected_user()
            return
        user = self.records[index]
        self.selected = user
        self.selected_label.setText(f"{user.display_name} · {user.domain}")
        self.identity_label.setText(f"{user.sam} · {user.upn}\n{user.dn}")
        values = self._values_from_user(user)
        self._loading_record = True
        try:
            for key, edit in self.edits.items():
                edit.setText(values.get(key, ""))
            self.mail_check.setChecked(bool(user.mail))
        finally:
            self._loading_record = False
        self._loaded_values = values
        self._dirty_fields.clear()
        self._mail_original_checked = bool(user.mail)
        self._mail_dirty = False
        self._update_save_button()

    @staticmethod
    def _values_from_user(user: UserRecord) -> dict[str, str]:
        return {
            "title": user.title,
            "department": user.department,
            "section": user.section,
            "division": user.division,
            "description": user.description,
            "office": user.office,
            "telephone": user.telephone,
            "mobile": user.mobile,
            "otp_mobile": user.otp_mobile,
            "manager_name": user.manager_name,
            "street_address": user.street_address,
            "target_ou": user.dn.split(",", 1)[1] if "," in user.dn else "",
        }

    def _clear_selected_user(self) -> None:
        self.selected = None
        self._loaded_values = {}
        self._dirty_fields.clear()
        self._mail_original_checked = False
        self._mail_dirty = False
        self._loading_record = True
        try:
            self.selected_label.setText("Пользователь не выбран")
            self.identity_label.clear()
            for edit in self.edits.values():
                edit.clear()
            self.mail_check.setChecked(False)
        finally:
            self._loading_record = False
        self._update_save_button()

    def _mark_field_dirty(self, key: str) -> None:
        if self._loading_record or self.selected is None:
            return
        value = self.edits[key].text().strip()
        if value == self._loaded_values.get(key, ""):
            self._dirty_fields.discard(key)
        else:
            self._dirty_fields.add(key)
        self._update_save_button()

    def _mark_mail_dirty(self, checked: bool) -> None:
        if self._loading_record or self.selected is None:
            return
        self._mail_dirty = checked != self._mail_original_checked
        self._update_save_button()

    def save(self) -> None:
        user = self.selected
        if not user or self._active_worker is not None:
            return

        changes: dict[str, Any] = {}
        for key in self._dirty_fields:
            value = self.edits[key].text().strip()
            if value != self._loaded_values.get(key, ""):
                changes[key] = value

        if self._mail_dirty:
            if self.mail_check.isChecked():
                domain = self.context.ad.domain_by_name.get(user.domain)
                if domain is None:
                    QMessageBox.critical(self, "Почта", f"Не найдена конфигурация домена: {user.domain}")
                    return
                changes["mail"] = user.sam + domain.email_suffix
            else:
                changes["mail"] = ""

        if not changes:
            QMessageBox.information(self, "Изменения", "Нет изменений для сохранения")
            self._dirty_fields.clear()
            self._mail_dirty = False
            self._update_save_button()
            return

        changed_names = [self.FIELD_LABELS.get(key, key) for key in changes]
        details = "\n".join(f"• {name}" for name in changed_names)
        answer = QMessageBox.question(
            self,
            "Подтверждение",
            f"Будут изменены только следующие поля пользователя {user.display_name}:\n\n{details}\n\nПродолжить?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        self._busy(True, f"Сохранение {len(changes)} изменённых полей…")
        worker = FunctionWorker(self._resolve_and_update, user, dict(changes))
        self._active_worker = worker
        worker.signals.result.connect(self._save_ready)
        worker.signals.error.connect(self._error)
        worker.signals.finished.connect(self._worker_finished)
        self.pool.start(worker)

    def _resolve_and_update(self, user: UserRecord, changes: dict[str, Any], progress=None) -> object:
        manager_name = changes.pop("manager_name", None)
        if manager_name is not None:
            if manager_name:
                managers = self.context.ad.find_managers(manager_name, user.domain)
                if len(managers) != 1:
                    raise RuntimeError(f"Руководитель найден неоднозначно: {len(managers)} совпадений")
                changes["manager_dn"] = managers[0].dn
            else:
                changes["manager_dn"] = ""
        return self.context.user_management.update(user, changes)

    def _save_ready(self, result: object) -> None:
        self.context.events.operations_changed.emit()
        data = getattr(result, "data", {})
        updated = data.get("updated_user") if isinstance(data, dict) else None
        if isinstance(updated, dict):
            self.selected = UserRecord.from_mapping(updated)
        self._dirty_fields.clear()
        self._mail_dirty = False
        QMessageBox.information(self, "Готово", "Изменены только выбранные поля. Операция записана в аудит.")
        if self._active_worker is None:
            QTimer.singleShot(0, self.search)
        else:
            self._refresh_after_finish = True

    def _show_context_menu(self, position) -> None:
        index = self.table.indexAt(position)
        if not index.isValid() or index.row() >= len(self.records):
            return
        self.table.selectRow(index.row())
        user = self.records[index.row()]

        menu = QMenu(self)
        copy_login = menu.addAction(f"Копировать логин: {user.sam}")
        print_welcome = menu.addAction("Печать приветственного листа")
        menu.addSeparator()
        delete_user = menu.addAction("Удалить пользователя")
        selected_action = menu.exec(self.table.viewport().mapToGlobal(position))

        if selected_action == copy_login:
            QApplication.clipboard().setText(user.sam)
        elif selected_action == print_welcome:
            self._print_welcome_for_user(user)
        elif selected_action == delete_user:
            self._delete_user(user)

    def _delete_user(self, user: UserRecord) -> None:
        if self._active_worker is not None:
            QMessageBox.information(self, "Удаление пользователя", "Дождитесь завершения текущей операции")
            return
        domain = self.context.ad.domain_by_name.get(user.domain)
        if domain is None:
            QMessageBox.critical(self, "Удаление пользователя", f"Не найдена конфигурация домена: {user.domain}")
            return
        domain_label = domain.label or domain.name
        answer = QMessageBox.question(
            self,
            "Удаление пользователя",
            f'Вы уверены, что хотите удалить пользователя из домена "{domain_label}"?\n\n'
            f"Пользователь: {user.display_name}\n"
            f"Логин: {user.sam}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        self._busy(True, f"Удаление {user.sam} из домена {domain_label}…")
        worker = FunctionWorker(self.context.user_management.delete, user)
        self._active_worker = worker
        worker.signals.result.connect(self._delete_ready)
        worker.signals.error.connect(self._error)
        worker.signals.finished.connect(self._worker_finished)
        self.pool.start(worker)

    def _delete_ready(self, result: object) -> None:
        self.context.events.operations_changed.emit()
        data = getattr(result, "data", {})
        deleted = data.get("deleted_user") if isinstance(data, dict) else {}
        recovery_path = str(data.get("recovery_path") or "") if isinstance(data, dict) else ""
        domain = str(deleted.get("domain") or (self.selected.domain if self.selected else ""))
        sam = str(deleted.get("sam") or (self.selected.sam if self.selected else ""))
        self._clear_selected_user()
        QMessageBox.information(
            self,
            "Пользователь удалён",
            f"Пользователь {sam} удалён из домена {domain}. Операция записана в аудит.\n\n"
            f"Recovery JSON: {recovery_path}",
        )
        self._refresh_after_finish = True

    def _print_welcome_for_user(self, user: UserRecord) -> None:
        if self._active_worker is not None:
            QMessageBox.information(self, "Печать", "Дождитесь завершения текущей операции")
            return
        if not self.context.welcome.available():
            QMessageBox.warning(
                self,
                "Приветственный лист",
                "Не найден шаблон New User.odt в папке adhelper\\templates.",
            )
            return
        password = self.context.settings.get_default_password()
        if not password:
            QMessageBox.warning(
                self,
                "Приветственный лист",
                "В настройках не задан пароль новых пользователей.",
            )
            return
        try:
            print_domain = select_welcome_domain(self.context.ad.domains)
        except RuntimeError as exc:
            QMessageBox.critical(self, "Приветственный лист", str(exc))
            return

        answer = QMessageBox.question(
            self,
            "Печать приветственного листа",
            "В лист будет подставлен пароль новых пользователей, сохранённый в настройках.\n\n"
            f"Пользователь: {user.display_name}\n"
            f"Учётка выбрана из домена: {user.domain}\n"
            f"Логин в приветственном листе: {print_domain.netbios}\\{user.sam}\n"
            f"Почта: {user.mail or 'не назначена'}\n\n"
            "Сформировать документ и отправить его на печать?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        self._busy(True, "Формирование и отправка приветственного листа на печать…")
        worker = FunctionWorker(self._generate_and_print_welcome, user, password, print_domain.netbios)
        self._active_worker = worker
        worker.signals.result.connect(self._welcome_print_ready)
        worker.signals.error.connect(self._error)
        worker.signals.finished.connect(self._worker_finished)
        self.pool.start(worker)

    def _generate_and_print_welcome(
        self,
        user: UserRecord,
        password: str,
        print_netbios: str,
        progress=None,
    ) -> Path:
        path = self.context.welcome.generate(
            login=user.sam,
            domain_login=f"{print_netbios}\\{user.sam}",
            email=user.mail,
            password=password,
        )
        self.context.welcome.print_document(path)
        return path

    def _welcome_print_ready(self, result: object) -> None:
        path = Path(result) if isinstance(result, (str, Path)) else None
        message = "Приветственный лист сформирован и отправлен на печать."
        if path is not None:
            message += f"\n\nФайл: {path}"
        QMessageBox.information(self, "Печать", message)

    def _busy(self, value: bool, message: str = "") -> None:
        self._is_busy = value
        if value:
            self.busy.start_indeterminate()
            self.busy_label.setText(message)
            self.busy_label.setVisible(bool(message))
        else:
            self.busy.stop()
            self.busy_label.clear()
            self.busy_label.hide()
        self.query.setEnabled(not value)
        self.show_fired.setEnabled(not value)
        self.search_button.setEnabled(not value)
        self.table.setEnabled(not value)
        self._update_save_button()

    def _update_save_button(self) -> None:
        has_changes = bool(self._dirty_fields) or self._mail_dirty
        enabled = (
            not self._is_busy
            and self._active_worker is None
            and self.selected is not None
            and not self.selected.is_fired
            and has_changes
        )
        self.save_button.setEnabled(enabled)

    def _worker_finished(self) -> None:
        self._active_worker = None
        self._busy(False)
        if self._refresh_after_finish:
            self._refresh_after_finish = False
            QTimer.singleShot(0, self.search)

    def _error(self, message: str, trace: str) -> None:
        self.context.events.log_message.emit(trace)
        QMessageBox.critical(self, "Ошибка", message)
