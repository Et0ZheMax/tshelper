from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import QThreadPool, QTimer, Qt
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QMenu, QMessageBox, QPushButton, QSplitter, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from ...context import AppContext
from ...models import UserRecord
from ...organization import (
    all_section_choices, canonical_unit, department_choices,
    departments_for_section, sections_for_department,
)
from ...services.ou_alignment import OUAlignment, parent_dn
from ...services.welcome import select_welcome_domain
from ...workers import FunctionWorker
from ..widgets import BusyBar, PageHeader, SelectionDialog


class UsersPage(QWidget):
    EDIT_FIELDS = [
        ("title", "title (Должность)"),
        ("division", "division (Подразделение)"),
        ("department", "department (Управление)"),
        ("section", "section (Отдел)"),
        ("description", "description (Описание)"),
        ("office", "physicalDeliveryOfficeName (Кабинет)"),
        ("telephone", "telephoneNumber (Стационарный)"),
        ("mobile", "mobile (Мобильный)"),
        ("otp_mobile", "otpMobile (OTP Mobile)"),
        ("manager_name", "manager (Руководитель)"),
        ("street_address", "streetAddress (Адрес)"),
        ("target_ou", "OU (Целевой OU)"),
    ]
    FIELD_LABELS = dict(EDIT_FIELDS) | {"mail": "mail (Почта)"}

    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.context = context
        self.pool = QThreadPool.globalInstance()
        self.records: list[UserRecord] = []
        self.selected: UserRecord | None = None
        self.edits: dict[str, QLineEdit | QComboBox] = {}
        self._loaded_values: dict[str, str] = {}
        self._dirty_fields: set[str] = set()
        self._mail_original_checked = False
        self._mail_dirty = False
        self._loading_record = False
        self._updating_org_fields = False
        self._linked_org_fields = False
        self._active_worker: FunctionWorker | None = None
        self._ou_worker: FunctionWorker | None = None
        self._ou_cache: dict[str, OUAlignment] = {}
        self._ou_current: OUAlignment | None = None
        self._ou_selected_key = ""
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
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Сотрудник", "Логин", "Домен", "department (Управление)", "Статус", "OU", "OU-контроль"])
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

        self.ou_card = QFrame()
        self.ou_card.setObjectName("InsetCard")
        ou_layout = QVBoxLayout(self.ou_card)
        ou_layout.setContentsMargins(12, 10, 12, 10)
        ou_title = QLabel("Контроль OU по оргструктуре")
        ou_title.setObjectName("CardTitle")
        ou_layout.addWidget(ou_title)
        self.ou_status_label = QLabel("Выберите пользователя")
        self.ou_status_label.setObjectName("OuStatus")
        self.ou_status_label.setProperty("state", "neutral")
        self.ou_status_label.setWordWrap(True)
        ou_layout.addWidget(self.ou_status_label)
        self.ou_details_label = QLabel()
        self.ou_details_label.setObjectName("Muted")
        self.ou_details_label.setWordWrap(True)
        self.ou_details_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        ou_layout.addWidget(self.ou_details_label)
        ou_buttons = QHBoxLayout()
        ou_buttons.addStretch(1)
        self.ou_choose_button = QPushButton("Выбрать OU…")
        self.ou_choose_button.clicked.connect(self._choose_ou_candidate)
        self.ou_choose_button.hide()
        ou_buttons.addWidget(self.ou_choose_button)
        self.ou_move_button = QPushButton("Переместить в правильный OU")
        self.ou_move_button.setObjectName("Primary")
        self.ou_move_button.clicked.connect(self._move_to_expected_ou)
        self.ou_move_button.hide()
        ou_buttons.addWidget(self.ou_move_button)
        ou_layout.addLayout(ou_buttons)
        right_layout.addWidget(self.ou_card)

        form = QFormLayout()
        for key, label in self.EDIT_FIELDS:
            if key in {"department", "section"}:
                edit = QComboBox()
                edit.setEditable(True)
                edit.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
                if key == "department":
                    edit.setToolTip("Выбор управления ограничивает список section (Отдел)")
                    edit.currentTextChanged.connect(self._on_department_changed)
                else:
                    edit.setToolTip("Выбор отдела автоматически подставляет связанный department (Управление)")
                    edit.currentTextChanged.connect(self._on_section_changed)
            else:
                edit = QLineEdit()
                edit.textEdited.connect(lambda _text, field=key: self._mark_field_dirty(field))
            self.edits[key] = edit
            form.addRow(label, edit)
        self.mail_check = QCheckBox("Корпоративная почта назначена")
        self.mail_check.toggled.connect(self._mark_mail_dirty)
        form.addRow("mail (Почта)", self.mail_check)
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
            ou = parent_dn(user.dn) or user.dn
            values = [
                user.display_name,
                user.sam,
                user.domain,
                user.department,
                "Активен" if user.enabled else "Отключён",
                ou,
                "—",
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
            self._configure_organization_fields(user, values)
            for key, edit in self.edits.items():
                self._set_field_text(key, values.get(key, ""))
            self.mail_check.setChecked(bool(user.mail))
        finally:
            self._loading_record = False
        self._loaded_values = values
        self._dirty_fields.clear()
        self._mail_original_checked = bool(user.mail)
        self._mail_dirty = False
        self._update_save_button()
        self._start_ou_analysis(user)

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
            "target_ou": parent_dn(user.dn),
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
            self._ou_selected_key = ""
            self._ou_current = None
            self._set_ou_panel("neutral", "Выберите пользователя", "")
            for key in self.edits:
                self._clear_field(key)
            self.mail_check.setChecked(False)
        finally:
            self._loading_record = False
        self._update_save_button()

    @staticmethod
    def _ou_cache_key(user: UserRecord) -> str:
        identity = user.guid or user.sam
        return "|".join((user.domain, identity, user.dn, user.division, user.department, user.section))

    def _set_ou_panel(self, state: str, status: str, details: str) -> None:
        self.ou_status_label.setProperty("state", state)
        self.ou_status_label.setText(status)
        self.ou_details_label.setText(details)
        style = self.ou_status_label.style()
        style.unpolish(self.ou_status_label)
        style.polish(self.ou_status_label)
        self.ou_move_button.hide()
        self.ou_choose_button.hide()

    def _start_ou_analysis(self, user: UserRecord, refresh: bool = False) -> None:
        key = self._ou_cache_key(user)
        self._ou_selected_key = key
        cached = None if refresh else self._ou_cache.get(key)
        if cached is not None:
            self._apply_ou_alignment(key, cached)
            return
        if self._ou_worker is not None:
            # The running result is still useful for the cache; a new analysis is
            # started when it finishes if the selected user has changed.
            self._set_ou_panel("neutral", "Проверка OU ожидает завершения предыдущей проверки…", "")
            return
        domain = self.context.ad.domain_by_name.get(user.domain)
        if domain is None:
            self._set_ou_panel("problem", "⚠ Не найдена конфигурация домена", user.domain)
            return
        if domain.profile != "omg":
            alignment = OUAlignment(
                status="not_applicable",
                current_dn=parent_dn(user.dn),
                message="Автопроверка оргструктуры включена для профиля OMG.",
            )
            self._ou_cache[key] = alignment
            self._apply_ou_alignment(key, alignment)
            return
        self._set_ou_panel("neutral", "Проверяем соответствие атрибутов и OU…", "")
        worker = FunctionWorker(self._run_ou_analysis, user, key, refresh)
        self._ou_worker = worker
        worker.signals.result.connect(self._ou_analysis_ready)
        worker.signals.error.connect(self._ou_analysis_error)
        worker.signals.finished.connect(self._ou_analysis_finished)
        self.pool.start(worker)

    def _run_ou_analysis(self, user: UserRecord, key: str, refresh: bool = False, progress=None) -> tuple[str, OUAlignment]:
        domain = self.context.ad.domain_by_name.get(user.domain)
        if domain is None:
            raise RuntimeError(f"Не найдена конфигурация домена: {user.domain}")
        return key, self.context.ou_resolver.analyze_user(domain, user, refresh=refresh)

    def _ou_analysis_ready(self, result: object) -> None:
        if not isinstance(result, tuple) or len(result) != 2 or not isinstance(result[1], OUAlignment):
            return
        key, alignment = result
        self._ou_cache[str(key)] = alignment
        self._apply_ou_alignment(str(key), alignment)

    def _ou_analysis_finished(self) -> None:
        self._ou_worker = None
        selected = self.selected
        if selected is not None:
            key = self._ou_cache_key(selected)
            if key == self._ou_selected_key and key not in self._ou_cache:
                QTimer.singleShot(0, lambda user=selected: self._start_ou_analysis(user))

    def _ou_analysis_error(self, message: str, trace: str) -> None:
        self.context.events.log_message.emit(trace)
        if self.selected is not None:
            self._set_ou_panel("problem", "⚠ Не удалось проверить OU", message)

    def _apply_ou_alignment(self, key: str, alignment: OUAlignment) -> None:
        if key != self._ou_selected_key:
            return
        self._ou_current = alignment
        if alignment.status == "ok":
            state = "ok"
            title = "✓ OU соответствует оргструктуре"
        elif alignment.status == "mismatch":
            state = "problem"
            title = "⚠ Найдено несоответствие OU"
        elif alignment.status == "unresolved":
            state = "problem"
            title = "⚠ Целевой OU не определён однозначно"
        else:
            state = "neutral"
            title = "OU-контроль не применяется"

        details = alignment.message
        if alignment.current_dn:
            details += f"\nТекущий OU: {alignment.current_name or alignment.current_dn}"
        if alignment.expected_dn:
            details += f"\nОжидаемый OU: {alignment.expected_name or alignment.expected_dn}"
        if alignment.matched_attribute and alignment.matched_value:
            russian = "Отдел" if alignment.matched_attribute == "section" else "Управление"
            details += f"\nОснование: {alignment.matched_attribute} ({russian}) = {alignment.matched_value}"
        if alignment.confidence:
            details += f"\nУверенность сопоставления: {alignment.confidence * 100:.0f}%"

        self._set_ou_panel(state, title, details.strip())
        self.ou_move_button.setVisible(alignment.can_move)
        self.ou_move_button.setEnabled(not self._is_busy and self._active_worker is None)
        self.ou_choose_button.setVisible(alignment.status == "unresolved" and bool(alignment.candidates))
        self.ou_choose_button.setEnabled(not self._is_busy and self._active_worker is None)
        self._set_table_ou_status(alignment)

    def _set_table_ou_status(self, alignment: OUAlignment) -> None:
        user = self.selected
        if user is None:
            return
        for row, record in enumerate(self.records):
            if record is user or (record.domain == user.domain and (record.guid or record.sam) == (user.guid or user.sam)):
                item = self.table.item(row, 6)
                if item is None:
                    item = QTableWidgetItem()
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    self.table.setItem(row, 6, item)
                if alignment.status == "ok":
                    item.setText("✓ Совпадает")
                elif alignment.status == "mismatch":
                    item.setText("⚠ Несовпадение")
                elif alignment.status == "unresolved":
                    item.setText("⚠ Не определён")
                else:
                    item.setText("—")
                item.setToolTip(alignment.message)
                break

    def _move_to_expected_ou(self) -> None:
        user = self.selected
        alignment = self._ou_current
        if user is None or alignment is None or not alignment.can_move or self._active_worker is not None:
            return
        self._confirm_and_move_ou(user, alignment.expected_dn, alignment.expected_name)

    def _choose_ou_candidate(self) -> None:
        user = self.selected
        alignment = self._ou_current
        if user is None or alignment is None or not alignment.candidates or self._active_worker is not None:
            return
        rows = []
        for item in alignment.candidates:
            row = dict(item)
            row["score_text"] = f"{float(item.get('score') or 0.0) * 100:.0f}%"
            rows.append(row)
        dialog = SelectionDialog(
            "Выберите правильный OU",
            rows,
            [("name", "OU"), ("score_text", "Совпадение"), ("dn", "DistinguishedName")],
            self,
        )
        if dialog.exec() and dialog.selected_row:
            target_dn = str(dialog.selected_row.get("dn") or "")
            target_name = str(dialog.selected_row.get("name") or "")
            if target_dn:
                self._confirm_and_move_ou(user, target_dn, target_name)

    def _confirm_and_move_ou(self, user: UserRecord, target_dn: str, target_name: str) -> None:
        current_dn = parent_dn(user.dn)
        answer = QMessageBox.question(
            self,
            "Перемещение пользователя",
            f"Переместить пользователя {user.display_name} в найденный OU?\n\n"
            f"Сейчас: {current_dn}\n\n"
            f"Будет: {target_dn}\n\n"
            "Атрибуты пользователя не изменятся. Операция будет записана в аудит.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._busy(True, f"Перемещение {user.sam} в {target_name or target_dn}…")
        worker = FunctionWorker(self.context.user_management.update, user, {"target_ou": target_dn})
        self._active_worker = worker
        worker.signals.result.connect(self._ou_move_ready)
        worker.signals.error.connect(self._error)
        worker.signals.finished.connect(self._worker_finished)
        self.pool.start(worker)

    def _ou_move_ready(self, result: object) -> None:
        self.context.events.operations_changed.emit()
        self._ou_cache.clear()
        QMessageBox.information(self, "OU исправлен", "Пользователь перемещён в выбранный OU. Операция записана в аудит.")
        self._refresh_after_finish = True

    def _field_text(self, key: str) -> str:
        widget = self.edits[key]
        if isinstance(widget, QComboBox):
            return widget.currentText().strip()
        return widget.text().strip()

    def _set_field_text(self, key: str, value: str) -> None:
        widget = self.edits[key]
        if isinstance(widget, QComboBox):
            widget.setEditText(value or "")
        else:
            widget.setText(value or "")

    def _clear_field(self, key: str) -> None:
        widget = self.edits[key]
        if isinstance(widget, QComboBox):
            widget.clear()
            widget.setEditText("")
        else:
            widget.clear()

    @staticmethod
    def _replace_combo_items(combo: QComboBox, choices: list[str], current: str = "") -> None:
        unique: list[str] = []
        normalized: set[str] = set()
        for value in choices:
            clean = str(value or "").strip()
            key = clean.casefold().replace("ё", "е")
            if clean and key not in normalized:
                normalized.add(key)
                unique.append(clean)
        current_clean = str(current or "").strip()
        current_key = current_clean.casefold().replace("ё", "е")
        if current_clean and current_key not in normalized:
            unique.append(current_clean)
        combo.clear()
        combo.addItem("")
        combo.addItems(unique)
        combo.setEditText(current_clean)

    def _configure_organization_fields(self, user: UserRecord, values: dict[str, str]) -> None:
        domain = self.context.ad.domain_by_name.get(user.domain)
        self._linked_org_fields = bool(domain is not None and domain.profile == "omg")
        department_combo = self.edits.get("department")
        section_combo = self.edits.get("section")
        if not isinstance(department_combo, QComboBox) or not isinstance(section_combo, QComboBox):
            return

        current_department = values.get("department", "")
        current_section = values.get("section", "")
        departments = department_choices() if self._linked_org_fields else []
        sections = sections_for_department(current_department) if self._linked_org_fields else []
        if self._linked_org_fields and not canonical_unit(current_department, departments):
            sections = all_section_choices()

        self._updating_org_fields = True
        try:
            self._replace_combo_items(department_combo, departments, current_department)
            self._replace_combo_items(section_combo, sections, current_section)
            section_combo.setEnabled(not self._linked_org_fields or bool(sections) or bool(current_section))
        finally:
            self._updating_org_fields = False

    def _on_department_changed(self, value: str) -> None:
        if self._loading_record or self._updating_org_fields:
            return
        section_combo = self.edits.get("section")
        if self._linked_org_fields and isinstance(section_combo, QComboBox):
            departments = department_choices()
            canonical = canonical_unit(value, departments)
            current_section = section_combo.currentText().strip()
            if canonical:
                sections = sections_for_department(canonical)
                preserved = canonical_unit(current_section, sections)
                new_section = preserved or ""
                enabled = bool(sections)
            else:
                sections = all_section_choices()
                new_section = current_section
                enabled = True
            self._updating_org_fields = True
            try:
                self._replace_combo_items(section_combo, sections, new_section)
                section_combo.setEnabled(enabled)
            finally:
                self._updating_org_fields = False
            self._mark_field_dirty("section")
        self._mark_field_dirty("department")

    def _on_section_changed(self, value: str) -> None:
        if self._loading_record or self._updating_org_fields:
            return
        department_combo = self.edits.get("department")
        section_combo = self.edits.get("section")
        if self._linked_org_fields and isinstance(department_combo, QComboBox) and isinstance(section_combo, QComboBox):
            parents = departments_for_section(value)
            if len(parents) == 1:
                parent = parents[0]
                self._updating_org_fields = True
                try:
                    self._replace_combo_items(department_combo, department_choices(), parent)
                    self._replace_combo_items(section_combo, sections_for_department(parent), value)
                    section_combo.setEnabled(True)
                finally:
                    self._updating_org_fields = False
                self._mark_field_dirty("department")
        self._mark_field_dirty("section")

    def _mark_field_dirty(self, key: str) -> None:
        if self._loading_record or self.selected is None:
            return
        value = self._field_text(key)
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
            value = self._field_text(key)
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
        if hasattr(self, "ou_move_button"):
            self.ou_move_button.setEnabled(not value and self._active_worker is None)
            self.ou_choose_button.setEnabled(not value and self._active_worker is None)
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
