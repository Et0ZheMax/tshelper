from __future__ import annotations

from dataclasses import replace
from typing import Any

from PySide6.QtCore import QThreadPool, Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFormLayout, QFrame, QGridLayout, QHBoxLayout, QLabel,
    QLineEdit, QMessageBox, QPushButton, QScrollArea, QSplitter, QStackedWidget, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget
)

from ...context import AppContext
from ...models import ParsedRequest
from ...parsers.request_parser import (
    extract_request_fields, format_request_text, parse_request, validation_errors,
)
from ...services.onboarding import OnboardingPlan
from ...workers import FunctionWorker
from ..widgets import BusyBar, PageHeader, SelectionDialog


class RequestTextEdit(QTextEdit):
    """Поле вставки, которое предпочитает обычный текст и восстанавливает строки."""

    def insertFromMimeData(self, source) -> None:  # type: ignore[override]
        if source.hasText():
            self.insertPlainText(format_request_text(source.text()))
            return
        super().insertFromMimeData(source)


class OnboardingPage(QWidget):
    FIELDS = [
        ("last_name", "Фамилия"), ("first_name", "Имя"), ("middle_name", "Отчество"),
        ("manager_name", "Руководитель"), ("management", "Управление"),
        ("department", "Отдел / подразделение"), ("title", "Должность"),
        ("office_room", "Кабинет"), ("mobile_phone", "Мобильный телефон"),
        ("start_date", "Дата выхода"), ("work_mode", "Режим работы"),
        ("equipment", "Оборудование"), ("office_os", "ОС ноутбука"),
        ("notes", "Примечание"),
    ]

    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.context = context
        self.pool = QThreadPool.globalInstance()
        self.request = ParsedRequest()
        self.plan: OnboardingPlan | None = None
        self.field_edits: dict[str, QLineEdit] = {}
        self.ou_edits: dict[str, QTextEdit] = {}
        self.manager_edits: dict[str, QLineEdit] = {}
        self._active_workers: list[FunctionWorker] = []
        self._busy_state = False
        self._plan_progress_current = 0
        self._plan_progress_total = 0
        self._external_callback_url = ""
        self._external_source_url = ""
        self._external_ticket_id: int | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.addWidget(PageHeader("Создание сотрудника", "Пошаговый мастер: заявка и карточка → AD-план → выполнение."))

        self.external_source_label = QLabel()
        self.external_source_label.setObjectName("Muted")
        self.external_source_label.setWordWrap(True)
        self.external_source_label.hide()
        root.addWidget(self.external_source_label)

        self.steps_label = QLabel()
        self.steps_label.setObjectName("Muted")
        root.addWidget(self.steps_label)
        self.busy = BusyBar()
        root.addWidget(self.busy)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_request_page())
        self.stack.addWidget(self._build_plan_page())
        self.stack.addWidget(self._build_execute_page())
        root.addWidget(self.stack, 1)

        actions = QHBoxLayout()
        self.back_button = QPushButton("← Назад")
        self.back_button.clicked.connect(self.back)
        self.next_button = QPushButton("Далее →")
        self.next_button.setObjectName("Primary")
        self.next_button.clicked.connect(self.next)
        self.reset_button = QPushButton("Очистить")
        self.reset_button.clicked.connect(self.reset)
        actions.addWidget(self.reset_button)
        actions.addStretch(1)
        actions.addWidget(self.back_button)
        actions.addWidget(self.next_button)
        root.addLayout(actions)
        self.context.events.domains_changed.connect(self.refresh_domains)
        self.context.events.addresses_changed.connect(self._addresses_changed)
        self._sync_navigation()

    def _card(self) -> tuple[QFrame, QVBoxLayout]:
        frame = QFrame()
        frame.setObjectName("Card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(18, 18, 18, 18)
        return frame, layout

    def _build_request_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)
        frame, card = self._card()

        title = QLabel("1. Вставьте и проверьте заявку")
        title.setObjectName("CardTitle")
        card.addWidget(title)
        hint = QLabel(
            "Слева — исходный текст заявки. Справа — данные, которые ADHelper распознал. "
            "Карточку можно исправить вручную до формирования плана AD."
        )
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        card.addWidget(hint)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        source_frame = QFrame()
        source_layout = QVBoxLayout(source_frame)
        source_layout.setContentsMargins(0, 0, 8, 0)
        source_title = QLabel("Текст заявки")
        source_title.setObjectName("CardTitle")
        source_layout.addWidget(source_title)
        source_hint = QLabel(
            "Просто вставьте заявку целиком. Однострочный текст автоматически разбивается по пунктам 1), 2), 3)…"
        )
        source_hint.setObjectName("Muted")
        source_hint.setWordWrap(True)
        source_layout.addWidget(source_hint)
        self.request_text = RequestTextEdit()
        self.request_text.setPlaceholderText("Вставьте заявку целиком…")
        source_layout.addWidget(self.request_text, 1)

        preview_scroll = QScrollArea()
        preview_scroll.setWidgetResizable(True)
        preview_body = QWidget()
        preview_layout = QVBoxLayout(preview_body)
        preview_layout.setContentsMargins(8, 0, 0, 0)
        preview_title = QLabel("Распознанная карточка сотрудника")
        preview_title.setObjectName("CardTitle")
        preview_layout.addWidget(preview_title)
        self.preview_status = QLabel("Вставьте текст заявки слева")
        self.preview_status.setObjectName("Muted")
        self.preview_status.setWordWrap(True)
        preview_layout.addWidget(self.preview_status)

        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.full_name_preview = QLineEdit()
        self.full_name_preview.setReadOnly(True)
        self.full_name_preview.setPlaceholderText("Сформируется из ФИО")
        form.addRow("Полное имя", self.full_name_preview)
        for key, label in self.FIELDS:
            edit = QLineEdit()
            self.field_edits[key] = edit
            if key in {"last_name", "first_name", "middle_name"}:
                edit.textChanged.connect(self._update_full_name_from_card)
            form.addRow(label, edit)

        self.has_photo = QCheckBox("Фотография сотрудника есть")
        self.need_mail = QCheckBox("Назначить корпоративную почту")
        self.need_internal_phone = QCheckBox("Нужен внутренний номер")
        self.need_servers_access = QCheckBox("Нужен доступ к серверам")
        self.need_folders_access = QCheckBox("Нужен доступ к папкам")
        flags_widget = QWidget()
        flags = QVBoxLayout(flags_widget)
        flags.setContentsMargins(0, 0, 0, 0)
        for widget in (
            self.has_photo, self.need_mail, self.need_internal_phone,
            self.need_servers_access, self.need_folders_access,
        ):
            flags.addWidget(widget)
        form.addRow("Дополнительно", flags_widget)
        preview_layout.addLayout(form)
        preview_layout.addStretch(1)
        preview_scroll.setWidget(preview_body)

        splitter.addWidget(source_frame)
        splitter.addWidget(preview_scroll)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([620, 620])
        card.addWidget(splitter, 1)

        options = QGridLayout()
        options.addWidget(QLabel("Адрес офиса"), 0, 0)
        self.address_combo = QComboBox()
        self.address_combo.setEditable(True)
        self.address_combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.address_combo.setToolTip(
            "Выберите сохранённый адрес офиса или отредактируйте его вручную для текущего пользователя"
        )
        self.refresh_addresses()
        options.addWidget(self.address_combo, 1, 0)
        address_hint = QLabel(
            "Адрес можно изменить прямо здесь. Город, индекс и страна подставляются автоматически "
            "только для адресов, сохранённых в настройках."
        )
        address_hint.setObjectName("Muted")
        address_hint.setWordWrap(True)
        options.addWidget(address_hint, 2, 0)
        self.domain_frame = QFrame()
        self.domain_layout = QHBoxLayout(self.domain_frame)
        self.domain_layout.setContentsMargins(0, 0, 0, 0)
        self.domain_checks: dict[str, QCheckBox] = {}
        self.refresh_domains()
        options.addWidget(QLabel("Домены"), 0, 1)
        options.addWidget(self.domain_frame, 1, 1)
        card.addLayout(options)

        self.request_text.textChanged.connect(self._update_request_preview)
        layout.addWidget(frame, 1)
        return page

    def _build_plan_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)
        frame, card = self._card()
        title = QLabel("2. План изменений в Active Directory")
        title.setObjectName("CardTitle")
        card.addWidget(title)
        self.plan_summary = QLabel("План ещё не сформирован")
        self.plan_summary.setWordWrap(True)
        self.plan_summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        card.addWidget(self.plan_summary)

        # Таблица из шести колонок обрезала Department, Manager и длинный DN OU.
        # Для двух доменов гораздо удобнее вертикальные карточки: каждое значение
        # получает всю доступную ширину и переносится на несколько строк.
        self.plan_scroll = QScrollArea()
        self.plan_scroll.setWidgetResizable(True)
        self.plan_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.plan_body = QWidget()
        self.plan_cards_layout = QVBoxLayout(self.plan_body)
        self.plan_cards_layout.setContentsMargins(0, 4, 0, 4)
        self.plan_cards_layout.setSpacing(12)
        self.plan_cards_layout.addStretch(1)
        self.plan_scroll.setWidget(self.plan_body)
        card.addWidget(self.plan_scroll, 1)

        self.warnings_label = QLabel()
        self.warnings_label.setWordWrap(True)
        self.warnings_label.setObjectName("Muted")
        self.warnings_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        card.addWidget(self.warnings_label)
        layout.addWidget(frame, 1)
        return page

    def _build_execute_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 8, 0, 0)
        frame, card = self._card()
        title = QLabel("3. Выполнение")
        title.setObjectName("CardTitle")
        card.addWidget(title)
        self.execute_summary = QLabel("После запуска здесь появится результат по каждому домену.")
        self.execute_summary.setWordWrap(True)
        card.addWidget(self.execute_summary)
        options = QHBoxLayout()
        self.create_welcome = QCheckBox("Создать приветственный документ")
        self.create_welcome.setChecked(True)
        self.print_welcome = QCheckBox("Отправить на печать")
        self.dry_run = QCheckBox("Проверка без изменений")
        self.duplicate_confirm = QCheckBox("Совпадения ФИО проверены — это новый сотрудник")
        self.duplicate_confirm.hide()
        options.addWidget(self.create_welcome)
        options.addWidget(self.print_welcome)
        options.addWidget(self.dry_run)
        options.addStretch(1)
        card.addLayout(options)
        card.addWidget(self.duplicate_confirm)
        self.result_table = QTableWidget(0, 3)
        self.result_table.setHorizontalHeaderLabels(["Шаг", "Статус", "Сообщение"])
        self.result_table.horizontalHeader().setStretchLastSection(True)
        card.addWidget(self.result_table, 1)
        self.run_button = QPushButton("Создать пользователя")
        self.run_button.setObjectName("Primary")
        self.run_button.clicked.connect(self.execute)
        card.addWidget(self.run_button, 0, Qt.AlignmentFlag.AlignRight)
        layout.addWidget(frame, 1)
        return page

    def _addresses_changed(self) -> None:
        self.refresh_addresses(use_default=True)

    def refresh_addresses(self, use_default: bool = False) -> None:
        if not hasattr(self, "address_combo"):
            return
        current = self.address_combo.currentText().strip()
        addresses = [item["address"] for item in self.context.settings.office_addresses()]
        self.address_combo.blockSignals(True)
        try:
            self.address_combo.clear()
            self.address_combo.addItems(addresses)
            target = self.context.settings.default_address() if use_default else (current or self.context.settings.default_address())
            match_index = self.address_combo.findText(target, Qt.MatchFlag.MatchFixedString)
            if match_index >= 0:
                self.address_combo.setCurrentIndex(match_index)
            else:
                self.address_combo.setEditText(target)
        finally:
            self.address_combo.blockSignals(False)

    def refresh_domains(self) -> None:
        if not hasattr(self, "domain_layout"):
            return
        if self.plan is not None:
            self.plan = None
            if hasattr(self, "stack"):
                self.stack.setCurrentIndex(0)
                self._sync_navigation()
        previous = {name: check.isChecked() for name, check in self.domain_checks.items()}
        while self.domain_layout.count():
            item = self.domain_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self.domain_checks = {}
        for domain in self.context.ad.domains:
            check = QCheckBox(domain.label)
            check.setChecked(previous.get(domain.name, True))
            self.domain_checks[domain.name] = check
            self.domain_layout.addWidget(check)
        self.domain_layout.addStretch(1)

    def selected_domains(self) -> list[str]:
        return [name for name, check in self.domain_checks.items() if check.isChecked()]

    def next(self) -> None:
        index = self.stack.currentIndex()
        if index == 0:
            # Карточка справа является источником истины: оператор может
            # исправить распознанные значения до обращения к AD.
            self.request = self._collect_request()
            errors = validation_errors(self.request)
            if errors:
                QMessageBox.warning(self, "Заявка", "\n".join(errors))
                return
            if not self.selected_domains():
                QMessageBox.warning(self, "Домены", "Выберите хотя бы один домен")
                return
            self._build_plan_async()
            return
        if index == 1:
            self._apply_edited_ous()
            self._populate_execute_summary()
            self.stack.setCurrentIndex(2)
        self._sync_navigation()

    def back(self) -> None:
        index = self.stack.currentIndex()
        if index > 0:
            self.stack.setCurrentIndex(index - 1)
        self._sync_navigation()

    def load_external_payload(self, payload: dict[str, object]) -> None:
        """Открывает мастер из GLPI и запоминает одноразовый callback."""
        self.reset()
        self._external_callback_url = str(payload.get("callback_url") or "").strip()
        self._external_source_url = str(payload.get("source_url") or "").strip()
        try:
            self._external_ticket_id = int(payload.get("ticket_id") or 0) or None
        except (TypeError, ValueError):
            self._external_ticket_id = None

        ticket_title = str(payload.get("ticket_title") or "").strip()
        if self._external_ticket_id:
            title = f"Получено из GLPI: заявка #{self._external_ticket_id}"
            if ticket_title:
                title += f" — {ticket_title}"
            self.external_source_label.setText(title)
            self.external_source_label.show()

        self.request_text.setPlainText(str(payload.get("request_text") or ""))
        self.request_text.setFocus()

    def _update_request_preview(self) -> None:
        text = self.request_text.toPlainText()
        self.request = parse_request(text)
        recognized = extract_request_fields(text)
        self._populate_details()
        missing = validation_errors(self.request)
        if not text.strip():
            self.preview_status.setText("Вставьте текст заявки слева")
        elif missing:
            self.preview_status.setText(
                f"Распознано полей: {len(recognized)}. Не найдено: "
                + ", ".join(item.replace("Не указана ", "") for item in missing)
                + ". Проверьте формат или заполните карточку вручную."
            )
        else:
            self.preview_status.setText(
                f"Распознано полей: {len(recognized)}. Фамилия и имя найдены — карточку можно проверить и продолжить."
            )

    def _update_full_name_from_card(self, _text: str = "") -> None:
        if not hasattr(self, "full_name_preview"):
            return
        display_name = " ".join(
            self.field_edits[key].text().strip()
            for key in ("last_name", "first_name", "middle_name")
            if key in self.field_edits and self.field_edits[key].text().strip()
        )
        self.full_name_preview.setText(display_name)

    def _populate_details(self) -> None:
        for key, _label in self.FIELDS:
            self.field_edits[key].setText(str(getattr(self.request, key)))
        self.has_photo.setChecked(self.request.has_photo)
        self.need_mail.setChecked(self.request.need_mail)
        self.need_internal_phone.setChecked(self.request.need_internal_phone)
        self.need_servers_access.setChecked(self.request.need_servers_access)
        self.need_folders_access.setChecked(self.request.need_folders_access)

    def _collect_request(self) -> ParsedRequest:
        values: dict[str, Any] = self.request.to_dict()
        for key, _label in self.FIELDS:
            values[key] = self.field_edits[key].text().strip()
        values.update({
            "has_photo": self.has_photo.isChecked(),
            "need_mail": self.need_mail.isChecked(),
            "need_internal_phone": self.need_internal_phone.isChecked(),
            "need_servers_access": self.need_servers_access.isChecked(),
            "need_folders_access": self.need_folders_access.isChecked(),
        })
        return ParsedRequest(**values)

    def _build_plan_async(self) -> None:
        try:
            password = self.context.settings.get_default_password()
        except Exception as exc:
            QMessageBox.critical(self, "Пароль", f"Не удалось прочитать пароль: {exc}")
            return
        if not password:
            QMessageBox.warning(self, "Пароль", "Сначала задайте пароль в разделе «Настройки»")
            return

        selected_domains = self.selected_domains()
        address = self.address_combo.currentText().strip()
        if not address:
            QMessageBox.warning(self, "Адрес офиса", "Укажите адрес офиса")
            return
        self._plan_progress_current = 0
        self._plan_progress_total = len(selected_domains) + 3
        self._set_busy(
            True,
            "Подготавливаем проверку заявки в Active Directory…",
            total_steps=self._plan_progress_total,
        )
        worker = FunctionWorker(
            self.context.onboarding.build_plan,
            self.request,
            selected_domains,
            address,
            password,
            self.context.settings.address_details(address),
        )
        self._track_worker(worker)
        worker.signals.progress.connect(self._plan_progress)
        worker.signals.result.connect(self._plan_ready)
        worker.signals.error.connect(self._worker_error)
        self.pool.start(worker)

    def _plan_progress(self, _key: str, message: str) -> None:
        self._plan_progress_current = min(
            self._plan_progress_current + 1,
            max(1, self._plan_progress_total),
        )
        self.busy.set_step(self._plan_progress_current, self._plan_progress_total)
        self.steps_label.setText(message)

    def _clear_plan_cards(self) -> None:
        while self.plan_cards_layout.count():
            layout_item = self.plan_cards_layout.takeAt(0)
            widget = layout_item.widget()
            if widget is not None:
                widget.deleteLater()

    @staticmethod
    def _selectable_value(text: str) -> QLabel:
        label = QLabel(text or "—")
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        label.setMinimumWidth(0)
        return label

    def _add_plan_row(self, layout: QGridLayout, row: int, caption: str, widget: QWidget) -> None:
        caption_label = QLabel(caption)
        caption_label.setObjectName("Muted")
        caption_label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(caption_label, row, 0)
        layout.addWidget(widget, row, 1)

    def _plan_ready(self, plan: object) -> None:
        try:
            if not isinstance(plan, OnboardingPlan):
                QMessageBox.critical(self, "План", "Сервис вернул неизвестный формат плана")
                return
            self.plan = plan
            self.plan_summary.setText(
                f"Сотрудник: <b>{plan.request.display_name}</b><br>"
                f"Логин: <b>{plan.sam}</b><br>"
                f"Адрес офиса: <b>{plan.address}</b><br>"
                f"Будет создан в доменах: {', '.join(item.domain.label for item in plan.domains)}"
            )
            self._clear_plan_cards()
            self.ou_edits.clear()
            self.manager_edits.clear()
            warnings: list[str] = []

            for item in plan.domains:
                domain_frame = QFrame()
                domain_frame.setObjectName("InsetCard")
                domain_frame.setFrameShape(QFrame.Shape.StyledPanel)
                domain_layout = QGridLayout(domain_frame)
                domain_layout.setContentsMargins(16, 14, 16, 14)
                domain_layout.setHorizontalSpacing(16)
                domain_layout.setVerticalSpacing(9)
                domain_layout.setColumnMinimumWidth(0, 125)
                domain_layout.setColumnStretch(1, 1)

                domain_title = QLabel(f"<b>{item.domain.label}</b>")
                domain_title.setObjectName("CardTitle")
                domain_layout.addWidget(domain_title, 0, 0, 1, 2)
                self._add_plan_row(
                    domain_layout, 1, "UPN",
                    self._selectable_value(plan.sam + item.domain.upn_suffix),
                )
                self._add_plan_row(
                    domain_layout, 2, "Department",
                    self._selectable_value(item.department),
                )
                self._add_plan_row(
                    domain_layout, 3, "Section",
                    self._selectable_value(item.section or "—"),
                )
                if item.division:
                    self._add_plan_row(
                        domain_layout, 4, "Division",
                        self._selectable_value(item.division),
                    )
                    manager_row = 5
                else:
                    manager_row = 4

                manager_widget = QWidget()
                manager_layout = QHBoxLayout(manager_widget)
                manager_layout.setContentsMargins(0, 0, 0, 0)
                manager_edit = QLineEdit(item.manager_name or "не назначен")
                manager_edit.setReadOnly(True)
                manager_edit.setToolTip(item.manager_name or "Руководитель не назначен")
                manager_button = QPushButton("Выбрать…")
                manager_button.setEnabled(bool(item.manager_candidates))
                manager_button.clicked.connect(
                    lambda checked=False, name=item.domain.name: self._choose_manager(name)
                )
                manager_layout.addWidget(manager_edit, 1)
                manager_layout.addWidget(manager_button)
                self._add_plan_row(domain_layout, manager_row, "Руководитель", manager_widget)
                self.manager_edits[item.domain.name] = manager_edit

                ou_edit = QTextEdit()
                ou_edit.setAcceptRichText(False)
                ou_edit.setPlainText(item.target_ou)
                ou_edit.setPlaceholderText("Distinguished Name целевого OU")
                ou_edit.setMinimumHeight(58)
                ou_edit.setMaximumHeight(78)
                ou_edit.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
                ou_edit.setToolTip(item.target_ou)
                ou_button = QPushButton("Выбрать OU…")
                ou_button.setEnabled(bool(item.ou_candidates))
                ou_button.clicked.connect(
                    lambda checked=False, name=item.domain.name: self._choose_ou(name)
                )
                ou_widget = QWidget()
                ou_layout = QVBoxLayout(ou_widget)
                ou_layout.setContentsMargins(0, 0, 0, 0)
                ou_layout.setSpacing(6)
                ou_layout.addWidget(ou_edit)
                ou_layout.addWidget(ou_button, 0, Qt.AlignmentFlag.AlignRight)
                self._add_plan_row(domain_layout, manager_row + 1, "Целевой OU", ou_widget)
                self.ou_edits[item.domain.name] = ou_edit

                self.plan_cards_layout.addWidget(domain_frame)
                warnings.extend(f"{item.domain.label}: {warning}" for warning in item.warnings)

            self.plan_cards_layout.addStretch(1)
            if plan.duplicate_users:
                duplicate_text = '; '.join(
                    f"{item.get('display_name')} · {item.get('sam')} · {item.get('domain')}"
                    for item in plan.duplicate_users
                )
                warnings.append('Найдены пользователи с таким же ФИО: ' + duplicate_text)
            self.warnings_label.setText(
                "⚠ " + "\n⚠ ".join(warnings)
                if warnings else "Все обязательные проверки пройдены."
            )
            self.stack.setCurrentIndex(1)
        finally:
            # Не полагаемся только на finished-сигнал QRunnable: на некоторых
            # сборках PySide6 объект QRunnable успевал автоудалиться, и экран
            # оставался в состоянии busy при уже отрисованном плане.
            self._set_busy(False)
            self._sync_navigation()


    def _domain_plan(self, domain_name: str):
        if not self.plan:
            return None
        return next((item for item in self.plan.domains if item.domain.name == domain_name), None)

    def _choose_manager(self, domain_name: str) -> None:
        item = self._domain_plan(domain_name)
        if not item or not item.manager_candidates:
            return
        dialog = SelectionDialog(
            f"Выбор руководителя · {item.domain.label}",
            item.manager_candidates,
            [("display_name", "ФИО"), ("sam", "Логин"), ("department", "Отдел"), ("dn", "DN")],
            self,
        )
        if dialog.exec() and dialog.selected_row:
            item.manager_name = str(dialog.selected_row.get("display_name") or "")
            item.manager_dn = str(dialog.selected_row.get("dn") or "")
            self.manager_edits[domain_name].setText(item.manager_name or "не назначен")

    def _choose_ou(self, domain_name: str) -> None:
        item = self._domain_plan(domain_name)
        if not item or not item.ou_candidates:
            return
        dialog = SelectionDialog(
            f"Выбор OU · {item.domain.label}",
            item.ou_candidates,
            [("name", "OU"), ("score", "Совпадение"), ("dn", "Distinguished Name")],
            self,
        )
        if dialog.exec() and dialog.selected_row:
            selected_dn = str(dialog.selected_row.get("dn") or "")
            if selected_dn:
                item.target_ou = selected_dn
                self.ou_edits[domain_name].setPlainText(selected_dn)
                if self.request.department:
                    self.context.ou_resolver.remember(self.request.department, selected_dn)

    def _apply_edited_ous(self) -> None:
        if not self.plan:
            return
        for item in self.plan.domains:
            edit = self.ou_edits.get(item.domain.name)
            if edit and edit.toPlainText().strip():
                item.target_ou = edit.toPlainText().strip()

    def _populate_execute_summary(self) -> None:
        if not self.plan:
            return
        self.execute_summary.setText(
            f"Будет создан <b>{self.plan.request.display_name}</b> с логином <b>{self.plan.sam}</b>. "
            "Перед выполнением ещё раз проверьте домены и OU."
        )
        self.result_table.setRowCount(0)
        self.duplicate_confirm.setVisible(bool(self.plan.duplicate_users))
        self.duplicate_confirm.setChecked(False)

    def execute(self) -> None:
        if not self.plan:
            return
        self.plan.create_welcome = self.create_welcome.isChecked()
        self.plan.print_welcome = self.print_welcome.isChecked()
        dry = self.dry_run.isChecked()
        if self.plan.duplicate_users and not self.duplicate_confirm.isChecked():
            QMessageBox.warning(self, "Совпадение ФИО", "Найдены существующие пользователи с таким же ФИО. Проверьте совпадения и подтвердите, что создаётся другой сотрудник.")
            return
        if not dry:
            answer = QMessageBox.question(
                self,
                "Подтверждение",
                f"Создать пользователя {self.plan.request.display_name}\n"
                f"с логином {self.plan.sam} в {len(self.plan.domains)} домен(ах)?",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self._set_busy(True, "Выполнение операции…")
        self.run_button.setEnabled(False)
        worker = FunctionWorker(self.context.onboarding.execute, self.plan, dry_run=dry)
        self._track_worker(worker)
        worker.signals.progress.connect(lambda _key, message: self.execute_summary.setText(message))
        worker.signals.result.connect(self._execution_ready)
        worker.signals.error.connect(self._worker_error)
        self.pool.start(worker)

    def _execution_ready(self, operation: object) -> None:
        self._set_busy(False)
        self.run_button.setEnabled(True)
        self.context.events.operations_changed.emit()
        steps = getattr(operation, "steps", [])
        self.result_table.setRowCount(len(steps))
        for row, step in enumerate(steps):
            for column, value in enumerate((step.title, step.status, step.message)):
                self.result_table.setItem(row, column, QTableWidgetItem(str(value)))
        status = getattr(operation, "status", "unknown")
        warnings = getattr(operation, "warnings", [])
        errors = getattr(operation, "errors", [])
        self.execute_summary.setText(
            f"Операция завершена: <b>{status}</b>. "
            f"Предупреждений: {len(warnings)}, ошибок: {len(errors)}."
        )
        if status in ("success", "simulated"):
            QMessageBox.information(self, "Готово", "Операция успешно завершена")
            if status == "success" and self._external_callback_url:
                callback_url = self._external_callback_url
                # Callback одноразовый: повторные сигналы/клики не должны создавать
                # вторую заявку. GLPI дополнительно обеспечивает идемпотентность.
                self._external_callback_url = ""
                if not QDesktopServices.openUrl(QUrl(callback_url)):
                    self._external_callback_url = callback_url
                    QMessageBox.warning(
                        self,
                        "GLPI",
                        "Пользователь создан, но не удалось открыть GLPI для создания связанной заявки. "
                        "Откройте исходную заявку и повторите автоматизацию — повторное создание пользователя не запускайте.",
                    )
        else:
            QMessageBox.warning(self, "Результат", "Операция завершена с предупреждениями или ошибками")

    def _track_worker(self, worker: FunctionWorker) -> None:
        # Явная ссылка не даёт Python-обёртке QRunnable исчезнуть до доставки
        # queued-сигналов result/error/finished в GUI-поток.
        self._active_workers.append(worker)
        worker.signals.finished.connect(lambda current=worker: self._worker_finished(current))

    def _worker_finished(self, worker: FunctionWorker) -> None:
        if worker in self._active_workers:
            self._active_workers.remove(worker)
        # result/error обычно уже сняли busy. Это страховка на случай, когда
        # обработчик результата не был вызван или завершился исключением.
        if not self._active_workers and self._busy_state:
            self._set_busy(False)
        if hasattr(self, "run_button"):
            self.run_button.setEnabled(True)

    def _worker_error(self, message: str, trace: str) -> None:
        self._set_busy(False)
        if hasattr(self, "run_button"):
            self.run_button.setEnabled(True)
        self.context.events.log_message.emit(trace)
        QMessageBox.critical(self, "Ошибка", message)

    def _set_busy(self, busy: bool, message: str = "", total_steps: int | None = None) -> None:
        self._busy_state = busy
        if busy:
            if total_steps is not None:
                self.busy.start_steps(total_steps)
            else:
                self.busy.start_indeterminate()
            self.back_button.setEnabled(False)
            self.next_button.setEnabled(False)
            if message:
                self.steps_label.setText(message)
            return

        self.busy.stop()
        self._sync_navigation()

    def _sync_navigation(self) -> None:
        index = self.stack.currentIndex()
        labels = ["1  Заявка и карточка", "2  План AD", "3  Выполнение"]
        self.steps_label.setText("   →   ".join(f"<b>{label}</b>" if idx == index else label for idx, label in enumerate(labels)))
        self.back_button.setEnabled(index > 0 and not self._busy_state)
        self.next_button.setVisible(index < 2)
        self.next_button.setEnabled(not self._busy_state)
        self.next_button.setText("Сформировать план →" if index == 0 else "Далее →")

    def reset(self) -> None:
        self.request_text.clear()
        self.request = ParsedRequest()
        self.plan = None
        self._external_callback_url = ""
        self._external_source_url = ""
        self._external_ticket_id = None
        if hasattr(self, "external_source_label"):
            self.external_source_label.clear()
            self.external_source_label.hide()
        self.result_table.setRowCount(0)
        self.stack.setCurrentIndex(0)
        self._sync_navigation()
