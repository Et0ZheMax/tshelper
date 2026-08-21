from __future__ import annotations

from typing import Any

from PySide6.QtCore import QThreadPool, Qt
from PySide6.QtWidgets import (
    QComboBox, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPlainTextEdit, QPushButton, QSplitter, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from ...context import AppContext
from ...models import UserRecord
from ...services.access_management import (
    ACCESS_ANY, ACCESS_READ, ACCESS_WRITE, GroupMatch, ParsedAccessRequest,
    infer_access_mode, parse_access_request,
)
from ...workers import FunctionWorker
from ..widgets import BusyBar, PageHeader


class AccessPage(QWidget):
    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.context = context
        self.pool = QThreadPool.globalInstance()
        self.parsed = ParsedAccessRequest()
        self.matches: list[GroupMatch] = []
        self.users: list[UserRecord] = []
        self._group_worker: FunctionWorker | None = None
        self._user_worker: FunctionWorker | None = None
        self._add_worker: FunctionWorker | None = None
        self._busy_jobs = 0

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.addWidget(PageHeader(
            "Доступы",
            "Умный поиск групп по заявке, пути, Description/Info и ACL ресурса. Добавление выполняется только после подтверждения.",
        ))
        self.busy = BusyBar()
        root.addWidget(self.busy)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self._build_request_card())
        splitter.addWidget(self._build_search_card())
        splitter.setSizes([290, 520])
        root.addWidget(splitter, 1)

        self.context.events.domains_changed.connect(self._refresh_domain_combo)
        self._refresh_domain_combo()
        self._update_cache_status()

    def _build_request_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 18, 18, 18)

        title_row = QHBoxLayout()
        title = QLabel("Заявка GLPI")
        title.setObjectName("CardTitle")
        title_row.addWidget(title)
        title_row.addStretch(1)
        parse_button = QPushButton("✨ Разобрать заявку")
        parse_button.setObjectName("Primary")
        parse_button.clicked.connect(self._parse_request)
        title_row.addWidget(parse_button)
        clear_button = QPushButton("Очистить")
        clear_button.clicked.connect(self._clear_request)
        title_row.addWidget(clear_button)
        layout.addLayout(title_row)

        self.request_text = QPlainTextEdit()
        self.request_text.setPlaceholderText(
            "Вставьте текст заявки целиком. ADHelper попробует определить сотрудника, путь и тип доступа."
        )
        self.request_text.setMaximumHeight(150)
        layout.addWidget(self.request_text)

        summary = QGridLayout()
        self.person_label = QLabel("—")
        self.path_label = QLabel("—")
        self.path_label.setWordWrap(True)
        self.file_label = QLabel("—")
        self.file_label.setWordWrap(True)
        self.mode_label = QLabel("—")
        summary.addWidget(QLabel("Сотрудник"), 0, 0)
        summary.addWidget(self.person_label, 0, 1)
        summary.addWidget(QLabel("Путь"), 1, 0)
        summary.addWidget(self.path_label, 1, 1)
        summary.addWidget(QLabel("Файл"), 2, 0)
        summary.addWidget(self.file_label, 2, 1)
        summary.addWidget(QLabel("Тип доступа"), 3, 0)
        summary.addWidget(self.mode_label, 3, 1)
        summary.setColumnStretch(1, 1)
        layout.addLayout(summary)
        return card

    def _build_search_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 18, 18, 18)

        controls = QHBoxLayout()
        self.domain_combo = QComboBox()
        self.domain_combo.setMinimumWidth(170)
        self.domain_combo.currentIndexChanged.connect(self._domain_changed)
        controls.addWidget(self.domain_combo)

        self.group_query = QLineEdit()
        self.group_query.setPlaceholderText("Путь, название ресурса или ключевые слова")
        self.group_query.returnPressed.connect(self.search_groups)
        controls.addWidget(self.group_query, 1)

        self.mode_combo = QComboBox()
        self.mode_combo.addItem("Авто", "auto")
        self.mode_combo.addItem("👁 Чтение (RO)", ACCESS_READ)
        self.mode_combo.addItem("✏ Запись (RW)", ACCESS_WRITE)
        self.mode_combo.addItem("Любой", ACCESS_ANY)
        controls.addWidget(self.mode_combo)

        self.search_button = QPushButton("Найти")
        self.search_button.setObjectName("Primary")
        self.search_button.clicked.connect(self.search_groups)
        controls.addWidget(self.search_button)

        self.refresh_button = QPushButton("↻ Из AD")
        self.refresh_button.setToolTip("Перечитать группы из настроенного OU групп доступа")
        self.refresh_button.clicked.connect(self.refresh_groups)
        controls.addWidget(self.refresh_button)
        layout.addLayout(controls)

        self.cache_status = QLabel()
        self.cache_status.setObjectName("Muted")
        layout.addWidget(self.cache_status)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Совпадение", "Группа", "Доступ", "Описание", "Почему"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._group_selected)
        layout.addWidget(self.table, 1)

        lower = QSplitter(Qt.Orientation.Horizontal)
        lower.addWidget(self._build_group_details())
        lower.addWidget(self._build_user_card())
        lower.setSizes([650, 650])
        layout.addWidget(lower)
        return card

    def _build_group_details(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("InsetCard")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 14, 14, 14)
        title = QLabel("Выбранная группа")
        title.setObjectName("CardTitle")
        layout.addWidget(title)
        self.group_title = QLabel("Группа не выбрана")
        self.group_title.setWordWrap(True)
        layout.addWidget(self.group_title)
        self.group_details = QLabel("Выберите строку в таблице, чтобы увидеть DN, Info и объяснение рейтинга.")
        self.group_details.setObjectName("Muted")
        self.group_details.setWordWrap(True)
        self.group_details.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.group_details)
        return frame

    def _build_user_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("InsetCard")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 14, 14, 14)
        title = QLabel("Сотрудник")
        title.setObjectName("CardTitle")
        layout.addWidget(title)

        row = QHBoxLayout()
        self.user_query = QLineEdit()
        self.user_query.setPlaceholderText("ФИО или логин")
        self.user_query.returnPressed.connect(self.search_users)
        row.addWidget(self.user_query, 1)
        self.user_search_button = QPushButton("Найти")
        self.user_search_button.clicked.connect(self.search_users)
        row.addWidget(self.user_search_button)
        layout.addLayout(row)

        self.user_combo = QComboBox()
        self.user_combo.currentIndexChanged.connect(self._user_selected)
        layout.addWidget(self.user_combo)
        self.user_status = QLabel("Сотрудник не выбран")
        self.user_status.setObjectName("Muted")
        self.user_status.setWordWrap(True)
        layout.addWidget(self.user_status)

        self.add_button = QPushButton("＋ Добавить в выбранную группу")
        self.add_button.setObjectName("Primary")
        self.add_button.setEnabled(False)
        self.add_button.clicked.connect(self.add_member)
        layout.addWidget(self.add_button)
        return frame

    def _refresh_domain_combo(self) -> None:
        current = self.domain_combo.currentData() if self.domain_combo.count() else ""
        self.domain_combo.blockSignals(True)
        self.domain_combo.clear()
        configured = self.context.access_management.configured_domains()
        for name in configured:
            domain = self.context.ad.domain_by_name.get(name)
            if domain:
                self.domain_combo.addItem(domain.label or domain.name, domain.name)
        self.domain_combo.blockSignals(False)
        if current:
            index = self.domain_combo.findData(current)
            if index >= 0:
                self.domain_combo.setCurrentIndex(index)
        if self.domain_combo.count() == 0:
            self.cache_status.setText("В Настройки → Домены задайте «OU групп доступа».")
            self.search_button.setEnabled(False)
            self.refresh_button.setEnabled(False)
        else:
            self.search_button.setEnabled(True)
            self.refresh_button.setEnabled(True)

    def _domain_name(self) -> str:
        return str(self.domain_combo.currentData() or "")

    def _domain_changed(self, _index: int = -1) -> None:
        self.matches = []
        self.table.setRowCount(0)
        self.users = []
        self.user_combo.clear()
        self._update_cache_status()
        self._update_add_button()

    def _update_cache_status(self, suffix: str = "") -> None:
        domain = self._domain_name()
        if not domain:
            return
        count = len(self.context.access_management.groups(domain))
        updated = self.context.access_management.updated_at(domain)
        updated_short = updated.replace("T", " ")[:19] if updated else ""
        text = f"Локальный индекс: {count} групп" if count else "Локальный индекс пуст — при первом поиске группы будут загружены из AD"
        if count and updated_short:
            text += f" · обновлён {updated_short}"
        if suffix:
            text += f" · {suffix}"
        self.cache_status.setText(text)

    def _parse_request(self) -> None:
        text = self.request_text.toPlainText().strip()
        if not text:
            QMessageBox.information(self, "Доступы", "Вставьте текст заявки")
            return
        self.parsed = parse_access_request(text)
        self.person_label.setText(self.parsed.person_text or "не определён")
        self.path_label.setText(self.parsed.path or "не определён")
        self.file_label.setText(self.parsed.file_name or "не указан")
        self.mode_label.setText(self._mode_text(self.parsed.access_mode))

        if self.parsed.search_text:
            self.group_query.setText(self.parsed.path or self.parsed.file_name or self.parsed.search_text)
        self.mode_combo.setCurrentIndex(0)
        if self.parsed.person_search:
            self.user_query.setText(self.parsed.person_search)
            self.search_users()
        self.search_groups()

    def _clear_request(self) -> None:
        self.request_text.clear()
        self.parsed = ParsedAccessRequest()
        self.person_label.setText("—")
        self.path_label.setText("—")
        self.file_label.setText("—")
        self.mode_label.setText("—")

    @staticmethod
    def _mode_text(mode: str) -> str:
        if mode == ACCESS_READ:
            return "Только чтение (RO)"
        if mode == ACCESS_WRITE:
            return "Чтение / запись (RW)"
        return "Не определён"

    def _desired_mode(self) -> str:
        selected = str(self.mode_combo.currentData() or "auto")
        if selected != "auto":
            return selected
        if self.parsed.access_mode in {ACCESS_READ, ACCESS_WRITE}:
            return self.parsed.access_mode
        return infer_access_mode(self.group_query.text())

    def refresh_groups(self) -> None:
        domain = self._domain_name()
        if not domain or self._group_worker is not None:
            return
        self._start_busy()
        self.refresh_button.setEnabled(False)
        worker = FunctionWorker(self.context.access_management.refresh_groups, domain)
        self._group_worker = worker
        worker.signals.progress.connect(lambda _key, message: self._update_cache_status(message))
        worker.signals.result.connect(self._refresh_ready)
        worker.signals.error.connect(self._error)
        worker.signals.finished.connect(self._group_finished)
        self.pool.start(worker)

    def _refresh_ready(self, groups: object) -> None:
        count = len(groups) if isinstance(groups, list) else 0
        self._update_cache_status(f"обновлено из AD: {count}")
        if self.group_query.text().strip():
            # После finished worker будет освобождён; поиск ставим в очередь GUI.
            from PySide6.QtCore import QTimer
            QTimer.singleShot(0, self.search_groups)

    def search_groups(self) -> None:
        domain = self._domain_name()
        query = self.group_query.text().strip()
        if not domain:
            QMessageBox.warning(self, "Доступы", "Не настроен OU групп доступа ни для одного домена")
            return
        if not query:
            QMessageBox.information(self, "Поиск групп", "Введите путь, название ресурса или ключевые слова")
            return
        if self._group_worker is not None:
            return
        self._start_busy()
        self.search_button.setEnabled(False)
        resource_path = self.parsed.path
        desired = self._desired_mode()
        worker = FunctionWorker(
            self.context.access_management.search,
            domain,
            query,
            desired,
            resource_path=resource_path,
            refresh_if_empty=True,
            inspect_acl=bool(resource_path),
        )
        self._group_worker = worker
        worker.signals.progress.connect(lambda _key, message: self._update_cache_status(message))
        worker.signals.result.connect(self._groups_ready)
        worker.signals.error.connect(self._error)
        worker.signals.finished.connect(self._group_finished)
        self.pool.start(worker)

    def _groups_ready(self, result: object) -> None:
        if not isinstance(result, tuple) or len(result) != 3:
            self.matches = []
            self.table.setRowCount(0)
            return
        matches, acl_entries, total = result
        self.matches = list(matches) if isinstance(matches, list) else []
        self.table.setRowCount(len(self.matches))
        for row, match in enumerate(self.matches):
            access = "RO" if match.access_mode == ACCESS_READ else "RW" if match.access_mode == ACCESS_WRITE else "—"
            values = [
                f"{match.score}%",
                match.group.sam or match.group.name,
                access,
                match.group.description or match.group.info,
                " · ".join(match.reasons),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, column, item)
        acl_count = len(acl_entries) if isinstance(acl_entries, list) else 0
        suffix = f"поиск по {total} группам, найдено {len(self.matches)}"
        if self.parsed.path:
            suffix += f", ACL: {acl_count} записей" if acl_count else ", ACL недоступен/пуст"
        self._update_cache_status(suffix)
        if self.matches:
            self.table.selectRow(0)
        else:
            self.group_title.setText("Ничего не найдено")
            self.group_details.setText("Попробуйте сократить запрос или выбрать режим «Любой».")
        self._update_add_button()

    def _group_selected(self) -> None:
        match = self._selected_match()
        if match is None:
            self.group_title.setText("Группа не выбрана")
            self.group_details.setText("Выберите строку в таблице.")
            self._update_add_button()
            return
        self.group_title.setText(f"{match.group.sam or match.group.name} · {match.score}%")
        details = [
            f"Тип: {self._mode_text(match.access_mode) if match.access_mode != ACCESS_ANY else 'не определён'}",
            f"Description: {match.group.description or '—'}",
            f"Info: {match.group.info or '—'}",
            f"DN: {match.group.dn or '—'}",
            f"Почему: {'; '.join(match.reasons) or 'совпадение по тексту'}",
        ]
        if match.acl_rights:
            details.append(f"ACL: {match.acl_rights}")
        self.group_details.setText("\n".join(details))
        self._update_add_button()

    def _selected_match(self) -> GroupMatch | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        row = rows[0].row()
        return self.matches[row] if 0 <= row < len(self.matches) else None

    def search_users(self) -> None:
        query = self.user_query.text().strip()
        domain = self._domain_name()
        if not query or not domain or self._user_worker is not None:
            return
        self._start_busy()
        self.user_search_button.setEnabled(False)
        self.user_status.setText(f"Поиск «{query}»…")
        worker = FunctionWorker(self.context.ad.search_users, query, [domain], False)
        self._user_worker = worker
        worker.signals.result.connect(self._users_ready)
        worker.signals.error.connect(self._error)
        worker.signals.finished.connect(self._user_finished)
        self.pool.start(worker)

    def _users_ready(self, result: object) -> None:
        self.users = list(result) if isinstance(result, list) else []
        self.user_combo.blockSignals(True)
        self.user_combo.clear()
        for user in self.users:
            label = f"{user.display_name} · {user.sam}"
            if user.department:
                label += f" · {user.department}"
            self.user_combo.addItem(label)
        self.user_combo.blockSignals(False)
        if not self.users:
            self.user_status.setText("Сотрудник не найден. Уточните ФИО или логин.")
        else:
            self.user_combo.setCurrentIndex(0)
            self._user_selected()
        self._update_add_button()

    def _selected_user(self) -> UserRecord | None:
        index = self.user_combo.currentIndex()
        return self.users[index] if 0 <= index < len(self.users) else None

    def _user_selected(self, _index: int = -1) -> None:
        user = self._selected_user()
        if user is None:
            self.user_status.setText("Сотрудник не выбран")
        else:
            details = f"{user.display_name} ({user.sam}) · {user.domain}"
            if user.department:
                details += f" · {user.department}"
            self.user_status.setText(details)
        self._update_add_button()

    def _update_add_button(self) -> None:
        match = self._selected_match()
        user = self._selected_user()
        already_member = False
        if match is not None and user is not None and match.group.dn:
            group_dn = match.group.dn.casefold()
            already_member = any(str(dn).casefold() == group_dn for dn in user.member_of)
        if already_member:
            self.add_button.setText("✓ Уже состоит в выбранной группе")
            self.add_button.setEnabled(False)
            return
        self.add_button.setText("＋ Добавить в выбранную группу")
        self.add_button.setEnabled(match is not None and user is not None and self._add_worker is None)

    def add_member(self) -> None:
        user = self._selected_user()
        match = self._selected_match()
        if user is None or match is None or self._add_worker is not None:
            return
        group = match.group
        answer = QMessageBox.question(
            self,
            "Подтверждение доступа",
            f"Добавить пользователя в группу?\n\n"
            f"Сотрудник: {user.display_name}\n"
            f"Логин: {user.sam}\n"
            f"Группа: {group.sam or group.name}\n"
            f"Рейтинг: {match.score}%\n"
            f"Тип: {self._mode_text(match.access_mode) if match.access_mode != ACCESS_ANY else 'не определён'}\n\n"
            f"Description: {group.description or '—'}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._start_busy()
        self.add_button.setEnabled(False)
        worker = FunctionWorker(self.context.access_management.add_member, user, group)
        self._add_worker = worker
        worker.signals.result.connect(self._add_ready)
        worker.signals.error.connect(self._error)
        worker.signals.finished.connect(self._add_finished)
        self.pool.start(worker)

    def _add_ready(self, result: object) -> None:
        self.context.events.operations_changed.emit()
        data = getattr(result, "data", {})
        membership = data.get("membership") if isinstance(data, dict) else {}
        if isinstance(membership, dict) and membership.get("already_member") and not membership.get("changed"):
            QMessageBox.information(self, "Доступы", "Пользователь уже состоит в выбранной группе. Операция записана в аудит.")
        else:
            user = self._selected_user()
            match = self._selected_match()
            if user is not None and match is not None and match.group.dn:
                if not any(str(dn).casefold() == match.group.dn.casefold() for dn in user.member_of):
                    user.member_of.append(match.group.dn)
            QMessageBox.information(self, "Готово", "Пользователь добавлен в группу. Членство повторно проверено в AD и записано в аудит.")
        self._update_add_button()

    def _group_finished(self) -> None:
        self._group_worker = None
        self.search_button.setEnabled(bool(self._domain_name()))
        self.refresh_button.setEnabled(bool(self._domain_name()))
        self._finish_busy()

    def _user_finished(self) -> None:
        self._user_worker = None
        self.user_search_button.setEnabled(True)
        self._finish_busy()

    def _add_finished(self) -> None:
        self._add_worker = None
        self._finish_busy()
        self._update_add_button()

    def _start_busy(self) -> None:
        self._busy_jobs += 1
        self.busy.start_indeterminate()

    def _finish_busy(self) -> None:
        self._busy_jobs = max(0, self._busy_jobs - 1)
        if self._busy_jobs == 0:
            self.busy.stop()

    def _error(self, message: str, trace: str) -> None:
        self.context.logger.error("AccessPage error: %s\n%s", message, trace)
        QMessageBox.critical(self, "Доступы", message)
