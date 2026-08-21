from __future__ import annotations

from copy import deepcopy

from PySide6.QtCore import QThreadPool, Signal
from PySide6.QtWidgets import (
    QComboBox, QFormLayout, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPushButton, QScrollArea, QVBoxLayout, QWidget
)

from ...constants import DOMAIN_CONFIGS, OFFICE_ADDRESSES
from ...context import AppContext
from ...workers import FunctionWorker
from ..widgets import BusyBar, PageHeader


class SettingsPage(QWidget):
    theme_changed = Signal(str)

    ADDRESS_FIELDS = [
        ("address", "Адрес", "Улица, дом, строение — это значение попадёт в streetAddress"),
        ("pobox", "Абонентский ящик / PO Box", "Например Москва; можно оставить пустым"),
        ("city", "Город", "Например Москва"),
        ("state", "Регион", "Например Москва"),
        ("postal_code", "Почтовый индекс", "Например 123182"),
        ("country", "Код страны", "Двухбуквенный код, например RU"),
    ]

    DOMAIN_FIELDS = [
        ("name", "Идентификатор", "Уникальное внутреннее имя, например pak-cspmz"),
        ("label", "Название в интерфейсе", "Подпись домена в мастере создания"),
        ("netbios", "NetBIOS", "Например PAK-CSPMZ"),
        ("server", "Контроллер домена", "FQDN контроллера, например dc03.example.ru"),
        ("search_base", "Search Base", "Корень поиска, например DC=example,DC=ru"),
        ("ou_dn", "Базовый OU", "OU по умолчанию для создания и проверки"),
        ("upn_suffix", "UPN-суффикс", "Например @example.ru"),
        ("email_suffix", "Почтовый суффикс", "Например @mail.example.ru"),
        ("fired_ou_dn", "OU уволенных", "Можно оставить пустым, если отдельный OU не используется"),
        ("group_search_base", "OU групп доступа", "Например OU=Group,OU=csp,DC=example,DC=ru; пусто = модуль доступов отключён"),
    ]

    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.context = context
        self.pool = QThreadPool.globalInstance()
        self._loading_domain = False
        self._domain_drafts: list[dict[str, str]] = []
        self._loading_address = False
        self._address_drafts: list[dict[str, str]] = []
        self._preflight_worker: FunctionWorker | None = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        root = QVBoxLayout(content)
        root.setContentsMargins(28, 24, 28, 24)
        root.addWidget(PageHeader("Настройки", "Пароль, домены, адрес по умолчанию, тема и диагностика окружения."))
        self.busy = BusyBar()
        root.addWidget(self.busy)

        general = QFrame()
        general.setObjectName("Card")
        form = QFormLayout(general)
        form.setContentsMargins(18, 18, 18, 18)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Новый пароль по умолчанию")
        password_row = QHBoxLayout()
        password_row.addWidget(self.password, 1)
        save_password = QPushButton("Сохранить через DPAPI")
        save_password.clicked.connect(self._save_password)
        password_row.addWidget(save_password)
        self.password_status = QLabel("Задан" if context.settings.has_default_password() else "Не задан")
        password_row.addWidget(self.password_status)
        form.addRow("Пароль новых пользователей", password_row)

        self.address = QComboBox()
        self._refresh_default_address_combo()
        self.address.currentTextChanged.connect(self._default_address_changed)
        form.addRow("Адрес по умолчанию", self.address)

        self.theme = QComboBox()
        self.theme.addItems(["Тёмная", "Светлая"])
        stored_theme = str(context.settings.get("theme", "dark"))
        self.theme.setCurrentIndex(0 if stored_theme == "dark" else 1)
        self.theme.currentIndexChanged.connect(self._theme_changed)
        form.addRow("Тема", self.theme)

        paths = QLabel(
            f"Конфигурация: {context.settings.path}\n"
            f"Аудит: {context.settings.audit_dir}\n"
            f"Recovery: {context.settings.recovery_dir}\n"
            f"Логи: {context.settings.log_dir}"
        )
        paths.setObjectName("Muted")
        paths.setWordWrap(True)
        form.addRow("Локальные данные", paths)
        root.addWidget(general)

        root.addWidget(self._build_addresses_card())
        root.addWidget(self._build_domains_card())

        diagnostic = QFrame()
        diagnostic.setObjectName("Card")
        diagnostic_layout = QVBoxLayout(diagnostic)
        diagnostic_layout.setContentsMargins(18, 18, 18, 18)
        diagnostic_layout.addWidget(QLabel("Диагностика"))
        self.diagnostic_label = QLabel("Проверка ещё не выполнялась")
        self.diagnostic_label.setObjectName("Muted")
        self.diagnostic_label.setWordWrap(True)
        diagnostic_layout.addWidget(self.diagnostic_label)
        self.check_button = QPushButton("Проверить PowerShell, AD-модуль, контроллеры и OU")
        self.check_button.clicked.connect(self._preflight)
        diagnostic_layout.addWidget(self.check_button)
        root.addWidget(diagnostic)
        root.addStretch(1)

        scroll.setWidget(content)
        outer.addWidget(scroll)
        self._load_address_drafts(context.settings.office_addresses())
        self._load_domain_drafts(context.settings.domain_configs())

    def _refresh_default_address_combo(self, preferred: str = "") -> None:
        if not hasattr(self, "address"):
            return
        addresses = [item["address"] for item in self.context.settings.office_addresses()]
        target = preferred or self.context.settings.default_address()
        self.address.blockSignals(True)
        try:
            self.address.clear()
            self.address.addItems(addresses)
            index = self.address.findText(target)
            self.address.setCurrentIndex(index if index >= 0 else 0)
        finally:
            self.address.blockSignals(False)

    def _default_address_changed(self, value: str) -> None:
        clean = str(value or "").strip()
        if not clean:
            return
        try:
            self.context.settings.set_default_address(clean)
            self.context.reload_office_addresses()
        except ValueError:
            # Комбобокс заполняется только сохранёнными значениями. Эта ветка
            # защищает от краткого промежуточного сигнала при его обновлении.
            return

    def _build_addresses_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 18, 18, 18)

        title_row = QHBoxLayout()
        title = QLabel("Адреса офисов")
        title.setObjectName("CardTitle")
        title_row.addWidget(title)
        title_row.addStretch(1)
        self.address_select = QComboBox()
        self.address_select.setMinimumWidth(360)
        self.address_select.currentIndexChanged.connect(self._show_address)
        title_row.addWidget(self.address_select)
        add_button = QPushButton("＋ Добавить")
        add_button.clicked.connect(self._add_address)
        title_row.addWidget(add_button)
        delete_button = QPushButton("Удалить")
        delete_button.clicked.connect(self._delete_address)
        title_row.addWidget(delete_button)
        layout.addLayout(title_row)

        hint = QLabel(
            "Эти адреса появляются в выпадающем списке мастера создания. Поле адреса в мастере остаётся "
            "редактируемым: разовое изменение не добавляет новый адрес в настройки. Дополнительные поля ниже "
            "используются для атрибутов City, State, PostalCode, POBox и Country в AD."
        )
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        self.address_fields: dict[str, QLineEdit] = {}
        for row, (key, label, placeholder) in enumerate(self.ADDRESS_FIELDS):
            edit = QLineEdit()
            edit.setPlaceholderText(placeholder)
            edit.textChanged.connect(lambda value, field=key: self._address_field_changed(field, value))
            self.address_fields[key] = edit
            grid.addWidget(QLabel(label), row, 0)
            grid.addWidget(edit, row, 1)
        layout.addLayout(grid)

        buttons = QHBoxLayout()
        restore = QPushButton("Вернуть встроенные адреса")
        restore.clicked.connect(self._restore_addresses)
        buttons.addWidget(restore)
        buttons.addStretch(1)
        save = QPushButton("Сохранить адреса")
        save.setObjectName("Primary")
        save.clicked.connect(self._save_addresses)
        buttons.addWidget(save)
        layout.addLayout(buttons)
        return card

    def _address_title(self, item: dict[str, str], index: int) -> str:
        return item.get("address") or f"Новый адрес {index + 1}"

    def _load_address_drafts(self, values: list[dict[str, str]], selected: int = 0) -> None:
        self._address_drafts = [dict(item) for item in deepcopy(values)]
        self.address_select.blockSignals(True)
        self.address_select.clear()
        for index, item in enumerate(self._address_drafts):
            self.address_select.addItem(self._address_title(item, index))
        self.address_select.blockSignals(False)
        if self._address_drafts:
            self.address_select.setCurrentIndex(max(0, min(selected, len(self._address_drafts) - 1)))
            self._show_address(self.address_select.currentIndex())

    def _show_address(self, index: int) -> None:
        if not (0 <= index < len(self._address_drafts)):
            return
        item = self._address_drafts[index]
        self._loading_address = True
        try:
            for key, edit in self.address_fields.items():
                edit.setText(str(item.get(key) or ""))
        finally:
            self._loading_address = False

    def _address_field_changed(self, key: str, value: str) -> None:
        if self._loading_address:
            return
        index = self.address_select.currentIndex()
        if not (0 <= index < len(self._address_drafts)):
            return
        self._address_drafts[index][key] = value
        if key == "address":
            self.address_select.setItemText(index, self._address_title(self._address_drafts[index], index))

    def _add_address(self) -> None:
        self._address_drafts.append({
            "address": "",
            "pobox": "",
            "city": "",
            "state": "",
            "postal_code": "",
            "country": "RU",
        })
        index = len(self._address_drafts) - 1
        self.address_select.addItem(self._address_title(self._address_drafts[index], index))
        self.address_select.setCurrentIndex(index)
        self.address_fields["address"].setFocus()

    def _delete_address(self) -> None:
        if len(self._address_drafts) <= 1:
            QMessageBox.warning(self, "Адреса офисов", "Нельзя удалить последний адрес офиса")
            return
        index = self.address_select.currentIndex()
        if not (0 <= index < len(self._address_drafts)):
            return
        title = self._address_title(self._address_drafts[index], index)
        answer = QMessageBox.question(self, "Удаление адреса", f"Удалить адрес «{title}»?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._address_drafts.pop(index)
        self._load_address_drafts(self._address_drafts, selected=min(index, len(self._address_drafts) - 1))

    def _restore_addresses(self) -> None:
        answer = QMessageBox.question(
            self,
            "Восстановление адресов",
            "Заменить текущий список встроенными адресами? Изменения сохранятся только после нажатия «Сохранить адреса».",
        )
        if answer == QMessageBox.StandardButton.Yes:
            self._load_address_drafts(deepcopy(OFFICE_ADDRESSES))

    def _validated_addresses(self) -> list[dict[str, str]]:
        clean: list[dict[str, str]] = []
        seen: set[str] = set()
        for index, source in enumerate(self._address_drafts, start=1):
            item = {key: str(source.get(key) or "").strip() for key, *_ in self.ADDRESS_FIELDS}
            if not item["address"]:
                raise ValueError(f"Адрес {index}: заполните поле «Адрес»")
            folded = item["address"].casefold()
            if folded in seen:
                raise ValueError(f"Адрес «{item['address']}» указан несколько раз")
            seen.add(folded)
            if item["country"] and (len(item["country"]) != 2 or not item["country"].isalpha()):
                raise ValueError(f"{item['address']}: код страны должен состоять из двух букв, например RU")
            item["country"] = item["country"].upper()
            clean.append(item)
        return clean

    def _save_addresses(self) -> None:
        try:
            values = self._validated_addresses()
            previous_default = self.context.settings.default_address()
            self.context.settings.set_office_addresses(values)
            self.context.reload_office_addresses()
        except Exception as exc:
            QMessageBox.critical(self, "Адреса офисов", str(exc))
            return
        self._load_address_drafts(self.context.settings.office_addresses(), self.address_select.currentIndex())
        self._refresh_default_address_combo(previous_default)
        QMessageBox.information(self, "Адреса офисов", "Список адресов сохранён и сразу доступен в мастере создания")

    def _build_domains_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 18, 18, 18)

        title_row = QHBoxLayout()
        title = QLabel("Домены Active Directory")
        title.setObjectName("CardTitle")
        title_row.addWidget(title)
        title_row.addStretch(1)
        self.domain_select = QComboBox()
        self.domain_select.setMinimumWidth(260)
        self.domain_select.currentIndexChanged.connect(self._show_domain)
        title_row.addWidget(self.domain_select)
        add_button = QPushButton("＋ Добавить")
        add_button.clicked.connect(self._add_domain)
        title_row.addWidget(add_button)
        delete_button = QPushButton("Удалить")
        delete_button.clicked.connect(self._delete_domain)
        title_row.addWidget(delete_button)
        layout.addLayout(title_row)

        hint = QLabel(
            "Данные сохраняются в config_v2.json и применяются сразу, без пересборки приложения. "
            "Профиль «OMG» включает дополнительные атрибуты division, section и otpMobile."
        )
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        self.domain_fields: dict[str, QLineEdit] = {}
        for row, (key, label, placeholder) in enumerate(self.DOMAIN_FIELDS):
            edit = QLineEdit()
            edit.setPlaceholderText(placeholder)
            edit.textChanged.connect(lambda value, field=key: self._domain_field_changed(field, value))
            self.domain_fields[key] = edit
            grid.addWidget(QLabel(label), row, 0)
            grid.addWidget(edit, row, 1)

        profile_row = len(self.DOMAIN_FIELDS)
        self.domain_profile = QComboBox()
        self.domain_profile.addItem("Стандартный", "standard")
        self.domain_profile.addItem("OMG — расширенные атрибуты", "omg")
        self.domain_profile.currentIndexChanged.connect(self._domain_profile_changed)
        grid.addWidget(QLabel("Профиль обработки"), profile_row, 0)
        grid.addWidget(self.domain_profile, profile_row, 1)
        layout.addLayout(grid)

        buttons = QHBoxLayout()
        restore = QPushButton("Вернуть встроенные значения")
        restore.clicked.connect(self._restore_domains)
        buttons.addWidget(restore)
        buttons.addStretch(1)
        save = QPushButton("Сохранить домены")
        save.setObjectName("Primary")
        save.clicked.connect(self._save_domains)
        buttons.addWidget(save)
        layout.addLayout(buttons)
        return card

    def _domain_title(self, item: dict[str, str], index: int) -> str:
        return item.get("label") or item.get("name") or f"Домен {index + 1}"

    def _load_domain_drafts(self, values: list[dict[str, str]], selected: int = 0) -> None:
        self._domain_drafts = [dict(item) for item in deepcopy(values)]
        self.domain_select.blockSignals(True)
        self.domain_select.clear()
        for index, item in enumerate(self._domain_drafts):
            self.domain_select.addItem(self._domain_title(item, index))
        self.domain_select.blockSignals(False)
        if self._domain_drafts:
            self.domain_select.setCurrentIndex(max(0, min(selected, len(self._domain_drafts) - 1)))
            self._show_domain(self.domain_select.currentIndex())

    def _show_domain(self, index: int) -> None:
        if not (0 <= index < len(self._domain_drafts)):
            return
        item = self._domain_drafts[index]
        self._loading_domain = True
        try:
            for key, edit in self.domain_fields.items():
                edit.setText(str(item.get(key) or ""))
            profile = str(item.get("profile") or "standard")
            profile_index = self.domain_profile.findData(profile)
            self.domain_profile.setCurrentIndex(profile_index if profile_index >= 0 else 0)
        finally:
            self._loading_domain = False

    def _domain_field_changed(self, key: str, value: str) -> None:
        if self._loading_domain:
            return
        index = self.domain_select.currentIndex()
        if not (0 <= index < len(self._domain_drafts)):
            return
        self._domain_drafts[index][key] = value
        if key in {"name", "label"}:
            self.domain_select.setItemText(index, self._domain_title(self._domain_drafts[index], index))

    def _domain_profile_changed(self, _index: int) -> None:
        if self._loading_domain:
            return
        index = self.domain_select.currentIndex()
        if 0 <= index < len(self._domain_drafts):
            self._domain_drafts[index]["profile"] = str(self.domain_profile.currentData() or "standard")

    def _add_domain(self) -> None:
        existing = {str(item.get("name") or "").casefold() for item in self._domain_drafts}
        number = len(self._domain_drafts) + 1
        name = f"domain-{number}"
        while name.casefold() in existing:
            number += 1
            name = f"domain-{number}"
        self._domain_drafts.append({
            "name": name,
            "label": f"Новый домен {number}",
            "netbios": "",
            "server": "",
            "search_base": "",
            "ou_dn": "",
            "upn_suffix": "",
            "email_suffix": "",
            "fired_ou_dn": "",
            "group_search_base": "",
            "profile": "standard",
        })
        self.domain_select.addItem(self._domain_title(self._domain_drafts[-1], len(self._domain_drafts) - 1))
        self.domain_select.setCurrentIndex(len(self._domain_drafts) - 1)

    def _delete_domain(self) -> None:
        if len(self._domain_drafts) <= 1:
            QMessageBox.warning(self, "Домены", "Нельзя удалить последний домен")
            return
        index = self.domain_select.currentIndex()
        if not (0 <= index < len(self._domain_drafts)):
            return
        title = self._domain_title(self._domain_drafts[index], index)
        answer = QMessageBox.question(self, "Удаление домена", f"Удалить конфигурацию «{title}»?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._domain_drafts.pop(index)
        self._load_domain_drafts(self._domain_drafts, selected=min(index, len(self._domain_drafts) - 1))

    def _restore_domains(self) -> None:
        answer = QMessageBox.question(
            self,
            "Восстановление доменов",
            "Заменить текущие значения встроенной конфигурацией? Изменения сохранятся только после нажатия «Сохранить домены».",
        )
        if answer == QMessageBox.StandardButton.Yes:
            self._load_domain_drafts(deepcopy(DOMAIN_CONFIGS))

    def _validated_domains(self) -> list[dict[str, str]]:
        required = ("name", "label", "netbios", "server", "search_base", "ou_dn", "upn_suffix", "email_suffix")
        clean: list[dict[str, str]] = []
        names: set[str] = set()
        for index, source in enumerate(self._domain_drafts, start=1):
            item = {key: str(source.get(key) or "").strip() for key, *_ in self.DOMAIN_FIELDS}
            item["profile"] = str(source.get("profile") or "standard").strip().lower()
            missing = [key for key in required if not item.get(key)]
            if missing:
                labels = {key: label for key, label, _ in self.DOMAIN_FIELDS}
                raise ValueError(f"Домен {index}: заполните поле «{labels[missing[0]]}»")
            folded = item["name"].casefold()
            if folded in names:
                raise ValueError(f"Идентификатор домена «{item['name']}» указан несколько раз")
            names.add(folded)
            if not item["upn_suffix"].startswith("@"):
                raise ValueError(f"{item['label']}: UPN-суффикс должен начинаться с @")
            if not item["email_suffix"].startswith("@"):
                raise ValueError(f"{item['label']}: почтовый суффикс должен начинаться с @")
            if item["profile"] not in {"standard", "omg"}:
                item["profile"] = "standard"
            clean.append(item)
        return clean

    def _save_domains(self) -> None:
        try:
            values = self._validated_domains()
            self.context.settings.set_domain_configs(values)
            self.context.reload_domain_configs()
        except Exception as exc:
            QMessageBox.critical(self, "Домены", str(exc))
            return
        self._load_domain_drafts(self.context.settings.domain_configs(), self.domain_select.currentIndex())
        QMessageBox.information(self, "Домены", "Конфигурация доменов сохранена и применена")

    def _save_password(self) -> None:
        value = self.password.text()
        if not value:
            QMessageBox.warning(self, "Пароль", "Введите пароль")
            return
        try:
            self.context.settings.set_default_password(value)
        except Exception as exc:
            QMessageBox.critical(self, "Пароль", str(exc))
            return
        self.password.clear()
        self.password_status.setText("Задан")
        QMessageBox.information(self, "Пароль", "Пароль сохранён с защитой Windows DPAPI")

    def _theme_changed(self, index: int) -> None:
        key = "dark" if index == 0 else "light"
        self.context.settings.set("theme", key)
        self.theme_changed.emit(key)

    def _preflight(self) -> None:
        if self._preflight_worker is not None:
            return
        self.check_button.setEnabled(False)
        self.check_button.setText("Проверка…")
        self.busy.start_steps(len(self.context.ad.domains) + 1)
        self.diagnostic_label.setText("Запуск диагностики. На каждый домен установлен тайм-аут 15 секунд.")
        worker = FunctionWorker(self.context.ad.preflight)
        self._preflight_worker = worker
        worker.signals.progress.connect(self._preflight_progress)
        worker.signals.result.connect(self._preflight_ready)
        worker.signals.error.connect(self._preflight_error)
        worker.signals.finished.connect(self._preflight_finished)
        self.pool.start(worker)

    def _preflight_progress(self, key: str, message: str) -> None:
        try:
            current_text, total_text = key.split("/", 1)
            self.busy.set_step(int(current_text), int(total_text))
        except (TypeError, ValueError):
            pass
        self.diagnostic_label.setText(message)

    def _preflight_error(self, message: str, trace: str) -> None:
        self.context.events.log_message.emit(trace)
        self.diagnostic_label.setText("Ошибка: " + message)

    def _preflight_finished(self) -> None:
        self.busy.stop()
        self.check_button.setEnabled(True)
        self.check_button.setText("Проверить PowerShell, AD-модуль, контроллеры и OU")
        self._preflight_worker = None

    def _preflight_ready(self, value: object) -> None:
        data = value if isinstance(value, dict) else {}
        lines = [
            f"PowerShell: {data.get('powershell_version', '—')}",
            f"Модуль ActiveDirectory: {'доступен' if data.get('ad_module') else 'не найден'}",
        ]
        for domain in data.get("domains", []):
            if not isinstance(domain, dict):
                continue
            state = "OK" if domain.get("server_ok") and domain.get("ou_ok") else "Ошибка"
            details = str(domain.get("message") or "").strip()
            suffix = f" · {details}" if details else ""
            lines.append(f"{domain.get('name')}: {state} · {domain.get('server')}{suffix}")
        self.diagnostic_label.setText("\n".join(lines))
