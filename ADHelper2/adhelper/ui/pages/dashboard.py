from __future__ import annotations

from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget
)

from ...context import AppContext
from ...workers import FunctionWorker
from ..widgets import BusyBar, MetricCard, PageHeader


class DashboardPage(QWidget):
    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.context = context
        self.pool = QThreadPool.globalInstance()
        self._preflight_worker: FunctionWorker | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        header_row = QHBoxLayout()
        header_row.addWidget(PageHeader("Обзор", "Состояние ADHelper, доменов и последних операций."), 1)
        self.refresh_button = QPushButton("Обновить диагностику")
        self.refresh_button.clicked.connect(self.refresh)
        header_row.addWidget(self.refresh_button)
        layout.addLayout(header_row)
        self.diagnostic_status = QLabel(
            "Проверка запускается вручную: PowerShell, модуль ActiveDirectory, контроллеры и базовые OU."
        )
        self.diagnostic_status.setObjectName("Muted")
        self.diagnostic_status.setWordWrap(True)
        layout.addWidget(self.diagnostic_status)
        self.busy = BusyBar()
        layout.addWidget(self.busy)

        cards = QGridLayout()
        self.ad_card = MetricCard("Active Directory", "Не проверено", "Запустите диагностику")
        self.domains_card = MetricCard("Домены", "—", "Доступность контроллеров")
        self.password_card = MetricCard("Пароль", "Задан" if context.settings.has_default_password() else "Не задан", "Хранится через Windows DPAPI")
        self.ops_card = MetricCard("Операции", str(len(context.audit.list_recent(100))), "Записей в локальном аудите")
        cards.addWidget(self.ad_card, 0, 0)
        cards.addWidget(self.domains_card, 0, 1)
        cards.addWidget(self.password_card, 0, 2)
        cards.addWidget(self.ops_card, 0, 3)
        layout.addLayout(cards)

        recent_frame = QFrame()
        recent_frame.setObjectName("Card")
        recent_layout = QVBoxLayout(recent_frame)
        recent_layout.setContentsMargins(16, 16, 16, 16)
        title = QLabel("Последние операции")
        title.setObjectName("CardTitle")
        recent_layout.addWidget(title)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Время", "Операция", "Сотрудник", "Статус", "Оператор"])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        recent_layout.addWidget(self.table)
        layout.addWidget(recent_frame, 1)
        self.context.events.operations_changed.connect(self.load_operations)
        self.load_operations()

    def load_operations(self) -> None:
        rows = self.context.audit.list_recent(15)
        self.table.setRowCount(len(rows))
        for row, item in enumerate(rows):
            values = [
                str(item.get("started_at") or "")[:19],
                str(item.get("operation_type") or ""),
                str(item.get("subject") or ""),
                str(item.get("status") or ""),
                str(item.get("operator") or ""),
            ]
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(value))
        self.ops_card.set_value(str(len(self.context.audit.list_recent(100))), "Записей в локальном аудите")
        self.password_card.set_value("Задан" if self.context.settings.has_default_password() else "Не задан")

    def refresh(self) -> None:
        if self._preflight_worker is not None:
            return
        self.refresh_button.setEnabled(False)
        self.refresh_button.setText("Проверка…")
        self.busy.start_steps(len(self.context.ad.domains) + 1)
        self.diagnostic_status.setText(
            "Запуск диагностики. На каждый домен установлен тайм-аут 15 секунд."
        )
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
        self.diagnostic_status.setText(message)

    def _preflight_finished(self) -> None:
        self.busy.stop()
        self.refresh_button.setEnabled(True)
        self.refresh_button.setText("Обновить диагностику")
        self._preflight_worker = None

    def _preflight_ready(self, data: object) -> None:
        result = data if isinstance(data, dict) else {}
        module_ok = bool(result.get("ad_module"))
        domains = result.get("domains") if isinstance(result.get("domains"), list) else []
        healthy = sum(1 for item in domains if isinstance(item, dict) and item.get("server_ok") and item.get("ou_ok"))
        self.ad_card.set_value("Готов" if module_ok else "Нет модуля", f"PowerShell {result.get('powershell_version', '—')}")
        self.domains_card.set_value(f"{healthy}/{len(domains)}", "Контроллер и базовый OU доступны")
        if module_ok and healthy == len(domains):
            self.diagnostic_status.setText("Диагностика завершена: окружение и все домены доступны.")
        elif not module_ok:
            self.diagnostic_status.setText("Диагностика завершена: модуль ActiveDirectory недоступен.")
        else:
            self.diagnostic_status.setText(f"Диагностика завершена: доступны {healthy} из {len(domains)} доменов.")

    def _preflight_error(self, message: str, trace: str) -> None:
        self.context.events.log_message.emit(trace)
        self.ad_card.set_value("Ошибка", message)
        self.domains_card.set_value("—", "Диагностика не выполнена")
        self.diagnostic_status.setText("Ошибка диагностики: " + message)
