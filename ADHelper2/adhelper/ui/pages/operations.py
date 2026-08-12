from __future__ import annotations

import json

from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QPlainTextEdit, QPushButton, QSplitter, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget
)

from ...context import AppContext
from ..widgets import PageHeader


class OperationsPage(QWidget):
    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.context = context
        self.rows: list[dict] = []
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        header = QHBoxLayout()
        header.addWidget(PageHeader("Операции и аудит", "История создания, редактирования, увольнения и восстановления сотрудников."), 1)
        refresh = QPushButton("Обновить")
        refresh.clicked.connect(self.load)
        header.addWidget(refresh)
        root.addLayout(header)

        splitter = QSplitter()
        left = QFrame(); left.setObjectName("Card")
        left_layout = QVBoxLayout(left)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Время", "ID", "Тип", "Сотрудник", "Статус", "Оператор"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._show_selected)
        left_layout.addWidget(self.table)

        right = QFrame(); right.setObjectName("Card")
        right_layout = QVBoxLayout(right)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        right_layout.addWidget(self.details)
        splitter.addWidget(left); splitter.addWidget(right)
        splitter.setSizes([800, 520])
        root.addWidget(splitter, 1)
        self.context.events.operations_changed.connect(self.load)
        self.load()

    def load(self) -> None:
        self.rows = self.context.audit.list_recent(300)
        self.table.setRowCount(len(self.rows))
        for row, item in enumerate(self.rows):
            values = [
                str(item.get("started_at") or "")[:19],
                str(item.get("operation_id") or "")[:8],
                str(item.get("operation_type") or ""),
                str(item.get("subject") or ""),
                str(item.get("status") or ""),
                str(item.get("operator") or ""),
            ]
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(value))

    def _show_selected(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            self.details.clear()
            return
        row = rows[0].row()
        if row < len(self.rows):
            self.details.setPlainText(json.dumps(self.rows[row], ensure_ascii=False, indent=2))
