from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QProgressBar, QVBoxLayout, QWidget


class PageHeader(QWidget):
    def __init__(self, title: str, subtitle: str = "") -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 12)
        title_label = QLabel(title)
        title_label.setObjectName("PageTitle")
        layout.addWidget(title_label)
        if subtitle:
            subtitle_label = QLabel(subtitle)
            subtitle_label.setObjectName("Muted")
            subtitle_label.setWordWrap(True)
            layout.addWidget(subtitle_label)


class MetricCard(QFrame):
    def __init__(self, title: str, value: str = "—", hint: str = "") -> None:
        super().__init__()
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        title_label = QLabel(title)
        title_label.setObjectName("CardTitle")
        self.value_label = QLabel(value)
        self.value_label.setObjectName("Metric")
        self.hint_label = QLabel(hint)
        self.hint_label.setObjectName("Muted")
        self.hint_label.setWordWrap(True)
        layout.addWidget(title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.hint_label)

    def set_value(self, value: str, hint: str = "") -> None:
        self.value_label.setText(value)
        if hint:
            self.hint_label.setText(hint)


class BusyBar(QProgressBar):
    def __init__(self) -> None:
        super().__init__()
        self.setRange(0, 0)
        self.setTextVisible(False)
        self.setFixedHeight(5)
        self.hide()

    def start_indeterminate(self) -> None:
        self.setRange(0, 0)
        self.setTextVisible(False)
        self.show()

    def start_steps(self, total: int) -> None:
        self.setRange(0, max(1, total))
        self.setValue(0)
        self.setTextVisible(False)
        self.show()

    def set_step(self, current: int, total: int | None = None) -> None:
        if total is not None and total > 0 and self.maximum() != total:
            self.setRange(0, total)
        self.setValue(max(self.minimum(), min(current, self.maximum())))

    def stop(self) -> None:
        self.hide()
        self.setRange(0, 0)

from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QLineEdit, QTableWidget, QTableWidgetItem
)


class SelectionDialog(QDialog):
    def __init__(self, title: str, rows: list[dict], columns: list[tuple[str, str]], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(900, 520)
        self._all_rows = rows
        self._columns = columns
        self.selected_row: dict | None = None
        layout = QVBoxLayout(self)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Фильтр…")
        self.filter_edit.textChanged.connect(self._render)
        layout.addWidget(self.filter_edit)
        self.table = QTableWidget(0, len(columns))
        self.table.setHorizontalHeaderLabels([label for _key, label in columns])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.doubleClicked.connect(self.accept)
        layout.addWidget(self.table, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._visible_rows: list[dict] = []
        self._render()

    def _render(self) -> None:
        query = self.filter_edit.text().strip().lower()
        self._visible_rows = [
            row for row in self._all_rows
            if not query or query in " ".join(str(row.get(key, "")) for key, _label in self._columns).lower()
        ]
        self.table.setRowCount(len(self._visible_rows))
        for row_index, row in enumerate(self._visible_rows):
            for column_index, (key, _label) in enumerate(self._columns):
                item = QTableWidgetItem(str(row.get(key, "")))
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row_index, column_index, item)

    def accept(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if rows:
            index = rows[0].row()
            if index < len(self._visible_rows):
                self.selected_row = self._visible_rows[index]
                super().accept()
                return
        super().reject()
