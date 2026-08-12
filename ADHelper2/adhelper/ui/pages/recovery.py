from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThreadPool, Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
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
from ...workers import FunctionWorker
from ..widgets import BusyBar, PageHeader
from .offboarding import LoginConfirmationDialog


class RecoveryPage(QWidget):
    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.context = context
        self.pool = QThreadPool.globalInstance()
        self.rows: list[dict] = []
        self.selected_path = ""
        self.selected_info: dict | None = None
        self._preview_valid = False
        self._busy_state = False
        self._active_workers: list[FunctionWorker] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.addWidget(PageHeader(
            "Восстановление из уволенных",
            "Выберите recovery JSON, созданный ADHelper до увольнения. Перед первым изменением восстановления "
            "будет сохранён отдельный rollback JSON текущего состояния учётки.",
        ))

        actions = QHBoxLayout()
        self.refresh_button = QPushButton("Обновить список")
        self.refresh_button.clicked.connect(self.load_files)
        self.open_button = QPushButton("Открыть JSON…")
        self.open_button.clicked.connect(self.open_file)
        actions.addWidget(self.refresh_button)
        actions.addWidget(self.open_button)
        actions.addStretch(1)
        root.addLayout(actions)

        self.progress_label = QLabel("")
        self.progress_label.setObjectName("Muted")
        self.progress_label.setWordWrap(True)
        self.progress_label.hide()
        root.addWidget(self.progress_label)
        self.busy = BusyBar()
        root.addWidget(self.busy)

        splitter = QSplitter()
        left = QFrame()
        left.setObjectName("Card")
        left_layout = QVBoxLayout(left)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Снимок", "Сотрудник", "Логин", "Домены", "Файл"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._select_row)
        left_layout.addWidget(self.table)

        right = QFrame()
        right.setObjectName("Card")
        right_layout = QVBoxLayout(right)
        self.title_label = QLabel("Recovery-файл не выбран")
        self.title_label.setObjectName("CardTitle")
        right_layout.addWidget(self.title_label)
        self.meta_label = QLabel("")
        self.meta_label.setObjectName("Muted")
        self.meta_label.setWordWrap(True)
        right_layout.addWidget(self.meta_label)
        self.plan_text = QTextEdit()
        self.plan_text.setReadOnly(True)
        self.plan_text.setPlaceholderText(
            "Выберите recovery JSON. Затем ADHelper сверит GUID, текущий OU, исходный OU и список восстанавливаемых атрибутов."
        )
        right_layout.addWidget(self.plan_text, 1)

        buttons = QHBoxLayout()
        self.preview_button = QPushButton("Проверить восстановление")
        self.preview_button.setEnabled(False)
        self.preview_button.clicked.connect(self.preview)
        self.execute_button = QPushButton("Восстановить учётку")
        self.execute_button.setEnabled(False)
        self.execute_button.clicked.connect(self.execute)
        buttons.addWidget(self.preview_button)
        buttons.addStretch(1)
        buttons.addWidget(self.execute_button)
        right_layout.addLayout(buttons)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([680, 620])
        root.addWidget(splitter, 1)

        self.steps_table = QTableWidget(0, 3)
        self.steps_table.setHorizontalHeaderLabels(["Этап", "Статус", "Сообщение / точная ошибка"])
        self.steps_table.horizontalHeader().setStretchLastSection(True)
        self.steps_table.setMinimumHeight(190)
        root.addWidget(self.steps_table)

        self.context.events.operations_changed.connect(self.load_files)
        self.load_files()

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

    def _execution_progress(self, key: str, message: str) -> None:
        self._progress(key, message)
        self.plan_text.append(message)

    def _finish_task(self) -> None:
        if not self._busy_state and not self.busy.isVisible():
            return
        self._busy_state = False
        self.busy.stop()
        self.progress_label.hide()
        self._update_buttons()

    def _update_buttons(self) -> None:
        enabled = not self._busy_state
        self.refresh_button.setEnabled(enabled)
        self.open_button.setEnabled(enabled)
        self.preview_button.setEnabled(enabled and bool(self.selected_path))
        self.execute_button.setEnabled(enabled and bool(self.selected_path) and self._preview_valid)

    def load_files(self) -> None:
        if self._busy_state:
            return
        self.rows = self.context.recovery.list_files(300)
        self.table.setRowCount(len(self.rows))
        for row, info in enumerate(self.rows):
            captured = str(info.get("captured_at") or "")[:19].replace("T", " ") or "—"
            domains = ", ".join(str(item) for item in (info.get("domains") or []))
            values = [
                captured,
                str(info.get("display_name") or ("Некорректный JSON" if not info.get("valid") else "")),
                str(info.get("sam") or ""),
                domains,
                str(info.get("filename") or ""),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, column, item)
        if not self.rows:
            self.plan_text.setPlainText(
                f"Recovery-файлы пока не найдены.\nПапка: {self.context.settings.recovery_dir}"
            )

    def open_file(self) -> None:
        path, _selected_filter = QFileDialog.getOpenFileName(
            self,
            "Открыть recovery JSON",
            str(self.context.settings.recovery_dir),
            "JSON (*.json);;Все файлы (*.*)",
        )
        if not path:
            return
        self._use_path(path)

    def _select_row(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        if row >= len(self.rows):
            return
        info = self.rows[row]
        if not info.get("valid"):
            self.selected_path = ""
            self.selected_info = None
            self._preview_valid = False
            self.title_label.setText("Некорректный recovery JSON")
            self.plan_text.setPlainText(str(info.get("error") or "Файл не прошёл проверку"))
            self._update_buttons()
            return
        self._use_path(str(info.get("path") or ""))

    def _use_path(self, path: str) -> None:
        self._preview_valid = False
        self.steps_table.setRowCount(0)
        try:
            info = self.context.recovery.load_file(path)
        except Exception as exc:
            self.selected_path = ""
            self.selected_info = None
            self.title_label.setText("Recovery JSON не принят")
            self.plan_text.setPlainText(str(exc))
            self._update_buttons()
            QMessageBox.critical(self, "Recovery JSON", str(exc))
            return
        self.selected_path = str(info["path"])
        self.selected_info = info
        self.title_label.setText(info["display_name"] or info["sam"])
        self.meta_label.setText(
            f"Логин: {info['sam']}\n"
            f"Снимок: {info.get('captured_at') or 'время не записано'}\n"
            f"Файл: {Path(self.selected_path).name}"
        )
        self.plan_text.setPlainText(
            "Файл прочитан локально. Active Directory ещё не проверялся и не изменялся.\n\n"
            "Нажмите «Проверить восстановление»."
        )
        self._update_buttons()

    def preview(self) -> None:
        if not self.selected_path:
            return
        self._preview_valid = False
        count = len((self.selected_info or {}).get("snapshots") or {})
        self._start_task(max(1, count), "Сопоставляем recovery JSON с текущими объектами AD…")
        worker = self._track_worker(FunctionWorker(self.context.recovery.preview, self.selected_path))
        worker.signals.progress.connect(self._progress)
        worker.signals.result.connect(self._preview_ready)
        worker.signals.error.connect(self._error)
        self.pool.start(worker)

    def _preview_ready(self, value: object) -> None:
        try:
            info = value if isinstance(value, dict) else {}
            rows = info.get("domains") or []
            lines = [
                "План восстановления:",
                "",
                f"Recovery JSON: {info.get('path', self.selected_path)}",
                f"Логин: {info.get('sam', '')}",
                "",
            ]
            errors: list[str] = []
            for row in rows:
                label = str(row.get("label") or row.get("domain") or row.get("source_domain") or "домен")
                snapshot = row.get("snapshot") or {}
                lines.extend([
                    f"• {label}",
                    f"  GUID: {snapshot.get('guid', '')}",
                    f"  Исходный DN: {snapshot.get('dn', '')}",
                ])
                if not row.get("ok"):
                    error = str(row.get("error") or "Проверка не пройдена")
                    errors.append(f"[{label}] {error}")
                    lines.append(f"  ПРОВЕРКА НЕ ПРОЙДЕНА: {error}")
                    lines.append("")
                    continue
                validation = row.get("validation") or {}
                raw_steps = [item for item in (validation.get("steps") or []) if isinstance(item, dict)]
                raw = raw_steps[0] if raw_steps else {}
                lines.extend([
                    f"  Текущий DN: {raw.get('current_dn', '')}",
                    f"  Исходный OU: {raw.get('original_parent', '')}",
                    f"  Атрибутов в recovery-политике: {raw.get('attributes_in_snapshot', 0)}",
                    f"  Реально требуется восстановить: {raw.get('attributes_to_restore', 0)}",
                    f"  Возврат в исходный OU: {'да' if raw.get('move_needed') else 'уже там'}",
                    f"  Исходный Enabled: {raw.get('original_enabled')}",
                    f"  Изменение Enabled: {'да' if raw.get('enabled_change_needed') else 'не требуется'}",
                    "",
                ])
            lines.extend([
                "Перед первым изменением ADHelper сохранит отдельный pre_restore JSON текущего состояния.",
                "Группы memberOf не перезаписываются: увольнение ADHelper их не удаляет.",
            ])
            if errors:
                lines.extend(["", "Исправьте ошибки перед запуском:", *[f"• {item}" for item in errors]])
                self._preview_valid = False
            else:
                lines.extend(["", "Все обязательные проверки пройдены. Восстановление можно запускать."])
                self._preview_valid = bool(rows)
            self.plan_text.setPlainText("\n".join(lines))
        finally:
            self._finish_task()

    def execute(self) -> None:
        if not self.selected_path or not self.selected_info or not self._preview_valid:
            QMessageBox.warning(self, "Восстановление", "Сначала выполните успешную проверку восстановления.")
            return
        sam = str(self.selected_info.get("sam") or "")
        answer = QMessageBox.warning(
            self,
            "Подтверждение восстановления",
            f"ADHelper восстановит учётку '{sam}' по выбранному recovery JSON.\n\n"
            "Будут возвращены сохранённые рабочие атрибуты, исходный OU и исходное состояние Enabled.\n"
            "До первого изменения будет создан rollback JSON текущего состояния.\n\nПродолжить?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        confirmation = LoginConfirmationDialog(sam, self)
        if confirmation.exec() != QDialog.DialogCode.Accepted:
            return

        count = len(self.selected_info.get("snapshots") or {})
        self._start_task(max(1, count * 5 + 1), "Начинаем безопасное восстановление…")
        self.steps_table.setRowCount(0)
        self.plan_text.append("\n--- Выполнение восстановления ---")
        worker = self._track_worker(FunctionWorker(self.context.recovery.execute, self.selected_path))
        worker.signals.progress.connect(self._execution_progress)
        worker.signals.result.connect(self._execute_ready)
        worker.signals.error.connect(self._error)
        self.pool.start(worker)

    def _execute_ready(self, operation: object) -> None:
        try:
            self.context.events.operations_changed.emit()
            steps = getattr(operation, "steps", []) or []
            self.steps_table.setRowCount(len(steps))
            for row, step in enumerate(steps):
                for column, value in enumerate((step.title, step.status, step.message)):
                    item = QTableWidgetItem(str(value))
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    self.steps_table.setItem(row, column, item)
            self.steps_table.resizeRowsToContents()

            status = str(getattr(operation, "status", "unknown"))
            data = getattr(operation, "data", {}) or {}
            errors = [str(item) for item in (getattr(operation, "errors", []) or [])]
            warnings = [str(item) for item in (getattr(operation, "warnings", []) or [])]
            rollback_path = str(data.get("pre_restore_path") or "")
            self.plan_text.append(f"\nИтог: {status}")
            if rollback_path:
                self.plan_text.append(f"Rollback JSON перед восстановлением: {rollback_path}")
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
                    "Учётка восстановлена",
                    f"Восстановление завершено.\n\nRollback JSON:\n{rollback_path}",
                )
            else:
                exact = "\n".join(f"• {item}" for item in errors[:6]) or "Смотрите таблицу этапов."
                QMessageBox.warning(
                    self,
                    "Восстановление завершилось не полностью",
                    f"Статус: {status}\n\n{exact}\n\nRollback JSON:\n{rollback_path}",
                )
            self._preview_valid = False
        finally:
            self._finish_task()

    def _error(self, message: str, trace: str) -> None:
        self.context.events.log_message.emit(trace)
        self.plan_text.append(f"\nОШИБКА: {message}")
        self._finish_task()
        QMessageBox.critical(self, "Ошибка восстановления", message)
