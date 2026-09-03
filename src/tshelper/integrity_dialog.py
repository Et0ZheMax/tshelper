"""Окно фоновой проверки целостности без изменения установленной копии."""

import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from .integrity import IntegrityCancelled, check_integrity


class IntegrityDialog(tk.Toplevel):
    def __init__(self, master, version):
        super().__init__(master)
        self.title("Проверка целостности файлов")
        self.geometry("860x540")
        self.minsize(640, 400)
        self.transient(master)
        self.running = True
        self.report = None
        self.cancelled = threading.Event()
        self.events = queue.Queue()
        self.progress_event = None
        self.protocol("WM_DELETE_WINDOW", self.close)

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill="both", expand=True)
        self.status = tk.StringVar(value="Подготовка проверки…")
        ttk.Label(frame, textvariable=self.status, wraplength=790).pack(anchor="w")
        self.progress = ttk.Progressbar(frame, mode="indeterminate")
        self.progress.pack(fill="x", pady=(10, 10))
        self.progress.start(15)
        ttk.Label(
            frame, wraplength=790,
            text="Эталон — официальный portable-архив установленной версии с проверкой SHA-256. "
                 "Файлы не заменяются. Данные профиля, журналы, кэши и виртуальные окружения не проверяются. "
                 "Для первого запуска потребуется загрузить архив релиза.",
        ).pack(anchor="w", pady=(0, 12))
        table_frame = ttk.Frame(frame)
        table_frame.pack(fill="both", expand=True)
        self.table = ttk.Treeview(table_frame, columns=("path", "status", "detail"), show="headings")
        for column, title, width in (
            ("path", "Файл", 340), ("status", "Результат", 160), ("detail", "Подробности", 240),
        ):
            self.table.heading(column, text=title)
            self.table.column(column, width=width, minwidth=100)
        vertical = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        horizontal = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.table.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(12, 0))
        self.copy_button = ttk.Button(buttons, text="Скопировать отчёт", command=self.copy_report, state="disabled")
        self.copy_button.pack(side="left")
        self.close_button = ttk.Button(buttons, text="Отмена", command=self.close)
        self.close_button.pack(side="right")

        def progress(stage, current, total):
            if self.cancelled.is_set():
                raise IntegrityCancelled()
            # Прогресс объединяется, чтобы загрузка не заполняла очередь тысячами событий.
            self.progress_event = (stage, current, total)

        def work():
            try:
                result = check_integrity(version, progress=progress)
                self.events.put(("result", result))
            except IntegrityCancelled:
                self.events.put(("cancelled", None))
            except Exception as exc:
                self.events.put(("error", str(exc)))

        threading.Thread(target=work, daemon=True, name="tshelper-integrity-check").start()
        self.after(100, self.poll)

    def poll(self):
        if self.progress_event is not None and not self.cancelled.is_set():
            stage, current, total = self.progress_event
            self.status.set(f"{stage}: {current * 100 / total:.0f}%" if total else stage)
        try:
            kind, result = self.events.get_nowait()
        except queue.Empty:
            self.after(100, self.poll)
            return
        self.running = False
        self.progress.stop()
        self.close_button.configure(text="Закрыть", state="normal")
        if self.cancelled.is_set() or kind == "cancelled":
            self.destroy()
        elif kind == "error":
            self.status.set(f"Не удалось завершить проверку: {result}")
        else:
            self.report = result
            self.status.set(result.summary())
            for item in result.issues:
                self.table.insert("", "end", values=(item.path, item.status, item.detail))
            self.copy_button.configure(state="normal")

    def close(self):
        if self.running:
            self.cancelled.set()
            self.status.set("Отмена проверки… Ожидаем завершения текущей операции.")
            self.close_button.configure(state="disabled")
        else:
            self.destroy()

    def copy_report(self):
        if self.report is not None:
            self.clipboard_clear()
            self.clipboard_append(self.report.as_text())
            messagebox.showinfo("Проверка целостности", "Отчёт скопирован в буфер обмена.", parent=self)
