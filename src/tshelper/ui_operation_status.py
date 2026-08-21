from __future__ import annotations

import tkinter as tk
from tkinter import ttk


DEFAULT_STAGES = [
    "Подготовка",
    "Pre-check",
    "Копирование payload",
    "Запуск установки",
    "Ожидание завершения установщика",
    "Post-check",
    "Завершено",
    "Ошибка",
]


class OperationStatusStrip(ttk.Frame):
    def __init__(self, master, *, stages: list[str] | None = None):
        super().__init__(master)
        self.stages = stages or list(DEFAULT_STAGES)
        self.stage_var = tk.StringVar(value=self.stages[0])

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", expand=True)

        status_row = ttk.Frame(self)
        status_row.pack(fill="x", pady=(4, 0))
        ttk.Label(status_row, text="Этап:").pack(side="left")
        self.status_label = ttk.Label(status_row, textvariable=self.stage_var)
        self.status_label.pack(side="left", padx=(6, 0))

    def start(self, stage: str = "Подготовка"):
        self.set_stage(stage)
        self.progress.start(10)

    def stop(self):
        self.progress.stop()

    def set_stage(self, stage: str):
        self.stage_var.set(stage if stage else "Подготовка")

    def mark_done(self):
        self.set_stage("Завершено")
        self.stop()

    def mark_error(self):
        self.set_stage("Ошибка")
        self.stop()
