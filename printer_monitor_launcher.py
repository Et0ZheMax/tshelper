"""Изолированный запуск Print Monitor из TSHelper."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable


PRINT_MONITOR_COMMIT = "92990ff3d2e8303b19fdc73c19eac11621df6821"


class PrinterMonitorUnavailable(RuntimeError):
    """Компонент отсутствует или для него не найден подходящий Python."""


def default_printers_path() -> Path:
    data_root = Path(os.environ.get("APPDATA") or Path.home()) / "TSHelper"
    return data_root / "printers.txt"


def resolve_python_executable() -> str:
    """Выбрать Python без консольного окна, когда это возможно."""
    if getattr(sys, "frozen", False):
        external = shutil.which("pythonw.exe") or shutil.which("python.exe")
        if not external:
            raise PrinterMonitorUnavailable(
                "Для запуска Print Monitor из собранной версии нужен Python 3.11+."
            )
        return external

    if os.name == "nt":
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        if pythonw.is_file():
            return str(pythonw)
    return sys.executable


def build_printer_monitor_command(executable: str, config_path: Path | str) -> list[str]:
    return [
        executable,
        "-m",
        "prn_site_ping",
        "--config",
        str(config_path),
        "--title",
        "TS HELPER — Мониторинг принтеров",
    ]


class PrinterMonitorLauncher:
    def __init__(
        self,
        *,
        working_directory: Path | str,
        popen_factory: Callable[..., subprocess.Popen] = subprocess.Popen,
    ) -> None:
        self.working_directory = Path(working_directory)
        self._popen_factory = popen_factory
        self._process: subprocess.Popen | None = None

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def start(self) -> bool:
        """Запустить компонент. Возвращает False, если окно уже работает."""
        if self.is_running:
            return False
        if importlib.util.find_spec("prn_site_ping") is None:
            raise PrinterMonitorUnavailable(
                "Компонент Print Monitor не установлен. Выполните: "
                "python -m pip install -r requirements.txt"
            )

        config_path = default_printers_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        command = build_printer_monitor_command(resolve_python_executable(), config_path)
        self._process = self._popen_factory(
            command,
            cwd=str(self.working_directory),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return True
