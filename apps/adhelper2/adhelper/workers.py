from __future__ import annotations

import inspect
import traceback
from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, Signal, Slot


class WorkerSignals(QObject):
    started = Signal()
    result = Signal(object)
    error = Signal(str, str)
    progress = Signal(str, str)
    finished = Signal()


class FunctionWorker(QRunnable):
    def __init__(self, function: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    @Slot()
    def run(self) -> None:
        self.signals.started.emit()
        try:
            parameters = inspect.signature(self.function).parameters.values()
            supports_progress = any(
                parameter.name == "progress" or parameter.kind == inspect.Parameter.VAR_KEYWORD
                for parameter in parameters
            )
            kwargs = dict(self.kwargs)
            if supports_progress:
                kwargs["progress"] = self.signals.progress.emit
            result = self.function(*self.args, **kwargs)
        except Exception as exc:
            self.signals.error.emit(str(exc), traceback.format_exc())
            self.signals.finished.emit()
            return
        self.signals.result.emit(result)
        self.signals.finished.emit()
