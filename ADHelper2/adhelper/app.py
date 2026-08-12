from __future__ import annotations

import argparse
import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox

from .constants import APP_NAME, APP_VERSION
from .context import AppContext
from .protocol import ProtocolError, decode_onboarding_uri, is_onboarding_uri, register_protocol_handler
from .ui.main_window import MainWindow


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} {APP_VERSION}")
    parser.add_argument("--search", default="", help="Открыть приложение с поиском")
    parser.add_argument("--autorun", action="store_true", help="Автоматически выполнить поиск")
    parser.add_argument("uri", nargs="?", default="", help="Служебная ссылка adhelper:// из GLPI")
    args = parser.parse_args(argv)

    # HKCU не требует прав администратора. Повторная регистрация безопасна и
    # позволяет перенесённой/обновлённой сборке автоматически поправить путь к EXE.
    register_protocol_handler()

    QApplication.setAttribute(Qt.ApplicationAttribute.AA_DontUseNativeMenuBar, True)
    app = QApplication(sys.argv[:1])
    app.setStyle("Fusion")
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    try:
        context = AppContext()
        window = MainWindow(context)
        window.show()
        if args.search:
            window.open_search(args.search, autorun=args.autorun)
        if args.uri:
            if not is_onboarding_uri(args.uri):
                raise ProtocolError("ADHelper получил неизвестную служебную ссылку")
            window.open_onboarding_payload(decode_onboarding_uri(args.uri))
        return app.exec()
    except Exception as exc:
        QMessageBox.critical(None, "Ошибка запуска ADHelper", str(exc))
        return 1
