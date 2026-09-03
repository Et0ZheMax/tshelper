from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QMessageBox

from ...services.onboarding import OnboardingPlan
from ...parsers.contractor_request_parser import (
    contractor_target_ous,
    extract_contractor_request_fields,
    parse_contractor_request,
    requested_domain_names,
)
from ...parsers.request_parser import validation_errors
from .onboarding import OnboardingPage


class AccountCreationPage(OnboardingPage):
    """Мастер создания учётных записей сотрудников контрагентов."""

    PAGE_TITLE = "Создать учетку"
    PAGE_SUBTITLE = "Создание учётных записей сотрудников контрагентов по тексту заявки."

    def __init__(self, context) -> None:
        super().__init__(context)
        self.create_welcome.setText("Создать и открыть текст ответа для заявки")
        self.create_welcome.setChecked(True)
        self.create_welcome.setEnabled(False)
        self.print_welcome.hide()

    def _explicit_ous_for_plan(self) -> dict[str, str] | None:
        return contractor_target_ous(self.context.ad.domains)

    def _plan_ready(self, plan: object) -> None:
        if isinstance(plan, OnboardingPlan):
            plan.welcome_kind = "contractor"
        super()._plan_ready(plan)

    def _execution_ready(self, operation: object) -> None:
        super()._execution_ready(operation)
        path_value = str(getattr(operation, "data", {}).get("welcome_path") or "")
        if path_value and not QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(path_value).resolve()))):
            QMessageBox.warning(
                self,
                "Ответ для заявки",
                f"Файл создан, но не удалось открыть его автоматически:\n{path_value}",
            )

    def _update_request_preview(self) -> None:
        text = self.request_text.toPlainText()
        self.request = parse_contractor_request(text)
        recognized = extract_contractor_request_fields(text)
        self._populate_details()

        mentioned_domains = requested_domain_names(text, list(self.domain_checks))
        if mentioned_domains:
            for name, check in self.domain_checks.items():
                check.setChecked(name in mentioned_domains)

        missing = validation_errors(self.request)
        if not text.strip():
            self.preview_status.setText("Вставьте текст заявки слева")
        elif missing:
            self.preview_status.setText(
                f"Распознано полей: {len(recognized)}. Не найдено: "
                + ", ".join(item.replace("Не указана ", "") for item in missing)
                + ". Проверьте текст или заполните карточку вручную."
            )
        else:
            self.preview_status.setText(
                f"Распознано полей: {len(recognized)}. Карточка учётной записи готова к проверке."
            )
