from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from PySide6.QtCore import QObject, Signal

from .services.ad_service import ADService
from .services.access_management import AccessManagementService
from .services.audit import AuditRepository
from .services.offboarding import OffboardingService
from .services.recovery import RecoveryService
from .services.onboarding import OnboardingService
from .services.ou_resolver import OUResolver
from .services.powershell import PowerShellClient
from .services.welcome import WelcomeDocumentService
from .services.user_management import UserManagementService
from .settings import SettingsStore


class EventBus(QObject):
    log_message = Signal(str)
    operations_changed = Signal()
    domains_changed = Signal()
    addresses_changed = Signal()


class AppContext:
    def __init__(self) -> None:
        self.settings = SettingsStore()
        self.events = EventBus()
        self.logger = self._setup_logging()

        def log(message: str) -> None:
            self.logger.info(message)
            self.events.log_message.emit(message)

        self.ps = PowerShellClient(logger=log)
        self.ad = ADService(self.ps, self.settings.domain_configs(), logger=log)
        self.audit = AuditRepository(self.settings)
        self.ou_resolver = OUResolver(self.ps, self.settings)
        self.welcome = WelcomeDocumentService(self.settings)
        self.onboarding = OnboardingService(self.ad, self.ou_resolver, self.audit, self.welcome, logger=log)
        self.offboarding = OffboardingService(self.ad, self.audit, logger=log)
        self.recovery = RecoveryService(self.ad, self.audit, logger=log)
        self.user_management = UserManagementService(self.ad, self.audit, logger=log)
        self.access_management = AccessManagementService(
            self.ad, self.audit, self.settings.base_dir / "access_groups_cache.json", logger=log
        )


    def reload_domain_configs(self) -> None:
        self.ad.set_domains(self.settings.domain_configs())
        self.ou_resolver.clear_cache()
        self.events.domains_changed.emit()

    def reload_office_addresses(self) -> None:
        self.events.addresses_changed.emit()

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger("adhelper2")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = RotatingFileHandler(
                self.settings.log_dir / "adhelper.log",
                maxBytes=2_000_000,
                backupCount=5,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
            logger.addHandler(handler)
        return logger
