from __future__ import annotations

import os
import tempfile
import zipfile
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET

from ..constants import WELCOME_TEMPLATE_PATH
from ..models import DomainConfig
from ..settings import SettingsStore

PLACEHOLDERS = ("{{LOGIN}}", "{{DOMAIN_LOGIN}}", "{{EMAIL}}", "{{PASSWORD}}")


def select_welcome_domain(domains: Iterable[DomainConfig]) -> DomainConfig:
    """Return the domain whose credentials must be printed on welcome sheets.

    Welcome sheets are intentionally tied to the OMG domain even when the
    selected account was found in another configured domain.  Failing loudly
    is safer than silently printing PAK-CSPMZ credentials.
    """
    for domain in domains:
        if domain.profile.casefold() == "omg":
            if not domain.netbios.strip():
                raise RuntimeError("У домена с профилем OMG не задан NetBIOS")
            return domain
    raise RuntimeError(
        "Для приветственного листа не настроен домен с профилем OMG. "
        "Откройте Настройки → Домены и назначьте нужному домену профиль OMG."
    )


class WelcomeDocumentService:
    def __init__(self, settings: SettingsStore, template_path: Path | None = None) -> None:
        self.settings = settings
        self.template_path = template_path or WELCOME_TEMPLATE_PATH

    def available(self) -> bool:
        return self.template_path.exists()

    def generate(self, *, login: str, domain_login: str, email: str, password: str) -> Path:
        if not self.template_path.exists():
            raise FileNotFoundError(f"Шаблон не найден: {self.template_path}")
        with zipfile.ZipFile(self.template_path, "r") as source:
            content = source.read("content.xml").decode("utf-8")
        replacements = {
            "{{LOGIN}}": login,
            "{{DOMAIN_LOGIN}}": domain_login,
            "{{EMAIL}}": email,
            "{{PASSWORD}}": password,
        }
        missing = [token for token in PLACEHOLDERS if token not in content]
        if missing:
            raise RuntimeError("В ODT-шаблоне отсутствуют плейсхолдеры: " + ", ".join(missing))
        for token, value in replacements.items():
            content = content.replace(token, value)
        ET.fromstring(content)
        output = self.settings.generated_dir / f"Welcome_{login}_{datetime.now():%Y%m%d_%H%M%S}.odt"
        with tempfile.TemporaryDirectory(prefix="adhelper2_welcome_") as temp_dir:
            temp_path = Path(temp_dir)
            with zipfile.ZipFile(self.template_path, "r") as source:
                source.extractall(temp_path)
            (temp_path / "content.xml").write_text(content, encoding="utf-8", newline="")
            with zipfile.ZipFile(output, "w") as target:
                mime = temp_path / "mimetype"
                if mime.exists():
                    target.write(mime, "mimetype", compress_type=zipfile.ZIP_STORED)
                for item in temp_path.rglob("*"):
                    if item.is_file() and item != mime:
                        target.write(item, item.relative_to(temp_path).as_posix(), compress_type=zipfile.ZIP_DEFLATED)
        return output

    @staticmethod
    def print_document(path: Path) -> None:
        if os.name != "nt":
            raise RuntimeError("Печать через os.startfile поддерживается только в Windows")
        os.startfile(str(path), "print")  # type: ignore[attr-defined]
