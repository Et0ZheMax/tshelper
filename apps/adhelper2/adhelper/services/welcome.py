from __future__ import annotations

import os
import tempfile
import zipfile
from collections.abc import Iterable
from datetime import datetime
from html import escape
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

    def generate_contractor_response(
        self,
        *,
        login: str,
        password: str,
        domains: Iterable[DomainConfig],
        secret_url: str = "",
    ) -> Path:
        """Создаёт HTML-заготовку ответа для заявки сотрудника контрагента."""
        domain_list = list(domains)
        if not domain_list:
            raise ValueError("Для ответа не переданы созданные домены")

        sections: list[str] = []
        for domain in domain_list:
            domain_login = f"{domain.netbios}\\{login}"
            if domain.profile.casefold() == "omg":
                title = "Учётная запись OMG"
                instruction = (
                    'Для изменения временного пароля перейдите на '
                    '<a href="https://mail.cspfmba.ru">mail.cspfmba.ru</a> '
                    'и войдите под своей учётной записью.'
                )
            else:
                title = f"Учётная запись {domain.netbios or domain.label}"
                instruction = (
                    "Войдите в систему под своей учётной записью. "
                    "При первом входе система предложит изменить временный пароль."
                )
            credentials = "" if secret_url else f"""
                  <div class="credentials warning">
                    <div><span>Логин:</span> <code>{escape(domain_login)}</code></div>
                    <div><span>Пароль:</span> <code>{escape(password)}</code></div>
                  </div>
            """
            sections.append(f"""
                <section>
                  <h2>{escape(title)}</h2>
                  <p>Ваша учётная запись создана. Ей задан временный пароль.</p>
                  <p>{instruction}</p>
                  {credentials}
                  <p>После входа задайте новый пароль.</p>
                  <p><strong>Требования к новому паролю:</strong></p>
                  <ul>
                    <li>не менее <strong>15 символов</strong>;</li>
                    <li>заглавные и строчные буквы;</li>
                    <li>как минимум один специальный символ, например: <code>! &quot; № #</code>.</li>
                  </ul>
                </section>
            """)

        secret_block = f"""
  <div class="secret-link">
    <strong>Данные для входа переданы через защищённый сервис YoPass.</strong>
    <p><a href="{escape(secret_url, quote=True)}">Открыть логины и временный пароль</a></p>
    <p class="notice">Ссылка действует 7 дней и раскрывает данные <strong>ТОЛЬКО ОДИН РАЗ</strong>.</p>
  </div>
        """ if secret_url else """
  <div class="fallback">
    <strong>Внимание:</strong> защищённую ссылку YoPass создать не удалось.
    Временный пароль приведён ниже открытым текстом.
  </div>
        """
        document = f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>Данные учётной записи</title>
  <style>
    body {{ max-width: 760px; margin: 40px auto; padding: 0 24px; color: #202124;
            font: 16px/1.55 "Segoe UI", Arial, sans-serif; }}
    h1 {{ font-size: 24px; }} h2 {{ margin-top: 0; font-size: 20px; }}
    section {{ margin: 24px 0; padding: 20px 24px; border: 1px solid #d9dde3;
               border-radius: 12px; background: #fafbfc; }}
    .credentials {{ margin: 18px 0; padding: 14px 16px; border-left: 4px solid #2878d0;
                    background: white; }}
    .credentials div + div {{ margin-top: 8px; }}
    .credentials span {{ display: inline-block; min-width: 76px; font-weight: 600; }}
    .secret-link {{ margin: 24px 0; padding: 18px 20px; border: 1px solid #83b5e8;
                    border-radius: 12px; background: #eef6ff; }}
    .secret-link a {{ display: inline-block; padding: 10px 16px; border-radius: 7px;
                      color: white; background: #1769aa; font-weight: 600; text-decoration: none; }}
    .notice {{ color: #4e5968; font-size: 14px; }}
    .fallback {{ margin: 24px 0; padding: 16px 18px; border-left: 4px solid #d9822b;
                 background: #fff4e5; }}
    .warning {{ border-left-color: #d9822b; }}
    code {{ padding: 2px 5px; border-radius: 4px; background: #eef1f4;
            font: 15px Consolas, monospace; }}
  </style>
</head>
<body>
  <h1>Добрый день!</h1>
  {secret_block}
  {''.join(sections)}
</body>
</html>
"""
        output = self.settings.generated_dir / f"Contractor_{login}_{datetime.now():%Y%m%d_%H%M%S}.html"
        output.write_text(document, encoding="utf-8")
        return output

    @staticmethod
    def print_document(path: Path) -> None:
        if os.name != "nt":
            raise RuntimeError("Печать через os.startfile поддерживается только в Windows")
        os.startfile(str(path), "print")  # type: ignore[attr-defined]
