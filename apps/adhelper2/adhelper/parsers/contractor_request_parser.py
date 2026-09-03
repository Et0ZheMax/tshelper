from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import fields

from ..models import DomainConfig, ParsedRequest


_EMPLOYEE_RE = re.compile(
    r"(?im)^\s*([А-ЯЁ][А-ЯЁа-яё'-]+)\s+([А-ЯЁ][А-ЯЁа-яё'-]+)\s+"
    r"([А-ЯЁ][А-ЯЁа-яё'-]+)\s*(?:\(([^)]+)\))?\s*$"
)
_PHONE_RE = re.compile(r"(?im)^\s*Мобильный\s+телефон\s+сотрудника\s*:\s*([^\r\n]+)")
_EMAIL_RE = re.compile(r"(?im)^\s*Почта\s+сотрудника\s*:\s*([^\s]+)")
_COMPANY_RE = re.compile(
    r"(?i)контрагента\s+((?:АО|ООО|ПАО|ИП)\s*(?:[«\"])[^»\"]+(?:[»\"]))"
)


def extract_contractor_request_fields(text: str) -> dict[str, str]:
    """Извлекает карточку сотрудника контрагента из свободного текста заявки."""
    source = (text or "").replace("\xa0", " ").replace(r"\@", "@")
    result: dict[str, str] = {}

    employee = _EMPLOYEE_RE.search(source)
    if employee:
        result.update({
            "last_name": employee.group(1).strip(),
            "first_name": employee.group(2).strip(),
            "middle_name": employee.group(3).strip(),
            "title": (employee.group(4) or "").strip(),
            "department": "outsource",
        })

    phone = _PHONE_RE.search(source)
    if phone:
        result["mobile_phone"] = phone.group(1).strip()

    email = _EMAIL_RE.search(source)
    if email:
        result["email"] = email.group(1).strip().rstrip(".,;")
        result["need_mail"] = "Да"

    company = _COMPANY_RE.search(source)
    if company:
        result["company"] = company.group(1).replace('"', '«', 1).replace('"', '»', 1).strip()

    return result


def parse_contractor_request(text: str) -> ParsedRequest:
    values = {field.name: field.default for field in fields(ParsedRequest)}
    for name, value in extract_contractor_request_fields(text).items():
        values[name] = value == "Да" if name == "need_mail" else value
    return ParsedRequest(**values)


def requested_domain_names(text: str, available_names: list[str]) -> set[str]:
    """Сопоставляет упомянутые в заявке домены с внутренними именами настроек."""
    normalized = (text or "").casefold()
    selected: set[str] = set()
    for name in available_names:
        aliases = {name.casefold(), name.casefold().replace("-", ".")}
        if name == "omg-cspfmba":
            aliases.update({"omg", "omg.cspfmba", "omg.cspfmba.ru"})
        elif name == "pak-cspmz":
            aliases.update({"pak-cspmz", "pak-cspmz.ru"})
        if any(re.search(rf"(?<![\w-]){re.escape(alias)}(?![\w-])", normalized) for alias in aliases):
            selected.add(name)
    return selected


def contractor_target_ous(domains: Iterable[DomainConfig]) -> dict[str, str]:
    """Возвращает соседний с базовым контейнер outsource для доменов без профиля OMG."""
    result: dict[str, str] = {}
    for domain in domains:
        if domain.profile.casefold() == "omg":
            continue
        base_ou = domain.ou_dn.strip()
        if base_ou.casefold().startswith("ou=outsource,"):
            result[domain.name] = base_ou
        elif base_ou:
            users_parent = re.search(r"(?i)(OU=Users,.*)$", base_ou)
            if users_parent:
                result[domain.name] = f"OU=outsource,{users_parent.group(1)}"
            else:
                _first_rdn, separator, parent_dn = base_ou.partition(",")
                result[domain.name] = f"OU=outsource,{parent_dn}" if separator else base_ou
    return result
