from __future__ import annotations

import re
from dataclasses import fields

from ..models import ParsedRequest

FIELD_MAP = {
    "Фамилия": "last_name",
    "Имя": "first_name",
    "Отчество": "middle_name",
    "Есть ли у вас фотография сотрудника": "has_photo",
    "Руководитель": "manager_name",
    "Управление": "management",
    "Отдел": "department",
    "Должность сотрудника": "title",
    "Дата выхода сотрудника": "start_date",
    "Режим работы сотрудника": "work_mode",
    "Номер кабинета": "office_room",
    "Предоставить электронный почтовый ящик для сотрудника": "need_mail",
    "Предоставить внутренний телефонный номер для сотрудника": "need_internal_phone",
    "Номер сотового телефона для переадресации": "mobile_phone",
    "Оборудование необходимое сотруднику": "equipment",
    "Операционная система для ноутбука в офисе": "office_os",
    "Операционная система для компьютера в офисе": "office_os",
    "Предоставить доступ к серверам": "need_servers_access",
    "Предоставить доступ к папкам": "need_folders_access",
    "Примечание": "notes",
}

BOOL_FIELDS = {
    "has_photo",
    "need_mail",
    "need_internal_phone",
    "need_servers_access",
    "need_folders_access",
}

# Маркер пункта заявки. Он намеренно распознаёт и неизвестные пункты, чтобы
# значение известного поля не захватывало весь оставшийся однострочный текст.
_NUMBERED_FIELD_RE = re.compile(
    r"(?<!\S)(?P<number>\d{1,3})\s*(?:\)\s*|\.\s+)(?P<label>[^:\r\n]{1,180}?)\s*:\s*",
    re.IGNORECASE,
)

# Запасной вариант для заявок без нумерации, но с нормальными переносами строк.
_LINE_FIELD_RE = re.compile(r"^\s*(?P<label>[^:]{1,180}?)\s*:\s*(?P<value>.*)$")


def _normalize_label(value: str) -> str:
    text = (value or "").replace("\xa0", " ").strip().lower().replace("ё", "е")
    text = re.sub(r"\s+", " ", text)
    return text.rstrip(" ?.!;:")


_NORMALIZED_FIELD_MAP = {
    _normalize_label(label): internal for label, internal in FIELD_MAP.items()
}


def _match_internal_field(label: str) -> str | None:
    normalized = _normalize_label(label)
    if not normalized:
        return None

    direct = _NORMALIZED_FIELD_MAP.get(normalized)
    if direct:
        return direct

    # В старых и новых формах после текста вопроса могут добавляться пояснения.
    # Сохраняем прежнюю логику startswith, но сравниваем нормализованные строки.
    for known_label, internal in _NORMALIZED_FIELD_MAP.items():
        if normalized.startswith(known_label):
            return internal
    return None


def parse_bool(value: str) -> bool:
    return value.strip().lower() in {"да", "yes", "y", "true", "1", "+"}


def format_request_text(text: str) -> str:
    """Приводит вставленный текст заявки к читаемому построчному виду.

    GLPI/браузер иногда отдаёт все пункты одной строкой. Перед каждым маркером
    вида ``2) Имя:`` добавляется перенос, при этом значения телефонов и дат не
    затрагиваются.
    """
    normalized = (text or "").replace("\r\n", "\n").replace("\r", "\n").replace("\xa0", " ")
    matches = list(_NUMBERED_FIELD_RE.finditer(normalized))
    if len(matches) < 2:
        return normalized.strip()

    chunks: list[str] = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(normalized)
        prefix = normalized[start:match.end()].strip()
        value = normalized[match.end():end].strip()
        chunks.append(f"{prefix} {value}" if value else prefix)

    leading = normalized[:matches[0].start()].strip()
    if leading:
        chunks.insert(0, leading)
    return "\n".join(chunk for chunk in chunks if chunk).strip()


def extract_request_fields(text: str) -> dict[str, str]:
    """Извлекает распознанные поля и их исходные строковые значения.

    Поддерживаются три реальных варианта буфера обмена: нормальные строки,
    полностью однострочный текст и смешанный формат, где часть пунктов имеет
    номера, а часть — нет.
    """
    source = (text or "").replace("\xa0", " ")
    result: dict[str, str] = {}

    for raw_line in source.splitlines() or [source]:
        line = raw_line.strip()
        if not line:
            continue

        numbered_matches = list(_NUMBERED_FIELD_RE.finditer(line))
        if numbered_matches:
            for index, match in enumerate(numbered_matches):
                end = numbered_matches[index + 1].start() if index + 1 < len(numbered_matches) else len(line)
                target = _match_internal_field(match.group("label"))
                if not target:
                    continue
                value = line[match.end():end].strip()
                result[target] = re.sub(r"\s+", " ", value)
            continue

        clean_line = re.sub(r"^\s*\d+\s*[.)]\s*", "", line)
        match = _LINE_FIELD_RE.match(clean_line)
        if not match:
            continue
        target = _match_internal_field(match.group("label"))
        if not target:
            continue
        result[target] = match.group("value").strip()

    return result


def parse_request(text: str) -> ParsedRequest:
    values = {field.name: field.default for field in fields(ParsedRequest)}
    for target, raw_value in extract_request_fields(text).items():
        values[target] = parse_bool(raw_value) if target in BOOL_FIELDS else raw_value
    return ParsedRequest(**values)


def validation_errors(request: ParsedRequest) -> list[str]:
    errors: list[str] = []
    if not request.last_name:
        errors.append("Не указана фамилия")
    if not request.first_name:
        errors.append("Не указано имя")
    return errors
