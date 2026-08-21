from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Callable, Iterable

from ..models import OperationResult, StepResult, UserRecord
from ..utils import operator_info
from .ad_service import ADService
from .audit import AuditRepository


ACCESS_READ = "ro"
ACCESS_WRITE = "rw"
ACCESS_ANY = "any"


@dataclass(slots=True)
class GroupRecord:
    domain: str
    name: str = ""
    sam: str = ""
    description: str = ""
    info: str = ""
    dn: str = ""
    managed_by: str = ""
    scope: str = ""
    category: str = ""

    @classmethod
    def from_mapping(cls, item: dict[str, Any]) -> "GroupRecord":
        return cls(
            domain=str(item.get("domain") or ""),
            name=str(item.get("name") or item.get("Name") or ""),
            sam=str(item.get("sam") or item.get("samAccountName") or item.get("SamAccountName") or ""),
            description=str(item.get("description") or item.get("Description") or ""),
            info=str(item.get("info") or item.get("Info") or ""),
            dn=str(item.get("dn") or item.get("distinguishedName") or item.get("DistinguishedName") or ""),
            managed_by=str(item.get("managedBy") or item.get("managed_by") or item.get("ManagedBy") or ""),
            scope=str(item.get("scope") or item.get("groupScope") or item.get("GroupScope") or ""),
            category=str(item.get("category") or item.get("groupCategory") or item.get("GroupCategory") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ParsedAccessRequest:
    raw_text: str = ""
    person_text: str = ""
    person_search: str = ""
    path: str = ""
    file_name: str = ""
    access_mode: str = ACCESS_ANY

    @property
    def search_text(self) -> str:
        return self.path or self.file_name or self.raw_text


@dataclass(slots=True)
class AclEntry:
    identity: str
    sam: str
    rights: str
    access_type: str = ""
    inherited: bool = False

    @classmethod
    def from_mapping(cls, item: dict[str, Any]) -> "AclEntry":
        identity = str(item.get("identity") or "")
        sam = str(item.get("sam") or "")
        if not sam and "\\" in identity:
            sam = identity.rsplit("\\", 1)[-1]
        return cls(
            identity=identity,
            sam=sam,
            rights=str(item.get("rights") or ""),
            access_type=str(item.get("accessType") or item.get("access_type") or ""),
            inherited=bool(item.get("inherited", False)),
        )


@dataclass(slots=True)
class GroupMatch:
    group: GroupRecord
    score: int
    access_mode: str
    reasons: list[str]
    acl_rights: str = ""


_STOP_WORDS = {
    "доступ", "доступа", "предоставить", "предоставления", "для", "сотрудника", "сотруднику",
    "сотрудник", "пользователю", "пользователь", "к", "файлу", "файл", "файла", "папке", "папку",
    "папки", "путь", "название", "на", "в", "и", "без", "редактирования", "редактирование",
    "чтения", "чтение", "записи", "запись", "только", "просим", "коллеги", "необходим", "необходимо",
    "необходима", "своевременной", "подготовки", "отчетов", "отчётов", "проекту", "по", "тип", "права",
    "прав", "общий", "диск", "read", "write", "modify", "readonly", "readwrite", "ro", "rw",
}

_READ_HINTS = (
    "только чтение", "только для чтения", "для чтения", "доступ на чтение", "без редактирования",
    "без изменения", "без записи", "без права записи", "только просмотр", "просмотр", "read only", "readonly", " read ",
)
_WRITE_HINTS = (
    "чтение/запись", "запись/чтение", "чтение и запись", "запись и чтение", "редактирование",
    "редактировать", "изменение", "изменять", "доступ на запись", "для записи", "read/write", "read write",
    "modify", "write",
)


def normalize_search_text(value: str) -> str:
    text = str(value or "").casefold().replace("ё", "е")
    text = text.replace("\\", " / ").replace("_", " ").replace("-", " ")
    text = re.sub(r"[^0-9a-zа-я/]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def search_tokens(value: str) -> list[str]:
    normalized = normalize_search_text(value).replace("/", " ")
    result: list[str] = []
    seen: set[str] = set()
    for token in normalized.split():
        if len(token) < 2 or token in _STOP_WORDS or re.fullmatch(r"[a-z]:?", token):
            continue
        if token not in seen:
            seen.add(token)
            result.append(token)
    return result


def infer_access_mode(text: str) -> str:
    normalized = " " + normalize_search_text(text) + " "
    # Сначала явные указания записи: они сильнее одиночного слова «чтение».
    if any(normalize_search_text(hint) in normalized for hint in _WRITE_HINTS):
        return ACCESS_WRITE
    if any(normalize_search_text(hint) in normalized for hint in _READ_HINTS):
        return ACCESS_READ
    if re.search(r"(?:^|[_\-.\s])(rw|write|modify)(?:$|[_\-.\s])", normalized):
        return ACCESS_WRITE
    if re.search(r"(?:^|[_\-.\s])(ro|read|readonly)(?:$|[_\-.\s])", normalized):
        return ACCESS_READ
    return ACCESS_ANY


def infer_group_access(group: GroupRecord) -> str:
    name = str(group.sam or group.name or "").casefold()
    # Суффикс в имени считаем наиболее надёжным сигналом. Это защищает от старых/ошибочных Description.
    if re.search(r"(?:^|[_\-.])(ro|read|readonly)$", name):
        return ACCESS_READ
    if re.search(r"(?:^|[_\-.])(rw|write|modify)$", name):
        return ACCESS_WRITE
    description = normalize_search_text(f"{group.description} {group.info}")
    if "доступ на запись" in description or "чтение запись" in description or "запись чтение" in description:
        return ACCESS_WRITE
    if "доступ на чтение" in description or "только чтение" in description:
        return ACCESS_READ
    return ACCESS_ANY


def _extract_person(text: str) -> tuple[str, str]:
    patterns = (
        r"(?:для\s+)?сотрудник(?:а|у|ом)?\s+([А-ЯЁA-Z][^\n\r,;:.]{1,100})",
        r"пользовател(?:ю|я)\s+([А-ЯЁA-Z][^\n\r,;:.]{1,100})",
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if not match:
            continue
        candidate = re.sub(r"\s+", " ", match.group(1)).strip(" .-–—")
        words = candidate.split()
        # Иногда форма GLPI вставляет подразделение прямо перед ФИО:
        # «для сотрудника ЛБиММИ Кикот Александры». Короткий токен с несколькими
        # заглавными буквами считаем аббревиатурой подразделения и не используем в AD-поиске.
        if len(words) >= 3:
            uppercase_count = sum(1 for ch in words[0] if ch.isupper())
            if len(words[0]) <= 14 and uppercase_count >= 3:
                words = words[1:]
                candidate = " ".join(words)
        # Обычно первым идёт фамилия. По ней AD-поиск устойчив к падежу имени: «Александры» vs «Александра».
        search = words[0] if words else candidate
        return candidate, search
    return "", ""


def _extract_path(text: str) -> str:
    # Путь после явной метки — самый безопасный вариант.
    match = re.search(r"(?im)^\s*путь(?:\s+к\s+(?:файлу|папке))?\s*:\s*(.+?)\s*$", text)
    if match:
        value = match.group(1).strip().strip('"')
        if value:
            return value
    # Windows drive / UNC из произвольной строки заявки.
    match = re.search(r"(?i)([A-Z]:\\[^\r\n]+)", text)
    if match:
        return match.group(1).strip().strip('"')
    match = re.search(r"(\\\\[^\r\n]+)", text)
    if match:
        return match.group(1).strip().strip('"')
    return ""


def _extract_file_name(text: str) -> str:
    match = re.search(r"(?im)^\s*название\s+файла\s*:\s*(.+?)\s*$", text)
    return match.group(1).strip().strip('"') if match else ""


def parse_access_request(text: str) -> ParsedAccessRequest:
    raw = str(text or "").strip()
    person_text, person_search = _extract_person(raw)
    return ParsedAccessRequest(
        raw_text=raw,
        person_text=person_text,
        person_search=person_search,
        path=_extract_path(raw),
        file_name=_extract_file_name(raw),
        access_mode=infer_access_mode(raw),
    )


def _path_tail(path: str) -> str:
    segments = [part.strip() for part in re.split(r"[\\/]+", str(path or "")) if part.strip()]
    return normalize_search_text(segments[-1]) if segments else ""


def rank_groups(
    groups: Iterable[GroupRecord],
    query: str,
    desired_access: str = ACCESS_ANY,
    *,
    resource_path: str = "",
    acl_entries: Iterable[AclEntry] | None = None,
    limit: int = 50,
) -> list[GroupMatch]:
    query = str(query or "").strip()
    if not query:
        return []
    desired_access = desired_access if desired_access in {ACCESS_READ, ACCESS_WRITE, ACCESS_ANY} else ACCESS_ANY
    query_normalized = normalize_search_text(query)
    tokens = search_tokens(query)
    tail = _path_tail(resource_path)
    acl_by_sam: dict[str, AclEntry] = {}
    for entry in acl_entries or []:
        if entry.sam:
            acl_by_sam[entry.sam.casefold()] = entry

    matches: list[GroupMatch] = []
    for group in groups:
        name_norm = normalize_search_text(group.sam or group.name)
        desc_norm = normalize_search_text(group.description)
        info_norm = normalize_search_text(group.info)
        blob = f"{name_norm} {desc_norm} {info_norm}".strip()
        score = 0.0
        reasons: list[str] = []
        has_evidence = False

        acl_entry = acl_by_sam.get((group.sam or group.name).casefold())
        if acl_entry is not None:
            score += 48
            has_evidence = True
            rights = acl_entry.rights or "права ресурса"
            reasons.append(f"есть в ACL: {rights}")

        if tail and tail in desc_norm:
            score += 52
            has_evidence = True
            reasons.append("совпал конечный каталог")

        if query_normalized and len(query_normalized) >= 4 and query_normalized in blob:
            score += 35
            has_evidence = True
            reasons.append("точная фраза")

        hits = 0
        fuzzy_hits = 0
        name_hits = 0
        blob_words = set(search_tokens(blob))
        for token in tokens:
            if token in name_norm:
                score += 8
                hits += 1
                name_hits += 1
            elif token in desc_norm:
                score += 6
                hits += 1
            elif token in info_norm:
                score += 4
                hits += 1
            elif len(token) >= 4 and blob_words:
                # Небольшая нечёткая поправка позволяет пережить опечатки вроде
                # «централная» → «центральной», не превращая поиск в шумный full fuzzy.
                candidates = [word for word in blob_words if abs(len(word) - len(token)) <= 3]
                ratio = max((SequenceMatcher(None, token, word).ratio() for word in candidates), default=0.0)
                same_stem = len(token) >= 7 and any(word.startswith(token[:6]) for word in candidates)
                if ratio >= 0.82 or same_stem:
                    score += 4 * max(ratio, 0.82 if same_stem else 0.0)
                    fuzzy_hits += 1
        if tokens:
            coverage = (hits + fuzzy_hits * 0.65) / len(tokens)
            score += coverage * 28
            if hits or fuzzy_hits:
                has_evidence = True
            if hits >= 2:
                reasons.append(f"ключевые слова {hits}/{len(tokens)}")
            elif name_hits:
                reasons.append("совпало имя группы")
            elif hits == 1:
                reasons.append("совпало ключевое слово")
            if fuzzy_hits:
                reasons.append(f"нечётких совпадений: {fuzzy_hits}")

        if tail and tail not in desc_norm:
            parts = [normalize_search_text(part) for part in re.split(r"[\\/]+", group.description) if part.strip()]
            ratio = max((SequenceMatcher(None, tail, part).ratio() for part in parts if part), default=0.0)
            if ratio >= 0.72:
                score += 15 * ratio
                has_evidence = True
                reasons.append("похожее имя каталога")

        if not has_evidence:
            continue

        group_access = infer_group_access(group)
        if desired_access in {ACCESS_READ, ACCESS_WRITE}:
            if group_access == desired_access:
                score += 20
                reasons.append("тип доступа совпал")
            elif group_access in {ACCESS_READ, ACCESS_WRITE}:
                score -= 40
                reasons.append("тип доступа не совпал")

        bounded = max(0, min(100, round(score)))
        if bounded >= 8:
            matches.append(
                GroupMatch(
                    group=group,
                    score=bounded,
                    access_mode=group_access,
                    reasons=reasons[:4],
                    acl_rights=acl_entry.rights if acl_entry else "",
                )
            )

    matches.sort(key=lambda item: (-item.score, item.group.sam.casefold(), item.group.name.casefold()))
    return matches[: max(1, limit)]


class AccessManagementService:
    def __init__(
        self,
        ad: ADService,
        audit: AuditRepository,
        cache_path: Path,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self.ad = ad
        self.audit = audit
        self.cache_path = Path(cache_path)
        self.logger = logger or (lambda _message: None)
        self._cache: dict[str, list[GroupRecord]] = {}
        self._updated_at: dict[str, str] = {}
        self._load_cache()

    def _load_cache(self) -> None:
        if not self.cache_path.exists():
            return
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        domains = payload.get("domains") if isinstance(payload, dict) else None
        if not isinstance(domains, dict):
            return
        updated = payload.get("updated_at") if isinstance(payload, dict) else None
        if isinstance(updated, dict):
            self._updated_at = {str(key): str(value) for key, value in updated.items()}
        for domain, rows in domains.items():
            if isinstance(rows, list):
                self._cache[str(domain)] = [GroupRecord.from_mapping(row) for row in rows if isinstance(row, dict)]

    def _save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": dict(self._updated_at),
            "domains": {
                domain: [group.to_dict() for group in groups]
                for domain, groups in self._cache.items()
            },
        }
        temp = self.cache_path.with_suffix(".tmp")
        temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(self.cache_path)

    def configured_domains(self) -> list[str]:
        return [domain.name for domain in self.ad.domains if domain.group_search_base]

    def groups(self, domain_name: str) -> list[GroupRecord]:
        return list(self._cache.get(domain_name, []))

    def updated_at(self, domain_name: str) -> str:
        return self._updated_at.get(domain_name, "")

    def refresh_groups(self, domain_name: str, progress=None) -> list[GroupRecord]:
        domain = self.ad.domain_by_name.get(domain_name)
        if domain is None:
            raise ValueError(f"Не найдена конфигурация домена: {domain_name}")
        if not domain.group_search_base:
            raise ValueError(f"Для домена {domain.label} не настроен OU групп доступа")
        if progress:
            progress("groups", f"{domain.label}: читаем группы из {domain.group_search_base}…")
        rows = self.ad.list_access_groups(domain_name)
        groups = [GroupRecord.from_mapping(item) for item in rows]
        self._cache[domain_name] = groups
        self._updated_at[domain_name] = datetime.now().astimezone().isoformat(timespec="seconds")
        self._save_cache()
        self.logger(f"[access] {domain_name}: индекс обновлён, {len(groups)} групп")
        if progress:
            progress("groups", f"{domain.label}: индекс обновлён — {len(groups)} групп")
        return list(groups)

    def inspect_acl(self, path: str) -> list[AclEntry]:
        if not str(path or "").strip():
            return []
        payload = self.ad.inspect_resource_acl(path)
        if not isinstance(payload, dict) or not payload.get("available"):
            return []
        rows = payload.get("entries") or []
        return [AclEntry.from_mapping(item) for item in rows if isinstance(item, dict)]

    def search(
        self,
        domain_name: str,
        query: str,
        desired_access: str = ACCESS_ANY,
        *,
        resource_path: str = "",
        refresh_if_empty: bool = True,
        inspect_acl: bool = True,
        progress=None,
    ) -> tuple[list[GroupMatch], list[AclEntry], int]:
        groups = self.groups(domain_name)
        if not groups and refresh_if_empty:
            groups = self.refresh_groups(domain_name, progress=progress)
        acl_entries: list[AclEntry] = []
        if inspect_acl and resource_path:
            if progress:
                progress("acl", f"Проверяем ACL ресурса {resource_path}…")
            try:
                acl_entries = self.inspect_acl(resource_path)
            except Exception as exc:
                self.logger(f"[access] ACL недоступен для {resource_path}: {exc}")
        matches = rank_groups(
            groups,
            query,
            desired_access,
            resource_path=resource_path,
            acl_entries=acl_entries,
        )
        return matches, acl_entries, len(groups)

    def add_member(self, user: UserRecord, group: GroupRecord, progress=None) -> OperationResult:
        if user.domain != group.domain:
            raise ValueError("Пользователь и группа должны находиться в одном домене")
        operation = OperationResult("group_access", user.display_name or user.sam, operator=operator_info()["username"])
        operation.data.update({
            "domain": user.domain,
            "sam": user.sam,
            "group": group.sam or group.name,
            "group_dn": group.dn,
            "description": group.description,
        })
        step = StepResult("membership", f"Добавление в группу {group.sam or group.name}")
        operation.steps.append(step)
        step.start()
        try:
            if progress:
                progress("membership", f"Проверяем членство {user.sam} → {group.sam or group.name}…")
            result = self.ad.manage_group_membership(user, group.dn or group.sam, action="add")
            operation.data["membership"] = result
            already = bool(result.get("already_member"))
            changed = bool(result.get("changed"))
            if already and not changed:
                step.finish("warning", "Пользователь уже состоит в группе", result)
                operation.warnings.append("Пользователь уже состоял в выбранной группе")
                operation.close("warning")
            else:
                step.finish("success", "Пользователь добавлен в группу", result)
                operation.close("success")
            return operation
        except Exception as exc:
            step.finish("failed", str(exc))
            operation.errors.append(str(exc))
            operation.close("failed")
            raise
        finally:
            if not operation.finished_at:
                operation.close("failed")
            self.audit.save(operation)
