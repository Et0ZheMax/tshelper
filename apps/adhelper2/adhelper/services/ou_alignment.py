from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any

from ..models import DomainConfig, UserRecord
from ..utils import normalize_text


@dataclass(slots=True)
class OUAlignment:
    status: str = "not_applicable"  # ok | mismatch | unresolved | not_applicable
    current_dn: str = ""
    current_name: str = ""
    expected_dn: str = ""
    expected_name: str = ""
    matched_attribute: str = ""
    matched_value: str = ""
    confidence: float = 0.0
    message: str = ""
    candidates: list[dict[str, Any]] = field(default_factory=list)

    @property
    def can_move(self) -> bool:
        return self.status == "mismatch" and bool(self.expected_dn)


def parent_dn(dn: str) -> str:
    """Return parent DN, respecting escaped commas in the first RDN."""
    escaped = False
    for index, char in enumerate(dn or ""):
        if char == "\\" and not escaped:
            escaped = True
            continue
        if char == "," and not escaped:
            return dn[index + 1 :].strip()
        escaped = False
    return ""


def rdn_name(dn: str) -> str:
    first = (dn or "").split(",", 1)[0]
    if "=" not in first:
        return first
    return first.split("=", 1)[1].replace("\\,", ",").strip()


def _stem_token(token: str) -> str:
    token = re.sub(r"[^0-9a-zа-я]+", "", token.casefold().replace("ё", "е"))
    if len(token) <= 4:
        return token
    # A tiny conservative Russian ending normalizer. It is intentionally not a
    # full morphological stemmer: we only need robust OU/attribute comparison.
    endings = (
        "иями", "ями", "ами", "ого", "ему", "ому", "ыми", "ими",
        "иях", "ах", "ях", "ией", "ией", "ий", "ии", "ия", "ию",
        "ие", "ые", "ой", "ый", "ая", "ое", "ые", "ов", "ев", "ей",
        "ам", "ям", "ом", "ем", "у", "ю", "а", "я", "ы", "и", "е",
    )
    for ending in endings:
        if token.endswith(ending) and len(token) - len(ending) >= 4:
            return token[: -len(ending)]
    return token


def _normalized_tokens(value: str) -> list[str]:
    text = normalize_text(value)
    return [_stem_token(token) for token in re.findall(r"[0-9a-zа-я]+", text, flags=re.IGNORECASE) if token]


def name_similarity(left: str, right: str) -> float:
    left_n = normalize_text(left)
    right_n = normalize_text(right)
    if not left_n or not right_n:
        return 0.0
    if left_n == right_n:
        return 1.0

    left_tokens = _normalized_tokens(left_n)
    right_tokens = _normalized_tokens(right_n)
    if not left_tokens or not right_tokens:
        return SequenceMatcher(None, left_n, right_n).ratio()

    left_set = set(left_tokens)
    right_set = set(right_tokens)
    intersection = len(left_set & right_set)
    union = len(left_set | right_set)
    token_score = intersection / union if union else 0.0
    sequence_score = SequenceMatcher(None, " ".join(left_tokens), " ".join(right_tokens)).ratio()
    return max(token_score, sequence_score)


def _candidate_rows(
    ous: list[dict[str, Any]],
    query: str,
    *,
    required_parent: str = "",
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    required_parent_cf = required_parent.casefold()
    for item in ous:
        name = str(item.get("name") or item.get("Name") or "").strip()
        dn = str(item.get("dn") or item.get("DistinguishedName") or "").strip()
        if not name or not dn:
            continue
        actual_parent = parent_dn(dn)
        hierarchy_match = not required_parent or actual_parent.casefold() == required_parent_cf
        score = name_similarity(query, name)
        if required_parent and not hierarchy_match:
            # Keep a few global alternatives for diagnostics, but strongly prefer
            # the expected branch of the OU hierarchy.
            score *= 0.72
        if score >= 0.45 or (required_parent and hierarchy_match):
            rows.append(
                {
                    "name": name,
                    "dn": dn,
                    "parent_dn": actual_parent,
                    "score": round(score, 4),
                    "hierarchy_match": hierarchy_match,
                }
            )
    rows.sort(key=lambda row: (-float(row["score"]), not bool(row["hierarchy_match"]), str(row["name"]).casefold()))
    return rows


def _choose(rows: list[dict[str, Any]], threshold: float = 0.84) -> dict[str, Any] | None:
    if not rows:
        return None
    top = rows[0]
    top_score = float(top["score"])
    if top_score < threshold:
        return None
    if len(rows) > 1:
        second = float(rows[1]["score"])
        # Never auto-pick between effectively tied OUs. This matters when the
        # same section name exists under more than one management branch.
        if top_score - second < 0.03:
            return None
        if top_score < 0.97 and top_score - second < 0.08:
            return None
    return top


def analyze_ou_alignment(domain: DomainConfig, user: UserRecord, ous: list[dict[str, Any]]) -> OUAlignment:
    current_dn = parent_dn(user.dn)
    current_name = rdn_name(current_dn)

    if domain.profile != "omg":
        return OUAlignment(
            status="not_applicable",
            current_dn=current_dn,
            current_name=current_name,
            message="Автопроверка оргструктуры включена для профиля OMG.",
        )

    if user.is_fired:
        return OUAlignment(
            status="not_applicable",
            current_dn=current_dn,
            current_name=current_name,
            message="Пользователь находится в сценарии увольнения; автоматический перенос OU отключён.",
        )

    department = (user.department or "").strip()
    section = (user.section or "").strip()
    if not department and not section:
        return OUAlignment(
            status="unresolved",
            current_dn=current_dn,
            current_name=current_name,
            message="Не заполнены department/section — целевой OU определить нельзя.",
        )

    department_rows = _candidate_rows(ous, department) if department else []
    department_match = _choose(department_rows, threshold=0.88) if department else None

    expected: dict[str, Any] | None = None
    candidates: list[dict[str, Any]] = []
    matched_attribute = ""
    matched_value = ""

    if section:
        required_parent = str(department_match.get("dn") or "") if department_match else ""
        section_rows = _candidate_rows(ous, section, required_parent=required_parent)
        # If department is filled but itself cannot be mapped, do not make an
        # automatic cross-branch move based on section alone. Offer candidates
        # for manual selection instead.
        if not department or department_match is not None:
            expected = _choose(section_rows, threshold=0.84)
        candidates = section_rows[:12]
        matched_attribute = "section"
        matched_value = section
    elif department:
        expected = department_match
        candidates = department_rows[:12]
        matched_attribute = "department"
        matched_value = department

    if expected is None:
        attr_name = "section (Отдел)" if section else "department (Управление)"
        return OUAlignment(
            status="unresolved",
            current_dn=current_dn,
            current_name=current_name,
            matched_attribute=matched_attribute,
            matched_value=matched_value,
            message=f"Не удалось однозначно сопоставить {attr_name} с OU. Нужен ручной выбор.",
            candidates=candidates,
        )

    expected_dn = str(expected.get("dn") or "")
    expected_name = str(expected.get("name") or "")
    confidence = float(expected.get("score") or 0.0)
    same = bool(current_dn) and current_dn.casefold() == expected_dn.casefold()
    if same:
        return OUAlignment(
            status="ok",
            current_dn=current_dn,
            current_name=current_name,
            expected_dn=expected_dn,
            expected_name=expected_name,
            matched_attribute=matched_attribute,
            matched_value=matched_value,
            confidence=confidence,
            message="Текущий OU соответствует организационным атрибутам пользователя.",
            candidates=candidates,
        )

    return OUAlignment(
        status="mismatch",
        current_dn=current_dn,
        current_name=current_name,
        expected_dn=expected_dn,
        expected_name=expected_name,
        matched_attribute=matched_attribute,
        matched_value=matched_value,
        confidence=confidence,
        message="Текущий OU не соответствует организационным атрибутам пользователя.",
        candidates=candidates,
    )
