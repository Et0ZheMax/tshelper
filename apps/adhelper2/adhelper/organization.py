from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from .constants import OMG_OU_TREE
from .models import ParsedRequest


def normalize_unit(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower().replace("ё", "е"))


def canonical_unit(value: str, choices: Sequence[str]) -> str:
    """Возвращает справочное написание значения без нечёткого угадывания."""
    normalized = normalize_unit(value)
    if not normalized:
        return ""
    return next((item for item in choices if normalize_unit(item) == normalized), "")


def department_choices(tree: Mapping[str, Sequence[str]] = OMG_OU_TREE) -> list[str]:
    return list(tree)


def all_section_choices(tree: Mapping[str, Sequence[str]] = OMG_OU_TREE) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for sections in tree.values():
        for section in sections:
            key = normalize_unit(section)
            if key and key not in seen:
                seen.add(key)
                values.append(section)
    return values


def sections_for_department(
    department: str,
    tree: Mapping[str, Sequence[str]] = OMG_OU_TREE,
) -> list[str]:
    canonical = canonical_unit(department, list(tree))
    return list(tree.get(canonical, ())) if canonical else []


def departments_for_section(
    section: str,
    tree: Mapping[str, Sequence[str]] = OMG_OU_TREE,
) -> list[str]:
    normalized = normalize_unit(section)
    if not normalized:
        return []
    return [
        department
        for department, sections in tree.items()
        if any(normalize_unit(item) == normalized for item in sections)
    ]


def get_omg_department_section(request: ParsedRequest) -> tuple[str, str]:
    dep_parts = [item.strip() for item in request.department.split("/") if item.strip()]
    department = ""
    section = ""
    departments = department_choices()
    if dep_parts:
        department = canonical_unit(dep_parts[0], departments)
    if department:
        if len(dep_parts) > 1:
            section = canonical_unit(dep_parts[-1], sections_for_department(department))
    elif dep_parts:
        department = canonical_unit(dep_parts[-1], departments)
    if not department:
        department = canonical_unit(request.management, departments)
    if not department and dep_parts:
        candidate = dep_parts[-1]
        parents = departments_for_section(candidate)
        if len(parents) == 1:
            department = parents[0]
            section = canonical_unit(candidate, sections_for_department(department))
    return department[:64], section[:64]


def get_pak_department(request: ParsedRequest) -> str:
    source = request.department or request.management
    parts = [item.strip() for item in source.split("/") if item.strip()]
    return (parts[-1] if parts else source).lower()[:64]
