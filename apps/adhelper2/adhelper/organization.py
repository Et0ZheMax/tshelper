from __future__ import annotations

import re

from .constants import OMG_OU_TREE
from .models import ParsedRequest


def normalize_unit(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower().replace("ё", "е"))


def get_omg_department_section(request: ParsedRequest) -> tuple[str, str]:
    dep_parts = [normalize_unit(item) for item in request.department.split("/") if item.strip()]
    management = normalize_unit(request.management)
    department = ""
    section = ""
    if dep_parts and dep_parts[0] in OMG_OU_TREE:
        department = dep_parts[0]
        if len(dep_parts) > 1:
            section = dep_parts[-1]
    elif dep_parts and dep_parts[-1] in OMG_OU_TREE:
        department = dep_parts[-1]
    if not department and management in OMG_OU_TREE:
        department = management
    if not department and dep_parts:
        candidate = dep_parts[-1]
        parents = [parent for parent, sections in OMG_OU_TREE.items() if candidate in sections]
        if len(parents) == 1:
            department = parents[0]
            section = candidate
    if section not in OMG_OU_TREE.get(department, []):
        section = ""
    return department[:64], section[:64]


def get_pak_department(request: ParsedRequest) -> str:
    source = request.department or request.management
    parts = [item.strip() for item in source.split("/") if item.strip()]
    return (parts[-1] if parts else source).lower()[:64]
