from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models import DomainConfig, UserRecord
from ..settings import SettingsStore
from ..utils import normalize_text
from .powershell import PowerShellClient
from .ou_alignment import OUAlignment, analyze_ou_alignment


@dataclass(slots=True)
class OUResolution:
    selected_dn: str = ""
    confidence: str = "none"
    candidates: list[dict[str, Any]] | None = None
    source: str = "none"


class OUResolver:
    def __init__(self, ps: PowerShellClient, settings: SettingsStore) -> None:
        self.ps = ps
        self.map_path = settings.base_dir / "ou_map_v2.json"
        self._cache: dict[tuple[str, str], list[dict[str, Any]]] = {}

    def clear_cache(self) -> None:
        self._cache.clear()

    def _load_map(self) -> dict[str, str]:
        if not self.map_path.exists():
            legacy = self.map_path.with_name('ou_map.json')
            if not legacy.exists():
                return {}
            source = legacy
        else:
            source = self.map_path
        try:
            item = json.loads(source.read_text(encoding="utf-8"))
            return item if isinstance(item, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def remember(self, department: str, dn: str) -> None:
        values = self._load_map()
        values[normalize_text(department)] = dn
        self.map_path.write_text(json.dumps(values, ensure_ascii=False, indent=2), encoding="utf-8")

    def list_ous(self, domain: DomainConfig, search_base: str | None = None, refresh: bool = False) -> list[dict[str, Any]]:
        base = search_base or domain.search_base
        key = (domain.name, base)
        if key in self._cache and not refresh:
            return self._cache[key]
        response = self.ps.invoke("list_ous", {"domain": domain.to_dict(), "search_base": base}, timeout=120)
        values = response.data if isinstance(response.data, list) else []
        self._cache[key] = values
        return values

    def analyze_user(self, domain: DomainConfig, user: UserRecord, refresh: bool = False) -> OUAlignment:
        if domain.profile != "omg" or user.is_fired:
            return analyze_ou_alignment(domain, user, [])
        ous = self.list_ous(domain, search_base=domain.ou_dn or domain.search_base, refresh=refresh)
        return analyze_ou_alignment(domain, user, ous)

    def resolve(self, domain: DomainConfig, department: str, search_base: str | None = None) -> OUResolution:
        query = normalize_text(department)
        if not query:
            return OUResolution()
        mapped = self._load_map().get(query)
        if mapped:
            return OUResolution(selected_dn=mapped, confidence="high", candidates=[], source="saved-map")
        candidates: list[dict[str, Any]] = []
        tokens = [token for token in query.split() if len(token) >= 4]
        last = normalize_text(department.split("/")[-1])
        for item in self.list_ous(domain, search_base=search_base):
            name = str(item.get("name") or item.get("Name") or "")
            dn = str(item.get("dn") or item.get("DistinguishedName") or "")
            normalized_name = normalize_text(name)
            score = 0
            if normalized_name == last:
                score = max(score, 6)
            if normalized_name == query:
                score = max(score, 8)
            if normalized_name.startswith(query) or query.startswith(normalized_name):
                score = max(score, 4)
            score = max(score, sum(1 for token in tokens if token in normalized_name))
            if score:
                candidates.append({"name": name, "dn": dn, "score": score})
        candidates.sort(key=lambda x: (-int(x["score"]), str(x["name"]).lower()))
        top = candidates[:20]
        if top and int(top[0]["score"]) >= 6 and (len(top) == 1 or int(top[0]["score"]) >= int(top[1]["score"]) + 2):
            return OUResolution(selected_dn=str(top[0]["dn"]), confidence="high", candidates=top, source="automatic")
        return OUResolution(selected_dn="", confidence="low" if top else "none", candidates=top, source="candidates")
