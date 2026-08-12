from __future__ import annotations

from typing import Any, Callable

from ..models import DomainConfig, UserRecord
from ..utils import sam_base, sam_with_suffix
from .powershell import PowerShellClient, PowerShellError, PowerShellTimeoutError


class ADService:
    def __init__(
        self,
        ps: PowerShellClient,
        domain_configs: list[dict[str, Any]],
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self.ps = ps
        self.logger = logger or (lambda _message: None)
        self.domains: list[DomainConfig] = []
        self.domain_by_name: dict[str, DomainConfig] = {}
        self.set_domains(domain_configs)

    def set_domains(self, domain_configs: list[dict[str, Any]]) -> None:
        domains = [DomainConfig.from_dict(value) for value in domain_configs]
        domains = [domain for domain in domains if domain.name]
        if not domains:
            raise ValueError("В конфигурации не задано ни одного домена")
        names = [domain.name.casefold() for domain in domains]
        if len(names) != len(set(names)):
            raise ValueError("Идентификаторы доменов должны быть уникальными")
        self.domains = domains
        self.domain_by_name = {domain.name: domain for domain in domains}

    def preflight(self, progress=None) -> dict[str, Any]:
        total = len(self.domains) + 1

        def report(current: int, message: str) -> None:
            if progress is not None:
                progress(f"{current}/{total}", message)

        report(0, "Проверяем Windows PowerShell и модуль ActiveDirectory…")
        environment = self.ps.invoke("preflight_environment", {}, timeout=12)
        env_data = environment.data if isinstance(environment.data, dict) else {}
        report(1, "PowerShell проверен. Переходим к контроллерам и базовым OU…")

        states: list[dict[str, Any]] = []
        if not env_data.get("ad_module"):
            message = str(env_data.get("message") or "Модуль ActiveDirectory недоступен")
            states = [
                {
                    "name": domain.name,
                    "label": domain.label,
                    "server": domain.server,
                    "configured_server": domain.server,
                    "server_ok": False,
                    "ou_ok": False,
                    "message": message,
                }
                for domain in self.domains
            ]
            report(total, "Проверка завершена: модуль ActiveDirectory недоступен")
        else:
            for index, domain in enumerate(self.domains, start=2):
                report(
                    index - 1,
                    f"{domain.label}: контроллер {domain.server}, AD Web Services и базовый OU…",
                )
                try:
                    response = self.ps.invoke(
                        "preflight_domain",
                        {"domain": domain.to_dict()},
                        timeout=15,
                    )
                    state = response.data if isinstance(response.data, dict) else {}
                except PowerShellTimeoutError:
                    state = {
                        "name": domain.name,
                        "label": domain.label,
                        "server": domain.server,
                        "configured_server": domain.server,
                        "server_ok": False,
                        "ou_ok": False,
                        "message": "Тайм-аут 15 сек. Проверьте сеть, DNS, VPN и TCP 9389 до контроллера",
                    }
                except PowerShellError as exc:
                    state = {
                        "name": domain.name,
                        "label": domain.label,
                        "server": domain.server,
                        "configured_server": domain.server,
                        "server_ok": False,
                        "ou_ok": False,
                        "message": str(exc),
                    }
                states.append(state)
                report(index, f"{domain.label}: проверка завершена")

        return {
            "powershell_version": env_data.get("powershell_version", "—"),
            "module_available": bool(env_data.get("module_available")),
            "ad_module": bool(env_data.get("ad_module")),
            "message": str(env_data.get("message") or ""),
            "domains": states,
        }

    def search_users(
        self,
        query: str,
        domains: list[str] | None = None,
        include_fired: bool = False,
        progress=None,
    ) -> list[UserRecord]:
        selected = [self.domain_by_name[name] for name in (domains or list(self.domain_by_name)) if name in self.domain_by_name]
        if not selected:
            return []

        # При наличии progress проверяем домены по одному. Так интерфейс показывает,
        # какой контроллер сейчас отвечает, вместо бесконечной неопределённой полосы.
        if progress is not None:
            rows: list[dict[str, Any]] = []
            total = len(selected)
            progress(f"0/{total}", "Подготовка поиска пользователя…")
            for index, domain in enumerate(selected, start=1):
                progress(f"{index - 1}/{total}", f"{domain.label}: поиск пользователя на {domain.server}…")
                response = self.ps.invoke(
                    "search_users",
                    {"query": query, "domains": [domain.to_dict()], "include_fired": include_fired},
                    timeout=60,
                )
                domain_rows = response.data if isinstance(response.data, list) else []
                rows.extend(item for item in domain_rows if isinstance(item, dict))
                progress(f"{index}/{total}", f"{domain.label}: поиск завершён")
        else:
            response = self.ps.invoke(
                "search_users",
                {"query": query, "domains": [item.to_dict() for item in selected], "include_fired": include_fired},
                timeout=120,
            )
            rows = response.data if isinstance(response.data, list) else []
        return [UserRecord.from_mapping(item) for item in rows if isinstance(item, dict)]

    def find_managers(self, query: str, domain_name: str) -> list[UserRecord]:
        domain = self.domain_by_name[domain_name]
        response = self.ps.invoke("find_managers", {"query": query, "domain": domain.to_dict()}, timeout=60)
        rows = response.data if isinstance(response.data, list) else []
        return [UserRecord.from_mapping(item) for item in rows if isinstance(item, dict)]

    def sam_exists(self, sam: str) -> bool:
        response = self.ps.invoke("check_sam", {"sam": sam, "domains": [item.to_dict() for item in self.domains]}, timeout=60)
        data = response.data if isinstance(response.data, dict) else {}
        return bool(data.get("exists"))

    def generate_sam(self, first_name: str, last_name: str) -> str:
        bases: list[str] = []
        for letters in (1, 2):
            candidate = sam_base(first_name, last_name, letters)
            if candidate and candidate not in bases:
                bases.append(candidate)
        if not bases:
            raise ValueError("Не удалось сформировать логин из имени и фамилии")
        for candidate in bases:
            if not self.sam_exists(candidate):
                return candidate
        for suffix in range(2, 1000):
            candidate = sam_with_suffix(bases[0], suffix)
            if not self.sam_exists(candidate):
                return candidate
        raise RuntimeError("Не удалось подобрать свободный sAMAccountName")

    def create_user(self, domain: DomainConfig, payload: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
        response = self.ps.invoke("create_user", {"domain": domain.to_dict(), "user": payload, "dry_run": dry_run}, timeout=180)
        return response.data if isinstance(response.data, dict) else {}

    def update_user(self, user: UserRecord, changes: dict[str, Any]) -> dict[str, Any]:
        domain = self.domain_by_name[user.domain]
        response = self.ps.invoke(
            "update_user",
            {"domain": domain.to_dict(), "identity": user.guid or user.sam, "changes": changes},
            timeout=180,
        )
        return response.data if isinstance(response.data, dict) else {}

    def snapshot_user(self, domain: DomainConfig, sam: str, guid: str = "") -> dict[str, Any] | None:
        response = self.ps.invoke(
            "snapshot_user",
            {"domain": domain.to_dict(), "sam": sam, "guid": guid},
            timeout=90,
        )
        return response.data if isinstance(response.data, dict) else None

    def restore_user(
        self,
        domain: DomainConfig,
        snapshot: dict[str, Any],
        dry_run: bool = False,
        phase: str = "all",
    ) -> dict[str, Any]:
        response = self.ps.invoke(
            "restore_user",
            {
                "domain": domain.to_dict(),
                "snapshot": snapshot,
                "dry_run": dry_run,
                "phase": phase,
            },
            timeout=120 if phase != "all" else 300,
        )
        return response.data if isinstance(response.data, dict) else {}

    def offboard_user(
        self,
        domain: DomainConfig,
        sam: str,
        snapshot: dict[str, Any],
        dry_run: bool = False,
        phase: str = "all",
    ) -> dict[str, Any]:
        response = self.ps.invoke(
            "offboard_user",
            {
                "domain": domain.to_dict(),
                "sam": sam,
                "snapshot": snapshot,
                "dry_run": dry_run,
                "phase": phase,
            },
            timeout=120 if phase != "all" else 240,
        )
        return response.data if isinstance(response.data, dict) else {}
