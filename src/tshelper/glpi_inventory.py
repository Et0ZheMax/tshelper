"""Очередь и кэш read-only сверки оборудования через браузерную сессию GLPI."""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path


STATE_VERSION = 1
JOB_LEASE_SECONDS = 90
SESSION_RETRY_SECONDS = 60
VALID_RESULT_STATUSES = {
    "ok",
    "not_found",
    "ambiguous",
    "no_computers",
    "session_required",
    "error",
}
INACTIVE_STATUS_MARKERS = (
    "списан",
    "утилиз",
    "архив",
    "удален",
    "удалён",
    "retired",
    "disposed",
    "archived",
    "deleted",
    "не используется",
    "неактив",
    "inactive",
)
REMOTE_ACCESS_PREFIXES = ("lr-", "wr-")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_login(value: str) -> str:
    login = str(value or "").strip().casefold().replace("\\", "/")
    if "/" in login:
        login = login.rsplit("/", 1)[-1]
    return re.sub(r"\s+", "", login)


def login_from_hostname(value: str) -> str:
    hostname = str(value or "").strip()
    if not hostname:
        return ""
    short = hostname.split(".", 1)[0]
    return normalize_login(re.sub(r"^(?:ws|lt|wr|lr|w|l)-", "", short, flags=re.IGNORECASE))


def login_from_user(user: dict) -> str:
    explicit = normalize_login(user.get("ad_login", ""))
    if explicit:
        return explicit
    return login_from_hostname(user.get("pc_name", ""))


def host_identity(value: str) -> str:
    return re.sub(r"\s+", "", str(value or "").strip().casefold())


def is_remote_access_hostname(value: str) -> bool:
    """Проверить hostname удалённого рабочего места, не управляемого TSHelper."""
    short_name = str(value or "").strip().split(".", 1)[0].casefold()
    return short_name.startswith(REMOTE_ACCESS_PREFIXES)


def os_family_from_text(value: str) -> str:
    text = str(value or "").strip().casefold()
    if any(marker in text for marker in ("windows", "microsoft", "win 10", "win 11")):
        return "windows"
    if any(marker in text for marker in ("linux", "ubuntu", "debian", "astra", "alt linux", "centos", "fedora")):
        return "linux"
    return "unknown"


def os_family_from_hostname(value: str) -> str:
    short_name = str(value or "").strip().split(".", 1)[0].casefold()
    if re.match(r"^(?:w|ws)-", short_name):
        return "windows"
    if re.match(r"^(?:l|lt)-", short_name):
        return "linux"
    return "unknown"


def _valid_hostname(value: str) -> str:
    hostname = str(value or "").strip()
    if not hostname or len(hostname) > 253:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9А-Яа-яЁё_.-]+", hostname):
        return ""
    return hostname


def normalize_computers(items) -> list[dict]:
    result = []
    seen = set()
    for raw in items if isinstance(items, list) else []:
        if not isinstance(raw, dict):
            continue
        itemtype = str(raw.get("itemtype") or "Computer").strip()
        if itemtype.casefold() != "computer":
            continue
        try:
            asset_id = int(raw.get("id") or raw.get("asset_id") or 0)
        except (TypeError, ValueError):
            asset_id = 0
        hostname = _valid_hostname(raw.get("hostname") or raw.get("name"))
        if asset_id <= 0 or not hostname or is_remote_access_hostname(hostname):
            continue
        key = asset_id
        if key in seen:
            continue
        seen.add(key)
        status = str(raw.get("status") or "").strip()
        explicit_active = raw.get("is_active")
        is_active = (
            bool(explicit_active)
            if isinstance(explicit_active, bool)
            else not any(marker in status.casefold() for marker in INACTIVE_STATUS_MARKERS)
        )
        os_name = str(raw.get("os") or raw.get("os_name") or "").strip()
        os_family = str(raw.get("os_family") or os_family_from_text(os_name)).strip().casefold()
        if os_family not in {"windows", "linux"}:
            os_family = "unknown"
        hostname_os_family = os_family_from_hostname(hostname)
        if hostname_os_family in {"windows", "linux"} and hostname_os_family != os_family:
            os_family = hostname_os_family
        result.append({
            "asset_id": asset_id,
            "hostname": hostname,
            "os_name": os_name,
            "os_family": os_family,
            "status": status,
            "serial": str(raw.get("serial") or "").strip()[:200],
            "inventory": str(raw.get("inventory") or "").strip()[:200],
            "relation": str(raw.get("relation") or "").strip()[:100],
            "is_active": is_active,
        })
    return result


def normalize_inventory_result(payload: dict, job: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("Результат GLPI Inventory должен быть JSON-объектом")
    status = str(payload.get("status") or "error").strip().casefold()
    if status not in VALID_RESULT_STATUSES:
        status = "error"
    job_login = normalize_login(job.get("login", ""))
    result_login = normalize_login(payload.get("login", "")) or job_login
    if result_login != job_login:
        raise ValueError("Расширение вернуло результат для другого login")
    try:
        glpi_user_id = int(payload.get("glpi_user_id") or 0)
    except (TypeError, ValueError):
        glpi_user_id = 0
    computers = normalize_computers(payload.get("computers"))
    if status == "ok" and not computers:
        status = "no_computers"
    return {
        "login": job_login,
        "status": status,
        "resolution": str(payload.get("resolution") or "").strip()[:100],
        "glpi_user_id": glpi_user_id,
        "glpi_name": str(payload.get("glpi_name") or "").strip()[:300],
        "computers": computers,
        "checked_at": str(payload.get("checked_at") or utc_now_iso()).strip()[:80],
        "parser_version": str(payload.get("parser_version") or "").strip()[:50],
        "error": str(payload.get("error") or "").strip()[:500],
        "source": "glpi_html",
    }


def active_computers(record: dict) -> list[dict]:
    return [
        item
        for item in record.get("computers", [])
        if item.get("is_active", True) and not is_remote_access_hostname(item.get("hostname", ""))
    ]


def recommend_inventory_update(user: dict, record: dict | None) -> dict:
    login = login_from_user(user)
    current_main = str(user.get("pc_name") or "").strip()
    current_options = [str(item).strip() for item in user.get("pc_options", []) if str(item).strip()]
    base = {
        "login": login,
        "safe": False,
        "changed": False,
        "reason": "Нет актуальных данных GLPI",
        "old_main": current_main,
        "old_options": current_options,
        "new_main": current_main,
        "new_options": current_options,
        "record": record or {},
    }
    if not record or normalize_login(record.get("login", "")) != login:
        return base
    if record.get("status") != "ok":
        base["reason"] = {
            "not_found": "Пользователь не найден в GLPI",
            "ambiguous": "В GLPI найдено несколько пользователей",
            "no_computers": "В GLPI нет активных компьютеров",
            "session_required": "Требуется вход в GLPI",
            "error": record.get("error") or "Ошибка чтения GLPI",
        }.get(record.get("status"), "Нет актуальных данных GLPI")
        return base
    if record.get("resolution") != "exact-login":
        base["reason"] = "Совпадение GLPI не подтверждено по точному login"
        return base

    computers = active_computers(record)
    if len(computers) != 1:
        base["reason"] = f"Активных компьютеров в GLPI: {len(computers)}"
        return base

    target = computers[0]["hostname"]
    target_key = host_identity(target)
    preserved = []
    seen = {target_key}
    for old_host in [current_main, *current_options]:
        old_key = host_identity(old_host)
        if not old_key or old_key in seen or is_remote_access_hostname(old_host):
            continue
        # w-login/l-login от AD были только догадками. Если GLPI подтвердил один
        # Computer, противоположный префикс с тем же login не является вторым ПК.
        if login_from_hostname(old_host) == login:
            continue
        seen.add(old_key)
        preserved.append(old_host)

    changed = target_key != host_identity(current_main) or preserved != current_options
    base.update({
        "safe": True,
        "changed": changed,
        "reason": (
            "GLPI подтвердил один активный Computer по точному login"
            if changed
            else "Уже совпадает с GLPI"
        ),
        "new_main": target,
        "new_options": preserved,
    })
    return base


def apply_recommendation(user: dict, recommendation: dict) -> dict:
    updated = dict(user)
    if not recommendation.get("safe"):
        return updated
    record = recommendation.get("record") or {}
    updated["ad_login"] = recommendation.get("login") or login_from_user(user)
    updated["pc_name"] = recommendation.get("new_main", user.get("pc_name", ""))
    updated["pc_options"] = list(recommendation.get("new_options") or [])
    updated["pc_source"] = "glpi_html"
    updated["glpi_user_id"] = int(record.get("glpi_user_id") or 0)
    updated["glpi_checked_at"] = record.get("checked_at", "")
    updated["glpi_computers"] = deepcopy([
        item
        for item in record.get("computers", [])
        if not is_remote_access_hostname(item.get("hostname", ""))
    ])
    return updated


def apply_inventory_computers(user: dict, record: dict | None) -> dict:
    """Сохранить в карточке все активные ПК из точного результата GLPI.

    Для нескольких ПК выбранный ранее основной сохраняется, если он всё ещё
    присутствует в GLPI. До первого явного выбора карточка помечается как
    требующая подтверждения основного компьютера.
    """
    updated = dict(user)
    login = login_from_user(user)
    if (
        not record
        or normalize_login(record.get("login", "")) != login
        or record.get("status") != "ok"
        or record.get("resolution") != "exact-login"
    ):
        return updated

    computers = active_computers(record)
    hosts = []
    hosts_by_key = {}
    for item in computers:
        hostname = str(item.get("hostname") or "").strip()
        key = host_identity(hostname)
        if not key or key in hosts_by_key:
            continue
        hosts_by_key[key] = hostname
        hosts.append(hostname)
    if not hosts:
        return updated

    current_main = str(user.get("pc_name") or "").strip()
    current_key = host_identity(current_main)
    primary = hosts_by_key.get(current_key, hosts[0])
    updated["ad_login"] = login
    updated["pc_name"] = primary
    updated["pc_options"] = [host for host in hosts if host_identity(host) != host_identity(primary)]
    updated["pc_primary_confirmed"] = (
        True
        if len(hosts) == 1
        else bool(user.get("pc_primary_confirmed")) and current_key in hosts_by_key
    )
    updated["pc_source"] = "glpi_html"
    updated["glpi_user_id"] = int(record.get("glpi_user_id") or 0)
    updated["glpi_checked_at"] = record.get("checked_at", "")
    updated["glpi_computers"] = deepcopy([
        item
        for item in record.get("computers", [])
        if not is_remote_access_hostname(item.get("hostname", ""))
    ])
    return updated


def choose_primary_computer(user: dict, primary_hostname: str) -> dict:
    """Закрепить один из сохранённых ПК как основной, не теряя остальные."""
    requested_key = host_identity(primary_hostname)
    hosts = []
    hosts_by_key = {}
    for value in [user.get("pc_name", ""), *(user.get("pc_options") or [])]:
        hostname = str(value or "").strip()
        key = host_identity(hostname)
        if not key or key in hosts_by_key or is_remote_access_hostname(hostname):
            continue
        hosts_by_key[key] = hostname
        hosts.append(hostname)
    if requested_key not in hosts_by_key:
        raise ValueError("Выбранный компьютер отсутствует в карточке пользователя")

    primary = hosts_by_key[requested_key]
    updated = dict(user)
    updated["pc_name"] = primary
    updated["pc_options"] = [host for host in hosts if host_identity(host) != requested_key]
    updated["pc_primary_confirmed"] = True
    return updated


class InventoryBridgeState:
    """Потокобезопасная персистентная очередь заданий для WebExtension."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._last_poll_at = 0.0
        self._state = self._load()

    def _empty_state(self) -> dict:
        return {
            "version": STATE_VERSION,
            "records": {},
            "jobs": [],
            "pause_until": 0,
            "manually_paused": False,
            "stats": {"completed": 0, "failed": 0},
        }

    def _load(self) -> dict:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return self._empty_state()
        if not isinstance(payload, dict):
            return self._empty_state()
        state = self._empty_state()
        state["records"] = payload.get("records") if isinstance(payload.get("records"), dict) else {}
        for record in state["records"].values():
            if isinstance(record, dict):
                record["computers"] = normalize_computers(record.get("computers", []))
        state["jobs"] = payload.get("jobs") if isinstance(payload.get("jobs"), list) else []
        try:
            state["pause_until"] = float(payload.get("pause_until") or 0)
        except (TypeError, ValueError):
            state["pause_until"] = 0
        state["manually_paused"] = bool(payload.get("manually_paused", False))
        state["stats"].update(payload.get("stats") if isinstance(payload.get("stats"), dict) else {})
        for job in state["jobs"]:
            if isinstance(job, dict) and job.get("status") == "running":
                job["status"] = "pending"
                job["claimed_at"] = 0
        return state

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=self.path.parent) as file_obj:
                temp_name = file_obj.name
                json.dump(self._state, file_obj, ensure_ascii=False, indent=2)
                file_obj.flush()
                os.fsync(file_obj.fileno())
            os.replace(temp_name, self.path)
        finally:
            if temp_name and os.path.exists(temp_name):
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass

    def _job_payload(self, user: dict, reason: str, priority: int) -> dict:
        login = login_from_user(user)
        try:
            glpi_user_id = int(user.get("glpi_user_id") or 0)
        except (TypeError, ValueError):
            glpi_user_id = 0
        if not glpi_user_id:
            cached = self._state.get("records", {}).get(login) or {}
            try:
                glpi_user_id = int(cached.get("glpi_user_id") or 0)
            except (TypeError, ValueError):
                glpi_user_id = 0
        return {
            "id": uuid.uuid4().hex,
            "login": login,
            "name": str(user.get("name") or "").strip()[:300],
            "glpi_user_id": glpi_user_id,
            "current_hosts": [
                str(value).strip()
                for value in [user.get("pc_name", ""), *(user.get("pc_options") or [])]
                if str(value).strip() and not is_remote_access_hostname(value)
            ],
            "reason": str(reason or "manual")[:50],
            "priority": int(priority),
            "status": "pending",
            "created_at": time.time(),
            "claimed_at": 0,
            "attempts": 0,
            "progress_stage": "Ожидает",
            "progress_message": "",
            "progress_at": "",
        }

    def enqueue(self, user: dict, reason: str, *, priority: int = 0, force: bool = False) -> str:
        login = login_from_user(user)
        if not login:
            return ""
        with self._lock:
            existing = next((job for job in self._state["jobs"] if job.get("login") == login), None)
            if existing and not force:
                if priority > int(existing.get("priority") or 0):
                    existing["priority"] = int(priority)
                    existing["reason"] = str(reason or existing.get("reason") or "manual")[:50]
                    self._save_locked()
                return str(existing.get("id") or "")
            if existing and existing.get("status") == "running":
                existing["priority"] = max(int(existing.get("priority") or 0), int(priority))
                existing["reason"] = str(reason or existing.get("reason") or "manual")[:50]
                self._state["pause_until"] = 0
                self._save_locked()
                return str(existing.get("id") or "")
            if existing:
                self._state["jobs"].remove(existing)
            if force:
                self._state["pause_until"] = 0
            job = self._job_payload(user, reason, priority)
            self._state["jobs"].append(job)
            self._save_locked()
            return job["id"]

    def enqueue_many(self, users: list[dict], reason: str, *, priority: int = 0, force: bool = False) -> int:
        added = 0
        dirty = False
        with self._lock:
            if force and self._state.get("pause_until"):
                self._state["pause_until"] = 0
                dirty = True
            active_by_login = {job.get("login"): job for job in self._state["jobs"]}
            for user in users:
                login = login_from_user(user)
                if not login:
                    continue
                existing = active_by_login.get(login)
                if existing and not force:
                    if priority > int(existing.get("priority") or 0):
                        existing["priority"] = int(priority)
                        existing["reason"] = str(reason or existing.get("reason") or "manual")[:50]
                        dirty = True
                    continue
                if existing and existing.get("status") == "running":
                    existing["priority"] = max(int(existing.get("priority") or 0), int(priority))
                    existing["reason"] = str(reason or existing.get("reason") or "manual")[:50]
                    dirty = True
                    continue
                if existing:
                    self._state["jobs"].remove(existing)
                job = self._job_payload(user, reason, priority)
                self._state["jobs"].append(job)
                active_by_login[login] = job
                added += 1
                dirty = True
            if dirty:
                self._save_locked()
        return added

    def _requeue_expired_locked(self) -> None:
        now = time.time()
        for job in self._state["jobs"]:
            if job.get("status") != "running":
                continue
            if now - float(job.get("claimed_at") or 0) > JOB_LEASE_SECONDS:
                job["status"] = "pending"
                job["claimed_at"] = 0

    def pause(self) -> dict:
        """Остановить выдачу новых заданий, сохранив очередь и текущий результат."""
        with self._lock:
            self._state["manually_paused"] = True
            self._save_locked()
            running = any(job.get("status") == "running" for job in self._state["jobs"])
            return {"ok": True, "manually_paused": True, "finishing_current": running}

    def resume(self) -> dict:
        """Продолжить выдачу заданий с сохранённой позиции очереди."""
        with self._lock:
            self._state["manually_paused"] = False
            self._save_locked()
            return {"ok": True, "manually_paused": False}

    def next_job(self) -> dict:
        with self._lock:
            self._last_poll_at = time.time()
            self._requeue_expired_locked()
            if self._state.get("manually_paused"):
                return {"ok": True, "job": None}
            if time.time() < float(self._state.get("pause_until") or 0):
                return {"ok": True, "job": None}
            if any(job.get("status") == "running" for job in self._state["jobs"]):
                return {"ok": True, "job": None}
            pending = [job for job in self._state["jobs"] if job.get("status") == "pending"]
            if not pending:
                return {"ok": True, "job": None}
            pending.sort(key=lambda job: (-int(job.get("priority") or 0), float(job.get("created_at") or 0)))
            job = pending[0]
            job["status"] = "running"
            job["claimed_at"] = time.time()
            job["attempts"] = int(job.get("attempts") or 0) + 1
            job["progress_stage"] = "Задание получено расширением"
            job["progress_message"] = ""
            job["progress_at"] = utc_now_iso()
            self._save_locked()
            public = {key: deepcopy(value) for key, value in job.items() if key not in {"status", "claimed_at", "attempts", "priority"}}
            return {"ok": True, "job": public}

    def complete(self, payload: dict) -> dict:
        job_id = str(payload.get("job_id") or "").strip() if isinstance(payload, dict) else ""
        if not job_id:
            raise ValueError("Не указан job_id")
        with self._lock:
            job = next((item for item in self._state["jobs"] if item.get("id") == job_id), None)
            if not job:
                raise KeyError("Задание не найдено или уже завершено")
            record = normalize_inventory_result(payload, job)
            record["name"] = str(job.get("name") or "")[:300]
            record["reason"] = str(job.get("reason") or "")[:50]
            record["attempts"] = int(job.get("attempts") or 0)
            record["duration_sec"] = max(0, round(time.time() - float(job.get("claimed_at") or time.time()), 1))
            self._state["records"][job["login"]] = record
            if record["status"] == "session_required":
                job["status"] = "pending"
                job["claimed_at"] = 0
                self._state["pause_until"] = time.time() + SESSION_RETRY_SECONDS
            else:
                self._state["jobs"].remove(job)
            stats_key = "failed" if record["status"] in {"error", "session_required"} else "completed"
            self._state["stats"][stats_key] = int(self._state["stats"].get(stats_key) or 0) + 1
            self._save_locked()
            return {"ok": True, "job": deepcopy(job), "record": deepcopy(record)}

    def progress(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("Прогресс GLPI Inventory должен быть JSON-объектом")
        job_id = str(payload.get("job_id") or "").strip()
        if not job_id:
            raise ValueError("Не указан job_id")
        with self._lock:
            job = next((item for item in self._state["jobs"] if item.get("id") == job_id), None)
            if not job:
                raise KeyError("Задание не найдено или уже завершено")
            login = normalize_login(payload.get("login", ""))
            if login and login != job.get("login"):
                raise ValueError("Расширение передало прогресс для другого login")
            job["progress_stage"] = str(payload.get("stage") or "Обработка").strip()[:120]
            job["progress_message"] = str(payload.get("message") or "").strip()[:500]
            job["parser_version"] = str(payload.get("parser_version") or "").strip()[:50]
            job["progress_at"] = str(payload.get("updated_at") or utc_now_iso()).strip()[:80]
            return {"ok": True}

    def status(self) -> dict:
        with self._lock:
            self._requeue_expired_locked()
            pending = sum(job.get("status") == "pending" for job in self._state["jobs"])
            running = sum(job.get("status") == "running" for job in self._state["jobs"])
            job_logins = {normalize_login(job.get("login", "")) for job in self._state["jobs"]}
            completed_records = [
                deepcopy(record)
                for login, record in self._state["records"].items()
                if normalize_login(login) not in job_logins and isinstance(record, dict)
            ]
            completed_records.sort(key=lambda record: str(record.get("checked_at") or ""), reverse=True)
            current = next((job for job in self._state["jobs"] if job.get("status") == "running"), None)
            current_job = None
            if current:
                current_job = {
                    key: deepcopy(current.get(key))
                    for key in (
                        "id", "login", "name", "reason", "current_hosts", "attempts",
                        "progress_stage", "progress_message", "progress_at", "claimed_at",
                        "parser_version",
                    )
                }
            status_counts = {}
            for record in completed_records:
                key = str(record.get("status") or "unknown")
                status_counts[key] = status_counts.get(key, 0) + 1
            all_logins = job_logins | {normalize_login(login) for login in self._state["records"]}
            return {
                "ok": True,
                "pending": pending,
                "running": running,
                "records": len(self._state["records"]),
                "total": len(all_logins),
                "processed": len(completed_records),
                "current_job": current_job,
                "recent_results": completed_records[:100],
                "status_counts": status_counts,
                "last_poll_age_sec": (
                    max(0, round(time.time() - self._last_poll_at, 1))
                    if self._last_poll_at
                    else None
                ),
                "manually_paused": bool(self._state.get("manually_paused")),
                "paused_seconds": max(0, round(float(self._state.get("pause_until") or 0) - time.time())),
                "stats": deepcopy(self._state["stats"]),
            }

    def record_for_login(self, login: str) -> dict | None:
        with self._lock:
            record = self._state["records"].get(normalize_login(login))
            return deepcopy(record) if isinstance(record, dict) else None

    def queue_info_for_login(self, login: str) -> dict | None:
        wanted = normalize_login(login)
        if not wanted:
            return None
        with self._lock:
            job = next((item for item in self._state["jobs"] if item.get("login") == wanted), None)
            if not job:
                return None
            result = deepcopy(job)
            if job.get("status") == "pending":
                pending = [item for item in self._state["jobs"] if item.get("status") == "pending"]
                pending.sort(key=lambda item: (-int(item.get("priority") or 0), float(item.get("created_at") or 0)))
                result["position"] = next(
                    (index for index, item in enumerate(pending, start=1) if item.get("id") == job.get("id")),
                    0,
                )
            return result

    def records(self) -> dict:
        with self._lock:
            return deepcopy(self._state["records"])

    def is_fresh(self, login: str, *, positive_ttl: int, negative_ttl: int) -> bool:
        record = self.record_for_login(login)
        if not record:
            return False
        try:
            checked = datetime.fromisoformat(str(record.get("checked_at") or "").replace("Z", "+00:00"))
            checked_ts = checked.timestamp()
        except (TypeError, ValueError):
            return False
        ttl = positive_ttl if record.get("status") == "ok" else negative_ttl
        return time.time() - checked_ts <= max(0, int(ttl))

    def hosts_for_login(self, login: str) -> list[str]:
        record = self.record_for_login(login)
        if not record or record.get("status") != "ok":
            return []
        return [item["hostname"] for item in active_computers(record) if item.get("hostname")]

    def os_for_host(self, hostname: str) -> str:
        if is_remote_access_hostname(hostname):
            return "unknown"
        wanted = host_identity(hostname)
        if not wanted:
            return "unknown"
        canonical_wanted = login_from_hostname(hostname)
        canonical_matches = set()
        with self._lock:
            for record in self._state["records"].values():
                for computer in record.get("computers", []):
                    if host_identity(computer.get("hostname")) == wanted:
                        value = str(computer.get("os_family") or "unknown")
                        hostname_value = os_family_from_hostname(computer.get("hostname"))
                        if hostname_value in {"windows", "linux"}:
                            return hostname_value
                        return value if value in {"windows", "linux"} else "unknown"
                    if (
                        canonical_wanted
                        and login_from_hostname(computer.get("hostname")) == canonical_wanted
                    ):
                        value = str(computer.get("os_family") or "unknown")
                        hostname_value = os_family_from_hostname(computer.get("hostname"))
                        if hostname_value in {"windows", "linux"}:
                            value = hostname_value
                        if value in {"windows", "linux"}:
                            canonical_matches.add(value)
        # AD может сохранить имя без префикса, хотя GLPI хранит тот же ПК как W-<login>.
        # Используем такое совпадение только при однозначной ОС, чтобы пары W-/L- не смешивались.
        if len(canonical_matches) == 1:
            return canonical_matches.pop()
        return "unknown"
