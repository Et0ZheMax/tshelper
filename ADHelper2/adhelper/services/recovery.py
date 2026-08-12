from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from ..models import DomainConfig, OperationResult, StepResult
from ..utils import operator_info
from .ad_service import ADService
from .audit import AuditRepository


class RecoveryService:
    """Restores offboarded accounts from immutable JSON snapshots created before offboarding."""

    PHASES = (
        ("attributes", "Восстановление рабочих атрибутов"),
        ("move", "Возврат в исходный OU"),
        ("enable", "Восстановление исходного состояния Enabled"),
    )

    def __init__(
        self,
        ad: ADService,
        audit: AuditRepository,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self.ad = ad
        self.audit = audit
        self.logger = logger or (lambda _message: None)

    def list_files(self, limit: int = 300) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        paths = sorted(
            self.audit.settings.recovery_dir.glob("recovery_*.json"),
            key=lambda item: item.stat().st_mtime if item.exists() else 0,
            reverse=True,
        )
        for path in paths[: max(1, limit)]:
            try:
                info = self.load_file(path)
            except Exception as exc:
                rows.append({
                    "path": str(path),
                    "filename": path.name,
                    "valid": False,
                    "error": str(exc),
                    "sam": "",
                    "display_name": "",
                    "captured_at": "",
                    "domains": [],
                })
                continue
            rows.append({
                "path": str(path),
                "filename": path.name,
                "valid": True,
                "error": "",
                "sam": info["sam"],
                "display_name": info["display_name"],
                "captured_at": info["captured_at"],
                "domains": list(info["snapshots"]),
            })
        return rows

    def load_file(self, path: str | Path) -> dict[str, Any]:
        source = Path(path).expanduser().resolve()
        if not source.is_file():
            raise ValueError(f"Recovery JSON не найден: {source}")
        try:
            payload = json.loads(source.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Не удалось прочитать recovery JSON: {exc}") from exc
        if not isinstance(payload, dict) or not payload:
            raise ValueError("Recovery JSON не содержит снимков доменов")

        snapshots: dict[str, dict[str, Any]] = {}
        sams: set[str] = set()
        display_names: list[str] = []
        captured: list[str] = []
        for source_key, raw in payload.items():
            if not isinstance(raw, dict):
                continue
            snapshot = dict(raw)
            attrs = snapshot.get("attributes")
            if not isinstance(attrs, dict):
                raise ValueError(f"[{source_key}] отсутствует объект attributes")
            sam = str(snapshot.get("sam") or attrs.get("SamAccountName") or "").strip()
            guid = str(snapshot.get("guid") or attrs.get("ObjectGUID") or "").strip()
            dn = str(snapshot.get("dn") or attrs.get("DistinguishedName") or "").strip()
            if not sam or not guid or not dn:
                raise ValueError(f"[{source_key}] в снимке отсутствует sam, guid или исходный DN")
            sams.add(sam.casefold())
            if snapshot.get("displayName"):
                display_names.append(str(snapshot["displayName"]).strip())
            if snapshot.get("captured_at"):
                captured.append(str(snapshot["captured_at"]))
            snapshots[str(source_key)] = snapshot

        if not snapshots:
            raise ValueError("В recovery JSON нет пригодных снимков")
        if len(sams) != 1:
            raise ValueError("Recovery JSON содержит снимки разных логинов; автоматическое восстановление заблокировано")
        first = next(iter(snapshots.values()))
        sam = str(first.get("sam") or first["attributes"].get("SamAccountName") or "").strip()
        display_name = next((item for item in display_names if item), str(first["attributes"].get("DisplayName") or sam))
        return {
            "path": str(source),
            "sam": sam,
            "display_name": display_name,
            "captured_at": min(captured) if captured else "",
            "snapshots": snapshots,
        }

    def _resolve_domain(self, source_key: str, snapshot: dict[str, Any]) -> DomainConfig:
        names = [source_key, str(snapshot.get("domain") or "")]
        for name in names:
            if name in self.ad.domain_by_name:
                return self.ad.domain_by_name[name]

        original_dn = str(snapshot.get("dn") or "").casefold()
        candidates = [
            domain for domain in self.ad.domains
            if domain.search_base and original_dn.endswith(domain.search_base.casefold())
        ]
        if len(candidates) == 1:
            return candidates[0]
        raise ValueError(
            f"Для снимка «{source_key}» не найден текущий домен в настройках. "
            "Проверьте идентификатор домена или Search Base."
        )

    def _resolved(self, info: dict[str, Any]) -> list[tuple[str, DomainConfig, dict[str, Any]]]:
        resolved: list[tuple[str, DomainConfig, dict[str, Any]]] = []
        used: set[str] = set()
        for source_key, snapshot in info["snapshots"].items():
            domain = self._resolve_domain(source_key, snapshot)
            if domain.name in used:
                raise ValueError(f"Несколько снимков сопоставились одному домену «{domain.label}»")
            used.add(domain.name)
            resolved.append((source_key, domain, snapshot))
        return resolved

    def preview(self, path: str | Path, progress=None) -> dict[str, Any]:
        progress = progress or (lambda _key, _message: None)
        info = self.load_file(path)
        resolved = self._resolved(info)
        total = max(1, len(resolved))
        rows: list[dict[str, Any]] = []
        progress(f"0/{total}", "Читаем recovery JSON и сопоставляем домены…")
        for index, (source_key, domain, snapshot) in enumerate(resolved, start=1):
            progress(
                f"{index - 1}/{total}",
                f"{domain.label}: сверяем GUID, текущий OU и существование исходного OU…",
            )
            row: dict[str, Any] = {
                "source_domain": source_key,
                "domain": domain.name,
                "label": domain.label,
                "snapshot": snapshot,
                "ok": False,
                "validation": {},
                "error": "",
            }
            try:
                validation = self.ad.restore_user(domain, snapshot, dry_run=True, phase="validate")
                steps = [item for item in (validation.get("steps") or []) if isinstance(item, dict)]
                raw = steps[0] if steps else {}
                status = str(raw.get("status") or "")
                row["validation"] = validation
                row["ok"] = bool(steps) and status in {"simulated", "success", "warning", "skipped"}
                if not row["ok"]:
                    row["error"] = str(raw.get("message") or "Проверка восстановления не пройдена")
            except Exception as exc:
                row["error"] = str(exc)
            rows.append(row)
            progress(
                f"{index}/{total}",
                f"{domain.label}: {'проверка пройдена' if row['ok'] else 'проверка не пройдена'}",
            )
        return {**info, "domains": rows, "valid": bool(rows) and all(row["ok"] for row in rows)}

    def execute(
        self,
        path: str | Path,
        progress: Callable[[str, str], None] | None = None,
    ) -> OperationResult:
        progress = progress or (lambda _key, _message: None)
        info = self.load_file(path)
        resolved = self._resolved(info)
        operation = OperationResult("restore", info["display_name"] or info["sam"], operator=operator_info()["username"])
        operation.data.update({"sam": info["sam"], "source_recovery_path": info["path"]})
        total = max(1, len(resolved) * 5 + 1)
        current = 0

        def report(message: str, advance: bool = False) -> None:
            nonlocal current
            if advance:
                current = min(total, current + 1)
            progress(f"{current}/{total}", message)

        try:
            # Gate 1: every domain must validate before the first write.
            validation_step = StepResult("validate_all", "Предварительная проверка всех доменов")
            validation_step.start()
            operation.steps.append(validation_step)
            validation_failed = False
            for _source_key, domain, snapshot in resolved:
                report(f"{domain.label}: проверяем GUID, текущий OU и исходный OU…")
                try:
                    result = self.ad.restore_user(domain, snapshot, dry_run=True, phase="validate")
                    raw_steps = [item for item in (result.get("steps") or []) if isinstance(item, dict)]
                    raw = raw_steps[0] if raw_steps else {}
                    validation_status = str(raw.get("status") or "")
                    if not raw_steps or validation_status not in {"simulated", "success", "warning", "skipped"}:
                        raise RuntimeError(str(raw.get("message") or "Проверка не пройдена"))
                    report(f"{domain.label}: предварительная проверка пройдена", advance=True)
                except Exception as exc:
                    validation_failed = True
                    operation.errors.append(f"[{domain.name}] проверка восстановления: {exc}")
                    report(f"{domain.label}: ОШИБКА проверки — {exc}", advance=True)
            if validation_failed:
                validation_step.finish("failed", "Есть ошибки; Active Directory не изменялся")
                operation.close("failed")
                return operation
            validation_step.finish("success", "Все домены проверены до первого изменения")

            # Gate 2: save the current fired state so restoration itself is reversible.
            backup_step = StepResult("pre_restore_snapshot", "Снимок состояния перед восстановлением")
            backup_step.start()
            operation.steps.append(backup_step)
            current_snapshots: dict[str, dict[str, Any]] = {}
            for _source_key, domain, snapshot in resolved:
                report(f"{domain.label}: сохраняем текущее состояние учётки из OU уволенных…")
                current_snapshot = self.ad.snapshot_user(domain, info["sam"], guid=str(snapshot.get("guid") or ""))
                if current_snapshot is None:
                    operation.errors.append(f"[{domain.name}] не удалось получить снимок перед восстановлением")
                    backup_step.finish("failed", "Не удалось создать обязательный rollback-снимок")
                    operation.close("failed")
                    report(f"{domain.label}: снимок перед восстановлением НЕ создан", advance=True)
                    return operation
                current_snapshot["recovery_kind"] = "pre_restore_rollback"
                current_snapshot["rollback_allowed_current_dn"] = str(snapshot.get("dn") or "")
                current_snapshots[domain.name] = current_snapshot
                report(f"{domain.label}: снимок перед восстановлением получен", advance=True)

            report("Записываем rollback JSON до первого изменения в Active Directory…")
            rollback_path = self.audit.save_pre_restore(operation.operation_id, info["sam"], current_snapshots)
            operation.data["pre_restore_path"] = str(rollback_path)
            backup_step.finish("success", "Rollback JSON создан до первого изменения", {"path": str(rollback_path)})
            report(f"Rollback JSON сохранён: {rollback_path}", advance=True)

            mutated_domains = 0
            for _source_key, domain, snapshot in resolved:
                domain_step = StepResult(domain.name, f"Восстановление в {domain.label}")
                domain_step.start()
                operation.steps.append(domain_step)
                domain_failed = False
                domain_mutated = False

                for phase, title in self.PHASES:
                    if domain_failed:
                        skipped = StepResult(f"{domain.name}:{phase}", f"{domain.label} · {title}")
                        skipped.finish("skipped", "Пропущено после ошибки предыдущего этапа")
                        operation.steps.append(skipped)
                        report(f"{domain.label}: {title} — пропущено после ошибки", advance=True)
                        continue

                    if phase == "attributes":
                        message = f"{domain.label}: восстанавливаем только атрибуты, сохранённые до увольнения…"
                    elif phase == "move":
                        message = f"{domain.label}: возвращаем объект в исходный OU из recovery JSON…"
                    else:
                        message = f"{domain.label}: восстанавливаем исходное состояние Enabled…"
                    report(message)

                    sub = StepResult(f"{domain.name}:{phase}", f"{domain.label} · {title}")
                    sub.start()
                    operation.steps.append(sub)
                    try:
                        result = self.ad.restore_user(domain, snapshot, dry_run=False, phase=phase)
                        raw_steps = [item for item in (result.get("steps") or []) if isinstance(item, dict)]
                        raw = raw_steps[0] if raw_steps else {}
                        raw_status = str(raw.get("status") or "success")
                        status = raw_status if raw_status in {"success", "warning", "failed", "skipped", "simulated"} else "success"
                        text = str(raw.get("message") or "Этап завершён")
                        sub.finish(status, text, result)
                        warnings = [str(item) for item in (result.get("warnings") or [])]
                        operation.warnings.extend(f"[{domain.name}] {item}" for item in warnings)
                        if status == "failed":
                            domain_failed = True
                            operation.errors.append(f"[{domain.name}] {title}: {text}")
                        elif phase == "attributes" and status in {"success", "warning"}:
                            restored = raw.get("restored") if isinstance(raw, dict) else []
                            if isinstance(restored, list) and restored:
                                domain_mutated = True
                        elif phase in {"move", "enable"} and status == "success":
                            domain_mutated = True
                        report(f"{domain.label}: {title} — {text}", advance=True)
                    except Exception as exc:
                        error = str(exc)
                        sub.finish("failed", error)
                        operation.errors.append(f"[{domain.name}] {title}: {error}")
                        domain_failed = True
                        report(f"{domain.label}: {title} — ОШИБКА: {error}", advance=True)

                if domain_mutated:
                    mutated_domains += 1
                if domain_failed:
                    domain_step.finish("failed", "Восстановление домена остановлено; см. точный этап")
                else:
                    domain_step.finish("success", "Атрибуты, OU и состояние Enabled восстановлены")

            operation.data["mutated_domains"] = mutated_domains
            if operation.errors and mutated_domains:
                operation.close("warning")
            elif operation.errors:
                operation.close("failed")
            elif operation.warnings:
                operation.close("warning")
            else:
                operation.close("success")
            report(f"Восстановление завершено со статусом: {operation.status}")
            return operation
        finally:
            if not operation.finished_at:
                operation.errors.append("Восстановление завершилось необработанной ошибкой")
                operation.close("failed")
            self.audit.save(operation)
