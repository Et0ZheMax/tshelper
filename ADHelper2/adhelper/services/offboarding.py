from __future__ import annotations

from typing import Callable

from ..models import OperationResult, StepResult
from ..utils import operator_info
from .ad_service import ADService
from .audit import AuditRepository


class OffboardingService:
    PHASES = (
        ("validate", "Проверка пользователя и OU уволенных"),
        ("clear", "Очистка рабочих атрибутов"),
        ("disable", "Отключение учётной записи"),
        ("move", "Перемещение в OU уволенных"),
    )

    def __init__(self, ad: ADService, audit: AuditRepository, logger: Callable[[str], None] | None = None) -> None:
        self.ad = ad
        self.audit = audit
        self.logger = logger or (lambda _message: None)

    def preview(self, sam: str, progress=None) -> dict[str, dict]:
        progress = progress or (lambda _key, _message: None)
        snapshots: dict[str, dict] = {}
        total = max(1, len(self.ad.domains) * 2)
        current = 0
        progress(f"{current}/{total}", "Подготовка проверки увольнения…")

        for domain in self.ad.domains:
            progress(f"{current}/{total}", f"{domain.label}: получаем recovery-снимок без изменений…")
            try:
                snapshot = self.ad.snapshot_user(domain, sam)
            except Exception as exc:
                current += 2
                progress(f"{current}/{total}", f"{domain.label}: ошибка получения снимка — {exc}")
                continue
            current += 1
            if not snapshot:
                current += 1
                progress(f"{current}/{total}", f"{domain.label}: пользователь не найден")
                continue

            snapshots[domain.name] = snapshot
            progress(f"{current}/{total}", f"{domain.label}: проверяем GUID и настроенный OU уволенных…")
            try:
                validation = self.ad.offboard_user(domain, sam, snapshot, dry_run=True, phase="validate")
                snapshot["offboarding_validation"] = validation
                progress(f"{current + 1}/{total}", f"{domain.label}: предварительная проверка пройдена")
            except Exception as exc:
                snapshot["validation_error"] = str(exc)
                progress(f"{current + 1}/{total}", f"{domain.label}: проверка не пройдена — {exc}")
            current += 1

        progress(f"{total}/{total}", "Проверка плана увольнения завершена")
        return snapshots

    def execute(
        self,
        sam: str,
        display_name: str,
        dry_run: bool = False,
        progress: Callable[[str, str], None] | None = None,
    ) -> OperationResult:
        progress = progress or (lambda _key, _message: None)
        operation = OperationResult("offboarding", display_name or sam, operator=operator_info()["username"])
        operation.data["sam"] = sam
        snapshots: dict[str, dict] = {}
        mutated_domains = 0

        # Максимальный план: снимок каждого домена + запись recovery + четыре фазы на домен.
        total = max(1, len(self.ad.domains) * (1 + len(self.PHASES)) + 1)
        current = 0

        def report(message: str, advance: bool = False) -> None:
            nonlocal current
            if advance:
                current = min(total, current + 1)
            progress(f"{current}/{total}", message)

        try:
            snapshot_step = StepResult("snapshot", "Резервный снимок атрибутов")
            operation.steps.append(snapshot_step)
            snapshot_step.start()

            for domain in self.ad.domains:
                report(f"{domain.label}: читаем все атрибуты, которые могут быть очищены…")
                try:
                    snapshot = self.ad.snapshot_user(domain, sam)
                    if snapshot:
                        snapshots[domain.name] = snapshot
                        report(f"{domain.label}: снимок получен", advance=True)
                    else:
                        report(f"{domain.label}: пользователь не найден — домен будет пропущен", advance=True)
                except Exception as exc:
                    operation.warnings.append(f"[{domain.name}] recovery-снимок: {exc}")
                    report(f"{domain.label}: ошибка снимка — {exc}", advance=True)

            if not snapshots:
                snapshot_step.finish("failed", "Пользователь не найден ни в одном домене")
                operation.errors.append("Пользователь не найден ни в одном настроенном домене")
                operation.close("failed")
                return operation

            report("Записываем recovery JSON до первого изменения в Active Directory…")
            recovery_path = self.audit.save_recovery(operation.operation_id, sam, snapshots)
            operation.data["recovery_path"] = str(recovery_path)
            operation.data["recovery_complete"] = True
            snapshot_step.finish(
                "success",
                "Recovery-файл создан до первого изменения",
                {"path": str(recovery_path), "domains": list(snapshots)},
            )
            report(f"Recovery JSON сохранён: {recovery_path}", advance=True)

            for domain in self.ad.domains:
                if domain.name not in snapshots:
                    step = StepResult(domain.name, f"Увольнение в {domain.label}")
                    step.finish("skipped", "Пользователь в домене не найден")
                    operation.steps.append(step)
                    # Четыре фазы этого домена отсутствуют, но шкала должна завершиться точно.
                    for phase, title in self.PHASES:
                        report(f"{domain.label}: {title} — пропущено", advance=True)
                    continue

                domain_step = StepResult(domain.name, f"Увольнение в {domain.label}")
                operation.steps.append(domain_step)
                domain_step.start()
                domain_warnings: list[str] = []
                domain_failed = False
                domain_mutated = False
                phase_results: dict[str, dict] = {}

                for phase, title in self.PHASES:
                    if domain_failed:
                        skipped = StepResult(f"{domain.name}:{phase}", f"{domain.label} · {title}")
                        skipped.finish("skipped", "Пропущено после ошибки предыдущего этапа")
                        operation.steps.append(skipped)
                        report(f"{domain.label}: {title} — пропущено после ошибки", advance=True)
                        continue

                    if phase == "clear":
                        validation = phase_results.get("validate", {})
                        validation_steps = validation.get("steps") or []
                        populated: list[str] = []
                        if validation_steps and isinstance(validation_steps[0], dict):
                            populated = [str(x) for x in (validation_steps[0].get("populated_attributes") or [])]
                        message = f"{domain.label}: очищаем заполненные рабочие атрибуты ({len(populated)})…"
                    elif phase == "validate":
                        message = f"{domain.label}: сверяем GUID пользователя и доступность OU уволенных…"
                    elif phase == "disable":
                        message = f"{domain.label}: отключаем учётную запись и проверяем Enabled=False…"
                    else:
                        message = f"{domain.label}: перемещаем объект и проверяем итоговый DN…"
                    report(message)

                    sub = StepResult(f"{domain.name}:{phase}", f"{domain.label} · {title}")
                    sub.start()
                    operation.steps.append(sub)
                    try:
                        result = self.ad.offboard_user(
                            domain,
                            sam,
                            snapshots[domain.name],
                            dry_run=dry_run,
                            phase=phase,
                        )
                        phase_results[phase] = result
                        warnings = [str(x) for x in (result.get("warnings") or [])]
                        domain_warnings.extend(warnings)
                        operation.warnings.extend(f"[{domain.name}] {warning}" for warning in warnings)

                        raw_steps = [item for item in (result.get("steps") or []) if isinstance(item, dict)]
                        raw = raw_steps[0] if raw_steps else {}
                        raw_status = str(raw.get("status") or ("simulated" if dry_run else "success"))
                        allowed = {"success", "warning", "failed", "skipped", "simulated"}
                        status = raw_status if raw_status in allowed else "success"
                        message = str(raw.get("message") or "Этап завершён")
                        sub.finish(status, message, result)

                        if not dry_run:
                            if phase == "clear" and isinstance(raw.get("cleared"), list) and raw.get("cleared"):
                                domain_mutated = True
                            elif phase == "disable" and status == "success":
                                domain_mutated = True
                            elif phase == "move" and status == "success":
                                domain_mutated = True
                        report(f"{domain.label}: {title} — {message}", advance=True)
                    except Exception as exc:
                        error = str(exc)
                        sub.finish("failed", error)
                        operation.errors.append(f"[{domain.name}] {title}: {error}")
                        domain_failed = True
                        report(f"{domain.label}: {title} — ОШИБКА: {error}", advance=True)

                if domain_mutated:
                    mutated_domains += 1
                if domain_failed:
                    domain_step.finish("failed", "Операция остановлена: см. точную ошибку в этапах")
                elif domain_warnings:
                    domain_step.finish("warning", f"Завершено с предупреждениями: {len(domain_warnings)}")
                else:
                    domain_step.finish("simulated" if dry_run else "success", "Все этапы завершены")

            operation.data["mutated_domains"] = mutated_domains
            if operation.errors and mutated_domains:
                operation.close("warning")
            elif operation.errors:
                operation.close("failed")
            elif operation.warnings:
                operation.close("warning")
            else:
                operation.close("simulated" if dry_run else "success")
            report(f"Операция завершена со статусом: {operation.status}")
            return operation
        finally:
            if not operation.finished_at:
                operation.errors.append("Операция завершилась необработанной ошибкой")
                operation.close("failed")
            # Аудит пишется даже после частичного выполнения или исключения.
            self.audit.save(operation)
