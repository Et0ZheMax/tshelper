from __future__ import annotations

from typing import Any, Callable

from ..models import OperationResult, StepResult, UserRecord
from ..utils import operator_info
from .ad_service import ADService
from .audit import AuditRepository


class UserManagementService:
    def __init__(self, ad: ADService, audit: AuditRepository, logger: Callable[[str], None] | None = None) -> None:
        self.ad = ad
        self.audit = audit
        self.logger = logger or (lambda _message: None)

    def update(self, user: UserRecord, changes: dict[str, Any], progress=None) -> OperationResult:
        operation = OperationResult("update", user.display_name or user.sam, operator=operator_info()["username"])
        operation.data.update({"sam": user.sam, "domain": user.domain, "changes": changes})
        step = StepResult("update", f"Изменение пользователя в {user.domain}")
        operation.steps.append(step)
        step.start()
        try:
            if progress:
                progress("update", f"Сохранение изменений для {user.sam}")
            result = self.ad.update_user(user, changes)
            operation.data["updated_user"] = result
            step.finish("success", "Изменения сохранены", result)
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

    def delete(self, user: UserRecord, progress=None) -> OperationResult:
        operation = OperationResult("delete", user.display_name or user.sam, operator=operator_info()["username"])
        operation.data.update({"sam": user.sam, "guid": user.guid, "domain": user.domain})
        snapshot_step = StepResult("snapshot", "Обязательный recovery-снимок перед удалением")
        operation.steps.append(snapshot_step)
        snapshot_step.start()
        delete_step: StepResult | None = None
        recovery_path = ""
        try:
            if progress:
                progress("snapshot", f"Сохранение recovery JSON для {user.sam} из домена {user.domain}")
            domain = self.ad.domain_by_name.get(user.domain)
            if domain is None:
                raise RuntimeError(f"Не найдена конфигурация домена: {user.domain}")
            snapshot = self.ad.snapshot_user(domain, user.sam, guid=user.guid)
            if not isinstance(snapshot, dict):
                raise RuntimeError("Не удалось получить обязательный recovery-снимок; удаление отменено")
            self._validate_delete_snapshot(user, domain.search_base, snapshot)
            snapshot["recovery_reason"] = "delete_user"
            snapshot["requires_ad_recycle_bin"] = True
            saved_path = self.audit.save_recovery(operation.operation_id, user.sam, {domain.name: snapshot})
            recovery_path = str(saved_path)
            operation.data.update({"recovery_path": recovery_path, "recovery_complete": True})
            snapshot_step.finish(
                "success",
                "Recovery JSON сохранён до удаления",
                {"path": recovery_path, "domain": domain.name},
            )

            delete_step = StepResult("delete", f"Удаление пользователя из {user.domain}")
            operation.steps.append(delete_step)
            delete_step.start()
            if progress:
                progress("delete", f"Удаление {user.sam} из домена {user.domain}")
            result = self.ad.delete_user(user)
            operation.data["deleted_user"] = result
            delete_step.finish("success", "Пользователь удалён", result)
            operation.close("success")
            return operation
        except Exception as exc:
            message = str(exc)
            if recovery_path and "Recovery JSON" not in message:
                message = f"{message}. Recovery JSON сохранён: {recovery_path}"
            if delete_step is not None and delete_step.status == "running":
                delete_step.finish("failed", message)
            elif snapshot_step.status == "running":
                snapshot_step.finish("failed", message)
            operation.errors.append(message)
            operation.close("failed")
            raise RuntimeError(message) from exc
        finally:
            if not operation.finished_at:
                operation.close("failed")
            self.audit.save(operation)

    @staticmethod
    def _validate_delete_snapshot(user: UserRecord, search_base: str, snapshot: dict[str, Any]) -> None:
        attributes = snapshot.get("attributes")
        if not isinstance(attributes, dict):
            raise RuntimeError("Recovery-снимок не содержит атрибуты пользователя; удаление отменено")
        snapshot_domain = str(snapshot.get("domain") or "").strip()
        snapshot_sam = str(snapshot.get("sam") or attributes.get("SamAccountName") or "").strip()
        snapshot_guid = str(snapshot.get("guid") or attributes.get("ObjectGUID") or "").strip()
        snapshot_dn = str(snapshot.get("dn") or attributes.get("DistinguishedName") or "").strip()
        if snapshot_domain.casefold() != user.domain.casefold():
            raise RuntimeError("Домен recovery-снимка не совпадает с выбранным доменом; удаление отменено")
        if snapshot_sam.casefold() != user.sam.casefold():
            raise RuntimeError("Логин recovery-снимка не совпадает с выбранным пользователем; удаление отменено")
        if user.guid and snapshot_guid.casefold() != user.guid.casefold():
            raise RuntimeError("GUID recovery-снимка не совпадает с выбранным пользователем; удаление отменено")
        if not snapshot_dn.casefold().endswith(("," + search_base).casefold()):
            raise RuntimeError("Пользователь recovery-снимка находится вне SearchBase выбранного домена; удаление отменено")
