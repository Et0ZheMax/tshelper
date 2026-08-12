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
        step = StepResult("delete", f"Удаление пользователя из {user.domain}")
        operation.steps.append(step)
        step.start()
        try:
            if progress:
                progress("delete", f"Удаление {user.sam} из домена {user.domain}")
            result = self.ad.delete_user(user)
            operation.data["deleted_user"] = result
            step.finish("success", "Пользователь удалён", result)
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
