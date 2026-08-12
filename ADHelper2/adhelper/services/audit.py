from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ..models import OperationResult
from ..settings import SettingsStore


class AuditRepository:
    def __init__(self, settings: SettingsStore) -> None:
        self.settings = settings
        self.jsonl_path = settings.audit_dir / "operations.jsonl"
        self.pretty_path = settings.audit_dir / "operations_latest.json"

    def save(self, operation: OperationResult) -> Path:
        payload = operation.to_dict()
        line = json.dumps(payload, ensure_ascii=False)
        with self.jsonl_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
        latest = self.list_recent(300)
        temp = self.pretty_path.with_suffix(".tmp")
        temp.write_text(json.dumps(latest, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(self.pretty_path)
        return self.jsonl_path

    def save_recovery(self, operation_id: str, subject: str, snapshots: dict[str, Any]) -> Path:
        safe_subject = "".join(ch for ch in subject if ch.isalnum() or ch in ("-", "_", "."))[:60] or "user"
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self.settings.recovery_dir / f"recovery_{safe_subject}_{stamp}_{operation_id[:8]}.json"
        path.write_text(json.dumps(snapshots, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def save_pre_restore(self, operation_id: str, subject: str, snapshots: dict[str, Any]) -> Path:
        safe_subject = "".join(ch for ch in subject if ch.isalnum() or ch in ("-", "_", "."))[:60] or "user"
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self.settings.recovery_dir / f"pre_restore_{safe_subject}_{stamp}_{operation_id[:8]}.json"
        path.write_text(json.dumps(snapshots, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    def list_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        if not self.jsonl_path.exists():
            return []
        result: list[dict[str, Any]] = []
        for line in self.jsonl_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                result.append(item)
        return result[-limit:][::-1]
