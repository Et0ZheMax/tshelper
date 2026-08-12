from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from adhelper.models import DomainConfig
from adhelper.services.recovery import RecoveryService


class _Settings:
    def __init__(self, root: Path) -> None:
        self.recovery_dir = root


class _Audit:
    def __init__(self, root: Path) -> None:
        self.settings = _Settings(root)
        self.saved = []

    def save_pre_restore(self, operation_id: str, sam: str, snapshots: dict) -> Path:
        path = self.settings.recovery_dir / f"pre_restore_{sam}_{operation_id}.json"
        path.write_text(json.dumps(snapshots), encoding="utf-8")
        return path

    def save(self, operation) -> Path:
        self.saved.append(operation)
        return self.settings.recovery_dir / "operations.jsonl"


class _AD:
    def __init__(self, fail_phase: str = "") -> None:
        self.domains = [
            DomainConfig(
                name="pak", label="PAK", netbios="PAK", server="dc1",
                search_base="DC=pak", ou_dn="OU=Users,DC=pak",
                upn_suffix="@pak", email_suffix="@mail",
                fired_ou_dn="OU=Fired,DC=pak", profile="standard",
            )
        ]
        self.domain_by_name = {"pak": self.domains[0]}
        self.calls: list[tuple[str, bool]] = []
        self.fail_phase = fail_phase

    def restore_user(self, domain, snapshot, dry_run=False, phase="all"):
        self.calls.append((phase, dry_run))
        if phase == self.fail_phase:
            return {"steps": [{"key": phase, "status": "failed", "message": "точная ошибка restore"}]}
        messages = {
            "validate": "Recovery JSON соответствует текущему объекту",
            "attributes": "Восстановлено атрибутов: 2",
            "move": "Пользователь возвращён в исходный OU",
            "enable": "Исходное состояние восстановлено: Enabled=True",
        }
        step = {"key": phase, "status": "simulated" if dry_run else "success", "message": messages[phase]}
        if phase == "validate":
            step.update({
                "attributes_in_snapshot": 2,
                "attributes_to_restore": 2,
                "move_needed": True,
                "original_enabled": True,
                "enabled_change_needed": True,
                "current_dn": "CN=User,OU=Fired,DC=pak",
                "original_parent": "OU=Users,DC=pak",
            })
        return {"steps": [step], "warnings": []}

    def snapshot_user(self, domain, sam, guid=""):
        return {
            "domain": domain.name,
            "guid": guid,
            "dn": "CN=User,OU=Fired,DC=pak",
            "enabled": False,
            "sam": sam,
            "attributes": {"title": None, "mail": None, "SamAccountName": sam},
            "clear_attributes": ["title", "mail"],
        }


def _snapshot() -> dict:
    return {
        "pak": {
            "domain": "pak",
            "guid": "11111111-1111-1111-1111-111111111111",
            "dn": "CN=User,OU=Users,DC=pak",
            "enabled": True,
            "displayName": "User Test",
            "sam": "user",
            "attributes": {
                "ObjectGUID": "11111111-1111-1111-1111-111111111111",
                "DistinguishedName": "CN=User,OU=Users,DC=pak",
                "Enabled": True,
                "SamAccountName": "user",
                "DisplayName": "User Test",
                "title": "Engineer",
                "mail": "u@example.test",
            },
            "clear_attributes": ["title", "mail"],
            "target_fired_ou_dn": "OU=Fired,DC=pak",
            "domain_profile": "standard",
            "captured_at": "2026-08-10T09:00:00+03:00",
        }
    }


class RecoveryServiceTests(unittest.TestCase):
    def test_load_supports_offboarding_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "recovery_user.json"
            path.write_text(json.dumps(_snapshot()), encoding="utf-8")
            service = RecoveryService(_AD(), _Audit(Path(temp_dir)))
            info = service.load_file(path)
        self.assertEqual(info["sam"], "user")
        self.assertEqual(info["display_name"], "User Test")
        self.assertEqual(list(info["snapshots"]), ["pak"])

    def test_old_recovery_without_clear_attributes_or_profile_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            payload = _snapshot()
            payload["pak"].pop("clear_attributes", None)
            payload["pak"].pop("domain_profile", None)
            path = Path(temp_dir) / "recovery_old_user.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            service = RecoveryService(_AD(), _Audit(Path(temp_dir)))
            info = service.load_file(path)
        self.assertEqual(info["sam"], "user")

    def test_preview_does_not_mutate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "recovery_user.json"
            path.write_text(json.dumps(_snapshot()), encoding="utf-8")
            ad = _AD()
            service = RecoveryService(ad, _Audit(Path(temp_dir)))
            result = service.preview(path)
        self.assertTrue(result["valid"])
        self.assertEqual(ad.calls, [("validate", True)])

    def test_execute_validates_all_then_saves_rollback_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "recovery_user.json"
            path.write_text(json.dumps(_snapshot()), encoding="utf-8")
            ad = _AD()
            audit = _Audit(root)
            service = RecoveryService(ad, audit)
            result = service.execute(path)
        self.assertEqual(result.status, "success")
        self.assertTrue(Path(result.data["pre_restore_path"]).name.startswith("pre_restore_"))
        self.assertEqual(ad.calls, [
            ("validate", True),
            ("attributes", False),
            ("move", False),
            ("enable", False),
        ])

    def test_validation_failure_blocks_all_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "recovery_user.json"
            path.write_text(json.dumps(_snapshot()), encoding="utf-8")
            ad = _AD(fail_phase="validate")
            service = RecoveryService(ad, _Audit(root))
            result = service.execute(path)
        self.assertEqual(result.status, "failed")
        self.assertEqual(ad.calls, [("validate", True)])
        self.assertTrue(any("точная ошибка restore" in item for item in result.errors))


class RecoverySourceRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = Path(__file__).resolve().parents[1]
        cls.script = (root / "adhelper" / "scripts" / "restore_user.ps1").read_text(encoding="utf-8-sig")
        cls.ui = (root / "adhelper" / "ui" / "pages" / "recovery.py").read_text(encoding="utf-8")
        cls.main = (root / "adhelper" / "ui" / "main_window.py").read_text(encoding="utf-8")

    def test_restore_script_is_guid_gated_and_whitelists_attributes(self) -> None:
        self.assertIn("$user.ObjectGUID.ToString() -ne $snapshotGuid", self.script)
        self.assertIn("Get-OffboardingClearAttributes", self.script)
        self.assertIn("$snapshotPropertyNames -notcontains $attribute", self.script)
        self.assertIn("$declaredClearAttrs -notcontains $attribute", self.script)

    def test_restore_order_is_attributes_move_enable(self) -> None:
        all_block = self.script.split("'all' {", 1)[1]
        self.assertLess(all_block.find("Invoke-AttributesPhase"), all_block.find("Invoke-MovePhase"))
        self.assertLess(all_block.find("Invoke-MovePhase"), all_block.find("Invoke-EnablePhase"))

    def test_restore_ui_has_determinate_progress_and_clickable_login_confirmation(self) -> None:
        self.assertIn("Шаг {current} из {total}", self.ui)
        self.assertIn("LoginConfirmationDialog", self.ui)
        self.assertIn("Восстановление", self.main)


if __name__ == "__main__":
    unittest.main()
