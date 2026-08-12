from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from adhelper.models import DomainConfig
from adhelper.services.offboarding import OffboardingService


class _Audit:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.saved = []

    def save_recovery(self, operation_id: str, sam: str, snapshots: dict) -> Path:
        path = self.root / f"recovery_{sam}_{operation_id}.json"
        path.write_text("{}", encoding="utf-8")
        return path

    def save(self, operation) -> Path:
        self.saved.append(operation)
        return self.root / "operations.jsonl"


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
        self.calls: list[str] = []
        self.fail_phase = fail_phase

    def snapshot_user(self, domain, sam):
        return {
            "domain": domain.name,
            "guid": "11111111-1111-1111-1111-111111111111",
            "dn": "CN=User,OU=Users,DC=pak",
            "enabled": True,
            "sam": sam,
            "attributes": {"title": "Engineer", "mail": "u@example.test"},
            "clear_attributes": ["title", "mail"],
        }

    def offboard_user(self, domain, sam, snapshot, dry_run=False, phase="all"):
        self.calls.append(phase)
        if phase == self.fail_phase:
            raise RuntimeError("точная ошибка теста")
        messages = {
            "validate": "Пользователь и OU проверены",
            "clear": "Очищено заполненных атрибутов: 2",
            "disable": "Учётная запись отключена",
            "move": "Пользователь перемещён",
        }
        step = {"key": phase, "status": "success", "message": messages[phase]}
        if phase == "validate":
            step["populated_attributes"] = ["title", "mail"]
        if phase == "clear":
            step["cleared"] = ["title", "mail"]
        return {"steps": [step], "warnings": []}


class OffboardingServiceTests(unittest.TestCase):
    def test_execute_runs_named_phases_and_reports_determinate_progress(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            ad = _AD()
            service = OffboardingService(ad, _Audit(Path(temp_dir)))
            events: list[tuple[str, str]] = []
            result = service.execute("user", "User", progress=lambda key, msg: events.append((key, msg)))

        self.assertEqual(ad.calls, ["validate", "clear", "disable", "move"])
        self.assertEqual(result.status, "success")
        self.assertTrue(result.data["recovery_complete"])
        self.assertTrue(any("Recovery JSON" in message for _key, message in events))
        self.assertTrue(all("/" in key for key, _message in events))

    def test_exact_phase_error_is_preserved_in_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            ad = _AD(fail_phase="move")
            service = OffboardingService(ad, _Audit(Path(temp_dir)))
            result = service.execute("user", "User")

        self.assertEqual(result.status, "warning")
        self.assertTrue(any("точная ошибка теста" in error for error in result.errors))
        self.assertTrue(result.data["recovery_complete"])


class OffboardingSourceRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = Path(__file__).resolve().parents[1]
        cls.ui = (root / "adhelper" / "ui" / "pages" / "offboarding.py").read_text(encoding="utf-8")
        cls.snapshot = (root / "adhelper" / "scripts" / "snapshot_user.ps1").read_text(encoding="utf-8-sig")
        cls.offboard = (root / "adhelper" / "scripts" / "offboard_user.ps1").read_text(encoding="utf-8-sig")

    def test_login_in_confirmation_dialog_is_clickable_and_copies_to_clipboard(self) -> None:
        self.assertIn("class LoginConfirmationDialog", self.ui)
        self.assertIn("linkActivated.connect(self._copy_login)", self.ui)
        self.assertIn("QApplication.clipboard().setText(self.login)", self.ui)

    def test_offboarding_uses_named_determinate_progress(self) -> None:
        self.assertIn("self.busy.start_steps", self.ui)
        self.assertIn("Шаг {current} из {total}", self.ui)
        self.assertIn("Сообщение / точная ошибка", self.ui)

    def test_snapshot_and_clear_use_one_shared_attribute_list(self) -> None:
        self.assertIn("Get-OffboardingClearAttributes", self.snapshot)
        self.assertIn("clear_attributes = @($clearAttrs)", self.snapshot)
        self.assertIn("Get-OffboardingClearAttributes", self.offboard)
        self.assertIn("target_fired_ou_dn", self.snapshot)

    def test_offboarding_warning_does_not_use_ambiguous_powershell_variable_colon(self) -> None:
        self.assertNotIn('$attribute:', self.offboard)
        self.assertIn('"Не очищен {0}: {1}" -f $attribute', self.offboard)

    def test_offboarding_avoids_generic_list_array_conversion_bug_in_windows_powershell_51(self) -> None:
        self.assertIn("System.Collections.Generic.List", self.offboard)
        self.assertIn("$populated.ToArray()", self.offboard)
        self.assertIn("$steps.ToArray()", self.offboard)
        self.assertIn("$warnings.ToArray()", self.offboard)
        self.assertNotIn("@($populated)", self.offboard)
        self.assertNotIn("@($steps)", self.offboard)
        self.assertNotIn("@($warnings)", self.offboard)


if __name__ == "__main__":
    unittest.main()
