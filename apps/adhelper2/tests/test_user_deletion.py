from __future__ import annotations

import unittest
from pathlib import Path

from adhelper.models import DomainConfig, UserRecord
from adhelper.services.ad_service import ADService
from adhelper.services.powershell import PowerShellResponse
from adhelper.services.user_management import UserManagementService


DOMAIN = {
    "name": "example",
    "label": "example.test",
    "netbios": "EXAMPLE",
    "server": "dc1.example.test",
    "search_base": "DC=example,DC=test",
    "ou_dn": "OU=Users,DC=example,DC=test",
    "upn_suffix": "@example.test",
    "email_suffix": "@example.test",
    "fired_ou_dn": "OU=Fired,DC=example,DC=test",
    "profile": "standard",
}


class FakePowerShell:
    def __init__(self) -> None:
        self.action = ""
        self.payload = {}
        self.timeout = 0

    def invoke(self, action, payload, timeout=120):
        self.action = action
        self.payload = payload
        self.timeout = timeout
        return PowerShellResponse(ok=True, data={"domain": "example", "sam": "ivanov", "guid": "guid-1"})


class FakeAudit:
    def __init__(self) -> None:
        self.saved = []
        self.recovery_calls = []

    def save(self, operation):
        self.saved.append(operation)

    def save_recovery(self, operation_id, subject, snapshots):
        self.recovery_calls.append((operation_id, subject, snapshots))
        return Path("C:/recovery/recovery_ivanov.json")


def snapshot_for(user: UserRecord) -> dict:
    return {
        "domain": user.domain,
        "sam": user.sam,
        "guid": user.guid,
        "dn": user.dn,
        "displayName": user.display_name,
        "attributes": {
            "SamAccountName": user.sam,
            "ObjectGUID": user.guid,
            "DistinguishedName": user.dn,
            "DisplayName": user.display_name,
        },
    }


class UserDeletionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.user = UserRecord(
            domain="example",
            display_name="Иванов Иван",
            sam="ivanov",
            guid="guid-1",
            dn="CN=Иванов Иван,OU=Users,DC=example,DC=test",
        )

    def test_ad_service_passes_selected_domain_and_identity_guards(self) -> None:
        powershell = FakePowerShell()
        service = ADService(powershell, [DOMAIN])

        result = service.delete_user(self.user)

        self.assertEqual(result["sam"], "ivanov")
        self.assertEqual(powershell.action, "delete_user")
        self.assertEqual(powershell.timeout, 120)
        self.assertEqual(powershell.payload["domain"]["name"], "example")
        self.assertEqual(powershell.payload["identity"], "guid-1")
        self.assertEqual(powershell.payload["expected_sam"], "ivanov")
        self.assertEqual(powershell.payload["expected_guid"], "guid-1")

    def test_management_service_audits_successful_deletion(self) -> None:
        class FakeAd:
            domain_by_name = {"example": DomainConfig.from_dict(DOMAIN)}

            @staticmethod
            def snapshot_user(_domain, sam, guid=""):
                self.assertEqual((sam, guid), ("ivanov", "guid-1"))
                return snapshot_for(self.user)

            @staticmethod
            def delete_user(user):
                return {"domain": user.domain, "sam": user.sam, "guid": user.guid}

        audit = FakeAudit()
        service = UserManagementService(FakeAd(), audit)

        operation = service.delete(self.user)

        self.assertEqual(operation.status, "success")
        self.assertEqual(operation.operation_type, "delete")
        self.assertEqual(operation.data["deleted_user"]["sam"], "ivanov")
        self.assertTrue(operation.data["recovery_complete"])
        self.assertEqual(operation.data["recovery_path"], "C:\\recovery\\recovery_ivanov.json")
        self.assertEqual(audit.recovery_calls[0][1], "ivanov")
        self.assertEqual(list(audit.recovery_calls[0][2]), ["example"])
        saved_snapshot = audit.recovery_calls[0][2]["example"]
        self.assertEqual(saved_snapshot["recovery_reason"], "delete_user")
        self.assertTrue(saved_snapshot["requires_ad_recycle_bin"])
        self.assertIs(audit.saved[0], operation)

    def test_management_service_audits_failed_deletion(self) -> None:
        class FailingAd:
            domain_by_name = {"example": DomainConfig.from_dict(DOMAIN)}

            @staticmethod
            def snapshot_user(_domain, _sam, guid=""):
                return snapshot_for(self.user)

            @staticmethod
            def delete_user(_user):
                raise RuntimeError("Access denied")

        audit = FakeAudit()
        service = UserManagementService(FailingAd(), audit)

        with self.assertRaisesRegex(RuntimeError, "Access denied"):
            service.delete(self.user)

        self.assertEqual(audit.saved[0].status, "failed")
        self.assertIn("Access denied", audit.saved[0].errors[0])
        self.assertIn("Recovery JSON сохранён", audit.saved[0].errors[0])

    def test_recovery_write_failure_prevents_deletion(self) -> None:
        class CountingAd:
            domain_by_name = {"example": DomainConfig.from_dict(DOMAIN)}
            delete_calls = 0

            @staticmethod
            def snapshot_user(_domain, _sam, guid=""):
                return snapshot_for(self.user)

            @classmethod
            def delete_user(cls, _user):
                cls.delete_calls += 1
                return {}

        class FailingAudit(FakeAudit):
            def save_recovery(self, _operation_id, _subject, _snapshots):
                raise OSError("disk full")

        audit = FailingAudit()
        service = UserManagementService(CountingAd(), audit)

        with self.assertRaisesRegex(RuntimeError, "disk full"):
            service.delete(self.user)

        self.assertEqual(CountingAd.delete_calls, 0)
        self.assertFalse(audit.saved[0].data.get("recovery_complete", False))

    def test_mismatched_snapshot_prevents_deletion(self) -> None:
        class MismatchedAd:
            domain_by_name = {"example": DomainConfig.from_dict(DOMAIN)}
            delete_calls = 0

            @staticmethod
            def snapshot_user(_domain, _sam, guid=""):
                snapshot = snapshot_for(self.user)
                snapshot["guid"] = "another-guid"
                return snapshot

            @classmethod
            def delete_user(cls, _user):
                cls.delete_calls += 1
                return {}

        audit = FakeAudit()
        service = UserManagementService(MismatchedAd(), audit)

        with self.assertRaisesRegex(RuntimeError, "GUID recovery-снимка"):
            service.delete(self.user)

        self.assertEqual(MismatchedAd.delete_calls, 0)
        self.assertEqual(audit.recovery_calls, [])

    def test_unknown_domain_stops_before_powershell(self) -> None:
        powershell = FakePowerShell()
        service = ADService(powershell, [DOMAIN])
        self.user.domain = "other"

        with self.assertRaisesRegex(ValueError, "Не найдена конфигурация домена"):
            service.delete_user(self.user)

        self.assertEqual(powershell.action, "")

    def test_powershell_script_revalidates_identity_before_removal(self) -> None:
        script = (
            Path(__file__).resolve().parents[1] / "adhelper" / "scripts" / "delete_user.ps1"
        ).read_text(encoding="utf-8-sig")
        self.assertIn("expected_sam", script)
        self.assertIn("expected_guid", script)
        self.assertIn("search_base", script)
        self.assertIn("EndsWith", script)
        self.assertIn("Get-ADOptionalFeature", script)
        self.assertIn("Recycle Bin Feature", script)
        self.assertIn("Remove-ADUser", script)
        self.assertIn("-Confirm:$false", script)


if __name__ == "__main__":
    unittest.main()
