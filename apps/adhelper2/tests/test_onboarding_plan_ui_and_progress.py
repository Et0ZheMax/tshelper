from __future__ import annotations

import unittest
from pathlib import Path

from adhelper.models import DomainConfig, ParsedRequest
from adhelper.services.onboarding import OnboardingService


class PlanPageSourceRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (
            Path(__file__).resolve().parents[1] / "adhelper" / "ui" / "pages" / "onboarding.py"
        ).read_text(encoding="utf-8")

    def test_plan_uses_full_width_domain_cards_instead_of_six_column_table(self) -> None:
        self.assertIn('self.plan_cards_layout = QVBoxLayout(self.plan_body)', self.source)
        self.assertIn('domain_frame.setObjectName("InsetCard")', self.source)
        self.assertIn('ou_edit.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)', self.source)
        self.assertNotIn('self.plan_table = QTableWidget(0, 6)', self.source)

    def test_plan_result_always_releases_busy_state(self) -> None:
        self.assertIn('finally:\n            # Не полагаемся только на finished-сигнал', self.source)
        self.assertIn('self._set_busy(False)', self.source)
        self.assertIn('self.next_button.setEnabled(not self._busy_state)', self.source)

    def test_workers_are_kept_until_finished_signal_is_delivered(self) -> None:
        self.assertIn('self._active_workers: list[FunctionWorker] = []', self.source)
        self.assertIn('def _track_worker(self, worker: FunctionWorker)', self.source)
        self.assertIn('self._active_workers.append(worker)', self.source)


class _FakeAD:
    def __init__(self) -> None:
        domain = DomainConfig(
            name="pak",
            label="pak.example",
            netbios="PAK",
            server="dc.pak.example",
            search_base="DC=pak,DC=example",
            ou_dn="OU=Users,DC=pak,DC=example",
            upn_suffix="@pak.example",
            email_suffix="@example.test",
            fired_ou_dn="OU=Fired,DC=pak,DC=example",
            profile="standard",
        )
        self.domain_by_name = {domain.name: domain}

    def search_users(self, _query, _domains, include_fired=False):
        return []

    def generate_sam(self, _first_name, _last_name):
        return "itest"

    def find_managers(self, _query, _domain_name):
        return []


class _FakeOUResolver:
    def resolve(self, *_args, **_kwargs):
        raise AssertionError("standard profile must not query dynamic OU list")


class OnboardingPlanProgressTests(unittest.TestCase):
    def test_build_plan_reports_named_steps_and_completion(self) -> None:
        service = OnboardingService(_FakeAD(), _FakeOUResolver(), None, None)
        events: list[tuple[str, str]] = []
        request = ParsedRequest(last_name="Иванов", first_name="Иван", department="ИТ")

        plan = service.build_plan(
            request,
            ["pak"],
            "Москва",
            "Password1!",
            progress=lambda key, message: events.append((key, message)),
        )

        self.assertEqual(plan.sam, "itest")
        self.assertEqual([key for key, _message in events], ["duplicates", "login", "pak", "complete"])
        self.assertTrue(all(message.strip() for _key, message in events))


if __name__ == "__main__":
    unittest.main()
