"""Регрессии проверки целостности; сеть и настоящая установка не используются."""

import hashlib
import io
import sys
import tempfile
import time
import tkinter as tk
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tshelper import integrity
from tshelper import integrity_dialog
from tshelper.updater import MANAGED_DIRECTORIES, get_release_for_version


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.reference = self.root / "reference"
        self.install = self.root / "install"
        for root in (self.reference, self.install):
            (root / "src").mkdir(parents=True)
            (root / "src/app.py").write_text("print('Тест')\n", encoding="utf-8")
            (root / "requirements.txt").write_text("requests\n", encoding="utf-8")

    def compare(self):
        return integrity.compare_installation(
            self.reference, self.install, integrity.IntegrityReport("5.15.5"),
        )

    def test_clean_and_runtime_exclusions(self):
        for folder in ("src/__pycache__", "apps/adhelper2/.venv"):
            (self.install / folder).mkdir(parents=True)
            (self.install / folder / "generated.py").write_text("тест", encoding="utf-8")
        (self.install / "users.json").write_text("{}", encoding="utf-8")
        report = self.compare()
        self.assertEqual(report.matched, 2)
        self.assertEqual(report.issues, [])

    def test_missing_changed_extra_and_nested_layout(self):
        (self.install / "requirements.txt").unlink()
        (self.install / "src/app.py").write_text("изменено", encoding="utf-8")
        (self.install / "src/src").mkdir()
        (self.install / "src/src/app.py").write_text("лишний файл", encoding="utf-8")
        statuses = {(item.path, item.status) for item in self.compare().issues}
        self.assertEqual(statuses, {
            ("requirements.txt", "Отсутствует"),
            ("src/app.py", "Изменён"),
            ("src/src/app.py", "Нет в эталоне"),
        })

    def test_directory_instead_of_file(self):
        (self.install / "requirements.txt").unlink()
        (self.install / "requirements.txt").mkdir()
        self.assertEqual(self.compare().issues[0].status, "Вместо файла каталог")

    def test_read_error_is_not_success(self):
        original = integrity.sha256_file

        def checksum(path):
            if path == self.install / "src/app.py":
                raise PermissionError("Доступ запрещён")
            return original(path)

        with patch.object(integrity, "sha256_file", side_effect=checksum):
            report = self.compare()
        self.assertEqual(report.issues[0].status, "Ошибка чтения")

    def test_link_is_not_followed(self):
        with patch.object(integrity, "_is_link", side_effect=lambda path: path == self.install / "src"):
            report = self.compare()
        self.assertIn("Недопустимая ссылка", [item.status for item in report.issues])

    def test_current_reference_is_not_replaced_by_latest(self):
        latest = type("Release", (), {"version": "6.0.0"})()
        with patch.object(integrity, "get_latest_release", return_value=latest), patch.object(
            integrity, "get_release_for_version", side_effect=RuntimeError("Эталон отсутствует"),
        ) as lookup:
            report = integrity.check_integrity("v5.15.5")
        lookup.assert_called_once_with("5.15.5", http_client=None)
        self.assertIn("Целостность не проверена", report.summary())
        self.assertIn("Доступно обновление", report.summary())

    def test_no_network_never_reports_success(self):
        with patch.object(integrity, "get_latest_release", side_effect=OSError("Нет сети")), patch.object(
            integrity, "get_release_for_version", side_effect=OSError("Нет сети"),
        ):
            report = integrity.check_integrity("5.15.5")
        self.assertTrue(report.latest_error)
        self.assertTrue(report.reference_error)
        self.assertNotIn("Файлы соответствуют", report.summary())

    def test_cancellation(self):
        def progress(*args):
            raise integrity.IntegrityCancelled()

        with self.assertRaises(integrity.IntegrityCancelled):
            integrity.check_integrity("5.15.5", progress=progress)

    def test_verified_archive_end_to_end(self):
        buffer = io.BytesIO()
        files = {
            "src/tshelper/version.py": '__version__ = "5.15.5"\n',
            "scripts/apply_update.ps1": "# Проверка\n",
            "requirements.txt": "requests\n",
            "pyproject.toml": "[project]\n",
            "run_tshelper.bat": "@echo off\n",
        }
        with zipfile.ZipFile(buffer, "w") as bundle:
            for folder in MANAGED_DIRECTORIES:
                bundle.writestr(f"TSHelper-v5.15.5/{folder}/", "")
            for name, content in files.items():
                bundle.writestr(f"TSHelper-v5.15.5/{name}", content.encode("utf-8"))
                target = self.install / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8", newline="\n")
        archive = buffer.getvalue()
        payload = {
            "tag_name": "v5.15.5", "assets": [{
                "name": "TSHelper-v5.15.5-portable.zip",
                "browser_download_url": "https://github.com/Et0ZheMax/tshelper/releases/download/v5.15.5/TSHelper-v5.15.5-portable.zip",
                "digest": "sha256:" + hashlib.sha256(archive).hexdigest(), "size": len(archive),
            }],
        }

        class Response:
            status_code = 200

            def json(self):
                return payload

            def iter_content(self, **kwargs):
                yield archive

        class Client:
            def get(self, *args, **kwargs):
                return Response()

        before = (self.install / "src/app.py").read_bytes()
        report = integrity.check_integrity(
            "5.15.5", install_root=self.install, cache_root=self.root / "cache", http_client=Client(),
        )
        self.assertFalse(report.reference_error)
        self.assertEqual(report.matched, len(files))
        self.assertEqual(report.issues[0].path, "src/app.py")
        self.assertEqual((self.install / "src/app.py").read_bytes(), before)
        self.assertIn("Версия актуальна", report.summary())
        payload["assets"][0]["digest"] = "sha256:" + "0" * 64
        report = integrity.check_integrity(
            "5.15.5", install_root=self.install, cache_root=self.root / "cache", http_client=Client(),
        )
        self.assertIn("SHA-256", report.reference_error)

    def test_release_lookup_validates_version(self):
        with self.assertRaises(RuntimeError):
            get_release_for_version("../../неверно")

    def test_menu_position_and_update_guard(self):
        source = (Path(__file__).resolve().parents[1] / "src/tshelper/app.py").read_text(encoding="utf-8")
        update = source.index('toolsm.add_command(label="Проверить обновления"')
        check = source.index('toolsm.add_command(label="Проверить целостность файлов"')
        self.assertLess(update, check)
        self.assertNotIn("add_separator", source[update:check])
        self.assertIn("integrity_window.running", source)


class IntegrityDialogTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(str(exc))
        self.root.withdraw()
        self.addCleanup(self.root.destroy)

    def wait_until(self, predicate):
        deadline = time.monotonic() + 5
        while not predicate() and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.01)
        self.assertTrue(predicate(), "Окно не завершило фоновую операцию")

    def test_background_report_and_copy(self):
        report = integrity.IntegrityReport("5.15.5", latest_version="5.15.5", checked=2, matched=1)
        report.issues.append(integrity.IntegrityIssue("src/app.py", "Изменён"))
        with patch.object(integrity_dialog, "check_integrity", return_value=report):
            dialog = integrity_dialog.IntegrityDialog(self.root, "v5.15.5")
            self.wait_until(lambda: not dialog.running)
        self.assertEqual(len(dialog.table.get_children()), 1)
        self.assertIn("Обнаружены расхождения", dialog.status.get())
        with patch.object(integrity_dialog.messagebox, "showinfo"):
            dialog.copy_report()
        self.assertIn("src/app.py", dialog.clipboard_get())
        dialog.close()

    def test_cancel_closes_after_worker_stops(self):
        def check(version, progress):
            for index in range(100):
                time.sleep(0.01)
                progress("Проверка", index, 100)

        with patch.object(integrity_dialog, "check_integrity", side_effect=check):
            dialog = integrity_dialog.IntegrityDialog(self.root, "v5.15.5")
            dialog.close()
            self.wait_until(lambda: not dialog.winfo_exists())
        self.assertFalse(dialog.running)


if __name__ == "__main__":
    unittest.main()
