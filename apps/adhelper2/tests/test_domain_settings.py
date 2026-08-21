from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adhelper.models import DomainConfig
from adhelper.settings import SettingsStore


class DomainConfigTests(unittest.TestCase):
    def test_legacy_omg_name_gets_omg_profile(self) -> None:
        domain = DomainConfig.from_dict({"name": "omg-cspfmba"})
        self.assertEqual(domain.profile, "omg")


class DomainSettingsTests(unittest.TestCase):
    def test_domains_are_persisted_and_reloaded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {"APPDATA": temp_dir}):
            store = SettingsStore()
            domains = store.domain_configs()
            self.assertGreaterEqual(len(domains), 1)
            domains[0]["server"] = "dc-test.example.ru"
            store.set_domain_configs(domains)

            reloaded = SettingsStore().domain_configs()
            self.assertEqual(reloaded[0]["server"], "dc-test.example.ru")
            config = json.loads((Path(temp_dir) / "ADHelper" / "config_v2.json").read_text(encoding="utf-8"))
            self.assertIn("domain_configs", config)


if __name__ == "__main__":
    unittest.main()
