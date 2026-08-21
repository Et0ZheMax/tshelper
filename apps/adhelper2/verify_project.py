from __future__ import annotations

import compileall
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent


def main() -> int:
    print("[1/4] Python syntax")
    if not compileall.compile_dir(ROOT, quiet=1):
        return 1

    print("[2/4] Required files")
    required = [
        ROOT / "main.py",
        ROOT / "adhelper" / "scripts" / "common.ps1",
        ROOT / "adhelper" / "scripts" / "create_user.ps1",
        ROOT / "adhelper" / "scripts" / "offboard_user.ps1",
        ROOT / "adhelper" / "scripts" / "restore_user.ps1",
        ROOT / "adhelper" / "scripts" / "list_access_groups.ps1",
        ROOT / "adhelper" / "scripts" / "inspect_resource_acl.ps1",
        ROOT / "adhelper" / "scripts" / "manage_group_membership.ps1",
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        print("Missing:", *missing, sep="\n")
        return 1

    print("[3/4] Core tests")
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    if not unittest.TextTestRunner(verbosity=1).run(suite).wasSuccessful():
        return 1

    print("[4/4] PySide6")
    if importlib.util.find_spec("PySide6") is None:
        print("PySide6 is not installed. Run: python -m pip install -r requirements.txt")
        return 1
    print("Project verification completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
