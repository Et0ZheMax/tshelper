from __future__ import annotations

import os
import re

EXE_SILENT_PRESETS = {
    "auto": ["/silent"],
    "nsis": ["/S"],
    "inno_setup": ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"],
    "installshield": ["/s"],
    "generic_silent": ["/silent"],
    "custom": [],
}

EXE_SILENT_PRESET_ORDER = ["auto", "nsis", "inno_setup", "installshield", "generic_silent", "custom"]


def normalize_silent_preset(raw_value: str, install_type: str = "") -> str:
    value = str(raw_value or "").strip().lower()
    if install_type.strip().lower() != "exe":
        return "custom"
    if value in EXE_SILENT_PRESETS:
        return value
    return "auto"


def infer_exe_silent_preset(path: str, title: str = "") -> tuple[str, str]:
    haystack = " ".join(
        [
            os.path.basename(path or "").lower(),
            str(title or "").lower(),
        ]
    )
    if re.search(r"\bnsis\b", haystack):
        return "nsis", "Найден маркер NSIS в имени файла/названии."
    if re.search(r"\binno\b|\binno setup\b|\bisetup\b", haystack):
        return "inno_setup", "Найден маркер Inno Setup в имени файла/названии."
    if re.search(r"\binstallshield\b|\bsetup launcher\b|\bisscript\b", haystack):
        return "installshield", "Найден маркер InstallShield в имени файла/названии."
    return "generic_silent", "Явные маркеры инсталлятора не найдены, выбран generic preset."


def preset_args_for_package(install_type: str, preset: str, current_args: list[str] | None = None) -> list[str]:
    install_type_norm = str(install_type or "").strip().lower()
    if install_type_norm != "exe":
        return list(current_args or [])
    preset_norm = normalize_silent_preset(preset, install_type=install_type_norm)
    if preset_norm == "custom":
        return list(current_args or [])
    return list(EXE_SILENT_PRESETS.get(preset_norm, EXE_SILENT_PRESETS["generic_silent"]))


def guess_silent_preset_from_args(install_type: str, silent_args: list[str] | None) -> str:
    install_type_norm = str(install_type or "").strip().lower()
    args = list(silent_args or [])
    if install_type_norm != "exe":
        return "custom"
    if not args:
        return "auto"
    for preset_name, preset_args in EXE_SILENT_PRESETS.items():
        if preset_name in {"auto", "custom"}:
            continue
        if args == preset_args:
            return preset_name
    return "custom"
