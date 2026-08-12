from __future__ import annotations

import getpass
import os
import platform
import re
from typing import Any

TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "yo",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}


def translit(value: str) -> str:
    return "".join(TRANSLIT.get(char, char if char.isalnum() else "") for char in value.lower())


def sam_base(first_name: str, last_name: str, prefix_letters: int = 1, max_length: int = 20) -> str:
    prefix = translit(first_name[:prefix_letters])
    surname = translit(last_name)
    result = re.sub(r"[^a-z0-9._-]", "", prefix + surname)
    return result[:max_length]


def sam_with_suffix(base: str, suffix: int | None, max_length: int = 20) -> str:
    suffix_text = "" if suffix is None else str(suffix)
    return f"{base[:max_length - len(suffix_text)]}{suffix_text}"


def normalize_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value or "")
    if len(digits) == 10:
        return "8" + digits
    if len(digits) >= 11 and digits[0] == "7":
        return "8" + digits[1:11]
    if len(digits) >= 11 and digits[0] == "8":
        return digits[:11]
    return digits


def normalize_text(value: str) -> str:
    text = (value or "").lower().replace("ё", "е").strip()
    return re.sub(r"\s+", " ", re.sub(r"[\\/\"']", " ", text))


def operator_info() -> dict[str, Any]:
    return {
        "username": os.environ.get("USERNAME") or getpass.getuser() or "unknown",
        "hostname": platform.node() or os.environ.get("COMPUTERNAME") or "unknown",
    }
