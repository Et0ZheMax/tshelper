import base64
import ctypes
from ctypes import wintypes
import argparse
import json
import os
import platform
import subprocess
import re
import sys
from datetime import datetime, timezone
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Callable, Any

# ==========================
# Конфигурация доменов
# ==========================

DOMAIN_CONFIGS = [
    {
        "name": "pak-cspmz",
        "label": "Создавать в pak-cspmz",
        "server": "dc03.pak-cspmz.ru",
        "search_base": "DC=pak-cspmz,DC=ru",
        "ou_dn": "OU=omg,OU=csp,OU=Users,OU=csp,DC=pak-cspmz,DC=ru",
        "upn_suffix": "@pak-cspmz.ru",
        "email_suffix": "@cspfmba.ru",
    },
    {
        "name": "omg-cspfmba",
        "label": "Создавать в omg.cspfmba",
        "server": "DC24.omg.cspfmba.ru",
        "search_base": "DC=omg,DC=cspfmba,DC=ru",
        "ou_dn": "OU=Institute of Synthetic Biology and Genetic Engineering,DC=omg,DC=cspfmba,DC=ru",
        "upn_suffix": "@omg.cspfmba.ru",
        "email_suffix": "@cspfmba.ru",
        "fired_ou_dn": "OU=Уволенные,OU=Users,OU=csp,DC=omg,DC=cspfmba,DC=ru",
    },
]

COMPANY_NAME = "ФГБУ «ЦСП» ФМБА России"

CONFIG_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "ADHelper")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
OU_MAP_PATH = os.path.join(CONFIG_DIR, "ou_map.json")
OFFBOARDING_LOG_PATH = os.path.join(CONFIG_DIR, "offboarding_log.jsonl")
CONFIG_PASSWORD_KEY = "password_token"
CONFIG_GEOMETRY_KEY = "window_geometry"

_POWERSHELL_EXE: Optional[str] = None
_PREFERRED_DC_CACHE: dict[str, str] = {}

_OU_CACHE: dict[str, list[dict[str, str]]] = {}

ADHELPER_DRYRUN_MODE = (os.environ.get("ADHELPER_DRYRUN") or "").strip() == "1"

ADDRESS_CHOICES = [
    "ул. Щукинская, дом 5, стр.5",
    "ул. Погодинская, д. 10, стр.2",
    "ул. Погодинская, д. 10, стр.1",
]

# Детали адреса для AD (атрибуты: l, postalCode, postOfficeBox, st, c)
ADDRESS_DETAILS = {
    "ул. Щукинская, дом 5, стр.5": {
        "pobox": "Москва",        # postOfficeBox
        "city": "Москва",         # l
        "state": "Москва",        # st
        "postal_code": "123182",  # postalCode
        "country": "RU",          # c
    },
    "ул. Погодинская, д. 10, стр.2": {
        "pobox": "Москва",
        "city": "Москва",
        "state": "Москва",
        "postal_code": "119121",
        "country": "RU",
    },
        "ул. Погодинская, д. 10, стр.1": {
        "pobox": "Москва",
        "city": "Москва",
        "state": "Москва",
        "postal_code": "119121",
        "country": "RU",
    },
}

# Структура OU для omg: Department -> Section
OMG_OU_TREE = {
    "outsource": [],
    "отдел научно-технического и методического обеспечения": [],
    "отдел редакционно-издательской деятельности": [],
    "управление организации и проведения исследований": [
        "лаборатория эпигенетических методов исследований",
        "отдел анализа и прогнозирования медико-биологических рисков здоровью",
        "отдел медицинской геномики",
        "отдел организации проведения клинических исследований",
    ],
    "управление цифровых систем и биоинформатики": [
        "отдел архивирования и хранения цифровой информации",
        "отдел информационно-ресурсного обеспечения",
        "отдел системной биологии и биоинформатики",
    ],
    "управление экспериментальной биотехнологии и генной инженерии": [
        "виварий",
        "лаборатория биобанкирования и мультиомиксных методов исследований",
        "лаборатория генной инженерии",
        "лаборатория гистологических исследований",
        "лаборатория иммунологии и клеточной биологии",
        "лаборатория метагеномных исследований",
        "лаборатория микробиологии и паразитологии",
        "лаборатория наноматериалов",
        "лаборатория опасных и социально значимых инфекций",
        "лаборатория разработки биотехнологических процессов",
        "лаборатория синтеза олигонуклеотидов и малых молекул",
    ],
}

OMG_DEPARTMENT_CHOICES = list(OMG_OU_TREE.keys())
OMG_SECTION_CHOICES = sorted({section for sections in OMG_OU_TREE.values() for section in sections})
OMG_SECTION_TO_DEPARTMENT = {
    section: department
    for department, sections in OMG_OU_TREE.items()
    for section in sections
}

OMG_DIVISION_VALUE = "институт синтетической биологии и генной инженерии"


# ==========================
# Вспомогательные функции
# ==========================

class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _blob_from_bytes(data: bytes) -> _DataBlob:
    buffer = ctypes.create_string_buffer(data)
    blob = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    blob._buffer = buffer
    return blob


def _bytes_from_blob(blob: _DataBlob) -> bytes:
    return ctypes.string_at(blob.pbData, blob.cbData)


def _crypt_protect(data: bytes) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    blob_in = _blob_from_bytes(data)
    blob_out = _DataBlob()
    if not crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(blob_out),
    ):
        raise ctypes.WinError()
    try:
        return _bytes_from_blob(blob_out)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def _crypt_unprotect(data: bytes) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    blob_in = _blob_from_bytes(data)
    blob_out = _DataBlob()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(blob_out),
    ):
        raise ctypes.WinError()
    try:
        return _bytes_from_blob(blob_out)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def encrypt_password(plain: str) -> str:
    if not plain:
        return ""
    raw = plain.encode("utf-16-le")
    protected = _crypt_protect(raw)
    return base64.b64encode(protected).decode("ascii")


def decrypt_password(token: str) -> str:
    if not token:
        return ""
    protected = base64.b64decode(token)
    raw = _crypt_unprotect(protected)
    return raw.decode("utf-16-le")


def load_config() -> dict:
    if not os.path.exists(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data

def save_config(data: dict) -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)


def ensure_config_dir() -> str:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    return CONFIG_DIR


def append_jsonl(path: str, obj: dict) -> None:
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(obj, ensure_ascii=False) + "\n")
        handle.flush()
        try:
            os.fsync(handle.fileno())
        except OSError:
            pass


def normalize_text(value: str) -> str:
    text = (value or "").strip().lower().replace("ё", "е")
    text = text.replace("/", " ").replace("\\", " ")
    text = text.replace('"', " ").replace("'", " ")
    text = re.sub(r"\.+$", "", text)
    return re.sub(r"\s+", " ", text)


def load_ou_map() -> dict[str, str]:
    if not os.path.exists(OU_MAP_PATH):
        return {}
    try:
        with open(OU_MAP_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}


def save_ou_map(data: dict[str, str]) -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(OU_MAP_PATH, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)

def load_password_token() -> str:
    data = load_config()
    return data.get(CONFIG_PASSWORD_KEY, "") or ""


def save_password_token(token: str) -> None:
    data = load_config()
    data[CONFIG_PASSWORD_KEY] = token
    save_config(data)

def find_powershell_exe() -> str:
    global _POWERSHELL_EXE
    if _POWERSHELL_EXE:
        return _POWERSHELL_EXE
    for candidate in ("powershell", "powershell.exe", "pwsh"):
        try:
            proc = subprocess.run(
                [candidate, "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            continue
        if proc.returncode == 0:
            _POWERSHELL_EXE = candidate
            return candidate
    _POWERSHELL_EXE = "powershell"
    return _POWERSHELL_EXE


def run_powershell(command: str, server: Optional[str] = None) -> subprocess.CompletedProcess:
    encoding_setup = "$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8; "
    server_setup = f"$PSDefaultParameterValues['*:Server']='{escape_ps_string(server)}'; " if server else ""
    full_cmd = [
        find_powershell_exe(),
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", encoding_setup + server_setup + command,
    ]
    return subprocess.run(
        full_cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def get_preferred_dc(domain_cfg: dict) -> str:
    domain_name = domain_cfg["name"]
    if domain_name in _PREFERRED_DC_CACHE:
        return _PREFERRED_DC_CACHE[domain_name]
    base_server = domain_cfg["server"]
    ps = (
        "Import-Module ActiveDirectory; "
        f"(Get-ADDomain -Server '{escape_ps_string(base_server)}').PDCEmulator"
    )
    proc = run_powershell(ps)
    pdc = (proc.stdout or "").strip()
    if proc.returncode == 0 and pdc:
        _PREFERRED_DC_CACHE[domain_name] = pdc
    else:
        _PREFERRED_DC_CACHE[domain_name] = base_server
    return _PREFERRED_DC_CACHE[domain_name]


def validate_ou_exists(domain_cfg: dict, ou_dn: str) -> bool:
    if not ou_dn:
        return False
    server = get_preferred_dc(domain_cfg)
    ou_escaped = escape_ps_string(ou_dn)
    ps = (
        "Import-Module ActiveDirectory; "
        f"Get-ADOrganizationalUnit -Server '{escape_ps_string(server)}' -Identity '{ou_escaped}' "
        "-ErrorAction Stop | Out-Null"
    )
    proc = run_powershell(ps, server=server)
    return proc.returncode == 0


def validate_ou_exists_on_server(server_name: str, ou_dn: str) -> bool:
    if not server_name or not ou_dn:
        return False
    ps = (
        "Import-Module ActiveDirectory; "
        f"Get-ADOrganizationalUnit -Server '{escape_ps_string(server_name)}' -Identity '{escape_ps_string(ou_dn)}' "
        "-ErrorAction Stop | Out-Null"
    )
    proc = run_powershell(ps, server=server_name)
    return proc.returncode == 0


def get_all_ous(domain_cfg: dict, search_base: Optional[str] = None) -> list[dict[str, str]]:
    domain_name = domain_cfg["name"]
    if domain_name in _OU_CACHE:
        return _OU_CACHE[domain_name]
    server = get_preferred_dc(domain_cfg)
    sb = search_base or domain_cfg.get("search_base") or ""
    sb_param = f" -SearchBase '{escape_ps_string(sb)}'" if sb else ""
    ps = (
        "Import-Module ActiveDirectory; "
        "$result = Get-ADOrganizationalUnit "
        f"-Server '{escape_ps_string(server)}' -Filter *{sb_param} "
        "-Properties DistinguishedName,Name -ErrorAction SilentlyContinue | "
        "Select-Object Name, DistinguishedName; "
        "$result | ConvertTo-Json -Depth 4"
    )
    proc = run_powershell(ps, server=server)
    if proc.returncode != 0:
        _OU_CACHE[domain_name] = []
        return []
    data, _ = parse_ps_json(proc.stdout)
    ous = []
    for item in data:
        name = (item.get("Name") or "").strip()
        dn = (item.get("DistinguishedName") or "").strip()
        if name and dn:
            ous.append({"Name": name, "DistinguishedName": dn})
    _OU_CACHE[domain_name] = ous
    return ous


def resolve_target_ou(domain_cfg: dict, dept_text: str, base_path_hint: Optional[str] = None) -> tuple[Optional[str], list[dict[str, Any]], str]:
    dept_original = (dept_text or "").strip()
    if not dept_original:
        return None, [], "none"

    ou_map = load_ou_map()
    map_key = normalize_text(dept_original)
    mapped_dn = ou_map.get(map_key) or ou_map.get(dept_original)
    if mapped_dn and validate_ou_exists(domain_cfg, mapped_dn):
        return mapped_dn, [{"Name": "mapped", "DistinguishedName": mapped_dn, "score": 999}], "high"

    ous = get_all_ous(domain_cfg, search_base=base_path_hint)
    dept_norm = normalize_text(dept_original)
    candidates = []

    path_parts = [normalize_text(p) for p in re.split(r"[\/]+", dept_original) if normalize_text(p)]
    last_part = path_parts[-1] if path_parts else ""

    for ou in ous:
        ou_name = ou["Name"]
        ou_dn = ou["DistinguishedName"]
        ou_norm = normalize_text(ou_name)
        score = 0

        if last_part and ou_norm == last_part:
            score = max(score, 4)

        if ou_norm.startswith(dept_norm) or dept_norm.startswith(ou_norm):
            score = max(score, 3)

        tokens = [t for t in dept_norm.split() if len(t) >= 4]
        token_score = sum(1 for token in tokens if token in ou_norm)
        score = max(score, token_score)

        if score > 0:
            candidates.append({"Name": ou_name, "DistinguishedName": ou_dn, "score": score})

    candidates.sort(key=lambda x: (-x["score"], x["Name"].lower()))
    top_candidates = candidates[:5]

    if not top_candidates:
        return None, [], "low"

    if len(top_candidates) == 1 and top_candidates[0]["score"] >= 3:
        return top_candidates[0]["DistinguishedName"], top_candidates, "high"

    if len(top_candidates) > 1 and top_candidates[0]["score"] >= 3 and top_candidates[0]["score"] >= top_candidates[1]["score"] + 2:
        return top_candidates[0]["DistinguishedName"], top_candidates, "high"

    return None, top_candidates, "low"

def escape_ps_string(value: str) -> str:
    return (value or "").replace("'", "''")

def escape_ldap_filter(value: str) -> str:
    if not value:
        return ""
    res = value
    res = res.replace("\\", "\\5c")
    res = res.replace("*", "\\2a")
    res = res.replace("(", "\\28")
    res = res.replace(")", "\\29")
    res = res.replace("\x00", "\\00")
    return res

def parse_ps_json(raw: str) -> tuple[list, str]:
    text = (raw or "").strip()
    if not text:
        return [], ""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], "Не удалось разобрать ответ PowerShell (ожидался JSON)."
    if isinstance(data, list):
        return data, ""
    if isinstance(data, dict):
        return [data], ""
    return [], "Не удалось разобрать ответ PowerShell (неизвестный формат)."


def extract_ou_from_dn(distinguished_name: str) -> str:
    dn = (distinguished_name or "").strip()
    if not dn:
        return ""
    parts = dn.split(",")
    if len(parts) <= 1:
        return dn
    return ",".join(parts[1:]).strip()


def short_ou_from_dn(distinguished_name: str) -> str:
    ou = extract_ou_from_dn(distinguished_name)
    if not ou:
        return ""
    chunks = [item.strip() for item in ou.split(",") if item.strip().upper().startswith("OU=")]
    if not chunks:
        return ou
    return " / ".join(chunk[3:] for chunk in chunks)


def command_failed_with_8329(proc: subprocess.CompletedProcess) -> bool:
    text = ((proc.stderr or "") + "\n" + (proc.stdout or "")).lower()
    return "8329" in text or "uninstantiated" in text

def translit_gost(text: str) -> str:
    mapping = {
        "а": "a",  "б": "b",  "в": "v",   "г": "g",   "д": "d",
        "е": "e",  "ё": "yo", "ж": "zh",  "з": "z",   "и": "i",
        "й": "y",
        "к": "k",  "л": "l",  "м": "m",   "н": "n",
        "о": "o",  "п": "p",  "р": "r",   "с": "s",   "т": "t",
        "у": "u",  "ф": "f",  "х": "kh",  "ц": "ts",  "ч": "ch",
        "ш": "sh", "щ": "shch", "ъ": None, "ы": "y",  "ь": None,
        "э": "e",  "ю": "yu", "я": "ya",
    }
    result = []
    for ch in text.lower():
        if ch in mapping:
            val = mapping[ch]
            if val:
                result.append(val)
        elif ch.isalnum():
            result.append(ch)
        else:
            continue
    return "".join(result)

def parse_bool(value: str) -> bool:
    value = value.strip().lower()
    return value in ("да", "yes", "y", "true", "1")

def normalize_phone(raw: str) -> str:
    """
    +7(917)561-44-55 -> 89175614455
    """
    if not raw:
        return ""
    digits = re.sub(r"\D", "", raw)
    if not digits:
        return ""
    if digits[0] == "7" and len(digits) >= 11:
        return "8" + digits[1:11]
    if digits[0] == "8" and len(digits) >= 11:
        return digits[:11]
    if len(digits) == 10:
        return "8" + digits
    return digits

def diff_field(new_value: str, old_value: str) -> Optional[str]:
    new_norm = (new_value or "").strip()
    old_norm = (old_value or "").strip()
    if new_norm == old_norm:
        return None
    return new_value

def parse_form(text: str) -> dict:
    field_map = {
        "Фамилия": "last_name",
        "Имя": "first_name",
        "Отчество": "middle_name",
        "Есть ли у вас фотография сотрудника": "has_photo",
        "Руководитель": "manager_name",
        "Управление": "management",
        "Отдел": "department",
        "Должность сотрудника": "title",
        "Дата выхода сотрудника": "start_date",
        "Режим работы сотрудника": "work_mode",
        "Номер кабинета": "office_room",
        "Предоставить электронный почтовый ящик для сотрудника": "need_mail",
        "Предоставить внутренний телефонный номер для сотрудника": "need_internal_phone",
        "Номер сотового телефона для переадресации": "mobile_phone",
        "Оборудование необходимое сотруднику": "equipment",
        "Операционная система для ноутбука в офисе": "office_os",
        "Предоставить доступ к серверам": "need_servers_access",
        "Предоставить доступ к папкам": "need_folders_access",
        "Примечание": "notes",
    }

    data = {v: None for v in field_map.values()}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        line = re.sub(r"^\d+\)\s*", "", line)
        if " :" in line:
            key_part, value_part = line.split(" :", 1)
        elif ":" in line:
            key_part, value_part = line.split(":", 1)
        else:
            continue
        key_part = key_part.strip()
        value_part = value_part.strip()

        matched_key = None
        for label, internal_key in field_map.items():
            if key_part.lower().startswith(label.lower()):
                matched_key = internal_key
                break

        if not matched_key:
            continue

        if matched_key in ("need_mail", "need_internal_phone", "has_photo",
                           "need_servers_access", "need_folders_access"):
            data[matched_key] = parse_bool(value_part)
        else:
            data[matched_key] = value_part

    return data

def user_exists_in_domain(server: str, sam: str) -> bool:
    ps = (
        "Import-Module ActiveDirectory; "
        "$u = Get-ADUser "
        f"-Filter \"SamAccountName -eq '{sam}'\" -ErrorAction SilentlyContinue; "
        "if ($u) { '1' } else { '0' };"
    )
    proc = run_powershell(ps, server=server)
    if proc.returncode != 0:
        return False
    output = (proc.stdout or "").strip()
    return output == "1"

def user_exists_in_any_domain(sam: str) -> bool:
    return any(user_exists_in_domain(cfg["server"], sam) for cfg in DOMAIN_CONFIGS)

def generate_samaccount_name(first_name: str, last_name: str) -> str:
    first_name = first_name.strip()
    last_name = last_name.strip()

    base = translit_gost(first_name[:1]) + translit_gost(last_name)
    candidates = [base]

    if len(first_name) > 1:
        two_letters = translit_gost(first_name[:2]) + translit_gost(last_name)
        if two_letters != base:
            candidates.append(two_letters)

    suffix = 2
    while True:
        for cand in candidates:
            if not user_exists_in_any_domain(cand):
                return cand
        candidates.append(f"{base}{suffix}")
        suffix += 1


def normalize_omg_unit_name(value: str) -> str:
    text = (value or "").strip().lower().replace("ё", "е")
    return re.sub(r"\s+", " ", text)


def get_omg_department_and_section(parsed: dict) -> tuple[str, str]:
    raw_dep = parsed.get("department") or ""
    raw_mgmt = parsed.get("management") or ""

    dep_parts = [normalize_omg_unit_name(part) for part in str(raw_dep).split("/") if part.strip()]
    mgmt = normalize_omg_unit_name(str(raw_mgmt))

    department = ""
    section = ""

    if dep_parts:
        if dep_parts[0] in OMG_OU_TREE:
            department = dep_parts[0]
            if len(dep_parts) > 1:
                section = dep_parts[-1]
        elif dep_parts[-1] in OMG_OU_TREE:
            department = dep_parts[-1]

    if not department and mgmt in OMG_OU_TREE:
        department = mgmt

    if not department and dep_parts:
        only_value = dep_parts[-1]
        owners = [dep for dep, sections in OMG_OU_TREE.items() if only_value in sections]
        if len(owners) == 1:
            department = owners[0]
            section = only_value

    if section and section not in OMG_OU_TREE.get(department, []):
        section = ""

    return department, section

def get_ad_department(parsed: dict) -> str:
    raw_dep = parsed.get("department")
    raw_mgmt = parsed.get("management")

    source = None
    if raw_dep:
        source = raw_dep
    elif raw_mgmt:
        source = raw_mgmt
    else:
        return ""

    parts = [p.strip() for p in str(source).split("/") if p.strip()]
    if parts:
        dep = parts[-1]
    else:
        dep = str(source).strip()

    dep = dep.lower()
    return dep[:64]

def get_omg_section(parsed: dict) -> str:
    """section для omg, максимум 32 символа"""
    _, section = get_omg_department_and_section(parsed)
    return section[:32]


def get_omg_ou_dn(cfg: dict, parsed: dict) -> str:
    department, section = get_omg_department_and_section(parsed)
    return get_omg_ou_dn_from_values(cfg, department, section)


def get_omg_ou_dn_from_values(cfg: dict, department: str, section: str) -> str:
    base_ou_dn = cfg["ou_dn"]
    department = normalize_omg_unit_name(department)
    section = normalize_omg_unit_name(section)

    if not department:
        return base_ou_dn

    if department not in OMG_OU_TREE:
        return base_ou_dn

    if section and section not in OMG_OU_TREE.get(department, []):
        section = ""

    branch = [f"OU={department}"]
    if section:
        branch.insert(0, f"OU={section}")
    return ",".join(branch + [base_ou_dn])

def get_address_details(address: str) -> dict:
    base = {
        "pobox": "",
        "city": "",
        "state": "",
        "postal_code": "",
        "country": "",
    }
    if not address:
        return base
    meta = ADDRESS_DETAILS.get(address)
    if not meta:
        return base
    res = base.copy()
    res.update(meta)
    return res

def manager_exists_for_domain(cfg: dict, manager_name: str) -> bool:
    """
    Проверяем, есть ли руководитель в ЭТОМ домене (без fallback).
    """
    name = (manager_name or "").strip()
    if not name:
        return False
    name_ps = name.replace("'", "''")

    ps = (
        "Import-Module ActiveDirectory; "
        f"$name = '{name_ps}'; "
        "$mgr = Get-ADUser "
        "-Filter \"SamAccountName -eq '$name' -or DisplayName -like '*$name*'\" "
        "-ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if ($mgr) { '1' } else { '0' }"
    )

    proc = run_powershell(ps, server=cfg["server"])
    if proc.returncode != 0:
        return False
    return (proc.stdout or "").strip() == "1"

def user_exists_in_domain_details(cfg: dict, sam: str, upn: str) -> tuple[bool, str]:
    """
    Проверяем наличие пользователя в домене по SamAccountName/UPN.
    """
    sam_ps = (sam or "").replace("'", "''")
    upn_ps = (upn or "").replace("'", "''")

    ps = (
        "Import-Module ActiveDirectory; "
        f"$sam = '{sam_ps}'; "
        f"$upn = '{upn_ps}'; "
        "$user = Get-ADUser "
        "-Filter \"SamAccountName -eq '$sam' -or UserPrincipalName -eq '$upn'\" "
        "-Properties SamAccountName, UserPrincipalName, DisplayName "
        "-ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if ($user) { "
        "  $user.SamAccountName + '|' + $user.UserPrincipalName + '|' + $user.DisplayName "
        "} "
    )

    proc = run_powershell(ps, server=cfg["server"])
    if proc.returncode != 0:
        return False, ""
    data = (proc.stdout or "").strip()
    if not data:
        return False, ""
    return True, data

def user_exists_by_display_name(cfg: dict, display_name: str) -> tuple[bool, str]:
    """
    Проверяем наличие пользователя в домене по DisplayName.
    """
    name = (display_name or "").strip()
    if not name:
        return False, ""
    name_ps = name.replace("'", "''")
    ps = (
        "Import-Module ActiveDirectory; "
        f"$name = '{name_ps}'; "
        "$user = Get-ADUser "
        "-Filter \"DisplayName -eq '$name'\" "
        "-Properties SamAccountName, DisplayName "
        "-ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if ($user) { "
        "  $user.SamAccountName + '|' + $user.DisplayName "
        "} "
    )
    proc = run_powershell(ps, server=cfg["server"])
    if proc.returncode != 0:
        return False, ""
    data = (proc.stdout or "").strip()
    if not data:
        return False, ""
    return True, data

def search_users_in_domain(
    cfg: dict,
    query: str,
    debug_log: Optional[Callable[[str], None]] = None,
) -> tuple[list, str]:
    query = (query or "").strip()
    if not query:
        return [], ""
    q_ldap = escape_ldap_filter(query)
    server = escape_ps_string(cfg["server"])
    search_base = escape_ps_string(cfg.get("search_base") or "")
    domain_name = cfg["name"]
    q_digits = re.sub(r"\D", "", query)
    q_digits_ldap = escape_ldap_filter(q_digits) if q_digits else ""
    filter_parts = [
        f"(displayName=*{q_ldap}*)",
        f"(samAccountName=*{q_ldap}*)",
    ]
    if q_digits_ldap:
        filter_parts.append(f"(telephoneNumber=*{q_digits_ldap}*)")
        filter_parts.append(f"(mobile=*{q_digits_ldap}*)")
        if domain_name == "omg-cspfmba":
            filter_parts.append(f"(otpMobile=*{q_digits_ldap}*)")
    ldap_filter = "(|" + "".join(filter_parts) + ")"
    ldap_filter_ps = escape_ps_string(ldap_filter)
    search_base_arg = f" -SearchBase '{search_base}'" if search_base else ""
    base_props = [
        "DisplayName",
        "SamAccountName",
        "UserPrincipalName",
        "telephoneNumber",
        "mobile",
        "title",
        "department",
        "physicalDeliveryOfficeName",
        "manager",
        "mail",
        "streetAddress",
        "postOfficeBox",
        "l",
        "st",
        "postalCode",
        "c",
        "description",
    ]
    extra_props = ["division", "section", "otpMobile"] if domain_name == "omg-cspfmba" else []
    props_arg = ",".join(base_props + extra_props)
    ps_lines = [
        "Import-Module ActiveDirectory",
        f"$ldap = '{ldap_filter_ps}'",
        f"$users = Get-ADUser -Server '{server}' -LDAPFilter $ldap -ResultSetSize 100"
        f"{search_base_arg} "
        f"-Properties {props_arg}",
        "$users | ForEach-Object {",
        "  $mgrName = ''",
        f"  if ($_.Manager) {{ $mgr = Get-ADUser -Server '{server}' -Identity $_.Manager "
        "-Properties DisplayName -ErrorAction SilentlyContinue; "
        "if ($mgr) { $mgrName = $mgr.DisplayName } }",
        "  $display = if ($_.DisplayName) { $_.DisplayName } else { $_.Name }",
        "  [pscustomobject]@{",
        f"    domain = '{domain_name}'",
        "    displayName = $display",
        "    sam = $_.SamAccountName",
        "    upn = $_.UserPrincipalName",
        "    telephoneNumber = $_.telephoneNumber",
        "    mobile = $_.mobile",
        "    otpMobile = $_.otpMobile",
        "    title = $_.title",
        "    department = $_.department",
        "    office = $_.physicalDeliveryOfficeName",
        "    managerName = $mgrName",
        "    mail = $_.mail",
        "    streetAddress = $_.streetAddress",
        "    postOfficeBox = $_.postOfficeBox",
        "    city = $_.l",
        "    state = $_.st",
        "    postalCode = $_.postalCode",
        "    country = $_.c",
        "    description = $_.description",
        "    division = $_.division",
        "    section = $_.section",
        "  }",
        "} | ConvertTo-Json -Depth 4",
    ]
    ps_command = "\n".join(ps_lines)
    proc = run_powershell(ps_command)
    if debug_log and domain_name == "pak-cspmz":
        stdout_preview = (proc.stdout or "").strip().replace("\r\n", "\n")
        stderr_preview = (proc.stderr or "").strip().replace("\r\n", "\n")
        if len(stdout_preview) > 500:
            stdout_preview = stdout_preview[:500] + "...(truncated)"
        if len(stderr_preview) > 500:
            stderr_preview = stderr_preview[:500] + "...(truncated)"
        debug_log("--- DEBUG: поиск пользователей в pak-cspmz ---")
        debug_log(f"Запрос: {query}")
        debug_log(f"Server: {cfg.get('server')}")
        debug_log(f"SearchBase: {cfg.get('search_base') or '(не задан)'}")
        debug_log(f"LDAP filter: {ldap_filter}")
        debug_log(f"PowerShell rc: {proc.returncode}")
        if stderr_preview:
            debug_log(f"STDERR: {stderr_preview}")
        debug_log(f"STDOUT preview: {stdout_preview or '(пусто)'}")
        debug_log("--- конец DEBUG ---")
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        msg = stderr or "PowerShell вернул ошибку поиска."
        return [], f"[{domain_name}] {msg}"
    results, parse_error = parse_ps_json(proc.stdout)
    if parse_error:
        return [], f"[{domain_name}] {parse_error}"
    return results, ""

def search_users_in_all_domains(
    query: str,
    debug_log: Optional[Callable[[str], None]] = None,
) -> tuple[list, list]:
    results = []
    errors = []
    for cfg in DOMAIN_CONFIGS:
        domain_results, error = search_users_in_domain(cfg, query, debug_log=debug_log)
        results.extend(domain_results)
        if error:
            errors.append(error)
    return results, errors

# ==========================
# Создание пользователя
# ==========================

def create_user_in_domain(
    cfg: dict,
    sam: str,
    parsed: dict,
    address: str,
    manager_name: str = "",
    password_plain: str = "",
    target_ou_dn: Optional[str] = None,
    dry_run: bool = False,
) -> tuple[str, bool]:
    last_name = parsed.get("last_name") or ""
    first_name = parsed.get("first_name") or ""
    middle_name = parsed.get("middle_name") or ""

    title_raw = parsed.get("title") or ""
    title = title_raw.strip().lower()

    office_room = (parsed.get("office_room") or "").strip()
    need_mail = parsed.get("need_mail") or False

    raw_mobile = parsed.get("mobile_phone") or ""
    mobile = normalize_phone(raw_mobile) if raw_mobile else ""

    display_name = " ".join(x for x in [last_name, first_name, middle_name] if x)

    upn = sam + cfg["upn_suffix"]
    email = sam + cfg["email_suffix"] if need_mail else ""

    description = title

    is_omg = (cfg["name"] == "omg-cspfmba")
    requested_target_ou_dn = (target_ou_dn or "").strip()
    target_ou_dn = requested_target_ou_dn or cfg["ou_dn"]
    fallback_ou_dn = cfg["ou_dn"]
    target_ou_dn_ps = target_ou_dn.replace("'", "''")
    fallback_ou_dn_ps = fallback_ou_dn.replace("'", "''")
    if is_omg:
        department, _ = get_omg_department_and_section(parsed)
        section = get_omg_section(parsed)
    else:
        department = get_ad_department(parsed)
        section = ""
    division = OMG_DIVISION_VALUE if is_omg else ""
    otp_mobile = mobile if is_omg and mobile else ""

    addr_meta = get_address_details(address)
    pobox = addr_meta["pobox"]
    city = addr_meta["city"]
    state = addr_meta["state"]
    postal_code = addr_meta["postal_code"]
    country = addr_meta["country"]  # RU

    mgr_name_value = (manager_name or "").strip()
    mgr_name_escaped = mgr_name_value.replace("'", "''")
    ad_server = escape_ps_string(get_preferred_dc(cfg))
    retry_server = escape_ps_string(cfg.get("server") or get_preferred_dc(cfg))

    password_escaped = password_plain.replace("'", "''")

    ps_lines = [
        "Import-Module ActiveDirectory",
        f"$srv = '{ad_server}'",
        f"$retrySrv = '{retry_server}'",
        f"$securePassword = ConvertTo-SecureString '{password_escaped}' -AsPlainText -Force",
        f"$name = '{display_name}'",
        f"$givenName = '{first_name}'",
        f"$surname = '{last_name}'",
        f"$sam = '{sam}'",
        f"$upn = '{upn}'",
        f"$title = '{title}'",
        f"$department = '{department}'",
        f"$company = '{COMPANY_NAME}'",
        f"$office = '{office_room}'",
        f"$street = '{address}'",
        f"$description = '{description}'",
        f"$mobile = '{mobile}'",
        f"$mail = '{email}'",
        f"$mgrName = '{mgr_name_escaped}'",
        f"$pobox = '{pobox}'",
        f"$city = '{city}'",
        f"$state = '{state}'",
        f"$postalCode = '{postal_code}'",
        f"$country = '{country}'",
        f"$targetPath = '{target_ou_dn_ps}'",
        f"$fallbackPath = '{fallback_ou_dn_ps}'",
        "$createdInFallbackOu = $false",
    ]

    if is_omg:
        ps_lines.append(f"$division = '{division}'")
        ps_lines.append(f"$otpMobile = '{otp_mobile}'")
        ps_lines.append(f"$section = '{section}'")

    new_aduser_cmd = (
        "New-ADUser "
        "-Server $srv "
        "-Path $targetPath "
        "-Name $name "
        "-GivenName $givenName "
        "-Surname $surname "
        "-SamAccountName $sam "
        "-UserPrincipalName $upn "
        "-DisplayName $name "
    )

    if title:
        new_aduser_cmd += "-Title $title "
    if department:
        new_aduser_cmd += "-Department $department "
    if COMPANY_NAME:
        new_aduser_cmd += "-Company $company "
    if office_room:
        new_aduser_cmd += "-Office $office "
    if email:
        new_aduser_cmd += "-EmailAddress $mail "

    # Адресные поля
    if pobox:
        new_aduser_cmd += "-POBox $pobox "
    if city:
        new_aduser_cmd += "-City $city "
    if state:
        new_aduser_cmd += "-State $state "
    if postal_code:
        new_aduser_cmd += "-PostalCode $postalCode "
    if country:
        new_aduser_cmd += "-Country $country "

    # В omg mobile не заполняем, только otpMobile
    if mobile and not is_omg:
        new_aduser_cmd += "-MobilePhone $mobile "

    if address:
        new_aduser_cmd += "-StreetAddress $street "
    if description:
        new_aduser_cmd += "-Description $description "

    if is_omg and division:
        new_aduser_cmd += "-Division $division "

    new_aduser_cmd += "-AccountPassword $securePassword -Enabled:$true "
    new_aduser_cmd += "-ChangePasswordAtLogon $true "

    other_attrs_parts = []
    if is_omg:
        if otp_mobile:
            other_attrs_parts.append("'otpMobile'=$otpMobile")
        if section:
            other_attrs_parts.append("'section'=$section")

    if other_attrs_parts:
        new_aduser_cmd += " -OtherAttributes @{" + "; ".join(other_attrs_parts) + "}"

    if is_omg and target_ou_dn != fallback_ou_dn:
        new_aduser_cmd_fallback = new_aduser_cmd.replace("-Path $targetPath", "-Path $fallbackPath")
        ps_lines.extend([
            "try {",
            f"  {new_aduser_cmd} -ErrorAction Stop",
            "} catch {",
            "  $errType = $_.Exception.GetType().FullName",
            "  $msg = (($_.Exception.Message) + ' ' + ($_.ToString()))",
            "  $isOuNotFound = ($errType -like '*ADIdentityNotFoundException*') -or "
            "($msg -like '*cannot find the object*') -or ($msg -like '*directory object not found*') -or "
            "($msg -like '*не удается найти*') -or ($msg -like '*объект не найден*')",
            "  if ($isOuNotFound) {",
            "    $createdInFallbackOu = $true",
            f"    {new_aduser_cmd_fallback} -ErrorAction Stop",
            "  } else {",
            "    throw",
            "  }",
            "}",
            "if ($createdInFallbackOu) {",
            "  Write-Output '__OU_CONFLICT_FALLBACK__'",
            "}",
        ])
    else:
        ps_lines.append(new_aduser_cmd)
    # Гарантируем смену пароля при первом входе даже если флаг ChangePasswordAtLogon
    # не применился на этапе создания.
    ps_lines.append("Set-ADUser -Server $srv -Identity $sam -ChangePasswordAtLogon $true")

    # Post-обработка Manager — только в СВОЁМ домене, без fallback
    post_mgr_cmd = (
        "if ($mgrName -ne '') { "
        "$mgr = Get-ADUser -Server $srv "
        "-Filter \"SamAccountName -eq '$mgrName' -or DisplayName -like '*$mgrName*'\" "
        "-ErrorAction SilentlyContinue | Select-Object -First 1; "
        "if ($mgr) { "
        "  Set-ADUser -Server $srv -Identity $sam -Manager $mgr.DistinguishedName "
        "} "
        "}"
    )

    ps_lines.append(post_mgr_cmd)

    ps_script = "; ".join(ps_lines)

    if dry_run:
        ps_script_safe = ps_script.replace(password_escaped, "<скрыто>")
        return f"[{cfg['name']}] DRY RUN PowerShell:\n{ps_script_safe}\n", False

    proc = run_powershell(ps_script)
    stderr = proc.stderr or ""
    stdout = proc.stdout or ""
    success = proc.returncode == 0

    log_lines = [
        f"[{cfg['name']}] New-ADUser/Set-ADUser выполнены, код {proc.returncode}",
        f"[{cfg['name']}] Server для создания: $srv='{ad_server}' (retry='{retry_server}')",
    ]
    if is_omg and not requested_target_ou_dn:
        log_lines.append(
            "Пояснение: целевой OU не определён resolver-ом, использован базовый контейнер домена (cfg['ou_dn'])."
        )

    # Человеческие расшифровки частых ошибок
    if "Server:8305" in stderr:
        log_lines.append(
            "Пояснение: AD вернул ошибку 8305 – объект с таким именем уже существует "
            "в целевой OU. Скорее всего, в этом контейнере уже есть пользователь "
            "с таким же ФИО (Name/CN), поэтому новый пользователь НЕ был создан."
        )

    if "ADIdentityNotFoundException" in stderr and "Set-ADUser" in stderr:
        log_lines.append(
            "Пояснение: не удалось установить руководителя (атрибут Manager) – "
            "объект руководителя не найден или недоступен в этом домене."
        )

    if "__OU_CONFLICT_FALLBACK__" in stdout:
        log_lines.append(
            "Пояснение: целевой OU по связке Управление/Отдел не найден. "
            "Пользователь создан в базовом OU домена, но требуется ручная проверка "
            "и перенос в правильный контейнер."
        )

    if stdout:
        log_lines.append("STDOUT:")
        log_lines.append(stdout)
    if stderr:
        log_lines.append("STDERR:")
        log_lines.append(stderr)

    return "\n".join(log_lines) + "\n", success


def update_user_in_domain(
    cfg: dict,
    sam: str,
    title: Optional[str],
    department: Optional[str],
    office_room: Optional[str],
    mobile_raw: Optional[str],
    telephone_raw: Optional[str],
    address: Optional[str],
    manager_name: Optional[str],
    need_mail: Optional[bool],
    description: Optional[str],
    division: Optional[str],
    section: Optional[str],
    target_ou_dn: Optional[str] = None,
) -> tuple[str, bool]:
    title_value = title.strip().lower() if title is not None else None
    department_value = department.strip().lower() if department is not None else None
    office_value = office_room.strip() if office_room is not None else None
    mobile = normalize_phone(mobile_raw) if mobile_raw is not None else None
    telephone = normalize_phone(telephone_raw) if telephone_raw is not None else None
    description_value = description.strip() if description is not None else None
    division_value = division.strip() if division is not None else None
    section_value = section.strip() if section is not None else None
    address_value = address.strip() if address is not None else None

    has_address_meta = bool(address_value and address_value in ADDRESS_DETAILS)
    addr_meta = get_address_details(address_value) if has_address_meta else get_address_details("")
    pobox = addr_meta["pobox"]
    city = addr_meta["city"]
    state = addr_meta["state"]
    postal_code = addr_meta["postal_code"]
    country = addr_meta["country"]

    manager_value = manager_name.strip() if manager_name is not None else None
    manager_escaped = manager_value.replace("'", "''") if manager_value is not None else ""

    email = sam + cfg["email_suffix"] if need_mail else ""

    is_omg = (cfg["name"] == "omg-cspfmba")
    otp_mobile = mobile if is_omg and mobile else ""
    ad_server = escape_ps_string(get_preferred_dc(cfg))
    retry_server = escape_ps_string(cfg["server"])

    ps_lines = [
        "Import-Module ActiveDirectory",
        f"$sam = '{sam}'",
        f"$srv = '{ad_server}'",
        f"$retrySrv = '{retry_server}'",
    ]

    if title_value is not None:
        ps_lines.append(f"$title = '{title_value}'")
    if department_value is not None:
        ps_lines.append(f"$department = '{department_value}'")
    if office_value is not None:
        ps_lines.append(f"$office = '{office_value}'")
    if address_value is not None:
        ps_lines.append(f"$street = '{address_value}'")
    if mobile is not None:
        ps_lines.append(f"$mobile = '{mobile}'")
    if telephone is not None:
        ps_lines.append(f"$telephone = '{telephone}'")
    if need_mail is not None:
        ps_lines.append(f"$mail = '{email}'")
    if manager_value is not None:
        ps_lines.append(f"$mgrName = '{manager_escaped}'")
    if address_value is not None:
        ps_lines.append(f"$pobox = '{pobox}'")
        ps_lines.append(f"$city = '{city}'")
        ps_lines.append(f"$state = '{state}'")
        ps_lines.append(f"$postalCode = '{postal_code}'")
        ps_lines.append(f"$country = '{country}'")
    if description_value is not None:
        ps_lines.append(f"$description = '{escape_ps_string(description_value)}'")
    if division_value is not None:
        ps_lines.append(f"$division = '{escape_ps_string(division_value)}'")
    if section_value is not None:
        ps_lines.append(f"$section = '{escape_ps_string(section_value)}'")

    if is_omg and mobile is not None:
        ps_lines.append(f"$otpMobile = '{otp_mobile}'")

    clear_parts = []
    if need_mail is False:
        clear_parts.append("'mail'")
    if title_value is not None and not title_value:
        clear_parts.append("'title'")
    if department_value is not None and not department_value:
        clear_parts.append("'department'")
    if office_value is not None and not office_value:
        clear_parts.append("'physicalDeliveryOfficeName'")
    if address_value is not None and not address_value:
        clear_parts.append("'streetAddress'")
        clear_parts.append("'postOfficeBox'")
        clear_parts.append("'l'")
        clear_parts.append("'st'")
        clear_parts.append("'postalCode'")
        clear_parts.append("'c'")
    if description_value is not None and not description_value:
        clear_parts.append("'description'")
    if division_value is not None and not division_value:
        clear_parts.append("'division'")
    if section_value is not None and not section_value:
        clear_parts.append("'section'")
    if address_value is not None and has_address_meta and not pobox:
        clear_parts.append("'postOfficeBox'")
    if address_value is not None and has_address_meta and not city:
        clear_parts.append("'l'")
    if address_value is not None and has_address_meta and not state:
        clear_parts.append("'st'")
    if address_value is not None and has_address_meta and not postal_code:
        clear_parts.append("'postalCode'")
    if address_value is not None and has_address_meta and not country:
        clear_parts.append("'c'")
    if mobile is not None and not mobile:
        clear_parts.append("'mobile'")
    if telephone is not None and not telephone:
        clear_parts.append("'telephoneNumber'")
    if manager_value is not None and not manager_value:
        clear_parts.append("'manager'")

    set_cmd = "Set-ADUser -Server $srv -Identity $sam "
    if title_value:
        set_cmd += "-Title $title "
    if department_value:
        set_cmd += "-Department $department "
    if office_value:
        set_cmd += "-Office $office "
    if address_value:
        set_cmd += "-StreetAddress $street "
    if address_value and has_address_meta and pobox:
        set_cmd += "-POBox $pobox "
    if address_value and has_address_meta and city:
        set_cmd += "-City $city "
    if address_value and has_address_meta and state:
        set_cmd += "-State $state "
    if address_value and has_address_meta and postal_code:
        set_cmd += "-PostalCode $postalCode "
    if address_value and has_address_meta and country:
        set_cmd += "-Country $country "
    if description_value:
        set_cmd += "-Description $description "
    if need_mail and email:
        set_cmd += "-EmailAddress $mail "
    if mobile and not is_omg:
        set_cmd += "-MobilePhone $mobile "
    if telephone:
        set_cmd += "-OfficePhone $telephone "
    if clear_parts:
        set_cmd += "-Clear @(" + ", ".join(clear_parts) + ") "

    if set_cmd.strip() != "Set-ADUser -Server $srv -Identity $sam":
        ps_lines.append(set_cmd)

    replace_parts = []
    if is_omg and otp_mobile:
        replace_parts.append("'otpMobile'=$otpMobile")
    if division_value:
        replace_parts.append("'division'=$division")
    if section_value:
        replace_parts.append("'section'=$section")

    if replace_parts:
        ps_lines.append("Set-ADUser -Server $srv -Identity $sam "
                        "-Replace @{" + "; ".join(replace_parts) + "}")

    if manager_value is not None:
        post_mgr_cmd = (
            "if ($mgrName -ne '') { "
            "$mgr = Get-ADUser -Server $srv "
            "-Filter \"SamAccountName -eq '$mgrName' -or DisplayName -like '*$mgrName*'\" "
            "-ErrorAction SilentlyContinue | Select-Object -First 1; "
            "if ($mgr) { "
            "  Set-ADUser -Server $srv -Identity $sam -Manager $mgr.DistinguishedName "
            "} "
            "}"
        )
        ps_lines.append(post_mgr_cmd)

    if target_ou_dn:
        target_ou_dn_escaped = escape_ps_string(target_ou_dn)
        if validate_ou_exists(cfg, target_ou_dn):
            ps_lines.extend([
                f"$targetOU = '{target_ou_dn_escaped}'",
                "$user = Get-ADUser -Server $srv -Identity $sam -Properties DistinguishedName,ObjectGUID -ErrorAction Stop",
                "if ($user -and $user.DistinguishedName) {",
                "  $currentDN = $user.DistinguishedName",
                "  $currentParent = ($currentDN -split ',', 2)[1]",
                "  if ($currentParent -ne $targetOU) {",
                "    $guid = $user.ObjectGUID",
                "    try {",
                "      Move-ADObject -Server $srv -Identity $guid -TargetPath $targetOU -ErrorAction Stop",
                "    } catch {",
                "      $msg = $_.Exception.Message",
                "      if (($msg -like '*ActiveDirectoryServer:8329*' -or $msg -like '*uninstantiated or deleted*') -and $retrySrv -ne $srv) {",
                "        Move-ADObject -Server $retrySrv -Identity $guid -TargetPath $targetOU -ErrorAction Stop",
                "      } else {",
                "        throw",
                "      }",
                "    }",
                "  }",
                "}",
            ])
        else:
            ps_lines.append("Write-Output '__MOVE_SKIPPED_INVALID_OU__'")

    ps_script = "; ".join(ps_lines)
    proc = run_powershell(ps_script)
    stderr = proc.stderr or ""
    stdout = proc.stdout or ""
    success = proc.returncode == 0

    log_lines = [f"[{cfg['name']}] Set-ADUser выполнен, код {proc.returncode}"]
    if "ADIdentityNotFoundException" in stderr and "Set-ADUser" in stderr:
        log_lines.append(
            "Пояснение: не удалось обновить руководителя – "
            "объект руководителя не найден или недоступен в этом домене."
        )
    if "ActiveDirectoryServer:8329" in stderr or "uninstantiated or deleted" in stderr:
        log_lines.append(
            "Перемещение в OU не выполнено: на контроллере домена нет родительского контейнера "
            "(репликация/OU). Попробуйте позже или используйте PDC."
        )
    if "__MOVE_SKIPPED_INVALID_OU__" in stdout:
        log_lines.append("Move пропущен: целевой OU не существует на выбранном контроллере домена.")
    if stdout:
        log_lines.append("STDOUT:")
        log_lines.append(stdout)
    if stderr:
        log_lines.append("STDERR:")
        log_lines.append(stderr)

    return "\n".join(log_lines) + "\n", success


# ==========================
# GUI
# ==========================

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Создание пользователя в AD из заявки")
        self.geometry("980x900")

        self.domain_vars = {}
        self.password_token = load_password_token()
        self.history_entries = []
        self.selected_history_index = None
        self._load_window_geometry()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._build_widgets()

    def _build_widgets(self):
        frm_top = ttk.Frame(self)
        frm_top.pack(fill="both", expand=True, padx=10, pady=10)

        lbl = ttk.Label(frm_top, text="Вставьте текст заявки:")
        lbl.pack(anchor="w")

        self.txt_input = tk.Text(frm_top, height=20, wrap="word")
        self.txt_input.pack(fill="both", expand=True)

        frm_middle = ttk.Frame(self)
        frm_middle.pack(fill="x", padx=10, pady=5)

        frm_addr = ttk.Frame(frm_middle)
        frm_addr.pack(fill="x", pady=2)
        ttk.Label(frm_addr, text="Адрес офиса:").pack(side="left")
        self.address_var = tk.StringVar(value=ADDRESS_CHOICES[0])
        self.cmb_address = ttk.Combobox(
            frm_addr,
            textvariable=self.address_var,
            values=ADDRESS_CHOICES,
            state="readonly",
            width=40,
        )
        self.cmb_address.pack(side="left", padx=5)

        frm_password = ttk.Frame(frm_middle)
        frm_password.pack(fill="x", pady=2)

        ttk.Label(frm_password, text="Пароль по умолчанию:").pack(side="left")
        self.password_status_var = tk.StringVar()
        self._sync_password_status()
        ttk.Label(frm_password, textvariable=self.password_status_var).pack(side="left", padx=5)
        ttk.Button(
            frm_password,
            text="Изменить пароль",
            command=self._open_password_modal,
        ).pack(side="left")

        frm_flags = ttk.Frame(frm_middle)
        frm_flags.pack(fill="x", pady=2)

        self.dry_run_var = tk.BooleanVar(value=False)
        chk_dry = ttk.Checkbutton(
            frm_flags,
            text="Только разобрать (без создания пользователей)",
            variable=self.dry_run_var,
        )
        chk_dry.pack(side="left", padx=5)

        frm_domains = ttk.LabelFrame(self, text="Домены для создания пользователя")
        frm_domains.pack(fill="x", padx=10, pady=5)

        for cfg in DOMAIN_CONFIGS:
            var = tk.BooleanVar(value=True)
            self.domain_vars[cfg["name"]] = var
            chk = ttk.Checkbutton(
                frm_domains,
                text=cfg["label"],
                variable=var,
            )
            chk.pack(anchor="w", padx=5, pady=2)

        frm_btn = ttk.Frame(self)
        frm_btn.pack(fill="x", padx=10, pady=5)

        btn_run = ttk.Button(frm_btn, text="Разобрать и создать", command=self.on_run)
        btn_run.pack(side="left")
        ttk.Button(frm_btn, text="Поиск пользователей", command=self._open_search_modal).pack(
            side="left", padx=6
        )
        ttk.Button(frm_btn, text="Увольнение", command=self._open_offboarding_modal).pack(
            side="left", padx=6
        )

        frm_log = ttk.Frame(self)
        frm_log.pack(fill="both", expand=True, padx=10, pady=5)

        ttk.Label(frm_log, text="Лог:").pack(anchor="w")

        self.txt_log = tk.Text(frm_log, height=12, wrap="word", state="disabled")
        self.txt_log.pack(fill="both", expand=True)

        frm_history = ttk.LabelFrame(self, text="История созданных пользователей (текущий запуск)")
        frm_history.pack(fill="both", expand=False, padx=10, pady=5)

        frm_history_inner = ttk.Frame(frm_history)
        frm_history_inner.pack(fill="both", expand=True, padx=8, pady=8)

        frm_history_list = ttk.Frame(frm_history_inner)
        frm_history_list.pack(side="left", fill="both", expand=False)

        self.history_listbox = tk.Listbox(
            frm_history_list,
            height=8,
            width=40,
            exportselection=False,
        )
        self.history_listbox.pack(side="left", fill="both", expand=False)
        self.history_listbox.bind("<<ListboxSelect>>", self._on_history_select)

        history_scroll = ttk.Scrollbar(frm_history_list, orient="vertical", command=self.history_listbox.yview)
        history_scroll.pack(side="right", fill="y")
        self.history_listbox.configure(yscrollcommand=history_scroll.set)

        frm_history_editor = ttk.Frame(frm_history_inner)
        frm_history_editor.pack(side="left", fill="both", expand=True, padx=(12, 0))

        ttk.Label(frm_history_editor, text="Редактирование выбранного пользователя:").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 6)
        )

        self.edit_title_var = tk.StringVar()
        self.edit_department_var = tk.StringVar()
        self.edit_section_var = tk.StringVar()
        self.edit_division_var = tk.StringVar()
        self.edit_description_var = tk.StringVar()
        self.edit_office_var = tk.StringVar()
        self.edit_mobile_var = tk.StringVar()
        self.edit_otp_mobile_var = tk.StringVar()
        self.edit_telephone_var = tk.StringVar()
        self.edit_manager_var = tk.StringVar()
        self.edit_need_mail_var = tk.BooleanVar()
        self.edit_address_var = tk.StringVar(value=ADDRESS_CHOICES[0])

        ttk.Label(frm_history_editor, text="Должность:").grid(row=1, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_history_editor, textvariable=self.edit_title_var, width=60).grid(
            row=1, column=1, sticky="w"
        )

        ttk.Label(frm_history_editor, text="Отдел (Department):").grid(row=2, column=0, sticky="e", padx=(0, 6))
        self.cmb_edit_department = ttk.Combobox(
            frm_history_editor,
            textvariable=self.edit_department_var,
            values=OMG_DEPARTMENT_CHOICES,
            state="normal",
            width=57,
        )
        self.cmb_edit_department.grid(row=2, column=1, sticky="w")
        self.cmb_edit_department.bind("<<ComboboxSelected>>", self._on_edit_department_changed)

        ttk.Label(frm_history_editor, text="Section:").grid(row=3, column=0, sticky="e", padx=(0, 6))
        self.cmb_edit_section = ttk.Combobox(
            frm_history_editor,
            textvariable=self.edit_section_var,
            values=OMG_SECTION_CHOICES,
            state="normal",
            width=57,
        )
        self.cmb_edit_section.grid(row=3, column=1, sticky="w")
        self.cmb_edit_section.bind("<<ComboboxSelected>>", self._on_edit_section_changed)

        ttk.Label(frm_history_editor, text="Division:").grid(row=4, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_history_editor, textvariable=self.edit_division_var, width=60).grid(
            row=4, column=1, sticky="w"
        )

        ttk.Label(frm_history_editor, text="Description:").grid(row=5, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_history_editor, textvariable=self.edit_description_var, width=60).grid(
            row=5, column=1, sticky="w"
        )

        ttk.Label(frm_history_editor, text="Кабинет:").grid(row=6, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_history_editor, textvariable=self.edit_office_var, width=60).grid(
            row=6, column=1, sticky="w"
        )

        ttk.Label(frm_history_editor, text="Мобильный:").grid(row=7, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_history_editor, textvariable=self.edit_mobile_var, width=60).grid(
            row=7, column=1, sticky="w"
        )

        ttk.Label(frm_history_editor, text="OTP Mobile (omg):").grid(row=8, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_history_editor, textvariable=self.edit_otp_mobile_var, width=60).grid(
            row=8, column=1, sticky="w"
        )

        ttk.Label(frm_history_editor, text="Стационарный:").grid(row=9, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_history_editor, textvariable=self.edit_telephone_var, width=60).grid(
            row=9, column=1, sticky="w"
        )

        ttk.Label(frm_history_editor, text="Руководитель:").grid(row=10, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_history_editor, textvariable=self.edit_manager_var, width=60).grid(
            row=10, column=1, sticky="w"
        )

        ttk.Label(frm_history_editor, text="Адрес офиса:").grid(row=11, column=0, sticky="e", padx=(0, 6))
        ttk.Combobox(
            frm_history_editor,
            textvariable=self.edit_address_var,
            values=ADDRESS_CHOICES,
            state="normal",
            width=57,
        ).grid(row=11, column=1, sticky="w")

        ttk.Checkbutton(
            frm_history_editor,
            text="Назначить корпоративную почту",
            variable=self.edit_need_mail_var,
        ).grid(row=12, column=1, sticky="w", pady=(4, 4))

        self.btn_save_changes = ttk.Button(
            frm_history_editor,
            text="Сохранить изменения",
            command=self._save_history_changes,
            state="disabled",
        )
        self.btn_save_changes.grid(row=13, column=1, sticky="w", pady=(6, 0))

    def log(self, msg: str):
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", msg + "\n")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def _sync_password_status(self):
        if self.password_token:
            self.password_status_var.set("пароль задан")
        else:
            self.password_status_var.set("пароль не задан")

    def _open_password_modal(self):
        modal = tk.Toplevel(self)
        modal.title("Пароль по умолчанию")
        modal.resizable(False, False)
        modal.transient(self)
        modal.grab_set()

        ttk.Label(modal, text="Введите пароль:").pack(anchor="w", padx=10, pady=(10, 4))
        password_var = tk.StringVar()
        entry = ttk.Entry(modal, textvariable=password_var, show="*", width=32)
        entry.pack(padx=10, pady=4)
        entry.focus_set()

        btn_frame = ttk.Frame(modal)
        btn_frame.pack(padx=10, pady=(6, 10), fill="x")

        def save_and_close():
            password_plain = password_var.get().strip()
            if not password_plain:
                messagebox.showerror("Ошибка", "Введите пароль.")
                return
            token = encrypt_password(password_plain)
            save_password_token(token)
            self.password_token = token
            self._sync_password_status()
            modal.destroy()

        ttk.Button(btn_frame, text="Сохранить", command=save_and_close).pack(side="left")
        ttk.Button(btn_frame, text="Отмена", command=modal.destroy).pack(side="left", padx=5)

    def open_search(self, query: str, autorun: bool = True):
        modal = self._open_search_modal()
        self.search_query_var.set((query or "").strip())
        if getattr(self, "_search_entry", None):
            self._search_entry.focus_set()
        if autorun and (query or "").strip():
            modal.after(50, lambda: self._run_search(modal))
        return modal

    def _open_search_modal(self):
        modal = tk.Toplevel(self)
        modal.title("Поиск пользователей в AD")
        modal.geometry("980x600")
        modal.transient(self)
        modal.grab_set()

        self.search_results = []
        self.selected_search_index = None

        self.search_query_var = tk.StringVar()
        self.search_result_count_var = tk.StringVar(value="Найдено: 0")
        self.search_selected_label_var = tk.StringVar(value="Пользователь не выбран")

        self.search_title_var = tk.StringVar()
        self.search_department_var = tk.StringVar()
        self.search_section_var = tk.StringVar()
        self.search_division_var = tk.StringVar()
        self.search_description_var = tk.StringVar()
        self.search_office_var = tk.StringVar()
        self.search_mobile_var = tk.StringVar()
        self.search_otp_mobile_var = tk.StringVar()
        self.search_telephone_var = tk.StringVar()
        self.search_manager_var = tk.StringVar()
        self.search_address_var = tk.StringVar()
        self.search_need_mail_var = tk.BooleanVar()

        frm_top = ttk.Frame(modal)
        frm_top.pack(fill="x", padx=10, pady=8)

        ttk.Label(frm_top, text="Поиск (ФИО, телефон, логин):").pack(side="left")
        entry = ttk.Entry(frm_top, textvariable=self.search_query_var, width=40)
        entry.pack(side="left", padx=6)
        entry.bind("<Return>", lambda _event: self._run_search(modal))
        ttk.Button(frm_top, text="Найти", command=lambda: self._run_search(modal)).pack(side="left")
        ttk.Label(frm_top, textvariable=self.search_result_count_var).pack(side="left", padx=10)

        frm_body = ttk.Frame(modal)
        frm_body.pack(fill="both", expand=True, padx=10, pady=8)

        frm_list = ttk.Frame(frm_body)
        frm_list.pack(side="left", fill="both", expand=False)

        self.search_listbox = tk.Listbox(
            frm_list,
            height=16,
            width=45,
            exportselection=False,
        )
        self.search_listbox.pack(side="left", fill="both", expand=False)
        self.search_listbox.bind("<<ListboxSelect>>", self._on_search_select)
        self.search_listbox.bind("<Double-Button-1>", self._on_search_select)

        search_scroll = ttk.Scrollbar(frm_list, orient="vertical", command=self.search_listbox.yview)
        search_scroll.pack(side="right", fill="y")
        self.search_listbox.configure(yscrollcommand=search_scroll.set)

        frm_editor = ttk.Frame(frm_body)
        frm_editor.pack(side="left", fill="both", expand=True, padx=(12, 0))

        ttk.Label(frm_editor, textvariable=self.search_selected_label_var).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 6)
        )

        ttk.Label(frm_editor, text="Должность:").grid(row=1, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_editor, textvariable=self.search_title_var, width=60).grid(row=1, column=1, sticky="w")

        ttk.Label(frm_editor, text="Отдел (Department):").grid(row=2, column=0, sticky="e", padx=(0, 6))
        self.cmb_search_department = ttk.Combobox(
            frm_editor,
            textvariable=self.search_department_var,
            values=OMG_DEPARTMENT_CHOICES,
            state="normal",
            width=57,
        )
        self.cmb_search_department.grid(row=2, column=1, sticky="w")
        self.cmb_search_department.bind("<<ComboboxSelected>>", self._on_search_department_changed)

        ttk.Label(frm_editor, text="Section:").grid(row=3, column=0, sticky="e", padx=(0, 6))
        self.cmb_search_section = ttk.Combobox(
            frm_editor,
            textvariable=self.search_section_var,
            values=OMG_SECTION_CHOICES,
            state="normal",
            width=57,
        )
        self.cmb_search_section.grid(row=3, column=1, sticky="w")
        self.cmb_search_section.bind("<<ComboboxSelected>>", self._on_search_section_changed)

        ttk.Label(frm_editor, text="Division:").grid(row=4, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_editor, textvariable=self.search_division_var, width=60).grid(row=4, column=1, sticky="w")

        ttk.Label(frm_editor, text="Description:").grid(row=5, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_editor, textvariable=self.search_description_var, width=60).grid(row=5, column=1, sticky="w")

        ttk.Label(frm_editor, text="Кабинет:").grid(row=6, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_editor, textvariable=self.search_office_var, width=60).grid(row=6, column=1, sticky="w")

        ttk.Label(frm_editor, text="Мобильный:").grid(row=7, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_editor, textvariable=self.search_mobile_var, width=60).grid(row=7, column=1, sticky="w")

        ttk.Label(frm_editor, text="OTP Mobile (omg):").grid(row=8, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_editor, textvariable=self.search_otp_mobile_var, width=60).grid(row=8, column=1, sticky="w")

        ttk.Label(frm_editor, text="Стационарный:").grid(row=9, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_editor, textvariable=self.search_telephone_var, width=60).grid(row=9, column=1, sticky="w")

        ttk.Label(frm_editor, text="Руководитель:").grid(row=10, column=0, sticky="e", padx=(0, 6))
        ttk.Entry(frm_editor, textvariable=self.search_manager_var, width=60).grid(row=10, column=1, sticky="w")

        ttk.Label(frm_editor, text="Адрес офиса:").grid(row=11, column=0, sticky="e", padx=(0, 6))
        ttk.Combobox(
            frm_editor,
            textvariable=self.search_address_var,
            values=ADDRESS_CHOICES,
            state="normal",
            width=57,
        ).grid(row=11, column=1, sticky="w")

        ttk.Checkbutton(
            frm_editor,
            text="Назначить корпоративную почту",
            variable=self.search_need_mail_var,
        ).grid(row=12, column=1, sticky="w", pady=(4, 4))

        self.btn_save_search = ttk.Button(
            frm_editor,
            text="Сохранить изменения",
            command=self._save_search_changes,
            state="disabled",
        )
        self.btn_save_search.grid(row=13, column=1, sticky="w", pady=(6, 0))

        self._search_modal = modal
        self._search_entry = entry
        entry.focus_set()
        return modal

    def _run_search(self, modal):
        query = self.search_query_var.get().strip()
        if not query:
            messagebox.showerror("Ошибка", "Введите строку для поиска.")
            return
        modal.configure(cursor="watch")
        modal.update_idletasks()
        results, errors = search_users_in_all_domains(query, debug_log=self.log)
        modal.configure(cursor="")
        self.search_results = sorted(
            results,
            key=lambda item: ((item.get("displayName") or "").lower(), item.get("domain") or ""),
        )
        self.search_listbox.delete(0, "end")
        for item in self.search_results:
            display_name = (
                item.get("displayName")
                or item.get("sam")
                or item.get("upn")
                or "(без имени)"
            )
            domain = item.get("domain") or "unknown"
            self.search_listbox.insert("end", f"{display_name} — {domain}")
        self.search_result_count_var.set(f"Найдено: {len(self.search_results)}")
        self.selected_search_index = None
        self.search_selected_label_var.set("Пользователь не выбран")
        self.btn_save_search.configure(state="disabled")
        if errors:
            messagebox.showwarning("Поиск", "Ошибки поиска:\n" + "\n".join(errors))
        if not self.search_results:
            messagebox.showinfo("Результаты", "Пользователи не найдены.")

    def _on_search_select(self, _event=None):
        selection = self.search_listbox.curselection()
        if not selection:
            self.selected_search_index = None
            self.btn_save_search.configure(state="disabled")
            return
        index = selection[0]
        self.selected_search_index = index
        entry = self.search_results[index]
        self.search_title_var.set(entry.get("title", "") or "")
        self.search_department_var.set(entry.get("department", "") or "")
        self._on_search_department_changed()
        self.search_section_var.set(entry.get("section", "") or "")
        self.search_division_var.set(entry.get("division", "") or "")
        self.search_description_var.set(entry.get("description", "") or "")
        self.search_office_var.set(entry.get("office", "") or "")
        self.search_mobile_var.set(entry.get("mobile", "") or "")
        self.search_otp_mobile_var.set(entry.get("otpMobile", "") or "")
        self.search_telephone_var.set(entry.get("telephoneNumber", "") or "")
        self.search_manager_var.set(entry.get("managerName", "") or "")
        self.search_address_var.set(entry.get("streetAddress", "") or "")
        self.search_need_mail_var.set(bool(entry.get("mail")))
        display_name = (
            entry.get("displayName")
            or entry.get("sam")
            or entry.get("upn")
            or "(без имени)"
        )
        domain = entry.get("domain") or "unknown"
        self.search_selected_label_var.set(f"Редактирование: {display_name} ({domain})")
        self.btn_save_search.configure(state="normal")

    def _select_target_ou_with_dialog(self, cfg: dict, dept_text: str) -> Optional[str]:
        resolved_dn, candidates, confidence = resolve_target_ou(cfg, dept_text, base_path_hint=cfg.get("ou_dn"))
        self.log(
            f"[{cfg['name']}] OU resolve: dept='{dept_text}', confidence={confidence}, "
            f"candidates={len(candidates)}"
        )
        if resolved_dn and confidence == "high":
            self.log(f"[{cfg['name']}] OU auto-resolved: {resolved_dn}")
            return resolved_dn

        if not candidates:
            self.log(f"[{cfg['name']}] Move пропущен: кандидаты OU не найдены для '{dept_text}'.")
            return None

        modal = tk.Toplevel(self)
        modal.title("Выбор OU")
        modal.geometry("900x420")
        modal.transient(self)
        modal.grab_set()

        ttk.Label(modal, text=f"Отдел из заявки: {dept_text}").pack(anchor="w", padx=10, pady=(10, 4))
        search_var = tk.StringVar()
        remember_var = tk.BooleanVar(value=False)
        selected_dn = tk.StringVar(value="")

        frame = ttk.Frame(modal)
        frame.pack(fill="both", expand=True, padx=10, pady=6)
        ttk.Label(frame, text="Поиск:").pack(anchor="w")
        entry = ttk.Entry(frame, textvariable=search_var)
        entry.pack(fill="x", pady=(0, 6))

        listbox = tk.Listbox(frame, height=12)
        listbox.pack(fill="both", expand=True)

        items = list(candidates)

        def redraw(*_args):
            query = normalize_text(search_var.get())
            listbox.delete(0, "end")
            for item in items:
                text = f"{item['Name']} | {item['DistinguishedName']}"
                if query and query not in normalize_text(text):
                    continue
                listbox.insert("end", text)

        search_var.trace_add("write", redraw)
        redraw()

        def choose():
            sel = listbox.curselection()
            if not sel:
                return
            idx = sel[0]
            visible = []
            q = normalize_text(search_var.get())
            for item in items:
                text = f"{item['Name']} | {item['DistinguishedName']}"
                if q and q not in normalize_text(text):
                    continue
                visible.append(item)
            if idx >= len(visible):
                return
            selected_dn.set(visible[idx]["DistinguishedName"])
            modal.destroy()

        ttk.Checkbutton(modal, text="Запомнить соответствие для этого отдела", variable=remember_var).pack(
            anchor="w", padx=10, pady=(0, 8)
        )
        btns = ttk.Frame(modal)
        btns.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(btns, text="Выбрать", command=choose).pack(side="left")
        ttk.Button(btns, text="Отмена", command=modal.destroy).pack(side="left", padx=8)

        modal.wait_window()
        chosen = selected_dn.get().strip()
        if not chosen:
            self.log(f"[{cfg['name']}] Move пропущен: выбор OU отменен пользователем.")
            return None

        self.log(f"[{cfg['name']}] OU выбран вручную: {chosen}")
        if remember_var.get():
            ou_map = load_ou_map()
            ou_map[normalize_text(dept_text)] = chosen
            save_ou_map(ou_map)
            self.log(f"[{cfg['name']}] Сопоставление отдела сохранено в ou_map.")
        return chosen

    def _save_search_changes(self):
        if self.selected_search_index is None:
            messagebox.showerror("Ошибка", "Выберите пользователя из результатов поиска.")
            return
        entry = self.search_results[self.selected_search_index]
        sam = entry.get("sam")
        domain_name = entry.get("domain")
        cfg = next((c for c in DOMAIN_CONFIGS if c["name"] == domain_name), None)
        if not cfg or not sam:
            messagebox.showerror("Ошибка", "Не удалось определить домен или логин пользователя.")
            return

        title = diff_field(self.search_title_var.get(), entry.get("title", ""))
        department = diff_field(self.search_department_var.get(), entry.get("department", ""))
        section = diff_field(self.search_section_var.get(), entry.get("section", ""))
        division = diff_field(self.search_division_var.get(), entry.get("division", ""))
        description = diff_field(self.search_description_var.get(), entry.get("description", ""))
        office_room = diff_field(self.search_office_var.get(), entry.get("office", ""))
        if domain_name == "omg-cspfmba":
            mobile_raw = diff_field(self.search_otp_mobile_var.get(), entry.get("otpMobile", ""))
        else:
            mobile_raw = diff_field(self.search_mobile_var.get(), entry.get("mobile", ""))
        telephone_raw = diff_field(
            self.search_telephone_var.get(),
            entry.get("telephoneNumber", ""),
        )
        manager_name = diff_field(self.search_manager_var.get(), entry.get("managerName", ""))
        address = diff_field(self.search_address_var.get(), entry.get("streetAddress", ""))
        need_mail_current = self.search_need_mail_var.get()
        need_mail_before = bool(entry.get("mail"))
        need_mail = need_mail_current if need_mail_current != need_mail_before else None

        target_ou_dn = None
        if domain_name == "omg-cspfmba" and (department is not None or section is not None):
            final_department = department if department is not None else (entry.get("department", "") or "")
            final_section = section if section is not None else (entry.get("section", "") or "")
            dept_text = " / ".join(x for x in [final_department, final_section] if x).strip() or final_department
            target_ou_dn = self._select_target_ou_with_dialog(cfg, dept_text)

        if all(
            value is None
            for value in (
                title,
                department,
                section,
                division,
                description,
                office_room,
                mobile_raw,
                telephone_raw,
                manager_name,
                address,
                need_mail,
            )
        ):
            messagebox.showinfo("Изменения", "Нет изменений для сохранения.")
            return

        confirm = messagebox.askyesno(
            "Подтверждение",
            f"Обновить данные пользователя '{entry.get('displayName')}' "
            f"в домене '{cfg['name']}'?",
        )
        if not confirm:
            self.log("Обновление отменено пользователем.")
            return

        result_log, success = update_user_in_domain(
            cfg,
            sam,
            title=title,
            department=department,
            office_room=office_room,
            mobile_raw=mobile_raw,
            telephone_raw=telephone_raw,
            address=address,
            manager_name=manager_name,
            need_mail=need_mail,
            description=description,
            division=division,
            section=section,
            target_ou_dn=target_ou_dn,
        )
        self.log(result_log)
        if success:
            updates = {}
            if title is not None:
                updates["title"] = title
            if department is not None:
                updates["department"] = department
            if section is not None:
                updates["section"] = section
            if division is not None:
                updates["division"] = division
            if description is not None:
                updates["description"] = description
            if office_room is not None:
                updates["office"] = office_room
            if mobile_raw is not None:
                if domain_name == "omg-cspfmba":
                    updates["otpMobile"] = mobile_raw
                else:
                    updates["mobile"] = mobile_raw
            if telephone_raw is not None:
                updates["telephoneNumber"] = telephone_raw
            if manager_name is not None:
                updates["managerName"] = manager_name
            if address is not None:
                updates["streetAddress"] = address
            if need_mail is not None:
                updates["mail"] = sam + cfg["email_suffix"] if need_mail else ""
            if updates:
                entry.update(updates)
            self.log(f"[{cfg['name']}] Изменения для пользователя '{entry.get('displayName')}' сохранены.")
        else:
            self.log(f"[{cfg['name']}] Не удалось сохранить изменения для пользователя '{entry.get('displayName')}'.")

    def _get_sections_for_department(self, department: str) -> list[str]:
        department_key = normalize_omg_unit_name(department)
        return OMG_OU_TREE.get(department_key, OMG_SECTION_CHOICES)

    def _get_department_for_section(self, section: str) -> str:
        section_key = normalize_omg_unit_name(section)
        return OMG_SECTION_TO_DEPARTMENT.get(section_key, "")

    def _sync_department_and_section(
        self,
        department_var: tk.StringVar,
        section_var: tk.StringVar,
        section_combobox: ttk.Combobox,
    ):
        sections = self._get_sections_for_department(department_var.get())
        section_combobox.configure(values=sections)

        current_section = normalize_omg_unit_name(section_var.get())
        if current_section and current_section not in sections:
            section_var.set("")

    def _sync_section_parent_department(self, department_var: tk.StringVar, section_var: tk.StringVar):
        department = self._get_department_for_section(section_var.get())
        if not department:
            return
        if normalize_omg_unit_name(department_var.get()) == department:
            return
        department_var.set(department)

    def _on_edit_department_changed(self, _event=None):
        self._sync_department_and_section(
            self.edit_department_var,
            self.edit_section_var,
            self.cmb_edit_section,
        )

    def _on_edit_section_changed(self, _event=None):
        self._sync_section_parent_department(self.edit_department_var, self.edit_section_var)
        self._on_edit_department_changed()

    def _on_search_department_changed(self, _event=None):
        self._sync_department_and_section(
            self.search_department_var,
            self.search_section_var,
            self.cmb_search_section,
        )

    def _on_search_section_changed(self, _event=None):
        self._sync_section_parent_department(self.search_department_var, self.search_section_var)
        self._on_search_department_changed()

    def _load_window_geometry(self):
        data = load_config()
        geometry = data.get(CONFIG_GEOMETRY_KEY)
        if geometry:
            try:
                self.geometry(geometry)
            except tk.TclError:
                pass

    def _on_close(self):
        data = load_config()
        data[CONFIG_GEOMETRY_KEY] = self.geometry()
        if self.password_token:
            data[CONFIG_PASSWORD_KEY] = self.password_token
        save_config(data)
        self.destroy()

    def _on_history_select(self, _event=None):
        selection = self.history_listbox.curselection()
        if not selection:
            self.selected_history_index = None
            self.btn_save_changes.configure(state="disabled")
            return
        index = selection[0]
        self.selected_history_index = index
        entry = self.history_entries[index]
        self.edit_title_var.set(entry.get("title", ""))
        self.edit_department_var.set(entry.get("department", ""))
        self._on_edit_department_changed()
        self.edit_section_var.set(entry.get("section", ""))
        self.edit_division_var.set(entry.get("division", ""))
        self.edit_description_var.set(entry.get("description", ""))
        self.edit_office_var.set(entry.get("office_room", ""))
        self.edit_mobile_var.set(entry.get("mobile_phone", ""))
        self.edit_otp_mobile_var.set(entry.get("otp_mobile", ""))
        self.edit_telephone_var.set(entry.get("telephone_number", ""))
        self.edit_manager_var.set(entry.get("manager_name", ""))
        self.edit_need_mail_var.set(bool(entry.get("need_mail")))
        self.edit_address_var.set(entry.get("address") or ADDRESS_CHOICES[0])
        self.btn_save_changes.configure(state="normal")

    def _save_history_changes(self):
        if self.selected_history_index is None:
            messagebox.showerror("Ошибка", "Выберите пользователя из истории.")
            return
        entry = self.history_entries[self.selected_history_index]
        cfg = entry["cfg"]
        sam = entry["sam"]

        title = diff_field(self.edit_title_var.get(), entry.get("title", ""))
        department = diff_field(self.edit_department_var.get(), entry.get("department", ""))
        section = diff_field(self.edit_section_var.get(), entry.get("section", ""))
        division = diff_field(self.edit_division_var.get(), entry.get("division", ""))
        description = diff_field(self.edit_description_var.get(), entry.get("description", ""))
        office_room = diff_field(self.edit_office_var.get(), entry.get("office_room", ""))
        if cfg["name"] == "omg-cspfmba":
            mobile_raw = diff_field(self.edit_otp_mobile_var.get(), entry.get("otp_mobile", ""))
        else:
            mobile_raw = diff_field(self.edit_mobile_var.get(), entry.get("mobile_phone", ""))
        telephone_raw = diff_field(
            self.edit_telephone_var.get(),
            entry.get("telephone_number", ""),
        )
        manager_name = diff_field(self.edit_manager_var.get(), entry.get("manager_name", ""))
        address = diff_field(self.edit_address_var.get(), entry.get("address", ""))
        need_mail_current = self.edit_need_mail_var.get()
        need_mail_before = bool(entry.get("need_mail"))
        need_mail = need_mail_current if need_mail_current != need_mail_before else None

        target_ou_dn = None
        if cfg["name"] == "omg-cspfmba" and (department is not None or section is not None):
            final_department = department if department is not None else (entry.get("department", "") or "")
            final_section = section if section is not None else (entry.get("section", "") or "")
            dept_text = " / ".join(x for x in [final_department, final_section] if x).strip() or final_department
            target_ou_dn = self._select_target_ou_with_dialog(cfg, dept_text)

        if all(
            value is None
            for value in (
                title,
                department,
                section,
                division,
                description,
                office_room,
                mobile_raw,
                telephone_raw,
                manager_name,
                address,
                need_mail,
            )
        ):
            messagebox.showinfo("Изменения", "Нет изменений для сохранения.")
            return

        confirm = messagebox.askyesno(
            "Подтверждение",
            f"Обновить данные пользователя '{entry['display_name']}' "
            f"в домене '{cfg['name']}'?",
        )
        if not confirm:
            self.log("Обновление отменено пользователем.")
            return

        result_log, success = update_user_in_domain(
            cfg,
            sam,
            title=title,
            department=department,
            office_room=office_room,
            mobile_raw=mobile_raw,
            telephone_raw=telephone_raw,
            address=address,
            manager_name=manager_name,
            need_mail=need_mail,
            description=description,
            division=division,
            section=section,
            target_ou_dn=target_ou_dn,
        )
        self.log(result_log)
        if success:
            updates = {}
            if title is not None:
                updates["title"] = title
            if department is not None:
                updates["department"] = department
            if section is not None:
                updates["section"] = section
            if division is not None:
                updates["division"] = division
            if description is not None:
                updates["description"] = description
            if office_room is not None:
                updates["office_room"] = office_room
            if mobile_raw is not None:
                if cfg["name"] == "omg-cspfmba":
                    updates["otp_mobile"] = mobile_raw
                else:
                    updates["mobile_phone"] = mobile_raw
            if telephone_raw is not None:
                updates["telephone_number"] = telephone_raw
            if manager_name is not None:
                updates["manager_name"] = manager_name
            if address is not None:
                updates["address"] = address
            if need_mail is not None:
                updates["need_mail"] = need_mail
            if updates:
                entry.update(updates)
            self.log(f"[{cfg['name']}] Изменения для пользователя '{entry['display_name']}' сохранены.")
        else:
            self.log(f"[{cfg['name']}] Не удалось сохранить изменения для пользователя '{entry['display_name']}'.")

    def on_run(self):
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")

        raw_text = self.txt_input.get("1.0", "end").strip()
        if not raw_text:
            messagebox.showerror("Ошибка", "Текст заявки пуст.")
            return

        if not self.password_token:
            self.log("Пароль по умолчанию не задан.")
            messagebox.showerror("Ошибка", "Введите пароль по умолчанию.")
            return

        try:
            password_plain = decrypt_password(self.password_token)
        except Exception:
            self.log("Не удалось расшифровать пароль. Задайте пароль заново.")
            messagebox.showerror("Ошибка", "Не удалось расшифровать пароль. Задайте пароль заново.")
            return

        parsed = parse_form(raw_text)

        required_fields = ["last_name", "first_name"]
        missing = [f for f in required_fields if not parsed.get(f)]
        if missing:
            self.log(f"Не хватает обязательных полей: {', '.join(missing)}")
            messagebox.showerror("Ошибка", "Не хватает обязательных полей (фамилия/имя).")
            return

        selected_configs = [
            cfg for cfg in DOMAIN_CONFIGS
            if self.domain_vars.get(cfg["name"]) and self.domain_vars[cfg["name"]].get()
        ]
        if not selected_configs:
            self.log("Не выбран ни один домен для создания пользователя.")
            messagebox.showerror("Ошибка", "Выберите хотя бы один домен в блоке галочек.")
            return

        last_name = parsed.get("last_name", "")
        first_name = parsed.get("first_name", "")
        middle_name = parsed.get("middle_name", "")

        display_name = " ".join(x for x in [last_name, first_name, middle_name] if x)
        existing_sam = None
        existing_domain_sams = {}
        for cfg in DOMAIN_CONFIGS:
            exists, details = user_exists_by_display_name(cfg, display_name)
            if exists:
                sam_found, display_found = (details.split("|") + ["", ""])[:2]
                existing_domain_sams[cfg["name"]] = sam_found
                if existing_sam and sam_found and existing_sam != sam_found:
                    self.log(
                        "Обнаружены разные логины для пользователя с одинаковым ФИО "
                        f"в доменах: {existing_domain_sams}. "
                        "Нужно выровнять логины вручную."
                    )
                    messagebox.showerror(
                        "Ошибка",
                        "В доменах найдены разные логины для одного ФИО. "
                        "Исправьте логины вручную и повторите попытку.",
                    )
                    return
                if sam_found:
                    existing_sam = sam_found

        if existing_sam:
            sam = existing_sam
            self.log(
                "Найден существующий пользователь с таким же ФИО. "
                f"Используем логин '{sam}' во всех доменах."
            )
        else:
            sam = generate_samaccount_name(first_name, last_name)

        address = self.address_var.get()
        addr_meta = get_address_details(address)

        title_raw = (parsed.get("title") or "").strip()
        title_norm = title_raw.lower()
        ad_department = get_ad_department(parsed)
        omg_department, section_preview = get_omg_department_and_section(parsed)

        mobile_raw = parsed.get("mobile_phone") or ""
        mobile_norm = normalize_phone(mobile_raw) if mobile_raw else ""

        self.log("--- Разобранные данные заявки ---")
        self.log(f"ФИО: {display_name}")
        self.log(f"Логин (sAMAccountName): {sam}")
        self.log(f"Должность (title): '{title_norm}'")
        self.log(f"Управление (сырое): {parsed.get('management') or ''}")
        self.log(f"Отдел (сырое): {parsed.get('department') or ''}")
        self.log(f"Department (AD): '{ad_department}'")
        self.log(f"Кабинет (office): {parsed.get('office_room') or ''}")
        self.log(f"Мобильный исходный: {mobile_raw}")
        self.log(f"Мобильный нормализованный: {mobile_norm}")
        self.log(f"Нужна почта: {'Да' if parsed.get('need_mail') else 'Нет'}")
        self.log(f"Адрес офиса (StreetAddress): {address}")
        self.log(
            f"Адресные поля: POBox='{addr_meta['pobox']}', "
            f"City='{addr_meta['city']}', State='{addr_meta['state']}', "
            f"PostalCode='{addr_meta['postal_code']}', Country='{addr_meta['country']}'"
        )
        self.log("")

        self.log("--- Предпросмотр атрибутов для доменов ---")
        create_target_ou: dict[str, str] = {}
        for cfg in selected_configs:
            upn_preview = sam + cfg["upn_suffix"]
            email_preview = sam + cfg["email_suffix"] if parsed.get("need_mail") else ""
            self.log(f"[{cfg['name']}] UPN: {upn_preview}, email: {email_preview or 'не задаётся'}")
            if cfg["name"] == "omg-cspfmba":
                fallback_ou = cfg["ou_dn"]
                dept_text = (parsed.get("department") or "").strip()
                resolved_dn, candidates, confidence = resolve_target_ou(
                    cfg,
                    dept_text,
                    base_path_hint=cfg.get("ou_dn"),
                )
                if resolved_dn and confidence == "high":
                    target_ou_preview = resolved_dn
                    self.log(
                        f"[{cfg['name']}] OU resolver: auto-selected '{target_ou_preview}' "
                        f"(dept='{dept_text}')"
                    )
                elif confidence == "low" and candidates:
                    selected_ou = self._select_target_ou_with_dialog(cfg, dept_text)
                    if selected_ou:
                        target_ou_preview = selected_ou
                    else:
                        target_ou_preview = fallback_ou
                        self.log(
                            f"[{cfg['name']}] OU resolver: OU не выбран, создание будет в fallback OU '{fallback_ou}'."
                        )
                else:
                    target_ou_preview = fallback_ou
                    self.log(
                        f"[{cfg['name']}] OU resolver: кандидаты не найдены, создание будет в fallback OU '{fallback_ou}'."
                    )
                create_target_ou[cfg["name"]] = target_ou_preview
                self.log(
                    f"[{cfg['name']}] department: '{omg_department}', "
                    f"division: '{OMG_DIVISION_VALUE}', "
                    f"section: '{section_preview}', "
                    f"target OU: '{target_ou_preview}', "
                    f"otpMobile: '{mobile_norm}' (MobilePhone не задаётся)"
                )
        self.log("")

        manager_name = parsed.get("manager_name") or ""
        if manager_name:
            self.log("--- Проверка наличия руководителя в ДАННОМ домене ---")
            for cfg in selected_configs:
                exists = manager_exists_for_domain(cfg, manager_name)
                if exists:
                    self.log(f"[{cfg['name']}] Руководитель '{manager_name}' найден в этом домене")
                else:
                    self.log(f"[{cfg['name']}] Руководитель '{manager_name}' НЕ найден в этом домене (Manager не будет установлен)")
            self.log("")
        else:
            self.log("Руководитель в заявке не указан.\n")

        configs_to_create = []
        for cfg in selected_configs:
            upn_preview = sam + cfg["upn_suffix"]
            exists, details = user_exists_in_domain_details(cfg, sam, upn_preview)
            if exists:
                sam_found, upn_found, display_found = (details.split("|") + ["", "", ""])[:3]
                self.log(
                    f"[{cfg['name']}] Пользователь уже существует в домене: "
                    f"Sam='{sam_found}', UPN='{upn_found}', DisplayName='{display_found}'. "
                    "Создание пропущено."
                )
            else:
                configs_to_create.append(cfg)

        if not configs_to_create:
            self.log("Создание пользователей остановлено: все выбранные домены уже содержат такого пользователя.")
            return

        dry_run = self.dry_run_var.get()
        dom_list_str = ", ".join(cfg["name"] for cfg in configs_to_create)

        if not dry_run:
            confirm = messagebox.askyesno(
                "Подтверждение",
                f"Создать пользователя '{display_name}' с логином '{sam}'\n"
                f"в доменах: {dom_list_str} ?",
            )
            if not confirm:
                self.log("Операция отменена пользователем.")
                return

        for cfg in configs_to_create:
            try:
                result_log, success = create_user_in_domain(
                    cfg,
                    sam,
                    parsed,
                    address,
                    manager_name=manager_name,
                    password_plain=password_plain,
                    target_ou_dn=create_target_ou.get(cfg["name"]),
                    dry_run=dry_run,
                )
                self.log(result_log)
                if success and not dry_run:
                    division_value = OMG_DIVISION_VALUE if cfg["name"] == "omg-cspfmba" else ""
                    section_value = section_preview if cfg["name"] == "omg-cspfmba" else ""
                    department_value = omg_department if cfg["name"] == "omg-cspfmba" else ad_department
                    history_entry = {
                        "display_name": display_name,
                        "sam": sam,
                        "cfg": cfg,
                        "address": address,
                        "title": title_norm,
                        "department": department_value,
                        "office_room": parsed.get("office_room") or "",
                        "mobile_phone": mobile_raw if cfg["name"] != "omg-cspfmba" else "",
                        "otp_mobile": mobile_raw if cfg["name"] == "omg-cspfmba" else "",
                        "telephone_number": "",
                        "manager_name": manager_name,
                        "need_mail": parsed.get("need_mail") or False,
                        "description": title_norm,
                        "division": division_value,
                        "section": section_value,
                    }
                    self.history_entries.append(history_entry)
                    self.history_listbox.insert(
                        "end", f"{display_name}\\{cfg['name']}"
                    )
            except Exception as e:
                self.log(f"[{cfg['name']}] Ошибка: {e}")

        if dry_run:
            self.log("DRY RUN завершён. Пользователи фактически не создавались.")
        else:
            self.log("Создание пользователей завершено.")



    def _offboarding_current_cfg(self) -> Optional[dict]:
        for cfg in DOMAIN_CONFIGS:
            if cfg["name"] == "omg-cspfmba":
                return cfg
        return None

    def _offboarding_set_step_status(self, step_key: str, status: str):
        mapping = {"pending": "◻", "running": "⏳", "success": "✅", "warn": "⚠️", "fail": "❌", "simulated": "🧪"}
        title = self.offboarding_step_titles.get(step_key, step_key)
        self.offboarding_step_vars[step_key].set(f"{mapping.get(status, '◻')} {title}")

    def _offboarding_log(self, text: str):
        self.offboarding_log_text.configure(state="normal")
        self.offboarding_log_text.insert("end", text + "\n")
        self.offboarding_log_text.see("end")
        self.offboarding_log_text.configure(state="disabled")
        self.log(text)

    def _open_offboarding_modal(self):
        cfg = self._offboarding_current_cfg()
        if not cfg:
            messagebox.showerror("Ошибка", "Не найдена конфигурация домена omg-cspfmba.")
            return
        if not self.domain_vars.get("omg-cspfmba", tk.BooleanVar(value=False)).get():
            messagebox.showinfo("Ограничение", "Увольнение доступно только для omg.")
            return

        modal = tk.Toplevel(self)
        modal.title("Увольнение сотрудника")
        modal.geometry("1320x780")
        modal.transient(self)
        modal.grab_set()

        self.offboarding_cfg = cfg
        self.offboarding_results = []
        self.offboarding_selected_user = None

        root = ttk.Frame(modal)
        root.pack(fill="both", expand=True, padx=10, pady=10)
        root.columnconfigure(0, weight=3)
        root.columnconfigure(1, weight=2)
        root.rowconfigure(1, weight=1)

        left = ttk.LabelFrame(root, text="Поиск и выбор пользователя")
        left.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, 8))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(2, weight=1)

        search_frame = ttk.Frame(left)
        search_frame.grid(row=0, column=0, sticky="ew", padx=8, pady=8)
        search_frame.columnconfigure(0, weight=1)

        ttk.Label(search_frame, text="ФИО или логин:").grid(row=0, column=0, sticky="w")
        self.offboarding_search_var = tk.StringVar()
        ttk.Entry(search_frame, textvariable=self.offboarding_search_var).grid(row=1, column=0, sticky="ew", pady=(2, 0))
        ttk.Button(search_frame, text="Найти", command=self._offboarding_search).grid(row=1, column=1, padx=(6, 0))

        columns = ("display", "sam", "upn", "ou")
        self.offboarding_tree = ttk.Treeview(left, columns=columns, show="headings", height=12)
        self.offboarding_tree.grid(row=2, column=0, sticky="nsew", padx=8)
        self.offboarding_tree.heading("display", text="DisplayName")
        self.offboarding_tree.heading("sam", text="sAMAccountName")
        self.offboarding_tree.heading("upn", text="UPN")
        self.offboarding_tree.heading("ou", text="OU")
        self.offboarding_tree.column("display", width=240)
        self.offboarding_tree.column("sam", width=160)
        self.offboarding_tree.column("upn", width=260)
        self.offboarding_tree.column("ou", width=330)
        self.offboarding_tree.bind("<<TreeviewSelect>>", self._offboarding_select_user)

        card = ttk.LabelFrame(left, text="Карточка пользователя")
        card.grid(row=3, column=0, sticky="ew", padx=8, pady=8)
        card.columnconfigure(1, weight=1)

        self.offboarding_card_vars = {}
        fields = [
            ("displayName", "DisplayName"), ("sam", "Sam"), ("upn", "UPN"), ("enabledText", "Статус"),
            ("dn", "Current DN"), ("ou", "Current OU"), ("mail", "Mail"), ("department", "Department"),
            ("title", "Title"), ("office", "Office"), ("mobile", "Mobile"),
        ]
        for row, (key, title) in enumerate(fields):
            ttk.Label(card, text=f"{title}:").grid(row=row, column=0, sticky="ne", padx=(4, 6), pady=2)
            var = tk.StringVar(value="")
            self.offboarding_card_vars[key] = var
            ttk.Label(card, textvariable=var, wraplength=560, justify="left").grid(row=row, column=1, sticky="w", pady=2)

        right = ttk.LabelFrame(root, text="Чек-лист шагов")
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)

        self.offboarding_step_titles = {
            "identity": "Шаг 1: Проверка и подтверждение личности",
            "clear": "Шаг 2: Очистка атрибутов (Общие/Адрес/Организация)",
            "disable": "Шаг 3: Отключение учётной записи",
            "move": "Шаг 4: Перемещение в OU Уволенные",
            "pak_clear": "Шаг 5: pak — очистка атрибутов",
            "pak_disable": "Шаг 6: pak — отключение учётной записи",
            "pak_move": "Шаг 7: pak — перемещение в OU Уволенные",
        }
        self.offboarding_step_vars = {}
        for idx, step_key in enumerate(("identity", "clear", "disable", "move", "pak_clear", "pak_disable", "pak_move")):
            var = tk.StringVar()
            self.offboarding_step_vars[step_key] = var
            self._offboarding_set_step_status(step_key, "pending")
            ttk.Label(right, textvariable=var).grid(row=idx, column=0, sticky="w", padx=8, pady=4)

        log_frame = ttk.LabelFrame(root, text="Лог выполнения")
        log_frame.grid(row=1, column=1, sticky="nsew", pady=(8, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.offboarding_log_text = tk.Text(log_frame, height=18, wrap="word", state="disabled")
        self.offboarding_log_text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)

        actions = ttk.Frame(modal)
        actions.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(actions, text="Проверить план", command=self._offboarding_dry_run).pack(side="left")
        self.offboarding_execute_btn = ttk.Button(actions, text="Выполнить увольнение", command=self._offboarding_execute, state="disabled")
        self.offboarding_execute_btn.pack(side="left", padx=6)
        ttk.Button(actions, text="Отмена/Закрыть", command=modal.destroy).pack(side="right")

    def _offboarding_search(self):
        query = (self.offboarding_search_var.get() or "").strip()
        if not query:
            messagebox.showerror("Ошибка", "Введите ФИО или логин для поиска.")
            return
        cfg = self.offboarding_cfg
        server = cfg.get("server") or get_preferred_dc(cfg)
        q_ldap = escape_ldap_filter(query)
        ldap_filter = f"(|(displayName=*{q_ldap}*)(samAccountName=*{q_ldap}*)(userPrincipalName=*{q_ldap}*))"
        ps = (
            "Import-Module ActiveDirectory; "
            f"$users = Get-ADUser -Server '{escape_ps_string(server)}' -LDAPFilter '{escape_ps_string(ldap_filter)}' "
            f"-SearchBase '{escape_ps_string(cfg.get('search_base') or '')}' -ResultSetSize 100 "
            "-Properties DisplayName,SamAccountName,UserPrincipalName,DistinguishedName,Enabled,mail,department,title,physicalDeliveryOfficeName,mobile,ObjectGUID; "
            "$users | Select-Object "
            "@{Name='displayName';Expression={$_.DisplayName}},@{Name='sam';Expression={$_.SamAccountName}},"
            "@{Name='upn';Expression={$_.UserPrincipalName}},@{Name='dn';Expression={$_.DistinguishedName}},"
            "@{Name='enabled';Expression={$_.Enabled}},@{Name='mail';Expression={$_.mail}},"
            "@{Name='department';Expression={$_.department}},@{Name='title';Expression={$_.title}},"
            "@{Name='office';Expression={$_.physicalDeliveryOfficeName}},@{Name='mobile';Expression={$_.mobile}},"
            "@{Name='guid';Expression={$_.ObjectGUID.ToString()}} | ConvertTo-Json -Depth 4"
        )
        proc = run_powershell(ps, server=server)
        if proc.returncode != 0:
            self._offboarding_log(f"[offboarding] Ошибка поиска: {(proc.stderr or '').strip()}")
            messagebox.showerror("Поиск", "Не удалось выполнить поиск пользователя в omg.")
            return
        results, err = parse_ps_json(proc.stdout)
        if err:
            self._offboarding_log(f"[offboarding] {err}")
            messagebox.showerror("Поиск", err)
            return
        self.offboarding_results = results
        for item in self.offboarding_tree.get_children():
            self.offboarding_tree.delete(item)
        for idx, user in enumerate(results):
            self.offboarding_tree.insert("", "end", iid=str(idx), values=(
                user.get("displayName") or "", user.get("sam") or "", user.get("upn") or "", short_ou_from_dn(user.get("dn") or "")
            ))
        self._offboarding_log(f"[offboarding] Найдено пользователей: {len(results)}")
        if not results:
            messagebox.showinfo("Поиск", "Пользователи не найдены.")

    def _offboarding_select_user(self, _event=None):
        sel = self.offboarding_tree.selection()
        if len(sel) != 1:
            self.offboarding_selected_user = None
            self.offboarding_execute_btn.configure(state="disabled")
            return
        idx = int(sel[0])
        if idx >= len(self.offboarding_results):
            self.offboarding_selected_user = None
            self.offboarding_execute_btn.configure(state="disabled")
            return
        user = self.offboarding_results[idx]
        user["ou"] = extract_ou_from_dn(user.get("dn") or "")
        user["enabledText"] = "Enabled" if bool(user.get("enabled")) else "Disabled"
        self.offboarding_selected_user = user
        for key, var in self.offboarding_card_vars.items():
            var.set(user.get(key) or "")
        self.offboarding_execute_btn.configure(state="normal")

    def _offboarding_dry_run(self):
        user = self.offboarding_selected_user
        cfg = self._offboarding_current_cfg()
        if not user or not cfg:
            messagebox.showerror("Ошибка", "Выберите одного пользователя для проверки плана.")
            return
        target_ou = cfg.get("fired_ou_dn") or ""
        if not validate_ou_exists(cfg, target_ou):
            self._offboarding_log(f"[offboarding] Целевой OU не найден: {target_ou}")
            messagebox.showerror("Ошибка", "Целевой OU Уволенные не найден в AD.")
            return
        self._offboarding_log("[offboarding] План действий:")
        self._offboarding_log(f"  Пользователь: {user.get('displayName')} ({user.get('sam')})")
        self._offboarding_log(f"  Текущий OU: {user.get('ou')}")
        self._offboarding_log(f"  Целевой OU: {target_ou}")
        self._offboarding_log("  Будут очищены атрибуты Общие/Адрес/Организация из безопасного списка.")

    def _offboarding_confirm_login(self, expected_sam: str) -> Optional[str]:
        modal = tk.Toplevel(self)
        modal.title("Подтверждение")
        modal.transient(self)
        modal.grab_set()
        modal.resizable(False, False)

        frm = ttk.Frame(modal, padding=12)
        frm.pack(fill="both", expand=True)

        ttk.Label(
            frm,
            text="Введите логин для подтверждения (samAccountName):",
            justify="left",
        ).pack(anchor="w")

        login_var = tk.StringVar()
        login_entry = ttk.Entry(frm, textvariable=login_var, width=40)
        login_entry.pack(fill="x", pady=(8, 4))

        hint_wrap = ttk.Frame(frm)
        hint_wrap.pack(anchor="w", pady=(0, 10))
        ttk.Label(hint_wrap, text="Ожидается: ", foreground="#666666", font=("TkDefaultFont", 9)).pack(side="left")

        copied_var = tk.StringVar(value="")
        expected_label = ttk.Label(
            hint_wrap,
            text=expected_sam,
            foreground="#1f6feb",
            cursor="hand2",
            font=("TkDefaultFont", 9, "underline"),
        )
        expected_label.pack(side="left")
        copied_label = ttk.Label(hint_wrap, textvariable=copied_var, foreground="#22863a", font=("TkDefaultFont", 9))
        copied_label.pack(side="left", padx=(8, 0))

        def on_copy_expected(_event=None):
            self.clipboard_clear()
            self.clipboard_append(expected_sam)
            copied_var.set("Скопировано!")
            modal.after(1500, lambda: copied_var.set(""))

        expected_label.bind("<Button-1>", on_copy_expected)

        result: dict[str, Optional[str]] = {"value": None}

        def on_confirm(_event=None):
            result["value"] = login_var.get()
            modal.destroy()

        def on_cancel(_event=None):
            result["value"] = None
            modal.destroy()

        btns = ttk.Frame(frm)
        btns.pack(fill="x")
        ttk.Button(btns, text="Подтвердить", command=on_confirm).pack(side="right")
        ttk.Button(btns, text="Отмена", command=on_cancel).pack(side="right", padx=(0, 8))

        modal.protocol("WM_DELETE_WINDOW", on_cancel)
        modal.bind("<Return>", on_confirm)
        modal.bind("<Escape>", on_cancel)

        modal.update_idletasks()
        modal.geometry(
            f"+{self.winfo_rootx() + (self.winfo_width() // 2) - (modal.winfo_width() // 2)}"
            f"+{self.winfo_rooty() + (self.winfo_height() // 2) - (modal.winfo_height() // 2)}"
        )
        login_entry.focus_set()
        self.wait_window(modal)
        return result["value"]

    def _offboarding_execute(self):
        cfg = self._offboarding_current_cfg()
        if not cfg or cfg.get("name") != "omg-cspfmba":
            messagebox.showerror("Ограничение", "Увольнение доступно только для omg.")
            return
        user = self.offboarding_selected_user
        if not user:
            messagebox.showerror("Ошибка", "Выберите ровно одного пользователя.")
            return

        target_ou = cfg.get("fired_ou_dn") or ""
        if not validate_ou_exists(cfg, target_ou):
            messagebox.showerror("Ошибка", f"Целевой OU не существует: {target_ou}")
            self._offboarding_log(f"[offboarding][omg] OU не найден: {target_ou}")
            return

        confirm_text = (
            f"DisplayName: {user.get('displayName')}\n"
            f"Sam: {user.get('sam')}\n"
            f"UPN: {user.get('upn')}\n"
            f"Текущий OU: {user.get('ou')}\n"
            f"Целевой OU: {target_ou}\n\n"
            "Изменения необратимы."
        )
        if not messagebox.askyesno("Подтверждение увольнения", confirm_text):
            self._offboarding_log("[offboarding] Операция отменена пользователем на этапе подтверждения.")
            return

        expected_sam = (user.get("sam") or "").strip()
        typed_sam = self._offboarding_confirm_login(expected_sam)
        if (typed_sam or "").strip().lower() != expected_sam.lower():
            messagebox.showerror("Ошибка", "Логин подтверждения не совпадает. Операция отменена.")
            self._offboarding_log("[offboarding] Неверный логин подтверждения, выполнение остановлено.")
            return

        step_keys = ("identity", "clear", "disable", "move", "pak_clear", "pak_disable", "pak_move")
        for step_key in step_keys:
            self._offboarding_set_step_status(step_key, "pending")
        step_statuses: dict[str, str] = {k: "pending" for k in step_keys}

        def set_step(step_key: str, status: str):
            step_statuses[step_key] = status
            self._offboarding_set_step_status(step_key, status)

        def now_local_iso() -> str:
            return datetime.now().astimezone().isoformat(sep=" ", timespec="seconds")

        def now_utc_iso() -> str:
            return datetime.now(timezone.utc).isoformat(timespec="seconds")

        def short_text(value: str) -> str:
            v = (value or "").strip()
            return v[:1000]

        def dn_to_ou(dn: str) -> str:
            if not dn:
                return ""
            parts = [part.strip() for part in dn.split(",") if part.strip().upper().startswith("OU=")]
            return ",".join(parts)

        def parse_clear_output(proc: subprocess.CompletedProcess) -> tuple[dict, list[str]]:
            stdout_lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
            json_lines = [line for line in stdout_lines if not line.startswith("__CLEAR_FAIL__:")]
            clear_fail_messages = [line for line in stdout_lines if line.startswith("__CLEAR_FAIL__:")]
            clear_result = {}
            if json_lines:
                clear_result = json.loads("\n".join(json_lines))
            return clear_result, clear_fail_messages

        attr_props = [
            "ObjectGUID", "DistinguishedName", "Enabled", "GivenName", "sn", "DisplayName", "samAccountName",
            "userPrincipalName", "mail", "department", "title", "company", "physicalDeliveryOfficeName",
            "telephoneNumber", "mobile", "streetAddress", "l", "st", "postalCode", "postOfficeBox", "co",
            "manager", "description", "info", "memberOf",
        ]
        attr_props_ps = ",".join(attr_props)

        def build_identity_cmd(server_name: str, sam_value: str) -> str:
            sam_ldap = escape_ldap_filter(sam_value)
            ldap_filter = f"(samAccountName={sam_ldap})"
            return (
                "Import-Module ActiveDirectory; "
                f"$users = @(Get-ADUser -Server '{escape_ps_string(server_name)}' "
                f"-LDAPFilter '{escape_ps_string(ldap_filter)}' -Properties {attr_props_ps}); "
                "$items = @($users | ForEach-Object { "
                "[PSCustomObject]@{ "
                "guid=$_.ObjectGUID.ToString(); dn=$_.DistinguishedName; enabled=$_.Enabled; givenName=$_.GivenName; sn=$_.sn; "
                "displayName=$_.DisplayName; samAccountName=$_.samAccountName; userPrincipalName=$_.userPrincipalName; mail=$_.mail; "
                "department=$_.department; title=$_.title; company=$_.company; physicalDeliveryOfficeName=$_.physicalDeliveryOfficeName; "
                "telephoneNumber=$_.telephoneNumber; mobile=$_.mobile; streetAddress=$_.streetAddress; l=$_.l; st=$_.st; postalCode=$_.postalCode; "
                "postOfficeBox=$_.postOfficeBox; co=$_.co; manager=$_.manager; description=$_.description; info=$_.info; "
                "memberOf=@($_.memberOf | Select-Object -First 30) "
                "} "
                "}); "
                "@{ count=@($users).Count; users=$items } | ConvertTo-Json -Depth 6"
            )

        def fetch_domain_identity(domain_cfg: dict, sam_value: str, prefix: str) -> dict:
            main_server = domain_cfg.get("server") or get_preferred_dc(domain_cfg)
            pdc_server = get_preferred_dc(domain_cfg)
            self._offboarding_log(f"[offboarding][{prefix}] Основной сервер: {main_server}; PDC: {pdc_server}")
            proc = run_powershell(build_identity_cmd(main_server, sam_value), server=main_server)
            self._offboarding_log(f"[offboarding][{prefix}][identity] rc={proc.returncode}")
            if proc.stdout.strip():
                self._offboarding_log(f"[offboarding][{prefix}][identity] STDOUT:\n" + proc.stdout.strip())
            if proc.stderr.strip():
                self._offboarding_log(f"[offboarding][{prefix}][identity] STDERR:\n" + proc.stderr.strip())
            raw_stdout = (proc.stdout or "").strip()
            if proc.returncode != 0 or not raw_stdout:
                return {
                    "server_main": main_server,
                    "server_pdc": pdc_server,
                    "identity_rc": proc.returncode,
                    "identity_stdout": short_text(proc.stdout),
                    "identity_stderr": short_text(proc.stderr),
                    "count": 0,
                    "user": None,
                }
            try:
                payload = json.loads(raw_stdout)
            except json.JSONDecodeError:
                self._offboarding_log(f"[offboarding][{prefix}][identity] Ошибка JSON, первые 300 символов STDOUT: {raw_stdout[:300]}")
                return {
                    "server_main": main_server,
                    "server_pdc": pdc_server,
                    "identity_rc": proc.returncode,
                    "identity_stdout": short_text(proc.stdout),
                    "identity_stderr": short_text(proc.stderr),
                    "count": 0,
                    "user": None,
                }
            if isinstance(payload, list):
                payload = payload[0] if payload else {}
            users = payload.get("users") or []
            if isinstance(users, dict):
                users = [users]
            return {
                "server_main": main_server,
                "server_pdc": pdc_server,
                "identity_rc": proc.returncode,
                "identity_stdout": short_text(proc.stdout),
                "identity_stderr": short_text(proc.stderr),
                "count": int(payload.get("count") or len(users)),
                "user": users[0] if users else None,
            }

        def add_step(audit_domain: dict, step_name: str, status: str, proc: Optional[subprocess.CompletedProcess] = None):
            audit_domain.setdefault("steps", []).append({
                "step": step_name,
                "status": status,
                "rc": None if proc is None else proc.returncode,
                "stderr": short_text("" if proc is None else (proc.stderr or "")),
                "stdout": short_text("" if proc is None else (proc.stdout or "")),
                "timestamp": now_local_iso(),
            })

        operator_username = ""
        try:
            operator_username = os.getlogin()
        except OSError:
            operator_username = os.environ.get("USERNAME") or "unknown"

        audit_entry = {
            "timestamp_local": now_local_iso(),
            "timestamp_utc": now_utc_iso(),
            "operator": {
                "username": operator_username,
                "hostname": platform.node() or (os.environ.get("COMPUTERNAME") or ""),
            },
            "action": "offboarding",
            "sam": expected_sam,
            "displayName": user.get("displayName") or "",
            "domains": {
                "omg-cspfmba": {"server_main": "", "server_pdc": "", "user_found": False, "steps": [], "clear_failed_attrs": []},
                "pak-cspmz": {"server_main": "", "server_pdc": "", "user_found": False, "steps": [], "clear_failed_attrs": []},
            },
        }

        omg_audit = audit_entry["domains"]["omg-cspfmba"]
        pak_audit = audit_entry["domains"]["pak-cspmz"]

        omg_identity = fetch_domain_identity(cfg, expected_sam, "omg")
        omg_audit["server_main"] = omg_identity["server_main"]
        omg_audit["server_pdc"] = omg_identity["server_pdc"]

        if omg_identity["count"] != 1 or not omg_identity["user"]:
            set_step("identity", "fail")
            add_step(omg_audit, "identity", "fail")
            messagebox.showerror("Ошибка", "Не удалось получить пользователя для увольнения в omg.")
            return

        omg_user = omg_identity["user"]
        guid = omg_user.get("guid") or ""
        dn_before = omg_user.get("dn") or ""
        omg_audit.update({
            "user_found": True,
            "guid": guid,
            "dn_before": dn_before,
            "ou_before": dn_to_ou(dn_before),
            "enabled_before": bool(omg_user.get("enabled")),
            "snapshot_before": omg_user,
        })
        set_step("identity", "success")
        add_step(omg_audit, "identity", "success")

        clear_attrs_omg = [
            "title", "department", "company", "physicalDeliveryOfficeName", "telephoneNumber", "mobile", "mail", "streetAddress",
            "l", "st", "postalCode", "postOfficeBox", "co", "manager", "description", "info",
            "facsimileTelephoneNumber", "homePhone", "ipPhone", "pager", "wWWHomePage", "otherTelephone", "otherMobile",
            "otherHomePhone", "otherPager", "extensionAttribute1", "extensionAttribute2", "extensionAttribute3", "extensionAttribute4",
            "extensionAttribute5", "extensionAttribute6", "extensionAttribute7", "extensionAttribute8", "extensionAttribute9",
            "extensionAttribute10", "extensionAttribute11", "extensionAttribute12", "extensionAttribute13", "extensionAttribute14",
            "extensionAttribute15", "division", "section",
        ]
        clear_failed_attrs: list[str] = []
        clear_list_ps = ",".join(f"'{escape_ps_string(x)}'" for x in clear_attrs_omg)
        clear_cmd = (
            "Import-Module ActiveDirectory; "
            f"$gid = [Guid]'{escape_ps_string(guid)}'; $failed = @(); $cleared = @(); "
            f"foreach ($a in @({clear_list_ps})) {{ try {{ Set-ADUser -Server '{escape_ps_string(omg_identity['server_main'])}' -Identity $gid -Clear $a -ErrorAction Stop; $cleared += $a; }} catch {{ $failed += $a; Write-Output ('__CLEAR_FAIL__:' + $a + ':' + $_.Exception.Message); }} }}; "
            f"Set-ADUser -Server '{escape_ps_string(omg_identity['server_main'])}' -Identity $gid "
            f"-GivenName '{escape_ps_string(omg_user.get('givenName') or '')}' "
            f"-Surname '{escape_ps_string(omg_user.get('sn') or '')}' "
            f"-DisplayName '{escape_ps_string(omg_user.get('displayName') or '')}' -ErrorAction Stop; "
            "@{ cleared=$cleared; failed=$failed } | ConvertTo-Json -Depth 4"
        )

        set_step("clear", "running")
        if ADHELPER_DRYRUN_MODE:
            self._offboarding_log(f"[offboarding][omg][clear] DRYRUN: пропуск Set-ADUser для GUID {guid}")
            set_step("clear", "simulated")
            add_step(omg_audit, "clear", "simulated")
        else:
            proc = run_powershell(clear_cmd, server=omg_identity["server_main"])
            self._offboarding_log(f"[offboarding][omg][clear] rc={proc.returncode}")
            if proc.stdout.strip():
                self._offboarding_log("[offboarding][omg][clear] STDOUT:\n" + proc.stdout.strip())
            if proc.stderr.strip():
                self._offboarding_log("[offboarding][omg][clear] STDERR:\n" + proc.stderr.strip())
            if proc.returncode != 0:
                set_step("clear", "fail")
                add_step(omg_audit, "clear", "fail", proc)
                return
            try:
                clear_result, clear_fail_messages = parse_clear_output(proc)
            except json.JSONDecodeError as exc:
                self._offboarding_log(f"[offboarding][omg][clear] Ошибка разбора JSON: {exc}")
                set_step("clear", "fail")
                add_step(omg_audit, "clear", "fail", proc)
                return
            clear_failed_attrs = [str(x) for x in (clear_result.get("failed") or []) if x]
            omg_audit["clear_failed_attrs"] = clear_failed_attrs
            if clear_failed_attrs:
                set_step("clear", "warn")
                add_step(omg_audit, "clear", "warn", proc)
                self._offboarding_log("[offboarding][omg][clear] Не удалось очистить атрибуты: " + ", ".join(clear_failed_attrs))
                for fail_line in clear_fail_messages[:5]:
                    self._offboarding_log("[offboarding][omg][clear] Причина: " + fail_line)
            else:
                set_step("clear", "success")
                add_step(omg_audit, "clear", "success", proc)

        disable_cmd = (
            "Import-Module ActiveDirectory; "
            f"Disable-ADAccount -Server '{escape_ps_string(omg_identity['server_main'])}' -Identity '{escape_ps_string(guid)}'; "
            f"(Get-ADUser -Server '{escape_ps_string(omg_identity['server_main'])}' -Identity '{escape_ps_string(guid)}' -Properties Enabled).Enabled"
        )
        set_step("disable", "running")
        if ADHELPER_DRYRUN_MODE:
            self._offboarding_log(f"[offboarding][omg][disable] DRYRUN: пропуск Disable-ADAccount для GUID {guid}")
            set_step("disable", "simulated")
            add_step(omg_audit, "disable", "simulated")
        else:
            proc = run_powershell(disable_cmd, server=omg_identity["server_main"])
            self._offboarding_log(f"[offboarding][omg][disable] rc={proc.returncode}")
            if proc.stdout.strip():
                self._offboarding_log("[offboarding][omg][disable] STDOUT:\n" + proc.stdout.strip())
            if proc.stderr.strip():
                self._offboarding_log("[offboarding][omg][disable] STDERR:\n" + proc.stderr.strip())
            enabled_check = (proc.stdout or "").strip().lower()
            if proc.returncode != 0 or enabled_check == "true":
                set_step("disable", "fail")
                add_step(omg_audit, "disable", "fail", proc)
                return
            set_step("disable", "success")
            add_step(omg_audit, "disable", "success", proc)

        move_cmd = (
            "Import-Module ActiveDirectory; "
            f"Move-ADObject -Server '{{srv}}' -Identity '{escape_ps_string(guid)}' -TargetPath '{escape_ps_string(target_ou)}'; "
            f"(Get-ADUser -Server '{{srv}}' -Identity '{escape_ps_string(guid)}' -Properties DistinguishedName,Enabled).DistinguishedName"
        )
        move_server = omg_identity["server_main"]
        if not validate_ou_exists_on_server(move_server, target_ou):
            if validate_ou_exists_on_server(omg_identity["server_pdc"], target_ou):
                move_server = omg_identity["server_pdc"]
                self._offboarding_log(f"[offboarding][omg][move] Целевой OU найден на PDC, перенос будет выполнен через {move_server}")
            else:
                self._offboarding_log(f"[offboarding][omg][move] OU не найден на серверах {omg_identity['server_main']} и {omg_identity['server_pdc']}: {target_ou}")
                set_step("move", "fail")
                add_step(omg_audit, "move", "fail")
                return

        set_step("move", "running")
        if ADHELPER_DRYRUN_MODE:
            self._offboarding_log(f"[offboarding][omg][move] DRYRUN: пропуск Move-ADObject в OU {target_ou}")
            set_step("move", "simulated")
            add_step(omg_audit, "move", "simulated")
        else:
            proc = run_powershell(move_cmd.format(srv=escape_ps_string(move_server)), server=move_server)
            self._offboarding_log(f"[offboarding][omg][move] rc={proc.returncode}")
            if proc.stdout.strip():
                self._offboarding_log("[offboarding][omg][move] STDOUT:\n" + proc.stdout.strip())
            if proc.stderr.strip():
                self._offboarding_log("[offboarding][omg][move] STDERR:\n" + proc.stderr.strip())
            if proc.returncode != 0 and command_failed_with_8329(proc) and omg_identity["server_pdc"].lower() != move_server.lower():
                self._offboarding_log(f"[offboarding][omg][move] Ошибка 8329/uninstantiated, ретрай на PDC: {omg_identity['server_pdc']}")
                proc = run_powershell(move_cmd.format(srv=escape_ps_string(omg_identity["server_pdc"])), server=omg_identity["server_pdc"])
                self._offboarding_log(f"[offboarding][omg][move][retry] Сервер: {omg_identity['server_pdc']}, rc={proc.returncode}")
                if proc.stdout.strip():
                    self._offboarding_log("[offboarding][omg][move][retry] STDOUT:\n" + proc.stdout.strip())
                if proc.stderr.strip():
                    self._offboarding_log("[offboarding][omg][move][retry] STDERR:\n" + proc.stderr.strip())
            dn_after = (proc.stdout or "").strip()
            if proc.returncode != 0 or target_ou.lower() not in dn_after.lower():
                set_step("move", "fail")
                add_step(omg_audit, "move", "fail", proc)
                return
            set_step("move", "success")
            add_step(omg_audit, "move", "success", proc)
            omg_audit["dn_after"] = dn_after
            omg_audit["ou_after"] = dn_to_ou(dn_after)

            omg_state_cmd = (
                "Import-Module ActiveDirectory; "
                f"Get-ADUser -Server '{escape_ps_string(move_server)}' -Identity '{escape_ps_string(guid)}' -Properties DistinguishedName,Enabled | "
                "Select-Object DistinguishedName,Enabled | ConvertTo-Json -Depth 4"
            )
            state_proc = run_powershell(omg_state_cmd, server=move_server)
            if state_proc.returncode == 0 and (state_proc.stdout or "").strip():
                try:
                    state_obj = json.loads((state_proc.stdout or "").strip())
                    omg_audit["enabled_after"] = bool(state_obj.get("Enabled"))
                    if not omg_audit.get("dn_after"):
                        omg_audit["dn_after"] = str(state_obj.get("DistinguishedName") or "")
                        omg_audit["ou_after"] = dn_to_ou(omg_audit["dn_after"])
                except json.JSONDecodeError:
                    self._offboarding_log("[offboarding][omg][move] Не удалось разобрать JSON состояния после disable+move.")

        omg_completed = all(step_statuses[k] in ("success", "simulated") for k in ("identity", "clear", "disable", "move"))
        pak_cfg = next((d for d in DOMAIN_CONFIGS if d.get("name") == "pak-cspmz"), None)
        pak_target_ou = "OU=Уволенные,OU=Users,OU=csp,DC=pak-cspmz,DC=ru"

        if not omg_completed:
            self._offboarding_log("[offboarding][pak] Пропуск: шаги omg завершены неуспешно.")
            for k in ("pak_clear", "pak_disable", "pak_move"):
                set_step(k, "warn")
                add_step(pak_audit, k.replace("pak_", ""), "warn")
        elif not pak_cfg:
            self._offboarding_log("[offboarding][pak] Конфигурация pak-cspmz не найдена.")
            for k in ("pak_clear", "pak_disable", "pak_move"):
                set_step(k, "warn")
                add_step(pak_audit, k.replace("pak_", ""), "warn")
        else:
            pak_identity = fetch_domain_identity(pak_cfg, expected_sam, "pak")
            pak_audit["server_main"] = pak_identity["server_main"]
            pak_audit["server_pdc"] = pak_identity["server_pdc"]

            if pak_identity["count"] != 1 or not pak_identity["user"]:
                self._offboarding_log("[offboarding][pak] Пользователь не найден однозначно, pak-шаги помечены как warn.")
                for k in ("pak_clear", "pak_disable", "pak_move"):
                    set_step(k, "warn")
                    add_step(pak_audit, k.replace("pak_", ""), "warn")
            else:
                pak_user = pak_identity["user"]
                pak_guid = pak_user.get("guid") or ""
                pak_dn_before = pak_user.get("dn") or ""
                pak_audit.update({
                    "user_found": True,
                    "guid": pak_guid,
                    "dn_before": pak_dn_before,
                    "ou_before": dn_to_ou(pak_dn_before),
                    "enabled_before": bool(pak_user.get("enabled")),
                    "snapshot_before": pak_user,
                })

                pak_clear_attrs = [
                    "title", "department", "company", "physicalDeliveryOfficeName", "telephoneNumber", "mobile", "mail",
                    "streetAddress", "l", "st", "postalCode", "postOfficeBox", "manager", "description", "info",
                ]
                pak_list_ps = ",".join(f"'{escape_ps_string(x)}'" for x in pak_clear_attrs)
                pak_clear_cmd = (
                    "Import-Module ActiveDirectory; "
                    f"$gid = [Guid]'{escape_ps_string(pak_guid)}'; $failed = @(); $cleared = @(); "
                    f"foreach ($a in @({pak_list_ps})) {{ try {{ Set-ADUser -Server '{escape_ps_string(pak_identity['server_main'])}' -Identity $gid -Clear $a -ErrorAction Stop; $cleared += $a; }} catch {{ $failed += $a; Write-Output ('__CLEAR_FAIL__:' + $a + ':' + $_.Exception.Message); }} }}; "
                    "@{ cleared=$cleared; failed=$failed } | ConvertTo-Json -Depth 4"
                )

                set_step("pak_clear", "running")
                if ADHELPER_DRYRUN_MODE:
                    self._offboarding_log(f"[offboarding][pak][clear] DRYRUN: пропуск Set-ADUser для GUID {pak_guid}")
                    set_step("pak_clear", "simulated")
                    add_step(pak_audit, "clear", "simulated")
                else:
                    proc = run_powershell(pak_clear_cmd, server=pak_identity["server_main"])
                    self._offboarding_log(f"[offboarding][pak][clear] rc={proc.returncode}")
                    if proc.stdout.strip():
                        self._offboarding_log("[offboarding][pak][clear] STDOUT:\n" + proc.stdout.strip())
                    if proc.stderr.strip():
                        self._offboarding_log("[offboarding][pak][clear] STDERR:\n" + proc.stderr.strip())
                    if proc.returncode != 0:
                        set_step("pak_clear", "fail")
                        add_step(pak_audit, "clear", "fail", proc)
                    else:
                        try:
                            pak_result, pak_fail_lines = parse_clear_output(proc)
                            pak_failed_attrs = [str(x) for x in (pak_result.get("failed") or []) if x]
                        except json.JSONDecodeError as exc:
                            self._offboarding_log(f"[offboarding][pak][clear] Ошибка разбора JSON: {exc}")
                            pak_failed_attrs = ["parse_json"]
                            pak_fail_lines = []
                        pak_audit["clear_failed_attrs"] = pak_failed_attrs
                        if pak_failed_attrs:
                            set_step("pak_clear", "warn")
                            add_step(pak_audit, "clear", "warn", proc)
                            self._offboarding_log("[offboarding][pak][clear] Не удалось очистить атрибуты: " + ", ".join(pak_failed_attrs))
                            for fail_line in pak_fail_lines[:5]:
                                self._offboarding_log("[offboarding][pak][clear] Причина: " + fail_line)
                        else:
                            set_step("pak_clear", "success")
                            add_step(pak_audit, "clear", "success", proc)

                pak_disable_cmd = (
                    "Import-Module ActiveDirectory; "
                    f"Disable-ADAccount -Server '{escape_ps_string(pak_identity['server_main'])}' -Identity '{escape_ps_string(pak_guid)}'; "
                    f"(Get-ADUser -Server '{escape_ps_string(pak_identity['server_main'])}' -Identity '{escape_ps_string(pak_guid)}' -Properties Enabled).Enabled"
                )
                set_step("pak_disable", "running")
                if ADHELPER_DRYRUN_MODE:
                    self._offboarding_log(f"[offboarding][pak][disable] DRYRUN: пропуск Disable-ADAccount для GUID {pak_guid}")
                    set_step("pak_disable", "simulated")
                    add_step(pak_audit, "disable", "simulated")
                else:
                    proc = run_powershell(pak_disable_cmd, server=pak_identity["server_main"])
                    self._offboarding_log(f"[offboarding][pak][disable] rc={proc.returncode}")
                    if proc.stdout.strip():
                        self._offboarding_log("[offboarding][pak][disable] STDOUT:\n" + proc.stdout.strip())
                    if proc.stderr.strip():
                        self._offboarding_log("[offboarding][pak][disable] STDERR:\n" + proc.stderr.strip())
                    enabled_check = (proc.stdout or "").strip().lower()
                    if proc.returncode != 0 or enabled_check == "true":
                        set_step("pak_disable", "fail")
                        add_step(pak_audit, "disable", "fail", proc)
                    else:
                        set_step("pak_disable", "success")
                        add_step(pak_audit, "disable", "success", proc)

                set_step("pak_move", "running")
                pak_move_server = pak_identity["server_main"]
                if not validate_ou_exists_on_server(pak_move_server, pak_target_ou):
                    if validate_ou_exists_on_server(pak_identity["server_pdc"], pak_target_ou):
                        pak_move_server = pak_identity["server_pdc"]
                        self._offboarding_log(f"[offboarding][pak][move] Целевой OU найден на PDC, перенос будет выполнен через {pak_move_server}")
                    else:
                        self._offboarding_log(f"[offboarding][pak][move] OU не найден на серверах {pak_identity['server_main']} и {pak_identity['server_pdc']}: {pak_target_ou}")
                        set_step("pak_move", "warn")
                        add_step(pak_audit, "move", "warn")
                        pak_move_server = ""

                if pak_move_server and ADHELPER_DRYRUN_MODE:
                    self._offboarding_log(f"[offboarding][pak][move] DRYRUN: пропуск Move-ADObject в OU {pak_target_ou}")
                    set_step("pak_move", "simulated")
                    add_step(pak_audit, "move", "simulated")
                elif pak_move_server:
                    pak_move_cmd = (
                        "Import-Module ActiveDirectory; "
                        f"Move-ADObject -Server '{{srv}}' -Identity '{escape_ps_string(pak_guid)}' -TargetPath '{escape_ps_string(pak_target_ou)}'; "
                        f"(Get-ADUser -Server '{{srv}}' -Identity '{escape_ps_string(pak_guid)}' -Properties DistinguishedName,Enabled) | "
                        "Select-Object DistinguishedName,Enabled | ConvertTo-Json -Depth 4"
                    )
                    proc = run_powershell(pak_move_cmd.format(srv=escape_ps_string(pak_move_server)), server=pak_move_server)
                    self._offboarding_log(f"[offboarding][pak][move] rc={proc.returncode}")
                    if proc.stdout.strip():
                        self._offboarding_log("[offboarding][pak][move] STDOUT:\n" + proc.stdout.strip())
                    if proc.stderr.strip():
                        self._offboarding_log("[offboarding][pak][move] STDERR:\n" + proc.stderr.strip())
                    if proc.returncode != 0 and command_failed_with_8329(proc) and pak_identity["server_pdc"].lower() != pak_move_server.lower():
                        self._offboarding_log(f"[offboarding][pak][move] Ошибка 8329/uninstantiated, ретрай на PDC: {pak_identity['server_pdc']}")
                        proc = run_powershell(pak_move_cmd.format(srv=escape_ps_string(pak_identity["server_pdc"])), server=pak_identity["server_pdc"])
                        self._offboarding_log(f"[offboarding][pak][move][retry] Сервер: {pak_identity['server_pdc']}, rc={proc.returncode}")
                    post_data, _ = parse_ps_json(proc.stdout)
                    post_obj = post_data[0] if post_data else {}
                    dn_after = str(post_obj.get("DistinguishedName") or "")
                    if proc.returncode != 0 or pak_target_ou.lower() not in dn_after.lower():
                        set_step("pak_move", "fail")
                        add_step(pak_audit, "move", "fail", proc)
                    else:
                        set_step("pak_move", "success")
                        add_step(pak_audit, "move", "success", proc)
                        pak_audit["dn_after"] = dn_after
                        pak_audit["ou_after"] = dn_to_ou(dn_after)
                        pak_audit["enabled_after"] = bool(post_obj.get("Enabled"))

        if ADHELPER_DRYRUN_MODE:
            omg_audit.setdefault("dn_after", omg_audit.get("dn_before", ""))
            omg_audit.setdefault("ou_after", omg_audit.get("ou_before", ""))
            omg_audit.setdefault("enabled_after", omg_audit.get("enabled_before"))
            pak_audit.setdefault("dn_after", pak_audit.get("dn_before", ""))
            pak_audit.setdefault("ou_after", pak_audit.get("ou_before", ""))
            pak_audit.setdefault("enabled_after", pak_audit.get("enabled_before"))

        audit_ok = True
        try:
            ensure_config_dir()
            append_jsonl(OFFBOARDING_LOG_PATH, audit_entry)
            self._offboarding_log(f"[offboarding][audit] Запись сохранена: {OFFBOARDING_LOG_PATH}")
        except OSError as exc:
            audit_ok = False
            self._offboarding_log(f"[offboarding][audit] Не удалось записать audit log: {exc}")

        self._offboarding_log(f"[offboarding] Увольнение завершено для {expected_sam}. DN до: {dn_before}")
        if clear_failed_attrs:
            failed_list = ", ".join(clear_failed_attrs)
            messagebox.showinfo(
                "Готово",
                f"Увольнение завершено, но часть полей не очистилась: {failed_list}. Требуется ручная проверка.",
            )
        elif not audit_ok:
            messagebox.showinfo("Готово", f"Процедура увольнения завершена для {expected_sam}, но audit log не записан.")
        else:
            messagebox.showinfo("Готово", f"Процедура увольнения завершена для {expected_sam}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ADHelper")
    parser.add_argument("--search", dest="search", default="", help="Строка поиска")
    parser.add_argument("--autorun", dest="autorun", action="store_true", help="Автозапуск поиска")
    parser.add_argument("--focus-search", dest="focus_search", action="store_true", help="Фокус на поле поиска")
    args = parser.parse_args(sys.argv[1:])

    app = App()
    if args.search:
        app.after(0, lambda q=args.search, ar=args.autorun: app.open_search(q, autorun=ar))
        if args.focus_search:
            app.after(80, lambda: getattr(app, "_search_entry", None) and app._search_entry.focus_set())
    app.mainloop()
