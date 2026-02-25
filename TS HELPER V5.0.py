# TS HELP AD — v5.0 (all-in-one + CallWatcher)
# Требуется: Python 3.9+, Windows
# Доп. пакеты (необязательно): ttkbootstrap, requests, pypiwin32
# pip install requests ttkbootstrap pypiwin32

import os, sys, json, re, time, threading, queue, subprocess, platform, shutil, webbrowser, locale, datetime, base64, urllib.parse, uuid, importlib, glob, socket
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, colorchooser
from concurrent.futures import ThreadPoolExecutor

# --- Версия приложения ---
VERSION = "v5.0"

# Цвета статусов (иконка в тексте)
STATUS_COLORS_DEFAULT = {
    "checking": "#f59e0b",
    "online":   "#16a34a",
    "offline":  "#9ca3af",
}

USE_BOOTSTRAP = False  # <— принудительно выключаем тему, чтобы цвета tk.Button работали
try:
    import ttkbootstrap as tb
    # USE_BOOTSTRAP = True   # не включаем
except:
    pass


def is_online(host: str, timeout_ms: int = 1200) -> bool:
    try:
        if platform.system() == "Windows":
            cp = subprocess.run(
                ["ping", "-n", "1", "-w", str(timeout_ms), host],
                capture_output=True, text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
        else:
            cp = subprocess.run(
                ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), host],
                capture_output=True, text=True
            )
        return cp.returncode == 0
    except Exception:
        return False

# --- Логи с ротацией ---
import logging
from logging.handlers import RotatingFileHandler
logger = logging.getLogger("app")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler("app.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(handler)
ACTION_LEVEL = logging.INFO + 1
CALL_LEVEL = logging.INFO + 2
logging.addLevelName(ACTION_LEVEL, "ACTION")
logging.addLevelName(CALL_LEVEL, "CALL")

def log_message(msg):
    logger.info(msg)

def log_action(msg):
    logger.log(ACTION_LEVEL, msg)

def log_call(msg):
    logger.log(CALL_LEVEL, msg)

# --- Локаль для сортировки ФИО ---
try:
    locale.setlocale(locale.LC_COLLATE, 'ru_RU.UTF-8')
except:
    pass


# --- DPAPI шифрование секретов (Windows) ---
DPAPI_AVAILABLE = False
try:
    import win32crypt
    DPAPI_AVAILABLE = True
except:
    pass

# --- Системный трей (Windows) ---
TRAY_AVAILABLE = False
try:
    import win32con, win32gui, win32gui_struct, win32api
    TRAY_AVAILABLE = True
except ImportError:
    pass


def _import_requests_optional():
    try:
        import requests
        return requests, None
    except ImportError:
        return None, "requests не установлен"

def dpapi_encrypt(s: str) -> str:
    if not DPAPI_AVAILABLE: return s
    blob = win32crypt.CryptProtectData(s.encode('utf-8'), None, None, None, None, 0)
    return "dpapi:" + base64.b64encode(blob).decode('ascii')

def dpapi_decrypt(s: str) -> str:
    if not DPAPI_AVAILABLE: return s
    if not s.startswith("dpapi:"): return s
    raw = base64.b64decode(s[len("dpapi:"):])
    data = win32crypt.CryptUnprotectData(raw, None, None, None, 0)[1]
    return data.decode('utf-8')

# --- Keyring для безопасного хранения ---
KEYRING_AVAILABLE = importlib.util.find_spec("keyring") is not None
if KEYRING_AVAILABLE:
    import keyring
    from keyring.errors import KeyringError, NoKeyringError
else:
    keyring = None
    class KeyringError(Exception):
        pass
    class NoKeyringError(Exception):
        pass


class SecretStorage:
    def __init__(self, service_name: str):
        self.service_name = service_name
        # На Windows храним зашифрованный DPAPI-файл как запасной вариант к keyring.
        self.secret_file = os.path.join(os.path.dirname(os.path.abspath(CONFIG_FILE)), 
                                        f".{self.service_name.replace(' ','_').lower()}_secrets.json")
        self._dpapi_cache = {}
        self.use_keyring = False
        self.use_dpapi_file = False
        self.available = self._check_available()
        self._ephemeral = {}

    def _check_available(self) -> bool:
        # Скрипт рассчитан на Windows, поэтому здесь же выбираем подходящее защищённое хранилище.
        if KEYRING_AVAILABLE and platform.system() == "Windows":
            try:
                keyring.get_keyring().get_password(self.service_name, "__tshelper_probe__")
                self.use_keyring = True
                return True
            except NoKeyringError:
                pass
            except Exception as e:
                log_message(f"Keyring недоступен: {e}")

        if DPAPI_AVAILABLE and platform.system() == "Windows":
            self._load_dpapi_file()
            self.use_dpapi_file = True
            return True

        return False

    def _load_dpapi_file(self):
        try:
            if os.path.exists(self.secret_file):
                with open(self.secret_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self._dpapi_cache = data
        except Exception as e:
            log_message(f"Ошибка загрузки хранилища секретов: {e}")
            self._dpapi_cache = {}

    def _save_dpapi_file(self):
        try:
            with open(self.secret_file, "w", encoding="utf-8") as f:
                json.dump(self._dpapi_cache, f, ensure_ascii=False, indent=2)
        except Exception as e:
            log_message(f"Ошибка сохранения хранилища секретов: {e}")

    def _is_ref(self, ref: str) -> bool:
        return isinstance(ref, str) and ref.startswith("kr:")

    def _generate_ref(self, key_name: str) -> str:
        return f"kr:{key_name}:{uuid.uuid4().hex}"

    def store_secret(self, key_name: str, secret: str, current_ref: str = "") -> str:
        if not secret:
            self.delete_secret(key_name, current_ref)
            return ""

        if not self.available:
            self._ephemeral[key_name] = secret
            return ""

        ref = current_ref if self._is_ref(current_ref) else self._generate_ref(key_name)

        if self.use_keyring:
            try:
                keyring.set_password(self.service_name, ref, secret)
                self._ephemeral.pop(key_name, None)
                return ref
            except KeyringError as e:
                log_message(f"Не удалось сохранить секрет {key_name}: {e}")
                return ""

        if self.use_dpapi_file:
            try:
                self._dpapi_cache[ref] = dpapi_encrypt(secret)
                self._save_dpapi_file()
                self._ephemeral.pop(key_name, None)
                return ref
            except Exception as e:
                log_message(f"DPAPI сохранение секрета {key_name} не удалось: {e}")
                return ""

        return ""

    def get_secret(self, key_name: str, ref: str):
        if self.available and self._is_ref(ref):
            if self.use_keyring:
                try:
                    return keyring.get_password(self.service_name, ref)
                except KeyringError as e:
                    log_message(f"Не удалось прочитать секрет {key_name}: {e}")
            elif self.use_dpapi_file:
                enc = self._dpapi_cache.get(ref)
                if enc:
                    try:
                        return dpapi_decrypt(enc)
                    except Exception as e:
                        log_message(f"DPAPI дешифрование секрета {key_name} не удалось: {e}")
        return self._ephemeral.get(key_name)

    def delete_secret(self, key_name: str, ref: str):
        if self.available and self._is_ref(ref):
            if self.use_keyring:
                try:
                    keyring.delete_password(self.service_name, ref)
                except Exception:
                    pass
            elif self.use_dpapi_file and ref in self._dpapi_cache:
                self._dpapi_cache.pop(ref, None)
                self._save_dpapi_file()
        self._ephemeral.pop(key_name, None)

# --- Debug dumps for PBX page ---
PBX_DEBUG_DUMP = True
PBX_DUMP_DIR = "./_pbx_debug"

def _pbx_dump(name: str, data):
    """Сохраняем дампы в _pbx_debug/ (raw html, plain, блоки по ext)."""
    if not PBX_DEBUG_DUMP:
        return
    try:
        os.makedirs(PBX_DUMP_DIR, exist_ok=True)
        path = os.path.join(PBX_DUMP_DIR, name)
        if isinstance(data, (bytes, bytearray)):
            with open(path, "wb") as f:
                f.write(data)
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
    except Exception as e:
        log_message(f"PBX dump error {name}: {e}")


# --- Константы ---
APP_NAME = "TS HELP AD"
CONFIG_FILE = "config.json"
USERS_FILE  = "users.json"
DOCK_ITEMS_FILE = "dock_items.json"

# AD defaults
AD_SERVER   = "DC02.pak-cspmz.ru"
AD_BASE_DN  = "OU=csp,OU=Users,OU=csp,DC=pak-cspmz,DC=ru"
AD_DOMAIN   = "pak-cspmz.ru"

# --- Утилиты JSON ---
def load_json(filename, default=None):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default if default is not None else {}
    except Exception as e:
        log_message(f"Ошибка чтения {filename}: {e}")
        return default if default is not None else {}

def save_json(filename, data):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
    except Exception as e:
        log_message(f"Ошибка записи {filename}: {e}")

def norm_name(n: str) -> str:
    p = n.strip().lower().split()
    return " ".join(p[:2]) if len(p) >= 2 else " ".join(p)

def clean_internal_number(num: str) -> str:
    """Минималистично очищаем внутренний номер, оставляя цифры и '+'."""
    if not num:
        return ""
    return re.sub(r"[^\d+]", "", str(num))

def which(name): return shutil.which(name)
def is_windows(): return platform.system().lower().startswith("win")

def run_as_admin(exe, args=""):
    try:
        import ctypes
        ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
        return True
    except Exception as e:
        log_message(f"run_as_admin error: {e}")
        return False

# --- GitHub auto-update check (в фоне) ---
def check_updates_async():
    try:
        import requests
    except:
        log_message("requests не установлен — пропускаем проверку обновлений")
        return
    try:
        resp = requests.get("https://api.github.com/repos/Et0ZheMax/tshelper/releases/latest", timeout=6)
        if resp.status_code != 200:
            log_message(f"GitHub API {resp.status_code}")
            return
        latest = resp.json().get("tag_name") or resp.json().get("name")
        if not latest:
            return
        if latest.strip() != VERSION.strip():
            def ask():
                if messagebox.askyesno("Обновление доступно",
                                       f"Доступна новая версия: {latest}\nВы используете: {VERSION}\nОткрыть страницу релиза?"):
                    webbrowser.open(resp.json().get("html_url", "https://github.com/Et0ZheMax/tshelper/releases"))
            try:
                app_root.after(0, ask)
            except:
                pass
    except Exception as e:
        log_message(f"Ошибка проверки обновлений: {e}")

# --- AD: получить пользователей через ldap3 ---
def get_ad_users(server, username, password, base_dn, domain):
    try:
        import ldap3
        ldap_server = ldap3.Server(server, get_info=ldap3.ALL)
        conn = ldap3.Connection(ldap_server, user=f"{username}@{domain}", password=password, auto_bind=True)
        search_filter = "(&(objectCategory=person)(objectClass=user))"
        attrs = ["cn", "sAMAccountName", "ipPhone", "telephoneNumber"]
        conn.search(search_base=base_dn, search_filter=search_filter, attributes=attrs)
        users = []
        for entry in conn.entries:
            cn = entry.cn.value if entry.cn else ""
            sam= entry.sAMAccountName.value if entry.sAMAccountName else ""
            ext = clean_internal_number(
                (entry.ipPhone.value if hasattr(entry, "ipPhone") else "")
                or (entry.telephoneNumber.value if hasattr(entry, "telephoneNumber") else "")
            )
            if cn and sam:
                users.append({"name": cn, "pc_name": f"w-{sam}", "ext": ext})
        conn.unbind()
        return users
    except Exception as e:
        log_message(f"AD error: {e}")
        messagebox.showerror("Ошибка AD", f"Не удалось получить пользователей из AD: {e}")
        return []


class GLPIClient:
    def __init__(self, api_url: str, app_token: str, user_token: str, prefix_field: str = "name", verify_ssl: bool = True):
        self.api_url = (api_url or "").strip().rstrip("/")
        self.app_token = app_token or ""
        self.user_token = user_token or ""
        self.prefix_field = prefix_field or "name"
        self.verify_ssl = bool(verify_ssl)
        self.session_token = None
        self.session = None

    def _headers(self, with_auth: bool = True):
        hdrs = {"App-Token": self.app_token}
        if with_auth and self.session_token:
            hdrs["Session-Token"] = self.session_token
        elif with_auth and self.user_token:
            hdrs["Authorization"] = f"user_token {self.user_token}"
        return hdrs

    def _ensure_session(self):
        if self.session:
            return True
        requests, err = _import_requests_optional()
        if not requests:
            log_message(err or "requests не установлен")
            messagebox.showerror("GLPI", err or "requests не установлен")
            return False
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        if not self.verify_ssl:
            try:
                requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        return True

    def _init_session(self) -> bool:
        if self.session_token:
            return True
        if not self.api_url or not self.app_token or not self.user_token:
            messagebox.showerror("GLPI", "Не заданы API URL/токены")
            return False
        if not self._ensure_session():
            return False
        try:
            resp = self.session.post(f"{self.api_url}/initSession", headers=self._headers())
            resp.raise_for_status()
            data = resp.json() if resp.content else {}
            self.session_token = data.get("session_token") or data.get("sessiontoken")
            if not self.session_token:
                raise ValueError("session_token отсутствует в ответе")
            return True
        except Exception as e:
            log_message(f"GLPI initSession error: {e}")
            messagebox.showerror("GLPI", f"Не удалось открыть сессию: {e}\nПроверьте URL (apirest.php) и опцию проверки SSL в настройках")
            return False

    def _search(self, itemtype: str, query: str):
        if not self._init_session():
            return []
        try:
            resp = self.session.get(
                f"{self.api_url}/search/{itemtype}",
                headers=self._headers(),
                params={"searchText": query}
            )
            resp.raise_for_status()
            data = resp.json()
            rows = data.get("data") if isinstance(data, dict) else None
            return rows if isinstance(rows, list) else []
        except Exception as e:
            log_message(f"GLPI search error ({itemtype}): {e}")
            return []

    def _first_user_id(self, login: str, full_name: str = ""):
        for q in (login, full_name):
            q = (q or "").strip()
            if not q:
                continue
            rows = self._search("User", q)
            for row in rows:
                if isinstance(row, dict):
                    uid = row.get("id") or row.get("2")
                    if uid:
                        return uid
                elif isinstance(row, list) and row:
                    possible = row[0].get("id") if isinstance(row[0], dict) else None
                    if possible:
                        return possible
        return None

    def _fetch_user_computers(self, user_id):
        if not self._init_session():
            return []
        try:
            resp = self.session.get(
                f"{self.api_url}/User/{user_id}/Computer",
                headers=self._headers()
            )
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("data") or []
        except Exception as e:
            log_message(f"GLPI get computers error: {e}")
        return []

    def _extract_name(self, item, key: str):
        if isinstance(item, dict):
            if key in item:
                return item.get(key)
            for v in item.values():
                if isinstance(v, dict) and key in v:
                    return v.get(key)
        return None

    def _to_pc_candidates(self, computers, login: str):
        names = []
        login = (login or "").strip()
        for c in computers:
            if isinstance(c, dict):
                for k in ("name", "1", "2", "computer_name"):
                    nm = self._extract_name(c, k) or c.get(k)
                    if nm:
                        names.append(str(nm))
                pref = self._extract_name(c, self.prefix_field) or c.get(self.prefix_field)
                if pref and login:
                    pref = str(pref).strip()
                    if pref and not pref.endswith("-"):
                        pref = pref + "-"
                    names.append(f"{pref}{login}")
            elif isinstance(c, list):
                for it in c:
                    if isinstance(it, dict) and "name" in it:
                        names.append(str(it.get("name")))
        uniq = []
        seen = set()
        for nm in names:
            key = nm.strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            uniq.append(nm.strip())
        return uniq

    def find_user_computers(self, login: str, full_name: str = ""):
        uid = self._first_user_id(login, full_name)
        computers = self._fetch_user_computers(uid) if uid else []
        if not computers:
            # fallback по текстовому поиску, если привязки не нашли
            fallback_query = login or full_name
            computers = self._search("Computer", fallback_query) if fallback_query else []
        candidates = self._to_pc_candidates(computers, login)
        filtered = [c for c in candidates if not c.lower().startswith(("wr-", "lr-"))]
        if not filtered:
            return {"main": None, "options": [], "source": self.prefix_field}
        main = filtered[0]
        return {
            "main": main,
            "options": [c for c in filtered[1:] if c.lower() != main.lower()],
            "source": self.prefix_field
        }


# --------------- Call Watcher (HTTP-парсер FreePBX) ---------------
def html_unwrap(html: str) -> str:
    from html import unescape
    txt = unescape(html)
    txt = re.sub(r"<script[\s\S]*?</script>", " ", txt, flags=re.I)
    txt = re.sub(r"<style[\s\S]*?</style>", " ", txt, flags=re.I)
    txt = re.sub(r"<[^>]+>", " ", txt)
    txt = txt.replace("\r", "\n")
    txt = re.sub(r"[ \t\u00a0]+", " ", txt)
    txt = re.sub(r"\n\s*\n\s*", "\n", txt)
    return txt.strip()

def looks_like_login(html: str) -> bool:
    h = html.lower()
    has_user = ('name="username"' in h) or ('id="username"' in h)
    has_pass = ('name="password"' in h) or ('id="password"' in h)
    has_logout = "logout" in h
    return (has_user and has_pass) and not has_logout

def extract_block_for_ext(text: str, ext: str) -> str:
    m = re.search(rf"(Endpoint:\s*{re.escape(ext)}\s*/\s*{re.escape(ext)}[\s\S]*?)(?=^Endpoint:\s|\Z)",
                  text, flags=re.I|re.M)
    if m: return m.group(1)
    m2 = re.search(rf"^.*\bExten:\s*{re.escape(ext)}\b.*$", text, flags=re.I|re.M)
    if m2:
        p = m2.start()
        starts = list(re.finditer(r"^Endpoint:\s.*$", text, flags=re.M))
        block_start = 0
        for hit in starts:
            if hit.start() <= p: block_start = hit.start()
            else: break
        mnext = re.search(r"^Endpoint:\s.*$", text[p:], flags=re.M)
        block_end = len(text) if not mnext else p + mnext.start()
        return text[block_start:block_end]
    return ""

def parse_caller_from_block(block: str, ext: str):
    if not block: return None
    in_block_for_ext = (
        re.search(rf"Endpoint:\s*{re.escape(ext)}\s*/\s*{re.escape(ext)}", block, flags=re.I) or
        re.search(rf"\bExten:\s*{re.escape(ext)}\b", block)
    )
    if not in_block_for_ext: return None
    if not is_block_active(block, ext):
        return None
    m = re.search(r'CLCID:\s*"?(?P<name>[^"]*)"?\s*<(?P<num>[^>]+)>', block)
    if m:
        name = (m.group("name") or "").strip()
        num  = (m.group("num") or "").strip()
        if num or name: return (num, name)
    m_num  = re.search(r"CallerIDNum:\s*(.+)", block)
    m_name = re.search(r"CallerIDName:\s*(.+)", block)
    num  = (m_num.group(1).strip() if m_num else "")
    name = (m_name.group(1).strip() if m_name else "")
    if num or name: return (num, name)
    m2 = re.search(r'CLCID:\s*"?(?P<name>[^"]*?)"?\s*(?P<num>\+?\d{5,15})', block)
    if m2: return (m2.group("num").strip(), m2.group("name").strip())
    return None

def is_block_active(block: str, ext: str) -> bool:
    if not block:
        return False
    in_block_for_ext = (
        re.search(rf"Endpoint:\s*{re.escape(ext)}\s*/\s*{re.escape(ext)}", block, flags=re.I) or
        re.search(rf"\bExten:\s*{re.escape(ext)}\b", block)
    )
    if not in_block_for_ext:
        return False
    active = any(
        re.search(pat, block, flags=re.I)
        for pat in [
            r"Ringing",
            r"Ring\+Inuse",
            r"\bDial\s+(Ring|Up)\b",
            r"Channel:.*\bUp\b",
        ]
    )
    if not active:
        m_inuse = re.search(r"In use\s+(\d+)", block, flags=re.I)
        active = bool(m_inuse and int(m_inuse.group(1)) > 0)
    return active

# --------- Главный класс окна ----------
class UserManager:
    def __init__(self, users_file):
        self.users_file = users_file
        self.users = [self._normalize_user(u) for u in load_json(self.users_file, default=[])]
    def get_users(self): return self.users
    def save(self): save_json(self.users_file, self.users)
    def add_user(self, u):
        self.users.append(self._normalize_user(u)); self.save()
    def update_user(self, old_pc_name, new_user):
        for i,u in enumerate(self.users):
            if u["pc_name"] == old_pc_name:
                self.users[i] = self._normalize_user(new_user); self.save(); return
    def delete_user(self, pc_name):
        self.users = [u for u in self.users if u["pc_name"] != pc_name]; self.save()

    def _normalize_user(self, u: dict):
        if not isinstance(u, dict):
            return {"name":"", "pc_name":"", "ext": ""}
        main = str(u.get("pc_name", "") or "")
        opts = u.get("pc_options") or []
        if not isinstance(opts, list):
            opts = []
        filtered = []
        seen = {main.lower(): main} if main else {}
        for opt in opts:
            if not opt:
                continue
            low = str(opt).lower()
            if low == main.lower() or low in seen:
                continue
            seen[low] = str(opt)
            filtered.append(str(opt))
        u["pc_name"] = main
        u["pc_options"] = filtered
        u["ext"] = clean_internal_number(u.get("ext", ""))
        return u

class SettingsManager:
    def __init__(self, path):
        self.path = path
        base_dir = os.path.dirname(os.path.abspath(self.path))
        self.dock_items_path = os.path.join(base_dir, DOCK_ITEMS_FILE)
        self.config = load_json(path, default={
            "window_geometry":"1100x720+200+100",
            "edit_window_geometry":"", "settings_window_geometry":"", "ad_sync_select_geometry":"", "ip_window_geometry":"",
            # AD creds
            "ad_username":"", "ad_password":"",
            "adhelper_path":"ADHelper(15).py",
            # Reset password
            "reset_password":"",
            # SSH
            "ssh_login":"", "ssh_password":"", "ssh_terminal":"Windows Terminal", "ssh_pass_enabled": False,
            "plink_hostkeys": {},
            # GLPI
            "glpi_api_url": "", "glpi_app_token": "", "glpi_user_token": "", "glpi_prefix_field": "name", "glpi_verify_ssl": True,
            # OMG defaults
            "omg_domain":"omg.cspfmba.ru", "omg_base_dn":"DC=omg,DC=cspfmba,DC=ru",
            # --- CallWatcher settings ---
            "cw_enabled": True,
            "cw_exts": "4444",  # несколько через запятую
            "cw_url": "http://pbx.pak-cspmz.ru/admin/config.php?display=asteriskinfo&module=peers",
            "cw_cookie": "mp1oomc5u57gpj1okil7hca2ue",     # строка Cookie: 'PHPSESSID=...; fpbx_admin=...'
            "cw_interval": 2,
            "cw_popup": True,
            "cw_login": "",
            "cw_password": "",
            # Цвета
            "ui_user_bg": "#ffffff", "ui_user_fg": "#000000",
            "ui_caller_bg": "#fff3cd", "ui_caller_fg": "#111111",  # жёлтый soft
            "ui_status_colors": STATUS_COLORS_DEFAULT,
            # Док-панель
            "dock_enabled": False,
            "dock_side": "left",
            "dock_settings_geometry": "",
            # Минимизация
            "minimize_to_tray": False,
            "minimize_to_widget": False,
            "mini_widget_geometry": "",
            "idle_timeout_minutes": 0,
        })
        self.secret_storage = SecretStorage(APP_NAME)
        self._secret_keys = {"ad_password", "ssh_password", "reset_password", "cw_password", "glpi_app_token", "glpi_user_token"}
        self._migrate_dock_items()

    def _migrate_plain_secret(self, key):
        current = self.config.get(key, "")
        if not current or (isinstance(current, str) and current.startswith("kr:")):
            return
        if not self.secret_storage.available:
            return
        if isinstance(current, str):
            try:
                current = dpapi_decrypt(current)
            except Exception:
                pass
        ref = self.secret_storage.store_secret(key, str(current), "")
        if ref:
            self.config[key] = ref
            self.save_config()

    def get_setting(self, k, default=None):
        if k in self._secret_keys:
            ref = self.config.get(k, "")
            secret = self.secret_storage.get_secret(k, ref)
            if secret:
                return secret
            self._migrate_plain_secret(k)
            ref = self.config.get(k, "")
            secret = self.secret_storage.get_secret(k, ref)
            if secret:
                return secret
            return self.config.get(k, default)
        return self.config.get(k, default)

    def set_setting(self, k, v):
        if k in self._secret_keys:
            ref = self.secret_storage.store_secret(k, v, self.config.get(k, ""))
            if not v:
                self.secret_storage.delete_secret(k, self.config.get(k, ""))
            self.config[k] = ref
            if not self.secret_storage.available:
                # без защищённого хранилища не показываем и не держим пароли в конфиге
                self.config[k] = ""
            self.save_config()
            return
        self.config[k] = v
        self.save_config()

    def can_show_secrets(self) -> bool:
        return self.secret_storage.available
    def save_config(self): save_json(self.path, self.config)

    # --- Отдельное хранение кнопок док-панели ---
    def _migrate_dock_items(self):
        legacy_items = self.config.get("dock_items")
        if isinstance(legacy_items, list):
            if self.set_dock_items(legacy_items, save_config=False):
                self.config.pop("dock_items", None)
                self.save_config()

    def get_dock_items(self, default=None):
        default = [] if default is None else default
        data = load_json(self.dock_items_path, default=None)
        if isinstance(data, list):
            return data
        return default

    def set_dock_items(self, items, save_config=True):
        normalized = items if isinstance(items, list) else []
        try:
            save_json(self.dock_items_path, normalized)
            success = True
        except Exception as e:
            log_message(f"Не удалось сохранить файл док-панели: {e}")
            success = False
        if success and save_config:
            self.config.pop("dock_items", None)
            self.save_config()
        return success

if TRAY_AVAILABLE:
    class SimpleSystemTray:
        """Простейшая иконка в трее на базе pywin32 с пунктами «Развернуть» и «Выход»."""
        def __init__(self, icon_path: str, tooltip: str, on_restore, on_exit, dispatcher=None):
            self.icon_path = icon_path
            self.tooltip = tooltip
            self.on_restore = on_restore
            self.on_exit = on_exit
            self.dispatcher = dispatcher
            self.hwnd = None
            self.hicon = None
            self._notify_msg = win32con.WM_USER + 20
            self._class_name = "TSHELPAD_TRAY"
            self._thread = None
            self._menu_actions = {1: self._safe_restore, 2: self._safe_exit}

        def _safe_restore(self, *_):
            try:
                if callable(self.on_restore):
                    if callable(self.dispatcher):
                        self.dispatcher(self.on_restore)
                    else:
                        self.on_restore()
            except Exception as e:
                log_message(f"Tray restore error: {e}")

        def _safe_exit(self, *_):
            try:
                if callable(self.on_exit):
                    if callable(self.dispatcher):
                        self.dispatcher(self.on_exit)
                    else:
                        self.on_exit()
            except Exception as e:
                log_message(f"Tray exit error: {e}")

        def _load_icon(self):
            try:
                ico_x = win32api.GetSystemMetrics(win32con.SM_CXSMICON)
                flags = win32con.LR_LOADFROMFILE | win32con.LR_DEFAULTSIZE
                return win32gui.LoadImage(None, self.icon_path, win32con.IMAGE_ICON, ico_x, ico_x, flags)
            except Exception as e:
                log_message(f"Не удалось загрузить иконку трея: {e}")
                return None

        def _wnd_proc(self, hwnd, msg, wparam, lparam):
            if msg == self._notify_msg:
                if lparam in (win32con.WM_LBUTTONUP, win32con.WM_LBUTTONDBLCLK):
                    self._safe_restore()
                elif lparam == win32con.WM_RBUTTONUP:
                    self._show_menu(hwnd)
                return 0
            if msg == win32con.WM_COMMAND:
                cmd_id = win32api.LOWORD(wparam)
                action = self._menu_actions.get(cmd_id)
                if action:
                    action()
                return 0
            if msg == win32con.WM_DESTROY:
                try:
                    win32gui.Shell_NotifyIcon(win32gui.NIM_DELETE, (hwnd, 0))
                except Exception:
                    pass
                win32gui.PostQuitMessage(0)
                return 0
            if msg == win32con.WM_CLOSE:
                win32gui.DestroyWindow(hwnd)
                return 0
            return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

        def _show_menu(self, hwnd):
            try:
                menu = win32gui.CreatePopupMenu()
                win32gui.AppendMenu(menu, win32con.MF_STRING, 1, "Развернуть")
                win32gui.AppendMenu(menu, win32con.MF_STRING, 2, "Выход")
                win32gui.SetForegroundWindow(hwnd)
                pos = win32gui.GetCursorPos()
                win32gui.TrackPopupMenu(menu, win32con.TPM_LEFTALIGN, pos[0], pos[1], 0, hwnd, None)
                win32gui.PostMessage(hwnd, win32con.WM_NULL, 0, 0)
            except Exception as e:
                log_message(f"Tray menu error: {e}")

        def _run(self):
            try:
                hinst = win32api.GetModuleHandle(None)
                wnd_class = win32gui.WNDCLASS()
                wnd_class.hInstance = hinst
                wnd_class.lpszClassName = self._class_name
                wnd_class.lpfnWndProc = self._wnd_proc
                try:
                    win32gui.RegisterClass(wnd_class)
                except Exception:
                    pass
                self.hwnd = win32gui.CreateWindow(self._class_name, self._class_name, 0, 0, 0, 0, 0, 0, 0, hinst, None)
                self.hicon = self._load_icon() or win32gui.LoadIcon(0, win32con.IDI_APPLICATION)
                flags = win32gui.NIF_ICON | win32gui.NIF_MESSAGE | win32gui.NIF_TIP
                tip = self.tooltip[:63] if self.tooltip else ""
                nid = (self.hwnd, 0, flags, self._notify_msg, self.hicon, tip)
                win32gui.Shell_NotifyIcon(win32gui.NIM_ADD, nid)
                win32gui.PumpMessages()
            except Exception as e:
                log_message(f"Tray loop error: {e}")
            finally:
                try:
                    if self.hwnd:
                        win32gui.DestroyWindow(self.hwnd)
                except Exception:
                    pass
                self.hwnd = None

        def show(self) -> bool:
            if not TRAY_AVAILABLE:
                return False
            if self._thread and self._thread.is_alive():
                return True
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            return True

        def destroy(self):
            if not self.hwnd:
                return
            try:
                win32gui.PostMessage(self.hwnd, win32con.WM_CLOSE, 0, 0)
            except Exception:
                pass
else:
    class SimpleSystemTray:
        def __init__(self, *_, **__):
            pass
        def show(self) -> bool:
            return False
        def destroy(self):
            pass


class LogViewer(tk.Toplevel):
    def __init__(self, master, settings, log_path: str = "app.log"):
        super().__init__(master)
        self.settings = settings
        self.log_path = log_path
        self.title("Просмотр логов")
        geom = self.settings.get_setting("log_window_geometry")
        if geom: self.geometry(geom)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.level_var = tk.StringVar(value="Все")
        self.date_from_var = tk.StringVar()
        self.date_to_var = tk.StringVar()
        self.autoscroll_var = tk.BooleanVar(value=True)
        self._auto_job = None
        self._auto_interval_ms = 1000

        top = ttk.Frame(self, padding=10); top.pack(fill="x")
        ttk.Label(top, text="Уровень:").grid(row=0, column=0, sticky="w", padx=(0,6))
        levels = ["Все", "DEBUG", "INFO", "ACTION", "CALL", "WARNING", "ERROR", "CRITICAL"]
        ttk.Combobox(top, values=levels, textvariable=self.level_var, state="readonly", width=10).grid(row=0, column=1, padx=(0,8))

        ttk.Label(top, text="С даты (ГГГГ-ММ-ДД):").grid(row=0, column=2, sticky="w")
        ttk.Entry(top, textvariable=self.date_from_var, width=12).grid(row=0, column=3, padx=(6,8))
        ttk.Label(top, text="По дату:").grid(row=0, column=4, sticky="w")
        ttk.Entry(top, textvariable=self.date_to_var, width=12).grid(row=0, column=5, padx=(6,8))

        ttk.Checkbutton(top, text="Автопрокрутка", variable=self.autoscroll_var).grid(row=0, column=6, padx=(0,8))
        ttk.Button(top, text="Обновить", command=self.reload_logs).grid(row=0, column=7)
        top.grid_columnconfigure(8, weight=1)

        frame = ttk.Frame(self, padding=(10,0)); frame.pack(fill="both", expand=True)
        self.text = tk.Text(frame, wrap="none", height=30)
        yscroll = ttk.Scrollbar(frame, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        self.text.configure(state="disabled")

        bottom = ttk.Frame(self, padding=10); bottom.pack(fill="x")
        ttk.Button(bottom, text="Скопировать в буфер", command=self.copy_to_clipboard).pack(side="left", padx=(0,6))
        ttk.Button(bottom, text="Сохранить…", command=self.save_to_file).pack(side="left")

        self.reload_logs()
        self._schedule_auto_reload()

    def on_close(self):
        self.settings.set_setting("log_window_geometry", self.geometry())
        if self._auto_job:
            try:
                self.after_cancel(self._auto_job)
            except Exception:
                pass
        self.destroy()

    def _schedule_auto_reload(self):
        try:
            self._auto_job = self.after(self._auto_interval_ms, self._auto_reload_logs)
        except Exception:
            self._auto_job = None

    def _auto_reload_logs(self):
        if not self.winfo_exists():
            return
        self.reload_logs(silent=True)
        self._schedule_auto_reload()

    def reload_logs(self, silent: bool = False):
        date_from, ok_from = self._parse_date_value(self.date_from_var.get().strip(), "С даты", silent=silent)
        if not ok_from:
            return
        date_to, ok_to = self._parse_date_value(self.date_to_var.get().strip(), "По дату", silent=silent)
        if not ok_to:
            return

        level = self.level_var.get().upper()
        entries = self._read_logs()
        filtered = []
        for dt, lvl, raw in entries:
            if level != "ВСЕ" and lvl.upper() != level:
                continue
            if date_from and dt.date() < date_from:
                continue
            if date_to and dt.date() > date_to:
                continue
            filtered.append(raw)

        self._render_text("\n".join(filtered))

    def _parse_date_value(self, value: str, label: str, silent: bool = False):
        if not value:
            return None, True
        try:
            return datetime.datetime.strptime(value, "%Y-%m-%d").date(), True
        except ValueError:
            if not silent:
                messagebox.showerror("Фильтр по дате", f"Некорректная дата в поле «{label}». Используйте формат ГГГГ-ММ-ДД.")
            else:
                log_message(f"Фильтр по дате: некорректное значение в поле {label}")
            return None, False

    def _read_logs(self):
        entries = []
        for path in sorted(glob.glob(f"{self.log_path}*"), key=os.path.getmtime):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        parsed = self._parse_line(line.rstrip("\n"))
                        if parsed:
                            entries.append(parsed)
            except Exception as e:
                log_message(f"Не удалось прочитать лог {path}: {e}")
        return entries

    def _parse_line(self, line: str):
        m = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (\w+): (.*)", line)
        if not m:
            return None
        try:
            ts = datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S,%f")
        except ValueError:
            return None
        return (ts, m.group(2), line)

    def _render_text(self, content: str):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        if content:
            self.text.insert("1.0", content)
        self.text.configure(state="disabled")
        if self.autoscroll_var.get():
            self.text.see("end")

    def copy_to_clipboard(self):
        try:
            data = self.text.get("sel.first", "sel.last")
        except tk.TclError:
            data = self.text.get("1.0", "end-1c")
        if not data:
            return
        self.clipboard_clear()
        self.clipboard_append(data)
        messagebox.showinfo("Буфер обмена", "Выдержка из логов скопирована.")

    def save_to_file(self):
        data = self.text.get("1.0", "end-1c")
        if not data:
            return messagebox.showinfo("Сохранение", "Нет данных для сохранения.")
        path = filedialog.asksaveasfilename(
            title="Сохранить логи",
            defaultextension=".txt",
            filetypes=[("Текстовый файл", "*.txt"), ("Все файлы", "*.*")],
            initialfile="app.log.txt",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
            messagebox.showinfo("Сохранение", f"Логи сохранены в {path}")
        except Exception as e:
            messagebox.showerror("Сохранение", f"Не удалось сохранить файл: {e}")

class MainWindow:
    def __init__(self, master):
        self.master = master
        self.master.title(f"{APP_NAME} {VERSION}")
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

        if USE_BOOTSTRAP:
            try: tb.Style("cosmo")
            except: pass

        self.settings = SettingsManager(CONFIG_FILE)
        geom = self.settings.get_setting("window_geometry","1100x720+200+100")
        self.master.geometry(geom)
        self.tray_icon = None
        self.mini_widget = None
        self._ignore_unmap = False
        self._is_minimized_custom = False
        self._force_exit = False
        self._idle_job = None
        self._idle_last_activity = time.time()
        self.idle_timeout_minutes = 0

        # стили (переопределяются при изменении настроек)
        self.style = ttk.Style(self.master)
        self._apply_button_styles()

        # иконки статусов
        self.status_icons = self._build_status_icons()

        # док-панель
        self.dock_items = self._normalize_dock_items(self.settings.get_dock_items([]))
        self.dock_enabled_var = tk.BooleanVar(master=self.master, value=bool(self.settings.get_setting("dock_enabled", False)))
        self.dock_side_var = tk.StringVar(master=self.master, value=self._normalize_dock_side(self.settings.get_setting("dock_side", "left")))

        self.users = UserManager(USERS_FILE)
        self.executor = ThreadPoolExecutor(max_workers=24)
        self.buttons = {}
        self.user_widgets = {}
        self.orphan_widgets = []
        self.empty_state_label = None
        self.search_job = None
        self.ping_generation = 0

        # активные звонки (список словарей)
        self.active_calls = []   # [{ext, num, name, ts, user, who_key}]
        self.calls_lock = threading.Lock()
        self.calls_ttl = 90      # сек держим вверху

        self.build_ui()
        self.populate_buttons()
        self._setup_idle_tracking()

        # Перестраивать сетку при изменении ширины (чтоб не «в столбик»)
        self._last_cols = None
        self.canvas.bind("<Configure>", self._on_canvas_resize)
        self.master.bind("<Unmap>", self._on_unmap)
        self.master.bind("<Map>", self._on_map)

        # авто-проверка обновлений и preflight
        threading.Thread(target=check_updates_async, daemon=True).start()
        threading.Thread(target=self.preflight_check, daemon=True).start()

        # Запуск колл-вотчера
        if self.settings.get_setting("cw_enabled", True):
            self.start_call_watcher()

    def _build_status_icons(self) -> dict:
        icons = {}
        colors = getattr(self, "status_colors", STATUS_COLORS_DEFAULT)
        for key, color in colors.items():
            icons[key] = self._make_status_icon(color)
        return icons

    def _make_status_icon(self, color: str, size: int = 14) -> tk.PhotoImage:
        img = tk.PhotoImage(width=size, height=size)
        r = (size - 2) / 2
        cx = cy = (size - 1) / 2
        for x in range(size):
            for y in range(size):
                dx, dy = x - cx, y - cy
                if dx*dx + dy*dy <= r*r:
                    img.put(color, (x, y))
        return img

    # --------- Работа с именами ПК ----------
    def get_allowed_prefixes(self) -> list:
        prefixes = self.settings.get_setting("pc_prefixes", ["w-", "l-"])
        if isinstance(prefixes, str):
            prefixes = [p.strip() for p in re.split(r"[;,]", prefixes) if p.strip()]
        elif isinstance(prefixes, (list, tuple, set)):
            prefixes = [str(p).strip() for p in prefixes if str(p).strip()]
        else:
            prefixes = []
        return prefixes

    def build_host_candidates(self, user: dict) -> list[str]:
        def add_variant(val: str):
            if not val:
                return
            low = val.lower()
            if low not in seen:
                seen.add(low)
                variants.append(val)

        prefixes = self.get_allowed_prefixes()
        default_prefix = prefixes[0] if prefixes else ""
        names = [user.get("pc_name", "")] + list(user.get("pc_options", []))
        variants = []
        seen = set()

        for name in names:
            clean, _ = self.normalize_pc_name(name)
            if clean:
                if default_prefix:
                    add_variant(f"{default_prefix}{clean}")
                for pref in prefixes:
                    if pref == default_prefix:
                        continue
                    add_variant(f"{pref}{clean}")
            add_variant(name)

        return variants

    def resolve_ip(self, host: str) -> str:
        try:
            return socket.gethostbyname(host)
        except Exception:
            return ""

    def ping_host_with_ip(self, host: str, timeout_ms: int = 1200) -> tuple[bool, str]:
        try:
            if platform.system() == "Windows":
                cp = subprocess.run(
                    ["ping", "-n", "1", "-w", str(timeout_ms), host],
                    capture_output=True, text=True,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    timeout=max(1, timeout_ms / 1000)
                )
            else:
                cp = subprocess.run(
                    ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), host],
                    capture_output=True, text=True, timeout=max(1, timeout_ms / 1000)
                )
            output = (cp.stdout or "") + (cp.stderr or "")
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", output)
            ip = m.group(1) if m else ""
            return cp.returncode == 0, ip
        except Exception as e:
            log_message(f"Пинг {host} завершился ошибкой: {e}")
            return False, ""

    def normalize_pc_name(self, pc_name: str) -> tuple[str, str]:
        for pref in self.get_allowed_prefixes():
            if pc_name.lower().startswith(pref.lower()):
                return pc_name[len(pref):], pref
        return pc_name, ""

    def get_display_pc_name(self, pc_name: str) -> str:
        clean, pref = self.normalize_pc_name(pc_name)
        return clean if pref else pc_name

    def _match_user_by_caller(self, name: str, num: str):
        """Подбираем пользователя по номеру (приоритетно) или по ФИО."""

        def clean_digits(value: str) -> str:
            return re.sub(r"\D", "", value or "")

        num_digits = clean_digits(num)
        if num_digits:
            for u in self.users.get_users():
                ext_digits = clean_digits(u.get("ext", ""))
                if ext_digits and (num_digits.endswith(ext_digits) or ext_digits.endswith(num_digits)):
                    return u

        key = norm_name(name) if name else ""
        if not key:
            return None
        for u in self.users.get_users():
            if norm_name(u.get("name", "")) == key:
                return u

        def name_tokens(value: str) -> list[str]:
            return [token for token in re.split(r"\s+", (value or "").strip().lower()) if token]

        caller_tokens = name_tokens(name)
        if not caller_tokens:
            return None
        caller_set = set(caller_tokens)
        for u in self.users.get_users():
            user_tokens = name_tokens(u.get("name", ""))
            if not user_tokens:
                continue
            user_set = set(user_tokens)
            if caller_set.issubset(user_set) or user_set.issubset(caller_set):
                return u
        return None

    # --------- UI ----------
    def build_ui(self):
        menubar = tk.Menu(self.master)
        filem = tk.Menu(menubar, tearoff=0)
        filem.add_command(label="Импорт пользователей…", command=self.import_users)
        filem.add_command(label="Экспорт пользователей…", command=self.export_users)
        filem.add_separator()
        filem.add_command(label="Настройки", command=self.open_settings)
        filem.add_separator()
        filem.add_command(label="Выход", command=self.on_closing)
        menubar.add_cascade(label="Файл", menu=filem)

        dockm = tk.Menu(menubar, tearoff=0)
        dockm.add_checkbutton(label="Активировать", variable=self.dock_enabled_var, command=self.toggle_dock_panel)
        pos_menu = tk.Menu(dockm, tearoff=0)
        pos_menu.add_radiobutton(label="Слева", value="left", variable=self.dock_side_var, command=self.change_dock_side)
        pos_menu.add_radiobutton(label="Справа", value="right", variable=self.dock_side_var, command=self.change_dock_side)
        dockm.add_cascade(label="Расположение", menu=pos_menu)
        dockm.add_separator()
        dockm.add_command(label="Настройки…", command=self.open_dock_settings)
        menubar.add_cascade(label="Док-панель", menu=dockm)

        toolsm = tk.Menu(menubar, tearoff=0)
        toolsm.add_command(label="Проверка окружения", command=self.show_env_check)
        toolsm.add_command(label="Просмотр логов", command=self.open_log_viewer)
        menubar.add_cascade(label="Инструменты", menu=toolsm)
        self.master.config(menu=menubar)

        # top
        top = ttk.Frame(self.master, padding=10); top.pack(side="top", fill="x")
        ttk.Label(top, text="Поиск:").pack(side="left")
        self.search_entry = ttk.Entry(top); self.search_entry.pack(side="left", fill="x", expand=True)
        self.search_entry.bind("<KeyRelease>", self.update_search)
        ttk.Button(top, text="Очистить", command=self.clear_search).pack(side="left", padx=(6, 0))
        self.master.bind_all("<Control-l>", self.clear_search)
        self.master.bind_all("<Control-L>", self.clear_search)

        # center area: док-панель + основное окно
        self.content = ttk.Frame(self.master, padding=(10,0))
        self.content.pack(side="top", fill="both", expand=True)
        self.content.grid_rowconfigure(0, weight=1)

        self.dock_container = ttk.Frame(self.content, padding=(0,0,10,0))
        self.dock_container.bind("<Configure>", self._on_dock_resize)
        dock_header = ttk.Frame(self.dock_container)
        dock_header.pack(fill="x", pady=(0,6))
        ttk.Label(dock_header, text="Док-панель", font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Button(dock_header, text="Настроить", command=self.open_dock_settings).pack(side="right")
        self.dock_buttons_frame = ttk.Frame(self.dock_container)
        self.dock_buttons_frame.pack(fill="both", expand=True)

        self.dock_divider = tk.Frame(self.content, bg="#b1b1b1", width=2)

        self.board_container = ttk.Frame(self.content)
        self.canvas = tk.Canvas(self.board_container, highlightthickness=0, bg=self.board_bg)
        vs = ttk.Scrollbar(self.board_container, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.canvas, bg=self.board_bg)
        self.canvas_window = self.canvas.create_window((0,0), window=self.inner, anchor="nw")

        self.inner.bind("<Configure>", self._update_scrollregion)
        self._bind_mousewheel()
        self._update_dock_layout()
        self._render_dock_buttons()

        # bottom
        bottom = ttk.Frame(self.master, padding=10); bottom.pack(side="bottom", fill="x")
        ttk.Button(bottom, text="Добавить", command=self.add_user).pack(side="left", padx=5)
        ttk.Button(bottom, text="AD Sync", command=self.ad_sync).pack(side="left", padx=5)
        ttk.Button(bottom, text="GLPI Sync", command=self.glpi_prefix_sync).pack(side="left", padx=5)
        self.count_lbl = ttk.Label(bottom, text="Найдено аккаунтов: 0"); self.count_lbl.pack(side="right")

    def _setup_idle_tracking(self):
        self._idle_last_activity = time.time()
        for seq in ("<Key>", "<Button>", "<Motion>", "<MouseWheel>"):
            self.master.bind_all(seq, self._mark_activity, add="+")
        self._apply_idle_timeout_setting(self.settings.get_setting("idle_timeout_minutes", 0))

    def _mark_activity(self, _event=None):
        self._idle_last_activity = time.time()
        self._schedule_idle_check()

    def _schedule_idle_check(self):
        if self._idle_job:
            self.master.after_cancel(self._idle_job)
            self._idle_job = None
        if self.idle_timeout_minutes <= 0 or self._is_minimized_custom:
            return
        delay = int(self.idle_timeout_minutes * 60 * 1000)
        self._idle_job = self.master.after(delay, self._on_idle_timeout)

    def _cancel_idle_check(self):
        if self._idle_job:
            self.master.after_cancel(self._idle_job)
            self._idle_job = None

    def _apply_idle_timeout_setting(self, minutes):
        try:
            minutes_value = float(minutes)
        except Exception:
            minutes_value = 0
        self.idle_timeout_minutes = max(0, minutes_value)
        self._schedule_idle_check()

    def _on_idle_timeout(self):
        self._idle_job = None
        if self._is_minimized_custom:
            return
        if self.idle_timeout_minutes <= 0:
            return
        if not self.settings.get_setting("minimize_to_widget", False):
            return
        elapsed = time.time() - self._idle_last_activity
        if elapsed < self.idle_timeout_minutes * 60:
            self._schedule_idle_check()
            return
        self.minimize_app()

    def open_log_viewer(self):
        if getattr(self, "log_window", None) and self.log_window.winfo_exists():
            self.log_window.lift(); self.log_window.focus_force()
            return
        self.log_window = LogViewer(self.master, self.settings)

    def _bind_mousewheel(self):
        # включаем прокрутку только когда курсор над канвой, чтобы не мешать другим окнам
        self.canvas.bind("<Enter>", lambda _e: self._toggle_mousewheel(True))
        self.canvas.bind("<Leave>", lambda _e: self._toggle_mousewheel(False))

    def _toggle_mousewheel(self, enable: bool):
        seqs = ("<MouseWheel>", "<Button-4>", "<Button-5>")
        for seq in seqs:
            if enable:
                self.canvas.bind_all(seq, self._on_mousewheel, add="+")
            else:
                try:
                    self.canvas.unbind_all(seq)
                except Exception:
                    pass

    def _mousewheel_delta(self, event) -> float:
        if getattr(event, "num", None) == 4:
            return 1
        if getattr(event, "num", None) == 5:
            return -1
        if getattr(event, "delta", 0):
            return event.delta / 120
        return 0

    def _on_mousewheel(self, event):
        delta = self._mousewheel_delta(event)
        if delta == 0:
            return "break"

        view = self.canvas.yview()
        if not view:
            return "break"

        start, end = view
        visible = end - start
        if visible >= 1:
            return "break"

        step = max(visible * 0.25, 0.02)
        target = start - delta * step
        max_start = max(0.0, 1.0 - visible)
        target = min(max(target, 0.0), max_start)
        self.canvas.yview_moveto(target)
        return "break"

    def _update_scrollregion(self, _=None):
        if getattr(self, "_sr_job", None):
            self.master.after_cancel(self._sr_job)
        self._sr_job = self.master.after(80, lambda: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

    # --------- Док-панель ----------
    def _normalize_dock_side(self, side: str) -> str:
        return "right" if str(side).lower().strip() == "right" else "left"

    def _normalize_dock_items(self, items) -> list[dict]:
        normalized = []
        for item in items or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or item.get("title") or "").strip()
            resource = str(item.get("resource") or item.get("target") or "").strip()
            action = str(item.get("action") or "open").strip().lower()
            if action not in {"open", "copy", "both"}:
                action = "open"
            copy_text = str(item.get("copy_text") or item.get("copy") or "").strip()
            if not name and not resource and not copy_text:
                continue
            normalized.append({
                "name": name or "Кнопка",
                "resource": resource,
                "action": action,
                "copy_text": copy_text,
            })
        return normalized

    def _update_dock_layout(self):
        if not getattr(self, "content", None):
            return

        for widget in (self.dock_container, self.dock_divider, self.board_container):
            try:
                widget.grid_forget()
            except Exception:
                pass

        for col in range(3):
            try:
                self.content.grid_columnconfigure(col, weight=0, minsize=0)
            except Exception:
                pass

        if self.dock_enabled_var.get():
            side = self._normalize_dock_side(self.dock_side_var.get())
            self.dock_side_var.set(side)
            if side == "left":
                dock_col, divider_col, board_col = 0, 1, 2
                dock_pad = (0, 8)
            else:
                dock_col, divider_col, board_col = 2, 1, 0
                dock_pad = (8, 0)

            self.content.grid_columnconfigure(dock_col, weight=1, minsize=220)
            self.content.grid_columnconfigure(board_col, weight=3)
            self.dock_container.grid(row=0, column=dock_col, sticky="nsew", padx=dock_pad)
            self.dock_divider.grid(row=0, column=divider_col, sticky="ns", padx=4, pady=6)
            self.board_container.grid(row=0, column=board_col, sticky="nsew")
        else:
            self.content.grid_columnconfigure(0, weight=1)
            self.board_container.grid(row=0, column=0, columnspan=3, sticky="nsew")

        self.content.grid_rowconfigure(0, weight=1)
        self.master.after(50, self._relayout_after_resize)

    def _compute_dock_cols(self) -> int:
        width = max(self.dock_container.winfo_width(), 260)
        btn_w, pad = 140, 12
        cols = (width + pad) // (btn_w + pad)
        return min(3, max(2, cols))

    def _render_dock_buttons(self):
        if not getattr(self, "dock_buttons_frame", None):
            return
        for w in self.dock_buttons_frame.winfo_children():
            w.destroy()

        cols = self._compute_dock_cols()
        if not self.dock_items:
            ttk.Label(self.dock_buttons_frame, text="Нет кнопок. Добавьте их в настройках.").grid(row=0, column=0, padx=6, pady=6, sticky="w")
            self.dock_buttons_frame.grid_columnconfigure(0, weight=1)
            return

        r = c = 0
        for item in self.dock_items:
            name = item.get("name") or "Кнопка"
            action = str(item.get("action", "open")).lower()
            if action not in {"open", "copy", "both"}:
                action = "open"
            marker = "📋 " if action == "copy" else "↗📋 " if action == "both" else ""
            title = f"{marker}{name}"
            btn = ttk.Button(self.dock_buttons_frame, text=title, command=lambda v=dict(item): self._run_dock_item(v))
            btn.grid(row=r, column=c, padx=4, pady=4, sticky="nsew")
            c += 1
            if c >= cols:
                c = 0
                r += 1

        for i in range(cols):
            self.dock_buttons_frame.grid_columnconfigure(i, weight=1)

    def _on_dock_resize(self, _=None):
        if getattr(self, "_dock_resize_job", None):
            try:
                self.master.after_cancel(self._dock_resize_job)
            except Exception:
                pass
        self._dock_resize_job = self.master.after(150, self._render_dock_buttons)

    def toggle_dock_panel(self):
        self.settings.set_setting("dock_enabled", self.dock_enabled_var.get())
        self._update_dock_layout()

    def change_dock_side(self):
        side = self._normalize_dock_side(self.dock_side_var.get())
        self.dock_side_var.set(side)
        self.settings.set_setting("dock_side", side)
        self._update_dock_layout()

    def _save_dock_items(self):
        self.dock_items = self._normalize_dock_items(self.dock_items)
        self.settings.set_dock_items(self.dock_items)
        self._render_dock_buttons()

    def _copy_dock_text(self, copy_text: str, button_name: str, show_success: bool = True):
        text = (copy_text or "").strip()
        if not text:
            return messagebox.showerror("Док-панель", "Не указана ссылка для копирования.")
        try:
            self.master.clipboard_clear()
            self.master.clipboard_append(text)
            self.master.update_idletasks()
            if show_success:
                messagebox.showinfo("Док-панель", f"Ссылка «{button_name}» скопирована в буфер обмена.")
        except Exception as e:
            messagebox.showerror("Док-панель", f"Не удалось скопировать ссылку: {e}")

    def _run_dock_item(self, item: dict):
        if not isinstance(item, dict):
            return
        action = str(item.get("action", "open")).lower()
        if action not in {"open", "copy", "both"}:
            action = "open"

        if action in {"copy", "both"}:
            self._copy_dock_text(item.get("copy_text", ""), item.get("name", "Кнопка"), show_success=(action == "copy"))

        if action in {"open", "both"}:
            self._open_dock_resource(item.get("resource", ""))

    def _open_dock_resource(self, resource: str):
        res = (resource or "").strip()
        if not res:
            return messagebox.showerror("Док-панель", "Не указан ресурс для этой кнопки.")
        try:
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", res):
                webbrowser.open(res)
                return
            if os.path.isdir(res):
                if is_windows():
                    os.startfile(res)
                else:
                    subprocess.Popen(["xdg-open", res])
                return
            if os.path.isfile(res):
                ext = os.path.splitext(res)[1].lower()
                if ext == ".ps1":
                    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", res] if is_windows() else ["pwsh", "-File", res]
                    subprocess.Popen(cmd, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                elif ext in {".bat", ".cmd"}:
                    subprocess.Popen(res, shell=True)
                elif ext == ".py":
                    subprocess.Popen([sys.executable, res])
                else:
                    if is_windows():
                        os.startfile(res)
                    else:
                        subprocess.Popen([res], shell=True)
                return
            if is_windows():
                os.startfile(res)
            else:
                subprocess.Popen(res, shell=True)
        except Exception as e:
            messagebox.showerror("Док-панель", f"Не удалось открыть ресурс: {e}")

    def open_dock_settings(self):
        if getattr(self, "dock_settings_window", None) and self.dock_settings_window.winfo_exists():
            self.dock_settings_window.lift(); self.dock_settings_window.focus_force()
            return

        win = tk.Toplevel(self.master); win.title("Настройка док-панели")
        geom = self.settings.get_setting("dock_settings_geometry", "")
        if geom:
            win.geometry(geom)
        win.transient(self.master)
        win.grab_set()
        win.protocol("WM_DELETE_WINDOW", lambda w=win: self._close_save_geo(w,"dock_settings_geometry"))
        self.dock_settings_window = win

        temp_items = [dict(item) for item in self.dock_items]

        frm = ttk.Frame(win, padding=10)
        frm.pack(fill="both", expand=True)
        frm.grid_columnconfigure(0, weight=1)
        frm.grid_columnconfigure(1, weight=1)
        frm.grid_rowconfigure(0, weight=1)

        list_frame = ttk.Frame(frm)
        list_frame.grid(row=0, column=0, rowspan=6, sticky="nsew", padx=(0,10))
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        lst = tk.Listbox(list_frame, height=14)
        lst.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(list_frame, orient="vertical", command=lst.yview)
        sb.grid(row=0, column=1, sticky="ns")
        lst.configure(yscrollcommand=sb.set)

        name_var = tk.StringVar()
        res_var = tk.StringVar()
        copy_var = tk.StringVar()
        action_var = tk.StringVar(value="open")
        selecting_list = False

        def refresh_list(selected_index=None):
            nonlocal selecting_list
            selecting_list = True
            lst.delete(0, "end")
            for idx, item in enumerate(temp_items):
                title = item.get("name") or f"Кнопка {idx+1}"
                action = str(item.get("action", "open")).lower()
                if action not in {"open", "copy", "both"}:
                    action = "open"
                if action == "copy":
                    value = item.get("copy_text")
                    marker = "📋"
                elif action == "both":
                    value = f"{(item.get('resource') or '').strip()} | {(item.get('copy_text') or '').strip()}"
                    marker = "↗📋"
                else:
                    value = item.get("resource")
                    marker = "↗"
                compact_value = (value or "—").strip()
                if len(compact_value) > 42:
                    compact_value = compact_value[:39] + "..."
                lst.insert("end", f"{idx+1}. {marker} {title} — {compact_value}")
            if selected_index is not None and 0 <= selected_index < len(temp_items):
                lst.selection_set(selected_index)
                lst.activate(selected_index)
                lst.see(selected_index)
            selecting_list = False

        def update_fields_visibility():
            action = action_var.get()
            if action == "copy":
                copy_lbl.grid()
                copy_entry.grid()
                res_lbl.grid_remove()
                res_entry.grid_remove()
            elif action == "both":
                res_lbl.grid()
                res_entry.grid()
                copy_lbl.grid()
                copy_entry.grid()
            else:
                res_lbl.grid()
                res_entry.grid()
                copy_lbl.grid_remove()
                copy_entry.grid_remove()

        def on_select(_=None):
            if selecting_list:
                return
            sel = lst.curselection()
            if not sel:
                return
            item = temp_items[sel[0]]
            name_var.set(item.get("name", ""))
            res_var.set(item.get("resource", ""))
            copy_var.set(item.get("copy_text", ""))
            action = str(item.get("action", "open")).lower()
            action_var.set(action if action in {"open", "copy", "both"} else "open")
            update_fields_visibility()

        def clear_form_for_new():
            lst.selection_clear(0, "end")
            name_var.set("")
            res_var.set("")
            copy_var.set("")
            action_var.set("open")
            update_fields_visibility()

        def add_or_update():
            title = name_var.get().strip()
            resource = res_var.get().strip()
            copy_text = copy_var.get().strip()
            action = action_var.get() if action_var.get() in {"open", "copy", "both"} else "open"
            if not title:
                return messagebox.showerror("Док-панель", "Заполните имя кнопки.")
            if action in {"copy", "both"} and not copy_text:
                return messagebox.showerror("Док-панель", "Укажите ссылку для копирования.")
            if action in {"open", "both"} and not resource:
                return messagebox.showerror("Док-панель", "Заполните ресурс (путь или URL).")
            new_item = {
                "name": title,
                "resource": resource,
                "action": action,
                "copy_text": copy_text,
            }
            sel = lst.curselection()
            if sel:
                temp_items[sel[0]] = new_item
                idx = sel[0]
            else:
                temp_items.append(new_item)
                idx = len(temp_items) - 1
            refresh_list(idx)
            on_select()

        def delete_selected():
            sel = lst.curselection()
            if not sel:
                return
            temp_items.pop(sel[0])
            refresh_list()
            clear_form_for_new()

        def move_item(delta: int):
            sel = lst.curselection()
            if not sel:
                return
            idx = sel[0]
            new_idx = idx + delta
            if new_idx < 0 or new_idx >= len(temp_items):
                return
            temp_items[idx], temp_items[new_idx] = temp_items[new_idx], temp_items[idx]
            refresh_list(new_idx)

        def save_and_close():
            self.dock_items = self._normalize_dock_items(temp_items)
            self._save_dock_items()
            self._update_dock_layout()
            self._close_save_geo(win,"dock_settings_geometry")

        ttk.Label(frm, text="Имя кнопки:").grid(row=0, column=1, sticky="w")
        ttk.Entry(frm, textvariable=name_var).grid(row=1, column=1, sticky="ew", pady=(0,6))

        action_row = ttk.Frame(frm)
        action_row.grid(row=2, column=1, sticky="w", pady=(0,6))
        ttk.Label(action_row, text="Действие:").pack(side="left")
        ttk.Radiobutton(action_row, text="Открыть", value="open", variable=action_var, command=update_fields_visibility).pack(side="left", padx=(8,2))
        ttk.Radiobutton(action_row, text="Копировать ссылку", value="copy", variable=action_var, command=update_fields_visibility).pack(side="left", padx=(0,2))
        ttk.Radiobutton(action_row, text="Открыть + копировать", value="both", variable=action_var, command=update_fields_visibility).pack(side="left")

        res_lbl = ttk.Label(frm, text="Ресурс (путь или URL):")
        res_lbl.grid(row=3, column=1, sticky="w")
        res_entry = ttk.Entry(frm, textvariable=res_var)
        res_entry.grid(row=4, column=1, sticky="ew", pady=(0,6))

        copy_lbl = ttk.Label(frm, text="Ссылка для копирования:")
        copy_lbl.grid(row=3, column=1, sticky="w")
        copy_entry = ttk.Entry(frm, textvariable=copy_var)
        copy_entry.grid(row=4, column=1, sticky="ew", pady=(0,6))
        copy_lbl.grid_remove()
        copy_entry.grid_remove()

        btn_row = ttk.Frame(frm)
        btn_row.grid(row=5, column=1, sticky="ew", pady=4)
        ttk.Button(btn_row, text="Добавить/обновить", command=add_or_update).pack(side="left")
        ttk.Button(btn_row, text="Удалить", command=delete_selected).pack(side="left", padx=6)
        ttk.Button(btn_row, text="Новая", command=clear_form_for_new).pack(side="left")

        order_row = ttk.Frame(frm)
        order_row.grid(row=6, column=1, sticky="ew", pady=4)
        ttk.Button(order_row, text="Вверх", command=lambda: move_item(-1)).pack(side="left")
        ttk.Button(order_row, text="Вниз", command=lambda: move_item(1)).pack(side="left", padx=6)

        ttk.Button(frm, text="Сохранить", command=save_and_close).grid(row=7, column=0, columnspan=2, pady=(10,0))

        lst.bind("<<ListboxSelect>>", on_select)
        refresh_list()
        clear_form_for_new()

    # --------- Кнопки/раскладка ----------
    def _compute_cols(self):
        avail = max(self.canvas.winfo_width(), 800)
        btn_w, pad = 210, 12
        return max(1, (avail + pad) // (btn_w + pad))
    
    def _on_canvas_resize(self, evt):
        # растянуть внутренний фрейм по ширине канвы — зазор пропадёт
        try:
            self.canvas.itemconfig(self.canvas_window, width=evt.width)
        except Exception:
            pass

        # дебаунс, чтобы не дёргалось при перерисовке
        if getattr(self, "_resize_job", None):
            self.master.after_cancel(self._resize_job)
        self._resize_job = self.master.after(120, self._relayout_after_resize)


    def _relayout_after_resize(self):
        self._resize_job = None
        cols = self._compute_cols()
        if cols != self._last_cols:
            self._last_cols = cols
            self.refresh_current_view()  # перестраиваем сетку только при реальном изменении числа колонок



    def _apply_button_styles(self):
        # читаем цвета из конфига (если там случайно был "#", подставляем дефолт)
        import re
        def norm(v, d):
            v = (v or "").strip()
            return v if re.fullmatch(r"#([0-9a-fA-F]{6})", v) else d

        self.user_bg   = norm(self.settings.get_setting("ui_user_bg", "#1f6feb"), "#1f6feb")   # синий как у тебя сейчас
        self.user_fg   = norm(self.settings.get_setting("ui_user_fg", "#ffffff"), "#ffffff")
        self.caller_bg = norm(self.settings.get_setting("ui_caller_bg", "#fff3cd"), "#fff3cd")
        self.caller_fg = norm(self.settings.get_setting("ui_caller_fg", "#111111"), "#111111")

        cfg_status = self.settings.get_setting("ui_status_colors", STATUS_COLORS_DEFAULT)
        if not isinstance(cfg_status, dict):
            cfg_status = {}
        self.status_colors = {
            key: norm(cfg_status.get(key, default), default)
            for key, default in STATUS_COLORS_DEFAULT.items()
        }

        # общий фон «доски» (чтобы вокруг кнопок не было «чужого» цвета)
        self.board_bg  = norm(self.settings.get_setting("ui_board_bg", "#f5e7d8"), "#f5e7d8")  # задай что хочешь

        # применяем к контейнерам
        try:
            self.canvas.configure(bg=self.board_bg)
            self.inner.configure(bg=self.board_bg)
            self.master.configure(bg=self.board_bg)
        except Exception:
            pass



    def _decorate_title(self, base, searching, ok):
        if searching:
            return ("🟢 " if ok else "🔴 ") + base
        return base

    def _open_user_menu(self, user: dict):
        btn = self.buttons.get(user.get("pc_name", ""))
        if btn:
            btn._show_menu()
        else:
            messagebox.showinfo("Пользователь", "Пользователь не найден в списке")

    def rebind_user_widget_key(self, old_pc: str, new_pc: str, widget=None):
        """Обновляем ключ кэша карточек при смене основного имени ПК."""
        if not old_pc or not new_pc or old_pc == new_pc:
            return
        target = widget or self.user_widgets.get(old_pc)
        if target and self.user_widgets.get(old_pc) is target:
            self.user_widgets.pop(old_pc, None)
            self.user_widgets[new_pc] = target
        if self.buttons.get(old_pc) is target:
            self.buttons.pop(old_pc, None)
            self.buttons[new_pc] = target

    def _get_filtered_users(self, text=None):
        if text is None:
            text = self.search_entry.get().lower().strip() if getattr(self, "search_entry", None) else ""
        all_users = self.users.get_users()
        if not text:
            return all_users
        return [
            u for u in all_users
            if text in u["name"].lower()
            or text in u["pc_name"].lower()
            or text in str(u.get("ext", "")).lower()
        ]

    def _sync_user_widgets(self):
        users = self.users.get_users()
        users_by_pc = {u.get("pc_name", ""): u for u in users if u.get("pc_name")}

        # удаляем карточки, которых больше нет в списке пользователей
        for pc_name in list(self.user_widgets.keys()):
            if pc_name not in users_by_pc:
                widget = self.user_widgets.pop(pc_name)
                widget.destroy()

        # создаём недостающие и обновляем данные существующих карточек
        for pc_name, user in users_by_pc.items():
            widget = self.user_widgets.get(pc_name)
            if widget is None:
                widget = UserButton(self.inner, user, app=self, style_name="User.TButton", caller=None, show_status=False)
                self.user_widgets[pc_name] = widget
            else:
                widget.user = user

    def get_visible_users(self, search_text: str):
        all_users = self.users.get_users()
        users_by_pc = {u.get("pc_name", ""): u for u in all_users if u.get("pc_name")}
        filtered_users = self._get_filtered_users(search_text)
        filtered_sorted = sorted(filtered_users, key=lambda u: locale.strxfrm(u["name"]))

        with self.calls_lock:
            now = time.time()
            self.active_calls = [c for c in self.active_calls if now - c["ts"] < self.calls_ttl]
            callers = sorted(self.active_calls, key=lambda c: c["ts"], reverse=True)

        caller_by_pc = {}
        orphan_calls = []
        pinned_users = []
        pinned_seen = set()

        for call in callers:
            user = call.get("user")
            pc_name = user.get("pc_name") if user else None
            mapped_user = users_by_pc.get(pc_name) if pc_name else None

            if not mapped_user and (call.get("name") or call.get("num")):
                matched_user = self._match_user_by_caller(call.get("name", ""), call.get("num", ""))
                if matched_user:
                    call["user"] = matched_user
                    mapped_user = users_by_pc.get(matched_user.get("pc_name"))

            if mapped_user:
                pc_name = mapped_user.get("pc_name")
                if pc_name:
                    caller_by_pc[pc_name] = call
                    if pc_name not in pinned_seen:
                        pinned_seen.add(pc_name)
                        pinned_users.append(mapped_user)
            else:
                orphan_calls.append(call)

        ordered_users = list(pinned_users)
        for user in filtered_sorted:
            if user.get("pc_name") not in pinned_seen:
                ordered_users.append(user)

        return ordered_users, filtered_sorted, caller_by_pc, orphan_calls

    def apply_call_state(self, caller_by_pc: dict):
        for pc_name, widget in self.user_widgets.items():
            widget.set_caller(caller_by_pc.get(pc_name))

    def render_grid(self, ordered_users, orphan_calls, show_empty_state=False):
        for widget in self.user_widgets.values():
            widget.grid_remove()
        for widget in self.orphan_widgets:
            widget.destroy()
        self.orphan_widgets = []
        if self.empty_state_label:
            self.empty_state_label.destroy()
            self.empty_state_label = None

        cols = self._compute_cols()
        row = col = 0
        self.buttons = {}

        if show_empty_state and not ordered_users:
            self.empty_state_label = ttk.Label(
                self.inner,
                text="Ничего не найдено. Попробуйте изменить запрос.",
                font=("Segoe UI", 12, "bold")
            )
            self.empty_state_label.grid(row=0, column=0, padx=16, pady=16, sticky="n")
            self.inner.grid_columnconfigure(0, weight=1)

        for user in ordered_users:
            widget = self.user_widgets.get(user.get("pc_name"))
            if not widget:
                continue
            widget.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")
            self.buttons[user["pc_name"]] = widget
            col += 1
            if col >= cols:
                col = 0
                row += 1

        # если звонок не удалось сопоставить с пользователем — показываем отдельной карточкой
        for call in orphan_calls:
            btn = tk.Button(
                self.inner,
                text=f"📞 {call['num'] or 'unknown'}\n{('(' + call['name'] + ')') if call['name'] else ''}\n→ {call['ext']}",
                bg=self.caller_bg,
                fg=self.caller_fg,
                activebackground=self.caller_bg,
                activeforeground=self.caller_fg,
                relief="ridge",
                bd=2,
                justify="center",
                wraplength=180,
            )
            btn.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")
            self.orphan_widgets.append(btn)
            col += 1
            if col >= cols:
                col = 0
                row += 1

        for i in range(cols):
            self.inner.grid_columnconfigure(i, weight=1)
        self._update_scrollregion()

    def populate_buttons(self, items=None, show_empty_state=False, show_status=False, search_text=None):
        if search_text is None:
            search_text = self.search_entry.get().lower().strip() if getattr(self, "search_entry", None) else ""
        self._sync_user_widgets()
        ordered_users, filtered_sorted, caller_by_pc, orphan_calls = self.get_visible_users(search_text)

        # статусы обновляем у всех карточек, но иконки показываем только в режиме поиска
        for widget in self.user_widgets.values():
            widget.show_status = show_status
            widget.set_status(widget.status_key)

        self.apply_call_state(caller_by_pc)
        show_empty = bool(search_text) and not filtered_sorted
        self.render_grid(ordered_users, orphan_calls, show_empty_state=show_empty)
        self.count_lbl.config(text=f"Найдено аккаунтов: {len(filtered_sorted)}")
        return filtered_sorted

    def refresh_current_view(self):
        if not getattr(self, "search_entry", None):
            self.populate_buttons()
            return
        self._do_search()


    # --------- Поиск ----------
    def update_search(self, _=None):
        if self.search_job: self.master.after_cancel(self.search_job)
        self.search_job = self.master.after(250, self._do_search)

    def _do_search(self):
        text = self.search_entry.get().lower().strip()
        show_status = len(text) >= 3
        filtered = self.populate_buttons(show_status=show_status, search_text=text)
        if show_status:
            self.ping_generation += 1
            gen = self.ping_generation
            for u in filtered:
                btn = self.buttons.get(u["pc_name"])
                if btn:
                    btn.set_status("checking")
                self.executor.submit(self._ping_task, u["pc_name"], gen)

    def clear_search(self, _=None):
        self.search_entry.delete(0, "end")
        self.search_entry.focus_set()
        self._do_search()
        return "break"

    def _ping_task(self, pc, gen):
        ok = self.check_availability(pc)
        if gen != self.ping_generation: return
        self.master.after(0, self._update_btn_style, pc, ok)

    def check_availability(self, pc):
        try:
            if is_windows():
                p = subprocess.run(["ping","-n","1",pc], capture_output=True, text=True, timeout=2,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                p = subprocess.run(["ping","-c","1",pc], capture_output=True, text=True, timeout=2)
            return p.returncode == 0
        except Exception as e:
            log_message(f"ping error {pc}: {e}")
            return False

    def _update_btn_style(self, pc, ok):
        btn = self.buttons.get(pc)
        if not btn: return
        btn.set_availability(ok, searching=(len(self.search_entry.get())>=3))

    # --------- Users CRUD ----------
    def add_user(self):
        win = tk.Toplevel(self.master); win.title("Добавить пользователя")
        geom = self.settings.get_setting("edit_window_geometry");
        if geom: win.geometry(geom)
        win.protocol("WM_DELETE_WINDOW", lambda w=win: self._close_save_geo(w,"edit_window_geometry"))
        ttk.Label(win, text="ФИО:").pack(pady=4, anchor="w"); e_name = ttk.Entry(win); e_name.pack(fill="x", padx=4)
        ttk.Label(win, text="Имя ПК:").pack(pady=4, anchor="w"); e_pc = ttk.Entry(win); e_pc.pack(fill="x", padx=4)
        ttk.Label(win, text="Внутренний номер:").pack(pady=4, anchor="w"); e_ext = ttk.Entry(win); e_ext.pack(fill="x", padx=4)
        def save():
            n=e_name.get().strip(); p=e_pc.get().strip(); ext=e_ext.get().strip()
            if not n or not p: return messagebox.showerror("Ошибка","Заполните поля")
            self.users.add_user({"name":n,"pc_name":p,"ext":ext}); self.refresh_current_view(); self._close_save_geo(win,"edit_window_geometry")
        ttk.Button(win, text="Сохранить", command=save).pack(pady=8)

    def open_edit_window(self, user):
        win = tk.Toplevel(self.master); win.title("Редактировать пользователя")
        geom = self.settings.get_setting("edit_window_geometry");
        if geom: win.geometry(geom)
        win.protocol("WM_DELETE_WINDOW", lambda w=win: self._close_save_geo(w,"edit_window_geometry"))
        ttk.Label(win, text="ФИО:").pack(pady=4, anchor="w"); e_name = ttk.Entry(win); e_name.insert(0,user["name"]); e_name.pack(fill="x", padx=4)
        ttk.Label(win, text="Имя ПК:").pack(pady=4, anchor="w"); e_pc = ttk.Entry(win); e_pc.insert(0,user["pc_name"]); e_pc.pack(fill="x", padx=4)
        ttk.Label(win, text="Внутренний номер:").pack(pady=4, anchor="w"); e_ext = ttk.Entry(win); e_ext.insert(0,user.get("ext","")); e_ext.pack(fill="x", padx=4)
        def save():
            n=e_name.get().strip(); p=e_pc.get().strip(); ext=e_ext.get().strip()
            if not n or not p: return messagebox.showerror("Ошибка","Заполните поля")

            old_pc = user.get("pc_name", "")
            new_user = {
                "name": n,
                "pc_name": p,
                "ext": ext,
                "pc_options": user.get("pc_options", []),
            }
            self.users.update_user(old_pc, new_user)

            # При переименовании основного ПК переносим ключ у существующего виджета, без пересоздания.
            if old_pc != p:
                self.rebind_user_widget_key(old_pc, p)

            widget = self.user_widgets.get(p)
            if widget:
                widget.user = new_user
                widget.set_status(widget.status_key)

            user.update(new_user)
            self.refresh_current_view()
            self._close_save_geo(win,"edit_window_geometry")
        ttk.Button(win, text="Сохранить", command=save).pack(pady=8)

    def delete_user_from_button(self, user):
        if messagebox.askyesno("Удалить", f"Удалить {user['name']}?"):
            self.users.delete_user(user["pc_name"]); self.refresh_current_view()

    # --------- AD sync ----------
    def _extract_login(self, pc_name: str) -> str:
        if not pc_name:
            return ""
        pc = pc_name.strip()
        return pc.split("-",1)[1] if "-" in pc else pc

    def open_in_ad(self, user: dict):
        login = self._extract_login(user.get("pc_name", ""))
        query = (login or user.get("name", "") or "").strip()
        if not query:
            return messagebox.showerror("ADHelper", "Не удалось определить строку поиска для пользователя")

        adhelper_path = self.settings.get_setting("adhelper_path", "").strip()
        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidates = []
        if adhelper_path:
            candidates.append(adhelper_path)
        candidates.extend(["ADHelper(15).py", "ADHelper.py"])

        resolved_path = ""
        for candidate in candidates:
            candidate_path = candidate if os.path.isabs(candidate) else os.path.join(script_dir, candidate)
            if os.path.isfile(candidate_path):
                resolved_path = candidate_path
                break

        if not resolved_path:
            messagebox.showwarning("ADHelper", "Укажите корректный путь к ADHelper в настройках")
            self.open_settings()
            return

        self._log_action(f"[AD] Launch: {resolved_path}, query={query}")

        cmd = [sys.executable, resolved_path, "--search", query, "--autorun", "--focus-search"]
        try:
            if is_windows():
                subprocess.Popen(cmd, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            else:
                subprocess.Popen(cmd)
        except Exception as exc:
            self._log_action(f"[AD] Launch error: {repr(exc)}")
            messagebox.showerror("ADHelper", f"Не удалось запустить ADHelper: {exc}")

    def _merge_pc_options(self, main_pc: str, *option_lists):
        main_pc = main_pc or ""
        seen = set()
        opts = []
        if main_pc:
            seen.add(main_pc.lower())
        for lst in option_lists:
            for val in lst or []:
                if not val:
                    continue
                low = str(val).lower()
                if low in seen:
                    continue
                seen.add(low)
                opts.append(str(val))
        return opts

    def _merge_user_records(self, existing: dict, incoming: dict):
        merged = dict(existing)
        main_pc = incoming.get("pc_name") or existing.get("pc_name") or ""
        merged["name"] = incoming.get("name") or existing.get("name")
        merged["pc_name"] = main_pc
        merged["ext"] = incoming.get("ext") or existing.get("ext") or ""
        options = self._merge_pc_options(main_pc, existing.get("pc_options", []), incoming.get("pc_options", []))
        if existing.get("pc_name") and existing.get("pc_name").lower() != main_pc.lower():
            options = self._merge_pc_options(main_pc, options, [existing.get("pc_name")])
        merged["pc_options"] = options
        return self.users._normalize_user(merged)

    def _make_glpi_client(self, silent: bool = False):
        url = self.settings.get_setting("glpi_api_url", "").strip()
        app_token = self.settings.get_setting("glpi_app_token", "").strip()
        user_token = self.settings.get_setting("glpi_user_token", "").strip()
        prefix_field = self.settings.get_setting("glpi_prefix_field", "name").strip() or "name"
        verify_ssl = self.settings.get_setting("glpi_verify_ssl", True)
        if isinstance(verify_ssl, str):
            verify_ssl = verify_ssl.strip().lower() not in {"0", "false", "no", "off"}
        if not url or not app_token or not user_token:
            if not silent:
                messagebox.showerror("GLPI", "Заполните URL API и токены GLPI в настройках")
            return None
        return GLPIClient(url, app_token, user_token, prefix_field, verify_ssl)

    def _apply_glpi_prefixes(self, users: list, glpi_client: GLPIClient, log_prefix: str):
        if not glpi_client:
            return users, False
        updated = []
        changed = False
        for u in users:
            login = self._extract_login(u.get("pc_name", ""))
            info = glpi_client.find_user_computers(login, u.get("name", "")) if login or u.get("name") else None
            if not info or not info.get("main"):
                updated.append(u)
                continue
            old_pc = u.get("pc_name", "")
            new_pc = info.get("main") or old_pc
            options = self._merge_pc_options(new_pc, u.get("pc_options", []), info.get("options", []))
            if old_pc.lower() != new_pc.lower():
                options = self._merge_pc_options(new_pc, options, [old_pc])
                changed = True
                log_action(f"{log_prefix}: {u.get('name','?')} {old_pc} -> {new_pc} (источник {info.get('source')})")
            else:
                log_message(f"{log_prefix}: {u.get('name','?')} — подтверждён {new_pc} (источник {info.get('source')})")
            updated.append(self.users._normalize_user({"name": u.get("name", ""), "pc_name": new_pc, "pc_options": options}))
            if set(map(str.lower, options)) != set(map(str.lower, u.get("pc_options", []))):
                changed = True
        return updated, changed

    def ad_sync(self):
        ad_user = self.settings.get_setting("ad_username","").strip()
        ad_pass = self.settings.get_setting("ad_password","").strip()
        if not ad_user or not ad_pass:
            return self.open_settings()
        ad_list = get_ad_users(AD_SERVER, ad_user, ad_pass, AD_BASE_DN, AD_DOMAIN)
        if not ad_list: return
        glpi_enabled = self.settings.get_setting("glpi_use_in_ad_sync", True)
        glpi_client = self._make_glpi_client(silent=True) if glpi_enabled else None
        if glpi_client:
            ad_list, _ = self._apply_glpi_prefixes(ad_list, glpi_client, "AD Sync")
        elif not glpi_enabled:
            log_message("AD Sync: проверка с GLPI отключена в настройках")
        by_norm = {norm_name(u["name"]): self.users._normalize_user(u) for u in self.users.get_users()}
        new_candidates = []
        for adu in ad_list:
            k = norm_name(adu["name"])
            if k in by_norm:
                by_norm[k] = self._merge_user_records(by_norm[k], adu)
            else:
                new_candidates.append(self.users._normalize_user(adu))
        if not new_candidates:
            self.users.users = list(by_norm.values()); self.users.save()
            self.populate_buttons()
            return messagebox.showinfo("AD Sync","Новых пользователей нет. Обновления применены.")
        self.show_ad_sync_selection(new_candidates, by_norm)

    def show_ad_sync_selection(self, new_users, merged_map):
        win = tk.Toplevel(self.master); win.title("Новые пользователи AD")
        geom = self.settings.get_setting("ad_sync_select_geometry")
        if geom: win.geometry(geom)
        win.protocol("WM_DELETE_WINDOW", lambda w=win: self._close_save_geo(w,"ad_sync_select_geometry"))
        vars = {}
        frm = ttk.Frame(win); frm.pack(fill="both", expand=True)
        canvas = tk.Canvas(frm, highlightthickness=0)
        vs = ttk.Scrollbar(frm, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        canvas.create_window((0,0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y"); canvas.pack(side="left", fill="both", expand=True)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        for u in new_users:
            var = tk.BooleanVar(value=True)
            vars[u["pc_name"]] = var
            ttk.Checkbutton(inner, text=f"{u['name']} ({u['pc_name']})", variable=var).pack(anchor="w", padx=8, pady=2)
        def apply_sel():
            sel = [u for u in new_users if vars[u["pc_name"]].get()]
            for u in sel:
                merged_map[norm_name(u["name"])] = u
            self.users.users = list(merged_map.values()); self.users.save()
            self.populate_buttons()
            self._close_save_geo(win,"ad_sync_select_geometry")
        ttk.Button(win, text="Добавить выбранных", command=apply_sel).pack(pady=8)

    def glpi_prefix_sync(self):
        glpi_client = self._make_glpi_client()
        if not glpi_client:
            return
        updated, changed = self._apply_glpi_prefixes(self.users.get_users(), glpi_client, "GLPI Sync")
        if changed:
            self.users.users = updated
            self.users.save()
            self.populate_buttons()
            messagebox.showinfo("GLPI", "Префиксы и ПК обновлены по данным GLPI")
        else:
            messagebox.showinfo("GLPI", "Изменений нет")

    # --------- Settings ----------
    def open_settings(self):
        win = tk.Toplevel(self.master); win.title("Настройки")
        geom = self.settings.get_setting("settings_window_geometry","900x620+250+150")
        win.geometry(geom)
        win.protocol("WM_DELETE_WINDOW", lambda w=win: self._close_save_geo(w,"settings_window_geometry"))
        nb = ttk.Notebook(win); nb.pack(fill="both", expand=True, padx=10, pady=10)

        can_show_secrets = self.settings.can_show_secrets()

        # Общие настройки
        tab_common = ttk.Frame(nb); nb.add(tab_common, text="Общее")
        ttk.Label(tab_common, text="Допустимые префиксы ПК (через запятую):").pack(pady=4, anchor="w")
        prefixes_var = tk.StringVar(value=", ".join(self.get_allowed_prefixes()))
        ttk.Entry(tab_common, textvariable=prefixes_var).pack(fill="x")
        minimize_to_tray = tk.BooleanVar(value=self.settings.get_setting("minimize_to_tray", False))
        minimize_to_widget = tk.BooleanVar(value=self.settings.get_setting("minimize_to_widget", False))
        ttk.Checkbutton(tab_common, text="Сворачивать в трей при закрытии/сворачивании", variable=minimize_to_tray).pack(anchor="w", pady=4)
        ttk.Checkbutton(tab_common, text="Сворачивать в мини-виджет поверх окон", variable=minimize_to_widget).pack(anchor="w", pady=2)
        ttk.Label(tab_common, text="Тайм-аут бездействия (минуты, 0 — отключить):").pack(pady=(8, 4), anchor="w")
        idle_timeout_var = tk.StringVar(value=str(self.settings.get_setting("idle_timeout_minutes", 0)))
        ttk.Entry(tab_common, textvariable=idle_timeout_var).pack(fill="x")

        def add_storage_warning(tab):
            if can_show_secrets:
                return
            ttk.Label(
                tab,
                text="Безопасное хранилище недоступно. Пароли не будут показываться в явном виде.",
                foreground="red",
                wraplength=520
            ).pack(fill="x", pady=4)

        def insert_secret(entry: ttk.Entry, key: str, default: str = ""):
            if can_show_secrets:
                entry.insert(0, self.settings.get_setting(key, default) or "")
            else:
                entry.insert(0, "")

        # AD creds
        tab_ad = ttk.Frame(nb); nb.add(tab_ad, text="Учетные данные AD")
        add_storage_warning(tab_ad)
        ttk.Label(tab_ad, text="Логин:").pack(pady=4, anchor="w")
        e_user = ttk.Entry(tab_ad); e_user.insert(0, self.settings.get_setting("ad_username","")); e_user.pack(fill="x")
        ttk.Label(tab_ad, text="Пароль:").pack(pady=4, anchor="w")
        e_pass = ttk.Entry(tab_ad, show="*"); insert_secret(e_pass, "ad_password", ""); e_pass.pack(fill="x")
        ttk.Label(tab_ad, text="Путь к ADHelper.py:").pack(pady=(10, 4), anchor="w")
        adhelper_row = ttk.Frame(tab_ad)
        adhelper_row.pack(fill="x")
        adhelper_path_var = tk.StringVar(value=self.settings.get_setting("adhelper_path", "ADHelper(15).py"))
        ttk.Entry(adhelper_row, textvariable=adhelper_path_var).pack(side="left", fill="x", expand=True)
        ttk.Button(
            adhelper_row,
            text="Обзор…",
            command=lambda: adhelper_path_var.set(
                filedialog.askopenfilename(
                    title="Выберите ADHelper",
                    filetypes=[("Python", "*.py"), ("Все файлы", "*.*")],
                ) or adhelper_path_var.get()
            ),
        ).pack(side="left", padx=(6, 0))

        # GLPI
        tab_glpi = ttk.Frame(nb); nb.add(tab_glpi, text="GLPI")
        add_storage_warning(tab_glpi)
        ttk.Label(tab_glpi, text="GLPI API URL (apirest.php)").pack(pady=4, anchor="w")
        e_glpi_url = ttk.Entry(tab_glpi); e_glpi_url.insert(0, self.settings.get_setting("glpi_api_url", "")); e_glpi_url.pack(fill="x")
        ttk.Label(tab_glpi, text="App Token:").pack(pady=4, anchor="w")
        e_glpi_app = ttk.Entry(tab_glpi, show="*"); insert_secret(e_glpi_app, "glpi_app_token", ""); e_glpi_app.pack(fill="x")
        ttk.Label(tab_glpi, text="User Token:").pack(pady=4, anchor="w")
        e_glpi_user = ttk.Entry(tab_glpi, show="*"); insert_secret(e_glpi_user, "glpi_user_token", ""); e_glpi_user.pack(fill="x")
        ttk.Label(tab_glpi, text="Поле с префиксом/OS (в ответе GLPI)").pack(pady=4, anchor="w")
        e_glpi_prefix = ttk.Entry(tab_glpi); e_glpi_prefix.insert(0, self.settings.get_setting("glpi_prefix_field", "name")); e_glpi_prefix.pack(fill="x")
        glpi_verify_ssl = tk.BooleanVar(value=self.settings.get_setting("glpi_verify_ssl", True))
        ttk.Checkbutton(tab_glpi, text="Проверять SSL-сертификат (снимите галочку для self-signed)", variable=glpi_verify_ssl).pack(pady=4, anchor="w")
        glpi_use_in_ad_sync = tk.BooleanVar(value=self.settings.get_setting("glpi_use_in_ad_sync", True))
        ttk.Checkbutton(tab_glpi, text="Использовать сверку с GLPI во время AD Sync", variable=glpi_use_in_ad_sync).pack(pady=4, anchor="w")

        # Reset password
        tab_rst = ttk.Frame(nb); nb.add(tab_rst, text="Пароль для сброса")
        add_storage_warning(tab_rst)
        ttk.Label(tab_rst, text="Новый пароль:").pack(pady=4, anchor="w")
        e_rst = ttk.Entry(tab_rst, show="*"); insert_secret(e_rst, "reset_password", "12340987"); e_rst.pack(fill="x")
        btn_toggle = ttk.Button(tab_rst, text="Показать")
        def toggle_pw():
            if e_rst.cget("show")=="*": e_rst.config(show=""); btn_toggle.config(text="Скрыть")
            else: e_rst.config(show="*"); btn_toggle.config(text="Показать")
        btn_toggle.config(command=toggle_pw); btn_toggle.pack(pady=4, anchor="e")

        # SSH
        tab_ssh = ttk.Frame(nb); nb.add(tab_ssh, text="SSH")
        add_storage_warning(tab_ssh)
        ttk.Label(tab_ssh, text="SSH Login:").pack(pady=4, anchor="w")
        e_ssh_login = ttk.Entry(tab_ssh); e_ssh_login.insert(0, self.settings.get_setting("ssh_login","")); e_ssh_login.pack(fill="x")
        ttk.Label(tab_ssh, text="SSH Password:").pack(pady=4, anchor="w")
        e_ssh_pass = ttk.Entry(tab_ssh, show="*"); insert_secret(e_ssh_pass, "ssh_password", ""); e_ssh_pass.pack(fill="x")
        ttk.Label(tab_ssh, text="Терминал:").pack(pady=4, anchor="w")
        ssh_term = tk.StringVar(value=self.settings.get_setting("ssh_terminal","Windows Terminal"))
        cmb = ttk.Combobox(tab_ssh, textvariable=ssh_term, values=("Windows Terminal","CMD","PowerShell"), state="readonly")
        cmb.pack(fill="x")
        ssh_pass_enabled = tk.BooleanVar(value=self.settings.get_setting("ssh_pass_enabled", False))
        ttk.Checkbutton(tab_ssh, text="Передавать пароль автоматически", variable=ssh_pass_enabled).pack(pady=4, anchor="w")
        ttk.Label(tab_ssh, text="Plink hostkeys (JSON: {\"host\":\"algo bits fingerprint\"})").pack(pady=4, anchor="w")
        txt_hostkeys = tk.Text(tab_ssh, height=6)
        txt_hostkeys.insert("1.0", json.dumps(self.settings.config.get("plink_hostkeys", {}), ensure_ascii=False, indent=2))
        txt_hostkeys.pack(fill="both", expand=True)

        # Телефония (CallWatcher)
        tab_cw = ttk.Frame(nb); nb.add(tab_cw, text="Телефония")
        add_storage_warning(tab_cw)
        cw_enabled = tk.BooleanVar(value=self.settings.get_setting("cw_enabled", True))
        ttk.Checkbutton(tab_cw, text="Включить отслеживание звонков", variable=cw_enabled).pack(anchor="w", pady=4)
        ttk.Label(tab_cw, text="Номера EXT (через запятую):").pack(anchor="w");
        e_exts = ttk.Entry(tab_cw); e_exts.insert(0, self.settings.get_setting("cw_exts","4444")); e_exts.pack(fill="x")
        ttk.Label(tab_cw, text="URL Peers-страницы FreePBX:").pack(anchor="w");
        e_url = ttk.Entry(tab_cw); e_url.insert(0, self.settings.get_setting("cw_url","")); e_url.pack(fill="x")
        ttk.Label(tab_cw, text="Логин/пароль для FreePBX (используются для автоподхвата cookie):").pack(anchor="w")
        e_pbx_login = ttk.Entry(tab_cw); e_pbx_login.insert(0, self.settings.get_setting("cw_login","")); e_pbx_login.pack(fill="x")
        e_pbx_pass = ttk.Entry(tab_cw, show="*"); insert_secret(e_pbx_pass, "cw_password", ""); e_pbx_pass.pack(fill="x")

        ttk.Label(tab_cw, text="Cookie (из DevTools или автоподхвата, всё после 'Cookie:'):").pack(anchor="w")
        cookie_row = ttk.Frame(tab_cw); cookie_row.pack(fill="x")
        e_cookie = ttk.Entry(cookie_row); e_cookie.insert(0, self.settings.get_setting("cw_cookie",""))
        e_cookie.pack(side="left", fill="x", expand=True)
        btn_test_cookie = ttk.Button(
            cookie_row,
            text="Тест",
            command=lambda: self._run_pbx_test(e_url.get(), e_cookie.get(), btn_test_cookie)
        )
        btn_test_cookie.pack(side="left", padx=6)
        btn_fetch_cookie = ttk.Button(
            cookie_row,
            text="Получить cookie",
            command=lambda: self._auto_fetch_pbx_cookie(
                e_url.get(), e_pbx_login.get(), e_pbx_pass.get(), e_cookie, btn_fetch_cookie
            )
        )
        btn_fetch_cookie.pack(side="left")
        ttk.Label(tab_cw, text="Интервал опроса, сек:").pack(anchor="w");
        e_interval = ttk.Entry(tab_cw); e_interval.insert(0, str(self.settings.get_setting("cw_interval",2))); e_interval.pack(fill="x")
        cw_popup = tk.BooleanVar(value=self.settings.get_setting("cw_popup", True))
        ttk.Checkbutton(tab_cw, text="Показывать всплывающее окно при звонке", variable=cw_popup).pack(anchor="w", pady=4)

        # Цвета
        tab_colors = ttk.Frame(nb); nb.add(tab_colors, text="Цвета")
        def pick_color(current):
            c = colorchooser.askcolor(current)[1]
            return c if c else current
        user_bg = tk.StringVar(value=self.settings.get_setting("ui_user_bg","#ffffff"))
        user_fg = tk.StringVar(value=self.settings.get_setting("ui_user_fg","#000000"))
        caller_bg = tk.StringVar(value=self.settings.get_setting("ui_caller_bg","#fff3cd"))
        caller_fg = tk.StringVar(value=self.settings.get_setting("ui_caller_fg","#111111"))
        status_checking = tk.StringVar(value=self.status_colors.get("checking", STATUS_COLORS_DEFAULT["checking"]))
        status_online = tk.StringVar(value=self.status_colors.get("online", STATUS_COLORS_DEFAULT["online"]))
        status_offline = tk.StringVar(value=self.status_colors.get("offline", STATUS_COLORS_DEFAULT["offline"]))
        for lbl, var in (("Фон кнопок пользователей", user_bg), ("Текст кнопок пользователей", user_fg),
                         ("Фон кнопок звонков", caller_bg), ("Текст кнопок звонков", caller_fg)):
            row = ttk.Frame(tab_colors); row.pack(fill="x", pady=4)
            ttk.Label(row, text=lbl).pack(side="left")
            ent = ttk.Entry(row, textvariable=var, width=12); ent.pack(side="left", padx=6)
            ttk.Button(row, text="Выбрать…", command=lambda v=var: v.set(pick_color(v.get()))).pack(side="left")

        for lbl, var in (("Статус: проверка", status_checking), ("Статус: в сети", status_online), ("Статус: недоступен", status_offline)):
            row = ttk.Frame(tab_colors); row.pack(fill="x", pady=4)
            ttk.Label(row, text=lbl).pack(side="left")
            ttk.Entry(row, textvariable=var, width=12).pack(side="left", padx=6)
            ttk.Button(row, text="Выбрать…", command=lambda v=var: v.set(pick_color(v.get()))).pack(side="left")

        board_bg = tk.StringVar(value=self.settings.get_setting("ui_board_bg","#f5e7d8"))

        row = ttk.Frame(tab_colors); row.pack(fill="x", pady=4)
        ttk.Label(row, text="Фон рабочей области").pack(side="left")
        ent = ttk.Entry(row, textvariable=board_bg, width=12); ent.pack(side="left", padx=6)
        ttk.Button(row, text="Выбрать…", command=lambda: board_bg.set(pick_color(board_bg.get()))).pack(side="left")


        # Save
        def save_all():
            prefixes = [p.strip() for p in re.split(r"[;,]", prefixes_var.get()) if p.strip()]
            self.settings.set_setting("pc_prefixes", prefixes)
            self.settings.set_setting("minimize_to_tray", minimize_to_tray.get())
            self.settings.set_setting("minimize_to_widget", minimize_to_widget.get())
            try:
                idle_minutes = float(idle_timeout_var.get().replace(",", ".").strip() or 0)
            except Exception:
                idle_minutes = 0
            self.settings.set_setting("idle_timeout_minutes", max(0, idle_minutes))
            self._apply_idle_timeout_setting(max(0, idle_minutes))
            self.settings.set_setting("ad_username", e_user.get().strip())
            self.settings.set_setting("ad_password", e_pass.get().strip())
            self.settings.set_setting("adhelper_path", adhelper_path_var.get().strip())
            self.settings.set_setting("reset_password", e_rst.get().strip())
            self.settings.set_setting("ssh_login", e_ssh_login.get().strip())
            self.settings.set_setting("ssh_password", e_ssh_pass.get().strip())
            self.settings.set_setting("ui_board_bg", board_bg.get())
            self.settings.set_setting("ssh_terminal", ssh_term.get())
            self.settings.set_setting("ssh_pass_enabled", ssh_pass_enabled.get())
            # hostkeys
            try:
                hk = json.loads(txt_hostkeys.get("1.0","end").strip() or "{}")
                if isinstance(hk, dict):
                    self.settings.config["plink_hostkeys"] = hk
                    self.settings.save_config()
            except Exception as e:
                messagebox.showerror("Hostkeys", f"Ошибка JSON: {e}")
                return

            # CallWatcher
            self.settings.set_setting("cw_enabled", cw_enabled.get())
            self.settings.set_setting("cw_exts", e_exts.get().strip())
            self.settings.set_setting("cw_url", e_url.get().strip())
            self.settings.set_setting("cw_cookie", e_cookie.get().strip())
            self.settings.set_setting("cw_login", e_pbx_login.get().strip())
            self.settings.set_setting("cw_password", e_pbx_pass.get().strip())
            try:
                self.settings.set_setting("cw_interval", int(e_interval.get().strip()))
            except:
                self.settings.set_setting("cw_interval", 2)
            self.settings.set_setting("cw_popup", cw_popup.get())

            # Цвета
            self.settings.set_setting("ui_user_bg", user_bg.get())
            self.settings.set_setting("ui_user_fg", user_fg.get())
            self.settings.set_setting("ui_caller_bg", caller_bg.get())
            self.settings.set_setting("ui_caller_fg", caller_fg.get())
            self.settings.set_setting("ui_status_colors", {
                "checking": status_checking.get(),
                "online": status_online.get(),
                "offline": status_offline.get(),
            })
            self._apply_button_styles()
            self.status_icons = self._build_status_icons()
            self.refresh_current_view()

            # GLPI
            self.settings.set_setting("glpi_api_url", e_glpi_url.get().strip())
            self.settings.set_setting("glpi_app_token", e_glpi_app.get().strip())
            self.settings.set_setting("glpi_user_token", e_glpi_user.get().strip())
            self.settings.set_setting("glpi_prefix_field", e_glpi_prefix.get().strip() or "name")
            self.settings.set_setting("glpi_verify_ssl", glpi_verify_ssl.get())
            self.settings.set_setting("glpi_use_in_ad_sync", glpi_use_in_ad_sync.get())

            self._close_save_geo(win,"settings_window_geometry")
            # перезапуск колл-вотчера с новыми настройками
            self.restart_call_watcher_if_needed()

        ttk.Button(win, text="Сохранить", command=save_all).pack(pady=8)

    def _close_save_geo(self, window, key):
        self.settings.set_setting(key, window.geometry())
        window.destroy()

    # --------- Preflight ----------
    def preflight_check(self):
        checks = {
            "wt.exe": bool(which("wt.exe")),
            "cmd.exe": True,
            "powershell": bool(which("powershell")),
            "plink.exe": bool(which("plink.exe")),
            "ssh": bool(which("ssh")),
            "ubuntu.exe": bool(which("ubuntu.exe")),
        }
        log_message(f"Preflight: {checks}")

    def show_env_check(self):
        checks = {
            "Windows Terminal (wt.exe)": which("wt.exe"),
            "PowerShell": which("powershell"),
            "CMD": "OK",
            "Plink": which("plink.exe"),
            "OpenSSH (ssh)": which("ssh"),
            "Ubuntu.exe (WSL проф.)": which("ubuntu.exe"),
        }
        text = []
        for k,v in checks.items():
            ok = bool(v)
            text.append(f"{'✅' if ok else '❌'} {k} : {v if v else 'нет в PATH'}")
        messagebox.showinfo("Проверка окружения", "\n".join(text))

    # --------- Импорт/экспорт ----------
    def import_users(self):
        path = filedialog.askopenfilename(title="Импорт пользователей (CSV/XLSX)", filetypes=[("CSV","*.csv"),("Excel","*.xlsx *.xls")])
        if not path: return
        users = self.users.get_users()
        added = 0
        try:
            if path.lower().endswith(".csv"):
                import csv
                with open(path, "r", encoding="utf-8") as f:
                    for row in csv.DictReader(f):
                        name = row.get("name") or row.get("ФИО") or ""
                        pc   = row.get("pc_name") or row.get("ПК") or ""
                        ext  = row.get("ext") or row.get("internal_number") or row.get("Внутренний номер") or ""
                        if name and pc:
                            users.append({"name":name.strip(),"pc_name":pc.strip(),"ext":str(ext).strip()}); added+=1
            else:
                try:
                    import pandas as pd
                except:
                    return messagebox.showerror("Импорт", "Для Excel нужен pandas+openpyxl")
                df = pd.read_excel(path)
                for _,r in df.iterrows():
                    name = str(r.get("name") or r.get("ФИО") or "").strip()
                    pc   = str(r.get("pc_name") or r.get("ПК") or "").strip()
                    ext  = str(r.get("ext") or r.get("internal_number") or r.get("Внутренний номер") or "").strip()
                    if name and pc:
                        users.append({"name":name,"pc_name":pc,"ext":ext}); added+=1
            self.users.users = users; self.users.save(); self.populate_buttons()
            messagebox.showinfo("Импорт", f"Импортировано: {added}")
        except Exception as e:
            messagebox.showerror("Импорт", str(e))

    def export_users(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")], title="Экспорт пользователей")
        if not path: return
        try:
            import csv
            with open(path, "w", encoding="utf-8", newline="") as f:
                w=csv.DictWriter(f, fieldnames=["name","pc_name","ext"]); w.writeheader()
                for u in self.users.get_users(): w.writerow({"name":u.get("name",""),"pc_name":u.get("pc_name",""),"ext":u.get("ext","")})
            messagebox.showinfo("Экспорт", "Готово")
        except Exception as e:
            messagebox.showerror("Экспорт", str(e))

    # --------- Вспомогательные окна ----------
    def show_ip_window(self, ip):
        win = tk.Toplevel(self.master); win.title("IP адрес")
        geom = self.settings.get_setting("ip_window_geometry")
        if geom: win.geometry(geom)
        win.protocol("WM_DELETE_WINDOW", lambda w=win: self._close_save_geo(w,"ip_window_geometry"))
        ttk.Label(win, text="IP адрес: "+ip).pack(pady=10)
        ttk.Button(win, text="Скопировать", command=lambda:self._copy(ip)).pack(pady=6)

    def _copy(self, txt):
        self.master.clipboard_clear(); self.master.clipboard_append(txt)

    # --------- Закрытие ----------
    def on_closing(self):
        if not self._force_exit and self._should_minimize_custom():
            return self.minimize_app()
        self._perform_exit()

    def _perform_exit(self):
        self.master.update_idletasks()
        self.settings.set_setting("window_geometry", self.master.geometry())
        self._hide_tray_icon()
        self._destroy_mini_widget()
        try: self.executor.shutdown(wait=False)
        except: pass
        try:
            self._stop_cw = True
        except:
            pass
        self.master.destroy()

    def exit_app(self):
        self._force_exit = True
        self._perform_exit()

    def _should_minimize_custom(self) -> bool:
        return bool(self.settings.get_setting("minimize_to_tray", False) or self.settings.get_setting("minimize_to_widget", False))

    def _on_unmap(self, _event):
        if self._ignore_unmap:
            return
        if self.master.state() == "iconic" and self._should_minimize_custom():
            self.master.after(50, self.minimize_app)

    def _on_map(self, _event):
        if not self._is_minimized_custom:
            self._destroy_mini_widget()
            self._hide_tray_icon()
        self._mark_activity()

    def minimize_app(self):
        if self._is_minimized_custom or not self._should_minimize_custom():
            return
        self._is_minimized_custom = True
        self._cancel_idle_check()
        self._ignore_unmap = True
        try:
            self.master.withdraw()
        finally:
            self.master.after(150, lambda: setattr(self, "_ignore_unmap", False))
        if self.settings.get_setting("minimize_to_widget", False):
            self._show_mini_widget()
        if self.settings.get_setting("minimize_to_tray", False):
            self._show_tray_icon()
        if not ((self.mini_widget and self.mini_widget.winfo_exists()) or self.tray_icon):
            self._is_minimized_custom = False
            self.master.deiconify()
            self.master.state("normal")
            log_message("Не удалось свернуть: ни виджет, ни трей недоступны")

    def restore_main_window(self):
        self._is_minimized_custom = False
        self._ignore_unmap = True
        try:
            self.master.deiconify()
            self.master.state("normal")
            self.master.lift()
            self.master.focus_force()
        finally:
            self.master.after(150, lambda: setattr(self, "_ignore_unmap", False))
        self._destroy_mini_widget()
        self._hide_tray_icon()
        self._mark_activity()

    def _remember_mini_geometry(self):
        if self.mini_widget and self.mini_widget.winfo_exists():
            try:
                self.settings.set_setting("mini_widget_geometry", self.mini_widget.geometry())
            except Exception:
                pass

    def _destroy_mini_widget(self):
        if getattr(self, "mini_widget", None) and self.mini_widget.winfo_exists():
            try:
                self._remember_mini_geometry()
                self.mini_widget.destroy()
            except Exception:
                pass
        self.mini_widget = None

    def _show_mini_widget(self):
        if getattr(self, "mini_widget", None) and self.mini_widget.winfo_exists():
            return
        widget = tk.Toplevel(self.master)
        self.mini_widget = widget
        widget.overrideredirect(True)
        widget.attributes("-topmost", True)
        try:
            widget.attributes("-alpha", 0.9)
        except Exception:
            pass
        widget.configure(bg="#1f2937")
        geom = self.settings.get_setting("mini_widget_geometry", "")
        if geom:
            try:
                widget.geometry(geom)
            except Exception:
                pass
        else:
            sw, sh = widget.winfo_screenwidth(), widget.winfo_screenheight()
            w, h = 240, 82
            widget.geometry(f"{w}x{h}+{sw - w - 30}+{sh - h - 60}")

        header = tk.Frame(widget, bg="#111827")
        header.pack(fill="x")
        title = tk.Label(header, text=f"{APP_NAME}", fg="#e5e7eb", bg="#111827", font=("Segoe UI", 10, "bold"))
        title.pack(side="left", padx=10, pady=6)
        btn_close = tk.Button(header, text="×", command=self.restore_main_window, bg="#111827", fg="#f3f4f6", relief="flat")
        btn_close.pack(side="right", padx=6, pady=6)
        body = tk.Frame(widget, bg="#1f2937")
        body.pack(fill="both", expand=True)
        tk.Label(body, text="Открыть TS HELP AD", fg="#f9fafb", bg="#1f2937", font=("Segoe UI", 11)).pack(pady=(10,2))
        tk.Button(body, text="Развернуть", command=self.restore_main_window, bg="#2563eb", fg="#f8fafc", relief="flat").pack(pady=(0,10), ipadx=8, ipady=2)

        def start_move(event):
            widget._drag_start_x = event.x
            widget._drag_start_y = event.y

        def do_move(event):
            dx = event.x - getattr(widget, "_drag_start_x", 0)
            dy = event.y - getattr(widget, "_drag_start_y", 0)
            try:
                x = widget.winfo_x() + dx
                y = widget.winfo_y() + dy
                widget.geometry(f"+{x}+{y}")
            except Exception:
                pass

        for el in (widget, header, title, body):
            el.bind("<ButtonPress-1>", start_move)
            el.bind("<B1-Motion>", do_move)
            el.bind("<Double-Button-1>", lambda _e: self.restore_main_window())
        widget.protocol("WM_DELETE_WINDOW", self.restore_main_window)

    def _show_tray_icon(self):
        if self.tray_icon:
            return
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ts-logo.ico")
        tooltip = f"{APP_NAME} {VERSION}"
        dispatcher = (lambda cb: self.master.after(0, cb))
        tray = SimpleSystemTray(icon_path, tooltip, self.restore_main_window, self.exit_app, dispatcher=dispatcher)
        if tray.show():
            self.tray_icon = tray
        else:
            log_message("Трей недоступен: pywin32 не установлен или среда не Windows")

    def _hide_tray_icon(self):
        if not self.tray_icon:
            return
        try:
            self.tray_icon.destroy()
        except Exception as e:
            log_message(f"Ошибка закрытия трея: {e}")
        self.tray_icon = None

    # ----------------- Call Watcher -----------------
    def start_call_watcher(self):
        if not self.settings.get_setting("cw_enabled", True):
            log_message("CallWatcher: отключен в настройках, поток не запущен")
            return

        url = self._normalize_pbx_url(self.settings.get_setting("cw_url", ""))
        if not url:
            log_message("CallWatcher: не задан URL Peers-страницы, слежение не запущено")
            return

        self._stop_cw = False
        t = threading.Thread(target=self._call_watcher_loop, daemon=True)
        t.start()

    def restart_call_watcher_if_needed(self):
        # просто перезапустим, чтобы подхватить новые настр.
        try:
            self._stop_cw = True
        except:
            pass
        self.start_call_watcher()

    def _run_pbx_test(self, url: str, cookie: str, btn: ttk.Button):
        url = (url or "").strip()
        cookie = (cookie or "").strip()

        def finalize(ok: bool, msg: str):
            try:
                btn.config(state="normal", text="Тест")
            except Exception:
                pass
            if ok:
                messagebox.showinfo("Проверка PBX", msg)
            else:
                messagebox.showerror("Проверка PBX", msg)

        def worker():
            try:
                btn.config(state="disabled", text="Тест…")
            except Exception:
                pass
            ok, msg = self._check_pbx_cookie(url, cookie)
            self.master.after(0, lambda: finalize(ok, msg))

        threading.Thread(target=worker, daemon=True).start()

    def _auto_fetch_pbx_cookie(self, url: str, username: str, password: str,
                               entry_cookie: ttk.Entry, btn: ttk.Button):
        url = (url or "").strip()
        username = (username or "").strip()
        password = password or ""

        def finalize(ok: bool, msg: str, new_cookie: str = ""):
            try:
                btn.config(state="normal", text="Получить cookie")
            except Exception:
                pass
            if ok and new_cookie:
                entry_cookie.delete(0, "end")
                entry_cookie.insert(0, new_cookie)
                self.settings.set_setting("cw_cookie", new_cookie)
                self.settings.set_setting("cw_login", username)
                self.settings.set_setting("cw_password", password)
                try:
                    self.restart_call_watcher_if_needed()
                except Exception:
                    pass
                messagebox.showinfo("Cookie PBX", msg)
            else:
                messagebox.showerror("Cookie PBX", msg)

        def worker():
            try:
                btn.config(state="disabled", text="Получение…")
            except Exception:
                pass
            ok, msg, new_cookie = self._login_and_get_cookie(url, username, password)
            self.master.after(0, lambda: finalize(ok, msg, new_cookie or ""))

        threading.Thread(target=worker, daemon=True).start()

    def _normalize_pbx_url(self, url: str) -> str:
        """Удаляет пробелы из URL PBX, чтобы не ломать парсинг."""
        return re.sub(r"\s+", "", url or "")

    def _check_pbx_cookie(self, url: str, cookie: str):
        url = self._normalize_pbx_url(url)
        if not url:
            return False, "Укажите URL Peers-страницы FreePBX"
        try:
            import requests
        except Exception:
            return False, "requests не установлен — тест недоступен"

        headers = {"User-Agent": "TSHelper/PbxTest"}
        if cookie:
            headers["Cookie"] = cookie
            if "=" not in cookie:
                return False, "Cookie должен содержать пары вида PHPSESSID=...; fpbx_admin=..."

        session = requests.Session()
        try:
            resp = session.get(url, headers=headers, timeout=20, allow_redirects=False)
            if resp.status_code in (301,302,303,307,308):
                loc = resp.headers.get("Location", "")
                if "login" in loc.lower():
                    return False, "Редирект на страницу логина — cookie не подошёл"
                resp = session.get(url, headers=headers, timeout=20)

            if resp.status_code != 200:
                return False, f"HTTP {resp.status_code} при обращении к PBX"

            if looks_like_login(resp.text):
                return False, "Похоже на форму логина — проверьте cookie"

            return True, "Страница PBX открывается, cookie принят"
        except Exception as e:
            return False, f"Ошибка запроса: {e}"

    def _build_pbx_login_url(self, peers_url: str) -> str:
        parsed = urllib.parse.urlsplit(self._normalize_pbx_url(peers_url))
        base_path = parsed.path.rsplit("/", 1)[0] if parsed.path else "/admin"
        if not base_path:
            base_path = "/admin"
        login_path = base_path.rstrip("/") + "/config.php"
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, login_path, "", ""))

    def _extract_pbx_token(self, html: str):
        m = re.search(r'name\s*=\s*"(?P<name>[\w:-]*token[\w:-]*)"[^>]*value\s*=\s*"(?P<val>[^"]+)"', html, flags=re.I)
        if m:
            return m.group("name"), m.group("val")
        m2 = re.search(r'name\s*=\s*"__csrf_magic"[^>]*value\s*=\s*"(?P<val>[^"]+)"', html, flags=re.I)
        if m2:
            return "__csrf_magic", m2.group("val")
        return None, None

    def _login_and_get_cookie(self, url: str, username: str, password: str):
        url = self._normalize_pbx_url(url)
        if not url:
            return False, "Укажите URL Peers-страницы FreePBX", None
        if not username or not password:
            return False, "Укажите логин и пароль FreePBX", None
        try:
            import requests
        except Exception:
            return False, "requests не установлен — автоподхват недоступен", None
        login_url = self._build_pbx_login_url(url)
        timeout = 20
        session = requests.Session()
        headers = {"User-Agent": "TSHelper/PbxLogin"}
        try:
            page = session.get(login_url, headers=headers, timeout=timeout)
        except Exception as e:
            return False, f"Ошибка открытия страницы логина: {e}", None

        token_name, token_val = self._extract_pbx_token(page.text)
        payload = {"username": username, "password": password, "submit": "Login"}
        if token_name and token_val:
            payload[token_name] = token_val

        try:
            resp = session.post(login_url, headers=headers, data=payload, timeout=timeout, allow_redirects=True)
        except Exception as e:
            return False, f"Ошибка авторизации: {e}", None

        if looks_like_login(resp.text):
            return False, "Не удалось авторизоваться в PBX — проверьте логин/пароль", None

        cookie_str = "; ".join([f"{c.name}={c.value}" for c in session.cookies if c.value])
        if not cookie_str:
            return False, "PBX не вернул cookie", None

        log_message("CallWatcher: cookie обновлена автоматически")
        return True, "Cookie получена и сохранена", cookie_str


    def _call_watcher_loop(self):
        import requests
        url     = self._normalize_pbx_url(self.settings.get_setting("cw_url", ""))
        if not url:
            log_message("CallWatcher: URL не задан, выходим из цикла")
            return
        cookie  = self.settings.get_setting("cw_cookie","").strip()
        if cookie and "=" not in cookie:
            log_message("CallWatcher: Cookie выглядит как голый ID. Нужна полная строка: 'PHPSESSID=...; fpbx_admin=...'.")
        interval= max(1, int(self.settings.get_setting("cw_interval", 2)))
        popup_on= bool(self.settings.get_setting("cw_popup", True))
        exts_raw= self.settings.get_setting("cw_exts","4444")
        watch_exts = list(dict.fromkeys([x.strip() for x in exts_raw.split(",") if x.strip()]))

        headers = {"User-Agent":"TSHelper/CallWatch"}
        if cookie: headers["Cookie"] = cookie
        session = requests.Session()

        seen, seen_ttl, dup_ttl = set(), {}, 25
        def gc_seen():
            now = time.time()
            for k, t in list(seen_ttl.items()):
                if t < now:
                    seen.discard(k); seen_ttl.pop(k, None)

        def normalize_caller(num: str, name: str):
            num_clean = (num or "").strip()
            if num_clean.lower() == "unknown":
                num_clean = ""
            name_clean = (name or "").strip()
            who_key = norm_name(name_clean) if name_clean else (num_clean or "unknown")
            return num_clean, name_clean, who_key

        def split_lines_context(text, ext, radius=8):
            """Возвращает окно строк вокруг первой строки с Exten:<ext>."""
            lines = text.splitlines()
            for i, ln in enumerate(lines):
                if re.search(rf"\bExten:\s*{re.escape(ext)}\b", ln):
                    lo = max(0, i - radius); hi = min(len(lines), i + radius + 1)
                    return "\n".join(lines[lo:hi])
            return ""

        while not getattr(self, "_stop_cw", False):
            try:
                gc_seen()
                r = session.get(url, headers=headers, timeout=12, allow_redirects=False)
                if r.status_code in (301,302,303,307,308):
                    loc = r.headers.get("Location","")
                    if "login" in loc.lower():
                        log_message("CallWatcher: редирект на логин — проверь Cookie")
                        time.sleep(interval); continue
                    r = session.get(url, headers=headers, timeout=12)

                if r.status_code != 200:
                    log_message(f"CallWatcher HTTP {r.status_code}")
                    time.sleep(interval); continue

                html = r.text
                if looks_like_login(html):
                    log_message("CallWatcher: страница логина — проверь Cookie")
                    time.sleep(interval); continue

                # сохраняем сырой html и плейн
                _pbx_dump("peers_raw.html", html)
                text = html_unwrap(html)
                _pbx_dump("peers_plain.txt", text)
                _pbx_dump("peersplain.txt", text)


                active_now = set()

                for ext in watch_exts:
                    block = extract_block_for_ext(text, ext)
                    if block:
                        _pbx_dump(f"endpoint_block_{ext}.txt", block)

                    with self.calls_lock:
                        prev_call = next((c for c in self.active_calls if c.get("ext") == ext), None)

                    block_active = is_block_active(block, ext)
                    caller = parse_caller_from_block(block, ext) if block_active and block else None

                    if not caller and block_active:
                        # строгий построчный резервный поиск ВОКРУГ Exten:<ext>
                        window = split_lines_context(text, ext, radius=10)
                        if window:
                            m = re.search(r'CLCID:\s*"(?P<name>.+?)"\s*<(?P<num>[^>]+)>', window)
                            if m:
                                caller = (m.group("num").strip(), m.group("name").strip())
                            else:
                                # альтернатива: CLCID только с именем, номер берём из CallerIDNum
                                mname = re.search(r'CLCID:\s*"(?P<name>.+?)"', window)
                                mnum  = re.search(r'CallerIDNum:\s*(.+)', window)
                                if mname or mnum:
                                    caller = ((mnum.group(1).strip() if mnum else ""), (mname.group(1).strip() if mname else ""))

                    if block_active and not caller and prev_call:
                        caller = (prev_call.get("num", ""), prev_call.get("name", ""))
                        prev_who_key = prev_call.get("who_key") or ""
                    else:
                        prev_who_key = prev_call.get("who_key") if prev_call else ""

                    if block_active and caller:
                        raw_num, raw_name = caller
                        num, name, who_key = normalize_caller(raw_num, raw_name)
                        who_key = who_key or prev_who_key or f"ext-{ext}"
                        who = (num or "unknown") + (f" ({name})" if name else "")
                        key = f"{ext}|{who_key}|{int(time.time()/dup_ttl)}"
                        active_now.add((ext, who_key))
                        if key not in seen:
                            seen.add(key); seen_ttl[key] = time.time() + dup_ttl
                            log_call(f"Звонок на {ext} от {who}")

                            matched_user = self._match_user_by_caller(name, num)

                            # 1) показать сверху
                            with self.calls_lock:
                                self.active_calls = [
                                    c for c in self.active_calls
                                    if not (c.get("ext") == ext and c.get("who_key") == who_key)
                                ]
                                started_ts = prev_call.get("ts") if prev_call else time.time()
                                self.active_calls.insert(0, {
                                    "ext": ext,
                                    "num": num or "",
                                    "name": name or "",
                                    "ts": started_ts,
                                    "user": matched_user,
                                    "who_key": who_key,
                                })
                            self.master.after(0, self.refresh_current_view)

                            # 2) всплывашка
                            if popup_on:
                                self.master.after(0, lambda e=ext, w=who: self._popup(f"Звонок на {e}", w))

                with self.calls_lock:
                    now_ts = time.time()
                    original_calls = list(self.active_calls)
                    filtered_calls = [
                        c for c in self.active_calls
                        if (c.get("ext"), c.get("who_key")) in active_now and now_ts - c["ts"] < self.calls_ttl
                    ]
                    ended_calls = [c for c in original_calls if c not in filtered_calls]
                    self.active_calls = filtered_calls

                for c in ended_calls:
                    duration = int(now_ts - c.get("ts", now_ts))
                    who = (c.get("num") or "unknown") + (f" ({c.get('name')})" if c.get("name") else "")
                    log_call(f"Звонок завершён на {c.get('ext')}: {who}, длительность ~{duration} c")

                if ended_calls:
                    self.master.after(0, self.refresh_current_view)

            except Exception as e:
                log_message(f"CallWatcher error: {e}")

            time.sleep(interval)


    # ---- попап без внешних библиотек (tkinter) ----
    def _popup(self, title: str, message: str, duration=6):
        # компактное окно в правом нижнем углу
        win = tk.Toplevel(self.master)
        win.overrideredirect(True)
        win.attributes("-topmost", True)

        frm = tk.Frame(win, bd=1, relief="solid", bg="white")
        frm.pack(padx=1, pady=1)
        tk.Label(frm, text=title, font=("Segoe UI", 11, "bold"), bg="white").pack(padx=10, pady=(10,0))
        tk.Label(frm, text=message, font=("Segoe UI", 10), bg="white", justify="left").pack(padx=10, pady=(2,10))

        self.master.update_idletasks(); win.update_idletasks()
        sw, sh = self.master.winfo_screenwidth(), self.master.winfo_screenheight()
        ww, wh = win.winfo_width(), win.winfo_height()
        win.geometry(f"+{sw-ww-20}+{sh-wh-40}")
        win.after(int(duration*1000), win.destroy)

# --- Кнопка пользователя ---
class UserButton(ttk.Frame):
    def __init__(self, master, user, app: MainWindow, style_name=None, caller=None, show_status=False):
        super().__init__(master)
        self.user = user
        self.app  = app
        self.avail = None
        self.status_key = "offline"
        self.caller_info = caller
        self.show_status = show_status
        self.status_image = None

        pc_label = self.app.get_display_pc_name(user['pc_name'])
        # создаём tk.Button, чтобы гарантированно красить
        self.btn = tk.Button(
            self,
            text=self._compose_text(pc_label),
            bg=self.app.user_bg, fg=self.app.user_fg,
            activebackground=self.app.user_bg, activeforeground=self.app.user_fg,
            relief="groove", bd=2, justify="left", wraplength=180, anchor="nw",
            command=self._show_menu
        )
        self.btn.pack(fill="both", expand=True)
        self.set_status(self.status_key)
        self._apply_caller_style()
        self.btn.bind("<Button-3>", self._rclick)

    def refresh_colors(self):
        self.btn.configure(
            bg=self.app.user_bg, fg=self.app.user_fg,
            activebackground=self.app.user_bg, activeforeground=self.app.user_fg
        )

    def set_status(self, status_key: str):
        """Запоминаем статус и перерисовываем текст/стиль."""
        self.status_key = status_key
        pc_label = self.app.get_display_pc_name(self.user["pc_name"])
        self.btn.config(text=self._compose_text(pc_label))
        self._apply_caller_style()

    def set_caller(self, caller):
        """Переключает карточку в режим звонка или обратно без пересоздания виджета."""
        self.caller_info = caller
        pc_label = self.app.get_display_pc_name(self.user["pc_name"])
        self.btn.config(text=self._compose_text(pc_label))
        self._apply_caller_style()

    def set_availability(self, ok, searching=False):
        self.avail = ok
        pc_label = self.app.get_display_pc_name(self.user["pc_name"])

        if searching:
            # пока идёт проверка доступности
            self.set_status("checking")
        else:
            # результат проверки: онлайн или оффлайн
            self.set_status("online" if ok else "offline")

        self.btn.config(text=self._compose_text(pc_label))
        self._apply_caller_style()


    def _status_label(self) -> str:
        return {"online": "Онлайн", "offline": "Оффлайн", "checking": "Проверка"}.get(self.status_key, "")

    def _compose_text(self, pc_label: str) -> str:
        ext = (self.user.get("ext") or "").strip()
        label = self._status_label() if self.show_status else ""
        label_prefix = f"{label} " if label else ""

        if ext:
            # первая строка: Онлайн • 📞 4588
            header = f"{label_prefix}• 📞 {ext}" if label_prefix else f"📞 {ext}"
            base = f"{header}\n{self.user['name']}\n({pc_label})"
        else:
            # без телефона — Онлайн ФИО
            header = f"{label_prefix}{self.user['name']}"
            base = f"{header}\n({pc_label})"

        # если нет активного звонка — возвращаем обычный текст карточки
        if not self.caller_info:
            return base

        # режим звонка: сверху инфа о звонке, снизу та же карточка со статусом
        num = self.caller_info.get("num") or "unknown"
        name = self.caller_info.get("name") or ""
        ext_target = self.caller_info.get("ext") or "?"
        who = f"\nЗвонит: {name}" if name else ""
        return f"📞 {num} → {ext_target}{who}\n{base}"


    def _status_image_for_key(self):
        if not self.show_status:
            return None
        return self.app.status_icons.get(self.status_key)

    def _apply_caller_style(self):
        pc_label = self.app.get_display_pc_name(self.user["pc_name"])
        if self.caller_info:
            gradient = self._make_gradient_image(220, 90, self.app.caller_bg, "#f97316")
            self.btn.config(
                bg=self.app.caller_bg,
                fg=self.app.caller_fg,
                activebackground=self.app.caller_bg,
                activeforeground=self.app.caller_fg,
                highlightthickness=2,
                highlightbackground="#fb923c",
                highlightcolor="#fb923c",
                relief="solid",
                bd=2,
                font=("Segoe UI", 10, "bold"),
                image=gradient,
                compound="center",
                wraplength=200,
                justify="center",
                text=self._compose_text(pc_label),
            )
            self.btn.gradient = gradient
            self.btn.image = gradient
            self.status_image = None
        else:
            # обычный режим — текст и, при поиске, цветной статус-иконкой
            status_image = self._status_image_for_key()
            self.btn.config(
                bg=self.app.user_bg,
                fg=self.app.user_fg,
                activebackground=self.app.user_bg,
                activeforeground=self.app.user_fg,
                highlightthickness=0,
                relief="groove",
                bd=2,
                font=("Segoe UI", 10),
                image=status_image or "",
                compound="left",
                anchor="nw",
                padx=8,
                pady=4,
                wraplength=190,
                justify="left",
                text=self._compose_text(pc_label),
            )
            self.btn.gradient = None
            self.btn.image = status_image
            self.status_image = status_image

    def _make_gradient_image(self, width: int, height: int, start_color: str, end_color: str):
        img = tk.PhotoImage(width=width, height=height)

        def hex_to_rgb(h: str):
            h = h.lstrip('#')
            return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

        def rgb_to_hex(rgb):
            return "#%02x%02x%02x" % rgb

        start_rgb = hex_to_rgb(start_color)
        end_rgb = hex_to_rgb(end_color)
        for y in range(height):
            ratio = y / max(1, height - 1)
            line_rgb = tuple(int(start_rgb[i] + (end_rgb[i] - start_rgb[i]) * ratio) for i in range(3))
            line_hex = rgb_to_hex(line_rgb)
            img.put(line_hex, to=(0, y, width, y+1))
        return img

    def _show_menu(self):
        m = tk.Menu(self, tearoff=0)
        if self.user.get("pc_options"):
            pc_menu = tk.Menu(m, tearoff=0)
            all_pcs = [self.user.get("pc_name", "")] + list(self.user.get("pc_options", []))
            for pc in all_pcs:
                label = pc
                if pc.lower() == self.user.get("pc_name", "").lower():
                    label += " (текущий)"
                pc_menu.add_command(label=label, command=lambda p=pc: self._switch_pc(p))
            m.add_cascade(label="ПК", menu=pc_menu)
            m.add_separator()
        m.add_command(label="RDP", command=self.rdp_connect)
        m.add_command(label="Удаленный помощник", command=self.remote_assistance)
        m.add_command(label="Проводник (C$)", command=self.open_explorer)
        m.add_command(label="Получить IP", command=self.get_ip)
        m.add_command(label="Открыть в AD", command=self.open_in_ad)
        m.add_command(label="Открыть в GLPI", command=self.open_glpi)
        m.add_separator()
        m.add_command(label="Сброс пароля pak", command=lambda: self.reset_password_ps("pak"))
        m.add_command(label="Сброс пароля omg", command=lambda: self.reset_password_ps("omg"))
        m.add_separator()
        m.add_command(label="Подключение по SSH", command=self.open_ssh_connection)
        m.add_separator()
        m.add_command(label="Редактировать", command=lambda: self.app.open_edit_window(self.user))
        m.add_command(label="Удалить", command=lambda: self.app.delete_user_from_button(self.user))
        x = self.winfo_rootx(); y = self.winfo_rooty()+self.winfo_height()
        m.post(x,y)

    def _rclick(self, _e): self._show_menu()
    # … дальше методы действий без изменений (rdp_connect, remote_assistance, open_explorer, get_ip, reset_password_ps, open_ssh_connection)


    def _switch_pc(self, pc):
        if not pc or pc.lower() == self.user.get("pc_name", "").lower():
            return
        old_pc = self.user.get("pc_name", "")
        new_user = dict(self.user)
        new_user["pc_name"] = pc
        new_user["pc_options"] = self.app._merge_pc_options(pc, self.user.get("pc_options", []), [old_pc])

        self.app.users.update_user(old_pc, new_user)
        self.user.update(new_user)
        self.app.rebind_user_widget_key(old_pc, pc, self)
        self.app.refresh_current_view()
        log_action(f"Выбран основной ПК {self.user.get('name','?')}: {old_pc} -> {pc}")


    # --- Actions ---
    def _log_action(self, action: str):
        pc_label = self.app.get_display_pc_name(self.user.get("pc_name", "?"))
        log_action(f"{self.user.get('name', '?')} ({pc_label}): {action}")

    def rdp_connect(self):
        try:
            self._log_action("Открыт RDP")
            if is_windows():
                subprocess.Popen(["mstsc","/v", self.user["pc_name"]], creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception as e:
            messagebox.showerror("RDP", str(e))

    def remote_assistance(self):
        try:
            self._log_action("Открыт удалённый помощник")
            if is_windows():
                run_as_admin("msra.exe", "/offerRA "+self.user["pc_name"])
        except Exception as e:
            messagebox.showerror("Удаленный помощник", str(e))

    def open_explorer(self):
        try:
            self._log_action("Открыт проводник C$")
            os.startfile(f"\\\\{self.user['pc_name']}\\c$")
        except Exception as e:
            messagebox.showerror("Проводник", str(e))

    def open_glpi(self):
        try:
            last_name = self.user["name"].split()[0]
        except Exception:
            return messagebox.showerror("GLPI", "Не удалось определить фамилию пользователя")
        if not last_name:
            return messagebox.showerror("GLPI", "Не удалось определить фамилию пользователя")
        url = f"https://inv.pak-cspmz.ru/front/search.php?globalsearch={urllib.parse.quote(last_name)}"
        self._log_action("Открыт профиль в GLPI")
        webbrowser.open(url)

    def open_in_ad(self):
        self._log_action("Открыт ADHelper")
        self.app.open_in_ad(self.user)

    def get_ip(self):
        def task():
            candidates = self.app.build_host_candidates(self.user) or [self.user.get("pc_name", "")]
            default_host = candidates[0] if candidates else self.user.get("pc_name", "")
            found_host = ""
            found_ip = ""

            log_message(f"Получение IP для {self.user.get('name','?')}: кандидаты {', '.join(candidates)}")
            for host in candidates:
                ok, ip = self.app.ping_host_with_ip(host)
                log_message(f"Проверка {host}: {'онлайн' if ok else 'недоступен'}, IP: {ip or 'не определён'}")
                if ok:
                    found_host, found_ip = host, ip
                    break
                if not found_ip and ip:
                    found_ip = ip

            ip_value = found_ip or "Не найден"

            def finalize():
                self.app.show_ip_window(ip_value)
                source = found_host or default_host or "?"
                self._log_action(f"Запрошен IP: {source} -> {ip_value}")

                current_pc = self.user.get("pc_name", "")
                if found_host and found_host.lower() != current_pc.lower():
                    msg = (
                        f"По основному имени {current_pc or 'не задано'} ответ не получен. "
                        f"Доступен хост {found_host}. Переключить пользователя на него?"
                    )
                    if messagebox.askyesno("Обновить имя ПК", msg):
                        old_pc = self.user.get("pc_name", "")
                        self._switch_pc(found_host)
                        log_action(f"Обновлён основной ПК для {self.user.get('name','?')}: {old_pc} -> {found_host}")

            self.app.master.after(0, finalize)
        threading.Thread(target=task, daemon=True).start()

    def reset_password_ps(self, which):
        new_pw = self.app.settings.get_setting("reset_password","12340987")
        sam, _ = self.app.normalize_pc_name(self.user["pc_name"])
        domain_map = {
            "pak": "pak-cspmz.ru",
            "omg": "omg.cspfmba.ru",
        }
        target_domain = domain_map.get(which)
        if not target_domain:
            return messagebox.showerror("Сброс пароля", f"Неизвестный домен: {which}")

        sam_escaped = sam.replace("'", "''")
        new_pw_escaped = str(new_pw).replace("'", "''")

        script = f"""
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$user = Get-ADUser -Filter "SamAccountName -eq '{sam_escaped}'" -Server '{target_domain}'
if (-not $user) {{ throw "Пользователь не найден: {sam_escaped}" }}
Set-ADAccountPassword -Identity $user.SamAccountName -Server '{target_domain}' -Reset -NewPassword (ConvertTo-SecureString -AsPlainText '{new_pw_escaped}' -Force)
Unlock-ADAccount -Identity $user.SamAccountName -Server '{target_domain}' -ErrorAction SilentlyContinue
Set-ADUser -Identity $user.SamAccountName -Server '{target_domain}' -ChangePasswordAtLogon $true
Write-Output "OK"
""".strip()

        cmd = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command", script,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            out = (result.stdout or "").strip()
            err = (result.stderr or "").strip()

            log_message(
                f"Сброс пароля {which}: rc={result.returncode}; user={sam}; domain={target_domain}; "
                f"stdout={out or '-'}; stderr={err or '-'}"
            )

            if result.returncode == 0:
                messagebox.showinfo("Сброс пароля", f"Успешно: {self.user['name']} ({which.upper()}).")
                self._log_action(f"Сброшен пароль ({which})")
            else:
                details = err or out or "Неизвестная ошибка PowerShell"
                messagebox.showerror("Сброс пароля", f"Ошибка ({which}):\n{details}")
        except Exception as e:
            log_message(f"Сброс пароля {which}: исключение {e}")
            messagebox.showerror("Сброс пароля", str(e))

    def open_ssh_connection(self):
        ssh_login = self.app.settings.get_setting("ssh_login","")
        ssh_password = self.app.settings.get_setting("ssh_password","")
        if not ssh_login:
            return messagebox.showerror("SSH", "Не задан SSH Login в настройках")
        candidates = self.app.build_host_candidates(self.user)
        if not candidates:
            return messagebox.showerror("SSH", "Не удалось определить имя хоста")
        preferred = candidates[0]
        resolved_host = ""
        resolved_ip = ""
        for host in candidates:
            ip = self.app.resolve_ip(host)
            if ip:
                resolved_host, resolved_ip = host, ip
                break

        target_host = resolved_host or preferred
        ssh_target = target_host
        if resolved_host and resolved_host.lower() != preferred.lower() and resolved_ip:
            ssh_target = resolved_ip
            log_message(f"SSH: имя {preferred} не разрешилось, используем IP {resolved_ip} от {resolved_host}")
        elif not resolved_host and resolved_ip:
            ssh_target = resolved_ip
        elif not resolved_host:
            log_message(f"SSH: ни одно из имён ({', '.join(candidates)}) не разрешилось, пробуем {ssh_target}")
        term = self.app.settings.get_setting("ssh_terminal","Windows Terminal")
        auto = self.app.settings.get_setting("ssh_pass_enabled", False)

        try:
            if term == "Windows Terminal":
                if auto: cmd = f'sshpass -p "{ssh_password}" ssh {ssh_login}@{ssh_target}'
                else:    cmd = f'ssh -o StrictHostKeyChecking=accept-new {ssh_login}@{ssh_target}'
                subprocess.Popen(["wt.exe","-p","Ubuntu","ubuntu.exe","-c",cmd])
            elif term in ("CMD","PowerShell"):
                if auto:
                    hostkeys = self.app.settings.config.get("plink_hostkeys", {})
                    hk = hostkeys.get(target_host.lower())
                    if hk:
                        plink_cmd = f'plink.exe -ssh -batch -hostkey "{hk}" -pw "{ssh_password}" {ssh_login}@{ssh_target}'
                    else:
                        plink_cmd = f'plink.exe -ssh -batch -pw "{ssh_password}" {ssh_login}@{ssh_target}'
                    if term=="CMD": subprocess.Popen(["cmd.exe","/k", plink_cmd])
                    else:           subprocess.Popen(["powershell","-NoExit","-Command", plink_cmd])
                else:
                    ssh_cmd = f'ssh -o StrictHostKeyChecking=accept-new {ssh_login}@{ssh_target}'
                    if term=="CMD": subprocess.Popen(["cmd.exe","/k", ssh_cmd])
                    else:           subprocess.Popen(["powershell","-NoExit","-Command", ssh_cmd])
            else:
                messagebox.showerror("SSH","Неизвестный терминал")
            self._log_action(f"Открыт SSH через {term} ({ssh_target})")
        except Exception as e:
            messagebox.showerror("SSH", str(e))

# --- main ---
if __name__ == "__main__":
    try:
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
    except: pass

    app_root = tb.Window() if USE_BOOTSTRAP else tk.Tk()
    app = MainWindow(app_root)
    app_root.mainloop()
