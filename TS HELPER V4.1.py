# TS HELP AD — v4.1 (all-in-one + CallWatcher)
# Требуется: Python 3.9+, Windows
# Доп. пакеты (необязательно): ttkbootstrap, requests, pypiwin32
# pip install requests ttkbootstrap pypiwin32

import os, sys, json, re, time, threading, queue, subprocess, platform, shutil, webbrowser, locale, datetime, base64, urllib.parse, uuid, importlib, glob, socket
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, colorchooser
from concurrent.futures import ThreadPoolExecutor

# --- Версия приложения ---
VERSION = "v4.1"

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


def _import_requests_optional():
    try:
        import requests
        return requests, None
    except ImportError:
        return None, "requests не установлен"


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
    if not active: return None
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
        self.config = load_json(path, default={
            "window_geometry":"1100x720+200+100",
            "edit_window_geometry":"", "settings_window_geometry":"", "ad_sync_select_geometry":"", "ip_window_geometry":"",
            # AD creds
            "ad_username":"", "ad_password":"",
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
        })
        self.secret_storage = SecretStorage(APP_NAME)
        self._secret_keys = {"ad_password", "ssh_password", "reset_password", "cw_password", "glpi_app_token", "glpi_user_token"}

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

        # стили (переопределяются при изменении настроек)
        self.style = ttk.Style(self.master)
        self._apply_button_styles()

        # иконки статусов
        self.status_icons = self._build_status_icons()

        self.users = UserManager(USERS_FILE)
        self.executor = ThreadPoolExecutor(max_workers=24)
        self.buttons = {}
        self.search_job = None
        self.ping_generation = 0

        # активные звонки (список словарей)
        self.active_calls = []   # [{ext, num, name, ts, user, who_key}]
        self.calls_lock = threading.Lock()
        self.calls_ttl = 90      # сек держим вверху

        self.build_ui()
        self.populate_buttons()

        # Перестраивать сетку при изменении ширины (чтоб не «в столбик»)
        self._last_cols = None
        self.canvas.bind("<Configure>", self._on_canvas_resize)

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

        # center scrollable
        mid = ttk.Frame(self.master, padding=(10,0)); mid.pack(side="top", fill="both", expand=True)
        self.canvas = tk.Canvas(mid, highlightthickness=0)
        vs = ttk.Scrollbar(mid, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.canvas, bg=self.board_bg)
        self.canvas_window = self.canvas.create_window((0,0), window=self.inner, anchor="nw")

        self.inner.bind("<Configure>", self._update_scrollregion)
        self._bind_mousewheel()

        # bottom
        bottom = ttk.Frame(self.master, padding=10); bottom.pack(side="bottom", fill="x")
        ttk.Button(bottom, text="Добавить", command=self.add_user).pack(side="left", padx=5)
        ttk.Button(bottom, text="AD Sync", command=self.ad_sync).pack(side="left", padx=5)
        ttk.Button(bottom, text="GLPI Sync", command=self.glpi_prefix_sync).pack(side="left", padx=5)
        self.count_lbl = ttk.Label(bottom, text="Найдено аккаунтов: 0"); self.count_lbl.pack(side="right")

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
            self.populate_buttons()  # перестраиваем сетку только при реальном изменении числа колонок



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

    def populate_buttons(self, items=None):
        for w in self.inner.winfo_children(): w.destroy()
        all_users = self.users.get_users() if items is None else items

        # 1) Активные звонки вверху (сортируем по времени убыв.)
        with self.calls_lock:
            now = time.time()
            self.active_calls = [c for c in self.active_calls if now - c["ts"] < self.calls_ttl]
            callers = sorted(self.active_calls, key=lambda c: c["ts"], reverse=True)

        caller_by_pc = {}
        orphan_calls = []
        for call in callers:
            user = call.get("user")
            pc_name = user.get("pc_name") if user else None
            if pc_name:
                caller_by_pc[pc_name] = call
            else:
                orphan_calls.append(call)

        self.buttons = {}
        cols = self._compute_cols()
        r=c=0

        # 2) Пользователи (отсортированы по ФИО)
        items_sorted = sorted(all_users, key=lambda u: locale.strxfrm(u["name"]))

        # приоритет звонящих пользователей — сначала по порядку звонков, потом остальные
        prioritized = []
        seen_pcs = set()
        for call in callers:
            user = call.get("user")
            pc = user.get("pc_name") if user else None
            if pc and pc not in seen_pcs:
                seen_pcs.add(pc)
                prioritized.append(pc)
        ordered_users = []
        for pc in prioritized:
            u = next((item for item in items_sorted if item.get("pc_name") == pc), None)
            if u:
                ordered_users.append(u)
        for u in items_sorted:
            if u.get("pc_name") not in seen_pcs:
                ordered_users.append(u)

        for u in ordered_users:
            caller = caller_by_pc.get(u.get("pc_name"))
            btn = UserButton(self.inner, u, app=self, style_name="User.TButton", caller=caller)
            btn.grid(row=r, column=c, padx=6, pady=6, sticky="nsew")
            self.buttons[u["pc_name"]] = btn
            c += 1
            if c >= cols: c = 0; r += 1

        # если звонок не удалось сопоставить с пользователем — показываем отдельной карточкой
        for call in orphan_calls:
            b = tk.Button(
                self.inner,
                text=f"📞 {call['num'] or 'unknown'}\n{('(' + call['name'] + ')') if call['name'] else ''}\n→ {call['ext']}",
                bg=self.caller_bg, fg=self.caller_fg, activebackground=self.caller_bg, activeforeground=self.caller_fg,
                relief="ridge", bd=2, justify="center", wraplength=180
            )
            b.grid(row=r, column=c, padx=6, pady=6, sticky="nsew")
            c += 1
            if c >= cols: c = 0; r += 1

        self.count_lbl.config(text=f"Найдено аккаунтов: {len(items_sorted)}")

        cols = self._compute_cols()
        # растянуть колонки – кнопки займут всю ширину, «зазора» не останется
        for i in range(cols):
            self.inner.grid_columnconfigure(i, weight=1)

        self._update_scrollregion()


    # --------- Поиск ----------
    def update_search(self, _=None):
        if self.search_job: self.master.after_cancel(self.search_job)
        self.search_job = self.master.after(250, self._do_search)

    def _do_search(self):
        text = self.search_entry.get().lower()
        allu = self.users.get_users()
        filtered = [
            u for u in allu
            if text in u["name"].lower()
            or text in u["pc_name"].lower()
            or text in str(u.get("ext", "")).lower()
        ]
        self.populate_buttons(filtered)
        if len(text) >= 3:
            self.ping_generation += 1
            gen = self.ping_generation
            for u in filtered:
                btn = self.buttons.get(u["pc_name"])
                if btn:
                    btn.set_status("checking")
                self.executor.submit(self._ping_task, u["pc_name"], gen)

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
            self.users.add_user({"name":n,"pc_name":p,"ext":ext}); self.populate_buttons(); self._close_save_geo(win,"edit_window_geometry")
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
            self.users.update_user(user["pc_name"], {"name":n,"pc_name":p,"ext":ext}); self.populate_buttons(); self._close_save_geo(win,"edit_window_geometry")
        ttk.Button(win, text="Сохранить", command=save).pack(pady=8)

    def delete_user_from_button(self, user):
        if messagebox.askyesno("Удалить", f"Удалить {user['name']}?"):
            self.users.delete_user(user["pc_name"]); self.populate_buttons()

    # --------- AD sync ----------
    def _extract_login(self, pc_name: str) -> str:
        if not pc_name:
            return ""
        pc = pc_name.strip()
        return pc.split("-",1)[1] if "-" in pc else pc

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
            self.settings.set_setting("ad_username", e_user.get().strip())
            self.settings.set_setting("ad_password", e_pass.get().strip())
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
            self.populate_buttons()

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
        self.master.update_idletasks()
        self.settings.set_setting("window_geometry", self.master.geometry())
        try: self.executor.shutdown(wait=False)
        except: pass
        try:
            self._stop_cw = True
        except:
            pass
        self.master.destroy()

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
                    caller = parse_caller_from_block(block, ext) if block else None

                    if not caller:
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

                    if caller:
                        raw_num, raw_name = caller
                        num, name, who_key = normalize_caller(raw_num, raw_name)
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
                                self.active_calls.insert(0, {
                                    "ext": ext,
                                    "num": num or "",
                                    "name": name or "",
                                    "ts": time.time(),
                                    "user": matched_user,
                                    "who_key": who_key,
                                })
                            self.master.after(0, self.populate_buttons)

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
                    self.master.after(0, self.populate_buttons)

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
    def __init__(self, master, user, app: MainWindow, style_name=None, caller=None):
        super().__init__(master)
        self.user = user
        self.app  = app
        self.avail = None
        self.status_key = "offline"
        self.caller_info = caller

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
        self.status_key = status_key
        icon = self.app.status_icons.get(status_key)
        if self.caller_info:
            # в режиме звонка статус показываем текстовым маркером
            self.btn.config(image="", compound="center", pady=6)
            self.btn.image = None
        elif icon:
            self.btn.config(image=icon, compound="left", padx=8, pady=4, anchor="nw")
            self.btn.image = icon
        else:
            self.btn.config(image="", compound="center", anchor="center", pady=0)
            self.btn.image = None
        self._apply_caller_style()

    def set_availability(self, ok, searching=False):
        self.avail = ok
        pc_label = self.app.get_display_pc_name(self.user["pc_name"])
        status_key = "online" if ok else "offline"
        self.set_status(status_key if searching else self.status_key)
        self.btn.config(text=self._compose_text(pc_label))
        self._apply_caller_style()

    def _status_marker(self) -> str:
        return {"online": "🟢", "offline": "⚫", "checking": "🟡"}.get(self.status_key, "")

    def _compose_text(self, pc_label: str) -> str:
        ext = (self.user.get("ext") or "").strip()
        if ext:
            header = f"📞 {ext}"
            indent = " " * (len(ext) + 3)  # отступ под заголовок с телефоном
            base = f"{header}\n{indent}{self.user['name']}\n{indent}({pc_label})"
        else:
            base = f"{self.user['name']}\n({pc_label})"

        if not self.caller_info:
            return base

        num = self.caller_info.get("num") or "unknown"
        name = self.caller_info.get("name") or ""
        ext_target = self.caller_info.get("ext") or "?"
        who = f"\nЗвонит: {name}" if name else ""
        marker = self._status_marker()
        marker_prefix = f"{marker} " if marker else ""
        return f"📞 {num} → {ext_target}{who}\n{marker_prefix}{base}"

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
                text=self._compose_text(pc_label)
            )
            self.btn.gradient = gradient
        else:
            self.btn.config(
                bg=self.app.user_bg,
                fg=self.app.user_fg,
                activebackground=self.app.user_bg,
                activeforeground=self.app.user_fg,
                highlightthickness=0,
                relief="groove",
                bd=2,
                font=("Segoe UI", 10),
                image=self.app.status_icons.get(self.status_key),
                compound="left",
                anchor="nw",
                padx=8,
                pady=4,
                wraplength=190,
                justify="left",
                text=self._compose_text(pc_label)
            )
            self.btn.gradient = None

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
        self.app.populate_buttons()
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
        script = f"""
Import-Module ActiveDirectory;
$user = Get-ADUser -Filter "SamAccountName -eq '{sam}'";
if (-not $user) {{ Write-Error 'User not found'; exit 1 }}
Set-ADAccountPassword $user.SamAccountName -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "{new_pw}" -Force) -PassThru | Out-Null;
Unlock-ADAccount -Identity $user.SamAccountName -ErrorAction SilentlyContinue;
Set-ADUser -Identity $user.SamAccountName -ChangePasswordAtLogon $true -ErrorAction SilentlyContinue;
Write-Output "OK";
"""
        if which == "omg":
            script = "$env:USERDNSDOMAIN='omg.cspfmba.ru';" + script
        try:
            run_as_admin("powershell.exe", f"-NoProfile -ExecutionPolicy Bypass -Command \"{script}\"")
            messagebox.showinfo("Сброс пароля", f"Запущено для {self.user['name']} ({which.upper()}).")
            self._log_action(f"Сброшен пароль ({which})")
        except Exception as e:
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
    app_root = tk.Tk()

