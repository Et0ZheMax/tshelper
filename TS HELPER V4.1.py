# TS HELP AD — v4.1 (all-in-one + CallWatcher)
# Требуется: Python 3.9+, Windows
# Доп. пакеты (необязательно): ttkbootstrap, requests, pypiwin32
# pip install requests ttkbootstrap pypiwin32

import os, sys, json, re, time, threading, queue, subprocess, platform, shutil, webbrowser, locale, datetime, base64, urllib.parse
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, colorchooser
from concurrent.futures import ThreadPoolExecutor

# --- Версия приложения ---
VERSION = "v4.1"

# Цвета статусов (иконка в тексте)
STATUS_COLORS = {
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
def log_message(msg): logger.info(msg)

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
        attrs = ["cn", "sAMAccountName"]
        conn.search(search_base=base_dn, search_filter=search_filter, attributes=attrs)
        users = []
        for entry in conn.entries:
            cn = entry.cn.value if entry.cn else ""
            sam= entry.sAMAccountName.value if entry.sAMAccountName else ""
            if cn and sam:
                users.append({"name": cn, "pc_name": f"w-{sam}"})
        conn.unbind()
        return users
    except Exception as e:
        log_message(f"AD error: {e}")
        messagebox.showerror("Ошибка AD", f"Не удалось получить пользователей из AD: {e}")
        return []

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
    ringy = any(x in block for x in ["Ringing", "Ring+Inuse", " Dial Ring ", " Dial Up "])
    if not ringy: return None
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
        self.users = load_json(self.users_file, default=[])
    def get_users(self): return self.users
    def save(self): save_json(self.users_file, self.users)
    def add_user(self, u):
        self.users.append(u); self.save()
    def update_user(self, old_pc_name, new_user):
        for i,u in enumerate(self.users):
            if u["pc_name"] == old_pc_name:
                self.users[i] = new_user; self.save(); return
    def delete_user(self, pc_name):
        self.users = [u for u in self.users if u["pc_name"] != pc_name]; self.save()

class SettingsManager:
    def __init__(self, path):
        self.path = path
        self.config = load_json(path, default={
            "window_geometry":"1100x720+200+100",
            "edit_window_geometry":"", "settings_window_geometry":"", "ad_sync_select_geometry":"", "ip_window_geometry":"",
            # AD creds
            "ad_username":"", "ad_password":"",
            # Reset password
            "reset_password":"dpapi:"+"" if DPAPI_AVAILABLE else "12340987",
            # SSH
            "ssh_login":"", "ssh_password":"", "ssh_terminal":"Windows Terminal", "ssh_pass_enabled": False,
            "plink_hostkeys": {},
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
            "ui_caller_bg": "#fff3cd", "ui_caller_fg": "#111111"  # жёлтый soft
        })
    def get_setting(self, k, default=None):
        v = self.config.get(k, default)
        if k in ("ad_password","ssh_password","reset_password","cw_password") and isinstance(v,str):
            try: v = dpapi_decrypt(v)
            except: pass
        return v
    def set_setting(self, k, v):
        if k in ("ad_password","ssh_password","reset_password","cw_password") and isinstance(v,str):
            try: v = dpapi_encrypt(v)
            except: pass
        self.config[k] = v
        self.save_config()
    def save_config(self): save_json(self.path, self.config)

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

        self.users = UserManager(USERS_FILE)
        self.executor = ThreadPoolExecutor(max_workers=24)
        self.buttons = {}
        self.search_job = None
        self.ping_generation = 0

        # активные звонки (список словарей)
        self.active_calls = []   # [{ext, num, name, ts}]
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
        self.count_lbl = ttk.Label(bottom, text="Найдено аккаунтов: 0"); self.count_lbl.pack(side="right")

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

    def populate_buttons(self, items=None):
        for w in self.inner.winfo_children(): w.destroy()
        all_users = self.users.get_users() if items is None else items

        # 1) Активные звонки вверху (сортируем по времени убыв.)
        with self.calls_lock:
            now = time.time()
            self.active_calls = [c for c in self.active_calls if now - c["ts"] < self.calls_ttl]
            callers = sorted(self.active_calls, key=lambda c: c["ts"], reverse=True)

        self.buttons = {}
        cols = self._compute_cols()
        r=c=0

        # Вставим «панель активных звонков»
        for call in callers:
            b = tk.Button(
                self.inner,
                text=f"📞 {call['num'] or 'unknown'}\n{('(' + call['name'] + ')') if call['name'] else ''}\n→ {call['ext']}",
                bg=self.caller_bg, fg=self.caller_fg, activebackground=self.caller_bg, activeforeground=self.caller_fg,
                relief="ridge", bd=2, justify="center", wraplength=180
            )
            b.grid(row=r, column=c, padx=6, pady=6, sticky="nsew")
            c += 1
            if c >= cols: c = 0; r += 1

        # 2) Пользователи (отсортированы по ФИО)
        items_sorted = sorted(all_users, key=lambda u: locale.strxfrm(u["name"]))
        for u in items_sorted:
            btn = UserButton(self.inner, u, app=self, style_name="User.TButton")
            btn.grid(row=r, column=c, padx=6, pady=6, sticky="nsew")
            self.buttons[u["pc_name"]] = btn
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
        filtered = [u for u in allu if text in u["name"].lower() or text in u["pc_name"].lower()]
        self.populate_buttons(filtered)
        if len(text) >= 3:
            self.ping_generation += 1
            gen = self.ping_generation
            for u in filtered:
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
        def save():
            n=e_name.get().strip(); p=e_pc.get().strip()
            if not n or not p: return messagebox.showerror("Ошибка","Заполните поля")
            self.users.add_user({"name":n,"pc_name":p}); self.populate_buttons(); self._close_save_geo(win,"edit_window_geometry")
        ttk.Button(win, text="Сохранить", command=save).pack(pady=8)

    def open_edit_window(self, user):
        win = tk.Toplevel(self.master); win.title("Редактировать пользователя")
        geom = self.settings.get_setting("edit_window_geometry"); 
        if geom: win.geometry(geom)
        win.protocol("WM_DELETE_WINDOW", lambda w=win: self._close_save_geo(w,"edit_window_geometry"))
        ttk.Label(win, text="ФИО:").pack(pady=4, anchor="w"); e_name = ttk.Entry(win); e_name.insert(0,user["name"]); e_name.pack(fill="x", padx=4)
        ttk.Label(win, text="Имя ПК:").pack(pady=4, anchor="w"); e_pc = ttk.Entry(win); e_pc.insert(0,user["pc_name"]); e_pc.pack(fill="x", padx=4)
        def save():
            n=e_name.get().strip(); p=e_pc.get().strip()
            if not n or not p: return messagebox.showerror("Ошибка","Заполните поля")
            self.users.update_user(user["pc_name"], {"name":n,"pc_name":p}); self.populate_buttons(); self._close_save_geo(win,"edit_window_geometry")
        ttk.Button(win, text="Сохранить", command=save).pack(pady=8)

    def delete_user_from_button(self, user):
        if messagebox.askyesno("Удалить", f"Удалить {user['name']}?"):
            self.users.delete_user(user["pc_name"]); self.populate_buttons()

    # --------- AD sync ----------
    def ad_sync(self):
        ad_user = self.settings.get_setting("ad_username","").strip()
        ad_pass = self.settings.get_setting("ad_password","").strip()
        if not ad_user or not ad_pass:
            return self.open_settings()
        ad_list = get_ad_users(AD_SERVER, ad_user, ad_pass, AD_BASE_DN, AD_DOMAIN)
        if not ad_list: return
        by_norm = {norm_name(u["name"]): u for u in self.users.get_users()}
        new_candidates = []
        for adu in ad_list:
            k = norm_name(adu["name"])
            if k in by_norm:
                if by_norm[k]["pc_name"].lower() != adu["pc_name"].lower():
                    by_norm[k]["pc_name"] = adu["pc_name"]
            else:
                new_candidates.append(adu)
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

    # --------- Settings ----------
    def open_settings(self):
        win = tk.Toplevel(self.master); win.title("Настройки")
        geom = self.settings.get_setting("settings_window_geometry","900x620+250+150")
        win.geometry(geom)
        win.protocol("WM_DELETE_WINDOW", lambda w=win: self._close_save_geo(w,"settings_window_geometry"))
        nb = ttk.Notebook(win); nb.pack(fill="both", expand=True, padx=10, pady=10)

        # AD creds
        tab_ad = ttk.Frame(nb); nb.add(tab_ad, text="Учетные данные AD")
        ttk.Label(tab_ad, text="Логин:").pack(pady=4, anchor="w")
        e_user = ttk.Entry(tab_ad); e_user.insert(0, self.settings.get_setting("ad_username","")); e_user.pack(fill="x")
        ttk.Label(tab_ad, text="Пароль:").pack(pady=4, anchor="w")
        e_pass = ttk.Entry(tab_ad, show="*"); e_pass.insert(0, self.settings.get_setting("ad_password","")); e_pass.pack(fill="x")

        # Reset password
        tab_rst = ttk.Frame(nb); nb.add(tab_rst, text="Пароль для сброса")
        ttk.Label(tab_rst, text="Новый пароль:").pack(pady=4, anchor="w")
        e_rst = ttk.Entry(tab_rst, show="*"); e_rst.insert(0, self.settings.get_setting("reset_password","12340987")); e_rst.pack(fill="x")
        btn_toggle = ttk.Button(tab_rst, text="Показать")
        def toggle_pw():
            if e_rst.cget("show")=="*": e_rst.config(show=""); btn_toggle.config(text="Скрыть")
            else: e_rst.config(show="*"); btn_toggle.config(text="Показать")
        btn_toggle.config(command=toggle_pw); btn_toggle.pack(pady=4, anchor="e")

        # SSH
        tab_ssh = ttk.Frame(nb); nb.add(tab_ssh, text="SSH")
        ttk.Label(tab_ssh, text="SSH Login:").pack(pady=4, anchor="w")
        e_ssh_login = ttk.Entry(tab_ssh); e_ssh_login.insert(0, self.settings.get_setting("ssh_login","")); e_ssh_login.pack(fill="x")
        ttk.Label(tab_ssh, text="SSH Password:").pack(pady=4, anchor="w")
        e_ssh_pass = ttk.Entry(tab_ssh, show="*"); e_ssh_pass.insert(0, self.settings.get_setting("ssh_password","")); e_ssh_pass.pack(fill="x")
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
        cw_enabled = tk.BooleanVar(value=self.settings.get_setting("cw_enabled", True))
        ttk.Checkbutton(tab_cw, text="Включить отслеживание звонков", variable=cw_enabled).pack(anchor="w", pady=4)
        ttk.Label(tab_cw, text="Номера EXT (через запятую):").pack(anchor="w");
        e_exts = ttk.Entry(tab_cw); e_exts.insert(0, self.settings.get_setting("cw_exts","4444")); e_exts.pack(fill="x")
        ttk.Label(tab_cw, text="URL Peers-страницы FreePBX:").pack(anchor="w");
        e_url = ttk.Entry(tab_cw); e_url.insert(0, self.settings.get_setting("cw_url","")); e_url.pack(fill="x")
        ttk.Label(tab_cw, text="Логин/пароль для FreePBX (используются для автоподхвата cookie):").pack(anchor="w")
        e_pbx_login = ttk.Entry(tab_cw); e_pbx_login.insert(0, self.settings.get_setting("cw_login","")); e_pbx_login.pack(fill="x")
        e_pbx_pass = ttk.Entry(tab_cw, show="*"); e_pbx_pass.insert(0, self.settings.get_setting("cw_password","")); e_pbx_pass.pack(fill="x")

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
        for lbl, var in (("Фон кнопок пользователей", user_bg), ("Текст кнопок пользователей", user_fg),
                         ("Фон кнопок звонков", caller_bg), ("Текст кнопок звонков", caller_fg)):
            row = ttk.Frame(tab_colors); row.pack(fill="x", pady=4)
            ttk.Label(row, text=lbl).pack(side="left")
            ent = ttk.Entry(row, textvariable=var, width=12); ent.pack(side="left", padx=6)
            ttk.Button(row, text="Выбрать…", command=lambda v=var: v.set(pick_color(v.get()))).pack(side="left")

        board_bg = tk.StringVar(value=self.settings.get_setting("ui_board_bg","#f5e7d8"))

        row = ttk.Frame(tab_colors); row.pack(fill="x", pady=4)
        ttk.Label(row, text="Фон рабочей области").pack(side="left")
        ent = ttk.Entry(row, textvariable=board_bg, width=12); ent.pack(side="left", padx=6)
        ttk.Button(row, text="Выбрать…", command=lambda: board_bg.set(pick_color(board_bg.get()))).pack(side="left")


        # Save
        def save_all():
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
            self._apply_button_styles()
            self.populate_buttons()

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
                        if name and pc:
                            users.append({"name":name.strip(),"pc_name":pc.strip()}); added+=1
            else:
                try:
                    import pandas as pd
                except:
                    return messagebox.showerror("Импорт", "Для Excel нужен pandas+openpyxl")
                df = pd.read_excel(path)
                for _,r in df.iterrows():
                    name = str(r.get("name") or r.get("ФИО") or "").strip()
                    pc   = str(r.get("pc_name") or r.get("ПК") or "").strip()
                    if name and pc:
                        users.append({"name":name,"pc_name":pc}); added+=1
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
                w=csv.DictWriter(f, fieldnames=["name","pc_name"]); w.writeheader()
                for u in self.users.get_users(): w.writerow(u)
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

    def _check_pbx_cookie(self, url: str, cookie: str):
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
            resp = session.get(url, headers=headers, timeout=10, allow_redirects=False)
            if resp.status_code in (301,302,303,307,308):
                loc = resp.headers.get("Location", "")
                if "login" in loc.lower():
                    return False, "Редирект на страницу логина — cookie не подошёл"
                resp = session.get(url, headers=headers, timeout=10)

            if resp.status_code != 200:
                return False, f"HTTP {resp.status_code} при обращении к PBX"

            if looks_like_login(resp.text):
                return False, "Похоже на форму логина — проверьте cookie"

            return True, "Страница PBX открывается, cookie принят"
        except Exception as e:
            return False, f"Ошибка запроса: {e}"

    def _build_pbx_login_url(self, peers_url: str) -> str:
        parsed = urllib.parse.urlsplit(peers_url)
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
        if not url:
            return False, "Укажите URL Peers-страницы FreePBX", None
        if not username or not password:
            return False, "Укажите логин и пароль FreePBX", None
        try:
            import requests
        except Exception:
            return False, "requests не установлен — автоподхват недоступен", None

        login_url = self._build_pbx_login_url(url)
        session = requests.Session()
        headers = {"User-Agent": "TSHelper/PbxLogin"}
        try:
            page = session.get(login_url, headers=headers, timeout=10)
        except Exception as e:
            return False, f"Ошибка открытия страницы логина: {e}", None

        token_name, token_val = self._extract_pbx_token(page.text)
        payload = {"username": username, "password": password, "submit": "Login"}
        if token_name and token_val:
            payload[token_name] = token_val

        try:
            resp = session.post(login_url, headers=headers, data=payload, timeout=10, allow_redirects=True)
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
        url     = self.settings.get_setting("cw_url","").strip()
        cookie  = self.settings.get_setting("cw_cookie","").strip()
        if cookie and "=" not in cookie:
            log_message("CallWatcher: Cookie выглядит как голый ID. Нужна полная строка: 'PHPSESSID=...; fpbx_admin=...'.")
        interval= max(1, int(self.settings.get_setting("cw_interval", 2)))
        popup_on= bool(self.settings.get_setting("cw_popup", True))
        exts_raw= self.settings.get_setting("cw_exts","4444")
        watch_exts = [x.strip() for x in exts_raw.split(",") if x.strip()]

        headers = {"User-Agent":"TSHelper/CallWatch"}
        if cookie: headers["Cookie"] = cookie
        session = requests.Session()

        seen, seen_ttl, dup_ttl = set(), {}, 25
        def gc_seen():
            now = time.time()
            for k, t in list(seen_ttl.items()):
                if t < now:
                    seen.discard(k); seen_ttl.pop(k, None)

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
                        num, name = caller
                        who = (num or "unknown") + (f" ({name})" if name else "")
                        key = f"{ext}|{who}|{int(time.time()/dup_ttl)}"
                        if key not in seen:
                            seen.add(key); seen_ttl[key] = time.time() + dup_ttl
                            log_message(f"CALL {ext}: {who}")

                            # 1) показать сверху
                            with self.calls_lock:
                                self.active_calls.insert(0, {"ext":ext, "num":num or "", "name":name or "", "ts":time.time()})
                            self.master.after(0, self.populate_buttons)

                            # 2) всплывашка
                            if popup_on:
                                self.master.after(0, lambda e=ext, w=who: self._popup(f"Звонок на {e}", w))

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
    def __init__(self, master, user, app: MainWindow, style_name=None):
        super().__init__(master)
        self.user = user
        self.app  = app
        self.avail = None

        # создаём tk.Button, чтобы гарантированно красить
        self.btn = tk.Button(
            self,
            text=f"{user['name']}\n({user['pc_name']})",
            bg=self.app.user_bg, fg=self.app.user_fg,
            activebackground=self.app.user_bg, activeforeground=self.app.user_fg,
            relief="groove", bd=2, justify="center", wraplength=180,
            command=self._show_menu
        )
        self.btn.pack(fill="both", expand=True)
        self.btn.bind("<Button-3>", self._rclick)

    def refresh_colors(self):
        self.btn.configure(
            bg=self.app.user_bg, fg=self.app.user_fg,
            activebackground=self.app.user_bg, activeforeground=self.app.user_fg
        )

    def set_availability(self, ok, searching=False):
        self.avail = ok
        prefix = "🟢 " if (searching and ok) else ("🔴 " if (searching and not ok) else "")
        self.btn.config(text=f"{prefix}{self.user['name']}\n({self.user['pc_name']})")

    def _show_menu(self):
        m = tk.Menu(self, tearoff=0)
        m.add_command(label="RDP", command=self.rdp_connect)
        m.add_command(label="Удаленный помощник", command=self.remote_assistance)
        m.add_command(label="Проводник (C$)", command=self.open_explorer)
        m.add_command(label="Получить IP", command=self.get_ip)
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


    # --- Actions ---
    def rdp_connect(self):
        try:
            if is_windows():
                subprocess.Popen(["mstsc","/v", self.user["pc_name"]], creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception as e:
            messagebox.showerror("RDP", str(e))

    def remote_assistance(self):
        try:
            if is_windows():
                run_as_admin("msra.exe", "/offerRA "+self.user["pc_name"])
        except Exception as e:
            messagebox.showerror("Удаленный помощник", str(e))

    def open_explorer(self):
        try:
            os.startfile(f"\\\\{self.user['pc_name']}\\c$")
        except Exception as e:
            messagebox.showerror("Проводник", str(e))

    def get_ip(self):
        def task():
            try:
                if is_windows():
                    p = subprocess.run(["ping","-n","1",self.user["pc_name"]], capture_output=True, text=True,
                                       creationflags=subprocess.CREATE_NO_WINDOW, timeout=2)
                else:
                    p = subprocess.run(["ping","-c","1",self.user["pc_name"]], capture_output=True, text=True, timeout=2)
                m = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", p.stdout)
                ip = m.group(1) if m else "Не найден"
            except Exception as e:
                ip = f"Ошибка: {e}"
            self.app.master.after(0, lambda: self.app.show_ip_window(ip))
        threading.Thread(target=task, daemon=True).start()

    def reset_password_ps(self, which):
        new_pw = self.app.settings.get_setting("reset_password","12340987")
        sam = self.user["pc_name"]
        if sam.lower().startswith("w-"): sam = sam[2:]
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
        except Exception as e:
            messagebox.showerror("Сброс пароля", str(e))

    def open_ssh_connection(self):
        ssh_login = self.app.settings.get_setting("ssh_login","")
        ssh_password = self.app.settings.get_setting("ssh_password","")
        if not ssh_login:
            return messagebox.showerror("SSH", "Не задан SSH Login в настройках")
        pc = self.user["pc_name"]
        if pc.lower().startswith("w-"): pc = pc[2:]
        term = self.app.settings.get_setting("ssh_terminal","Windows Terminal")
        auto = self.app.settings.get_setting("ssh_pass_enabled", False)

        try:
            if term == "Windows Terminal":
                if auto: cmd = f'sshpass -p "{ssh_password}" ssh {ssh_login}@{pc}'
                else:    cmd = f'ssh -o StrictHostKeyChecking=accept-new {ssh_login}@{pc}'
                subprocess.Popen(["wt.exe","-p","Ubuntu","ubuntu.exe","-c",cmd])
            elif term in ("CMD","PowerShell"):
                if auto:
                    hostkeys = self.app.settings.config.get("plink_hostkeys", {})
                    hk = hostkeys.get(pc.lower())
                    if hk:
                        plink_cmd = f'plink.exe -ssh -batch -hostkey "{hk}" -pw "{ssh_password}" {ssh_login}@{pc}'
                    else:
                        plink_cmd = f'plink.exe -ssh -batch -pw "{ssh_password}" {ssh_login}@{pc}'
                    if term=="CMD": subprocess.Popen(["cmd.exe","/k", plink_cmd])
                    else:           subprocess.Popen(["powershell","-NoExit","-Command", plink_cmd])
                else:
                    ssh_cmd = f'ssh -o StrictHostKeyChecking=accept-new {ssh_login}@{pc}'
                    if term=="CMD": subprocess.Popen(["cmd.exe","/k", ssh_cmd])
                    else:           subprocess.Popen(["powershell","-NoExit","-Command", ssh_cmd])
            else:
                messagebox.showerror("SSH","Неизвестный терминал")
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

