import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import subprocess
import os
import threading
import queue
import webbrowser
from pywinauto import Application
import ctypes
import platform
import time
import json
import datetime
import locale
import re
from concurrent.futures import ThreadPoolExecutor
from ldap3 import Server, Connection, MODIFY_REPLACE
from PIL import Image, ImageTk  # Для иконок
import ldap3  # Для работы с Active Directory

os.chdir(os.path.dirname(os.path.abspath(__file__)))
locale.setlocale(locale.LC_COLLATE, 'ru_RU.UTF-8')

# --- Глобальные функции для работы с буфером обмена ---

def on_paste(event):
    widget = event.widget
    try:
        text = widget.clipboard_get()
        widget.insert(tk.INSERT, text)
    except tk.TclError:
        pass
    return "break"

def on_copy(event):
    widget = event.widget
    try:
        selected_text = widget.selection_get()
        widget.clipboard_clear()
        widget.clipboard_append(selected_text)
    except tk.TclError:
        pass
    return "break"




# === Константы и настройки ===
APP_NAME = "User Manager by MLepeshev (spasibo na sber mojesh perevesti)"
CONFIG_FILE = "config.json"
USERS_FILE = "users.json"
DEFAULT_CHECK_INTERVAL = 5  # секунд (не используется)
LOG_FILE = "app.log"

# === Active Directory Settings ===
AD_SERVER = "DC02.pak-cspmz.ru"  # Замените на адрес вашего AD-сервера
# Жёстко заданные данные удалены – теперь берутся из настроек
AD_BASE_DN = "OU=csp,OU=Users,OU=csp,DC=pak-cspmz,DC=ru"  # Базовый DN
AD_DOMAIN = "pak-cspmz.ru"        # Ваш домен

def run_as_admin(command, params):
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", command, params, None, 1)
    if result <= 32:
        raise RuntimeError(f"Ошибка при запуске процесса с повышенными правами: {result}")

def log_message(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now()} - {message}\n")

def load_json(filename, default=None):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default if default is not None else {}
    except json.JSONDecodeError:
        log_message(f"Ошибка при чтении JSON из {filename}")
        return default if default is not None else {}

def save_json(filename, data):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
    except Exception as e:
        log_message(f"Ошибка при записи в {filename}: {e}")

def save_main_window_geometry(self):
    width = self.master.winfo_width()
    height = self.master.winfo_height()
    x = self.master.winfo_x()
    y = self.master.winfo_y()
    geom = f"{width}x{height}+{x}+{y}"
    self.settings_manager.set_setting("window_geometry", geom)

def get_ad_users(server, username, password, base_dn, domain):
    try:
        ldap_server = ldap3.Server(server, get_info=ldap3.ALL)
        conn = ldap3.Connection(ldap_server, user=f"{username}@{domain}", password=password, auto_bind=True)
        search_filter = "(&(objectCategory=person)(objectClass=user))"
        search_attributes = ["cn", "sAMAccountName"]
        conn.search(search_base=base_dn, search_filter=search_filter, attributes=search_attributes)
        log_message(f"Найдено записей: {len(conn.entries)}")
        
        user_list = []
        for entry in conn.entries:
            user_name = entry.cn.value if entry.cn else ""
            sam_account_name = entry.sAMAccountName.value if entry.sAMAccountName else ""
            if user_name and sam_account_name:
                pc_name = f"w-{sam_account_name}"
                user_list.append({"name": user_name, "pc_name": pc_name})
        conn.unbind()
        return user_list
    except Exception as e:
        log_message(f"Ошибка при работе с Active Directory: {e}")
        messagebox.showerror("Ошибка", f"Не удалось получить пользователей из Active Directory: {e}")
        return []

# === Классы ===

class UserManager:
    """Управляет списком пользователей, сохранённым в файле."""
    def __init__(self, users_file):
        self.users_file = users_file
        self.users = load_json(self.users_file, default=[])
    def get_users(self):
        return self.users
    def add_user(self, user):
        self.users.append(user)
        self.save_users()
    def update_user(self, old_pc_name, new_user):
        for i, user in enumerate(self.users):
            if user["pc_name"] == old_pc_name:
                self.users[i] = new_user
                self.save_users()
                return
        log_message(f"Пользователь с pc_name {old_pc_name} не найден")
    def delete_user(self, pc_name):
        self.users = [user for user in self.users if user["pc_name"] != pc_name]
        self.save_users()
    def save_users(self):
        save_json(self.users_file, self.users)

class SettingsManager:
    """Управляет настройками приложения."""
    def __init__(self, config_file):
        self.config_file = config_file
        self.config = load_json(self.config_file, default={
            "window_geometry": "800x600",
            "ad_username": "",
            "ad_password": "",
            "edit_window_geometry": "",
            "settings_window_geometry": "",
            "ad_sync_geometry": "",
            "ad_sync_select_geometry": "",
            "ip_window_geometry": ""
        })
    def get_setting(self, key, default=None):
        return self.config.get(key, default)
    def set_setting(self, key, value):
        self.config[key] = value
        self.save_config()
    def save_config(self):
        save_json(self.config_file, self.config)

class UserButton(ttk.Button):
    """Кнопка пользователя с контекстным меню.
       Редактирование теперь доступно через правый клик."""
    def __init__(self, master, user, available, app, *args, **kwargs):
        self.user = user
        self.available = available
        self.app = app
        button_text = f"{self.user['name']}\n({self.user['pc_name']})"
        # По умолчанию используем стиль "TButton" (с синей обводкой)
        self.style = "TButton"
        super().__init__(master, text=button_text, style=self.style, command=self.show_actions, *args, **kwargs)
        # Удалены tooltip – больше не показываем всплывающие окна при наведении
        self.bind("<Button-3>", self.on_right_click)

    def open_glpi(self):
        # Извлекаем фамилию (первое слово) и переходим по ссылке
        try:
            last_name = self.user["name"].split()[0]
        except IndexError:
            messagebox.showerror("Ошибка", "Не удалось определить фамилию пользователя")
            return
        url = f"https://inv.pak-cspmz.ru/front/search.php?globalsearch={last_name}"
        webbrowser.open(url)

   
    def open_ssh_connection(self):
        """Подключение по ssh через sshpass с выбором терминала из настроек."""
        ssh_login = self.app.settings_manager.get_setting("ssh_login", "")
        ssh_password = self.app.settings_manager.get_setting("ssh_password", "")
        if not ssh_login or not ssh_password:
            messagebox.showerror("Ошибка", "Не заданы данные SSH в настройках")
            return
        pc_name = self.user["pc_name"]
        if pc_name.lower().startswith("w-"):
            pc_name = pc_name[2:]
        cmd = f'sshpass -p "{ssh_password}" ssh {ssh_login}@{pc_name}'
        terminal_type = self.app.settings_manager.get_setting("ssh_terminal", "Windows Terminal")
        try:
            if terminal_type == "Windows Terminal":
                subprocess.Popen(["wt.exe", "-p", "Ubuntu", "ubuntu.exe", "-c", cmd])
            elif terminal_type == "CMD":
                subprocess.Popen(["cmd.exe", "/k", cmd])
            elif terminal_type == "PowerShell":
                subprocess.Popen(["powershell", "-NoExit", "-Command", cmd])
            else:
                messagebox.showerror("Ошибка", f"Неизвестный тип терминала: {terminal_type}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось подключиться по ssh: {e}")
            log_message(f"Ошибка подключения по ssh: {e}")














    
    def show_actions(self):
        menu = tk.Menu(self.master, tearoff=0)
        menu.add_command(label="RDP", command=self.rdp_connect)
        menu.add_command(label="Удаленный помощник", command=self.remote_assistance)
        menu.add_command(label="Проводник (C$)", command=self.open_explorer)
        menu.add_command(label="Получить IP", command=self.get_ip)
        menu.add_command(label="Открыть PS терминал", command=self.open_ps_terminal)
        menu.add_command(label="Открыть в GLPI", command=self.open_glpi)
        # Добавляем пункты сброса пароля через PowerShell:
        menu.add_command(label="Сбросить пароль pak", command=lambda: self.app.reset_password_ps("pak-cspmz.ru", self.user))
        menu.add_command(label="Сбросить пароль omg", command=lambda: self.app.reset_password_ps("omg.cspfmba.ru", self.user))
        # Новый пункт для SSH-подключения
        menu.add_command(label="Подключение по ssh", command=self.open_ssh_connection)
        x = self.winfo_rootx()
        y = self.winfo_rooty() + self.winfo_height()
        menu.post(x, y)

        
    def open_ps_terminal(self):
        try:
            subprocess.Popen(["powershell", "-NoExit", f"Enter-PSSession -ComputerName {self.user['pc_name']}"])
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось открыть PS терминал: {e}")
            log_message(f"Ошибка при открытии PS терминала: {e}")
        
    def on_right_click(self, event):
        # Контекстное меню с опциями "Редактировать" и "Удалить"
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Редактировать", command=lambda: self.app.open_edit_window(self.user))
        menu.add_command(label="Удалить", command=lambda: self.app.delete_user_from_button(self.user))
        menu.tk_popup(event.x_root, event.y_root)
        
    def rdp_connect(self):
        self.app.run_action(lambda: self._rdp_connect())
    def remote_assistance(self):
        self.app.run_action(lambda: self._remote_assistance())
    def open_explorer(self):
        self.app.run_action(lambda: self._open_explorer())
    def _rdp_connect(self):
        try:
            if platform.system() == "Windows":
                subprocess.Popen(["mstsc", "/v", self.user["pc_name"]], creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                subprocess.Popen(["mstsc", "/v", self.user["pc_name"]])
        except Exception as e:
            messagebox.showerror("Ошибка RDP", f"Не удалось подключиться по RDP: {e}")
            log_message(f"Ошибка RDP: {e}")
    def _remote_assistance(self):
        try:
            if platform.system() == "Windows":
                run_as_admin("msra.exe", "/offerRA " + self.user["pc_name"])
            else:
                messagebox.showerror("Ошибка", "Удаленный помощник доступен только на Windows.")
        except Exception as e:
            messagebox.showerror("Ошибка удаленного помощника", f"Не удалось предложить удаленный помощник: {e}")
            log_message(f"Ошибка удаленного помощника: {e}")
    def _open_explorer(self):
        try:
            os.startfile(f"\\\\{self.user['pc_name']}\\c$")
        except Exception as e:
            messagebox.showerror("Ошибка проводника", f"Не удалось открыть проводник: {e}")
            log_message(f"Ошибка проводника: {e}")
    def get_ip(self):
        self.app.run_action(lambda: self._get_ip())
    def _get_ip(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.check_output(
                    ["ping", "-n", "1", self.user["pc_name"]],
                    universal_newlines=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                result = subprocess.check_output(
                    ["ping", "-c", "1", self.user["pc_name"]],
                    universal_newlines=True
                )
            ips = re.findall(r'\[([\d\.]+)\]', result)
            ip = ips[0] if ips else "Не найден"
        except Exception as e:
            ip = "Ошибка: " + str(e)
        self.app.master.after(0, lambda: self.app.show_ip_window(ip))
    def update_style(self, available):
        self.available = available
        if len(self.app.search_entry.get()) >= 3:
            new_style = "Green.TButton" if available else "Red.TButton"
        else:
            new_style = "TButton"
        self.config(style=new_style)

class MainWindow:
    """Главное окно приложения."""
    def __init__(self, master):
        self.master = master
        self.master.title(APP_NAME)
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.loading = False  # загрузка происходит из файла
        self.configure_timer = None  # для дебаунса
        self.last_canvas_width = None  # для отслеживания изменения ширины

        # Менеджеры настроек и пользователей
        self.settings_manager = SettingsManager(CONFIG_FILE)
        self.user_manager = UserManager(USERS_FILE)
        self.users = self.user_manager.get_users()

        self.master.geometry(self.settings_manager.get_setting("window_geometry", "800x600"))

        # Загрузка иконок
        self.icons = self.load_icons()

        # Настройка стилей – базовый стиль TButton с синей обводкой
        self.style = ttk.Style()
        self.style.configure("TButton", padding=5, relief="flat", background="#059fff", foreground="black")
        self.style.configure("Green.TButton", background="#04d1b9", foreground="black")
        self.style.configure("Red.TButton", background="#b32456", foreground="black")
        self.style.configure("TProgressbar", thickness=10, background="blue")

        # Атрибуты для проверки доступности
        self.buttons = {}
        self.availability_queue = queue.Queue()
        self.executor = ThreadPoolExecutor(max_workers=20)

        # Для хранения AD-учетных данных (до конца сессии)
        self.ad_credentials = {}
        ad_user = self.settings_manager.get_setting("ad_username")
        ad_pass = self.settings_manager.get_setting("ad_password")
        if ad_user and ad_pass:
            self.ad_credentials = {"username": ad_user, "password": ad_pass}

        # UI
        self.create_widgets()

        # Заполняем кнопками
        self.populate_buttons()

        # Обработчик изменения размеров окна с дебаунсом
        self.master.bind("<Configure>", self.on_configure)

    def on_closing(self):
        self.master.update_idletasks()
        width = self.master.winfo_width()
        height = self.master.winfo_height()
        x = self.master.winfo_x()
        y = self.master.winfo_y()
        geom = f"{width}x{height}+{x}+{y}"
        self.settings_manager.set_setting("window_geometry", geom)
        self.settings_manager.save_config()
        self.executor.shutdown(wait=False)
        self.master.destroy()

    def add_clipboard_bindings(self, entry):
        def paste_wrapper(event):
            # Проверяем, что физическая клавиша V (keycode 86) нажата
            if event.keycode == 86:
                return on_paste(event)
        def copy_wrapper(event):
            # Проверяем, что физическая клавиша C (keycode 67) нажата
            if event.keycode == 67:
                return on_copy(event)
        entry.bind("<Control-KeyPress>", paste_wrapper)
        entry.bind("<Control-KeyPress>", copy_wrapper, add="+")



    def load_icons(self):
        icons = {}
        try:
            icons["add"] = ImageTk.PhotoImage(Image.open("icons/add.png").resize((16, 16)))
            icons["AD"] = ImageTk.PhotoImage(Image.open("icons/AD.png").resize((16, 16)))
            icons["settings"] = ImageTk.PhotoImage(Image.open("icons/setting.png").resize((16, 16)))
            icons["fix"] = ImageTk.PhotoImage(Image.open("icons/fix.png").resize((16, 16)))
        except FileNotFoundError as e:
            log_message(f"Ошибка при загрузке иконок: {e}")
            messagebox.showerror("Ошибка", "Не удалось загрузить иконки. Убедитесь, что папка 'icons' находится в том же каталоге, что и скрипт.")
        return icons

    def create_widgets(self):
        # === Меню ===
        self.menubar = tk.Menu(self.master)
        self.filemenu = tk.Menu(self.menubar, tearoff=0)
        self.filemenu.add_command(label="Настройки", command=self.open_settings, image=self.icons.get("settings"), compound="left")
        self.filemenu.add_separator()
        self.filemenu.add_command(label="Выход", command=self.on_closing)
        self.menubar.add_cascade(label="Файл", menu=self.filemenu)
        self.master.config(menu=self.menubar)

        # === Верхняя панель ===
        self.top_frame = ttk.Frame(self.master, padding=10)
        self.top_frame.pack(side="top", fill="x")
        ttk.Label(self.top_frame, text="Поиск:").pack(side="left")
        self.search_entry = ttk.Entry(self.top_frame)
        self.search_entry.pack(side="left", fill="x", expand=True)
        self.search_entry.bind("<KeyRelease>", self.update_search)

        # === Панель с кнопками пользователей ===
        self.button_frame = ttk.Frame(self.master, padding=10)
        self.button_frame.pack(side="top", fill="both", expand=True)
        self.canvas = tk.Canvas(self.button_frame)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar = ttk.Scrollbar(self.button_frame, orient="vertical", command=self.canvas.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.bind('<Configure>', lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<MouseWheel>", self.on_mousewheel)
        self.canvas.bind("<Button-4>", self.on_mousewheel)
        self.canvas.bind("<Button-5>", self.on_mousewheel)
        self.inner_frame = ttk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.inner_frame, anchor="nw")
        self.inner_frame.bind("<MouseWheel>", self.on_mousewheel)

        # === Нижняя панель ===
        self.bottom_frame = ttk.Frame(self.master, padding=10)
        self.bottom_frame.pack(side="bottom", fill="x")
        self.add_button = ttk.Button(self.bottom_frame, text="Добавить", command=self.add_user,
                                     image=self.icons.get("add"), compound="left")
        self.add_button.pack(side="left", padx=5)
        self.fix_all_button = ttk.Button(self.bottom_frame, text="ПОЧИНИТЬ ВСЁ", command=self.fix_all,
                                     image=self.icons.get("fix"), compound="left")
        self.fix_all_button.pack(side="right", padx=5)
        self.ad_sync_button = ttk.Button(self.bottom_frame, text="AD Sync", command=self.ad_sync,
                                     image=self.icons.get("AD"), compound="left")
        self.ad_sync_button.pack(side="left", padx=5)
        self.account_count_label = ttk.Label(self.bottom_frame, text="Найдено аккаунтов: 0")
        self.account_count_label.pack(side="right", padx=5)
        self.progressbar = ttk.Progressbar(self.bottom_frame, orient="horizontal", mode="indeterminate")
        self.populate_buttons()

    def on_mousewheel(self, event):
        if event.delta > 0 and self.canvas.yview()[0] == 0:
            return "break"
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        return "break"


    def reset_password_ps(self, target_domain, user):
        """
        Сбрасывает пароль пользователя с использованием PowerShell.
        target_domain: "pak-cspmz.ru" или "omg.cspfmba.ru"
        Новый пароль берется из настроек ("reset_password").
        """
        # Извлекаем пароль для сброса из настроек:
        new_password = self.settings_manager.get_setting("reset_password", "12340987")
        # Извлекаем sAMAccountName из pc_name (если pc_name начинается с "w-", убираем его)
        sam = user["pc_name"]
        if sam.lower().startswith("w-"):
            sam = sam[2:]
        ps_command = (
            "Import-Module ActiveDirectory; "
            f"Set-ADAccountPassword -Identity '{sam}' -Reset -NewPassword "
            f"(ConvertTo-SecureString -AsPlainText '{new_password}' -Force) -PassThru"
        )
        if target_domain == "pak-cspmz.ru":
            ps_command += " -Server 'pak-cspmz.ru'"
        elif target_domain == "omg.cspfmba.ru":
            ps_command += " -Server 'omg.cspfmba.ru'"
        try:
            result = subprocess.run(["powershell", "-Command", ps_command],
                                    capture_output=True, text=True, check=True)
            messagebox.showinfo("Успех", f"Пароль успешно сброшен в домене {target_domain}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Ошибка", f"Ошибка сброса пароля: {e.stderr}")
            log_message(f"Ошибка сброса пароля в {target_domain} для {sam}: {e.stderr}")



    def on_configure(self, event):
        new_width = self.canvas.winfo_width()
        if self.last_canvas_width is None or abs(new_width - self.last_canvas_width) > 20:
            self.last_canvas_width = new_width
            if self.configure_timer is not None:
                self.master.after_cancel(self.configure_timer)
            self.configure_timer = self.master.after(300, self.populate_buttons)

    def populate_buttons(self, users=None):
        if self.loading:
            for widget in self.inner_frame.winfo_children():
                widget.destroy()
            ttk.Label(self.inner_frame, text="Загрузка пользователей...").pack(padx=10, pady=10)
            return
        if users is None:
            users = self.users
        users = sorted(users, key=lambda u: locale.strxfrm(u["name"]))
        for widget in self.inner_frame.winfo_children():
            widget.destroy()
        self.buttons = {}
        available_width = self.canvas.winfo_width() or 800
        button_width = 150
        num_columns = max(1, available_width // (button_width + 10))
        row = 0
        col = 0
        for user in users:
            button = UserButton(self.inner_frame, user, False, self)
            button.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")
            self.buttons[user["pc_name"]] = button
            col += 1
            if col >= num_columns:
                col = 0
                row += 1
        self.account_count_label.config(text=f"Найдено аккаунтов: {len(users)}")

    def run_action(self, action):
        self.executor.submit(action)

    def check_availability(self, pc_name):
        try:
            if platform.system() == "Windows":
                ping_command = ["ping", "-n", "1", pc_name]
                creationflags = subprocess.CREATE_NO_WINDOW
            else:
                ping_command = ["ping", "-c", "1", pc_name]
                creationflags = 0
            result = subprocess.Popen(ping_command,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      creationflags=creationflags)
            stdout, stderr = result.communicate(timeout=2)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except Exception as e:
            log_message(f"Ошибка при пинге {pc_name}: {e}")
            return False

    def check_pc_availability(self, pc_name):
        available = self.check_availability(pc_name)
        self.master.after(0, self.update_button_style, pc_name, available)

    def update_button_style(self, pc_name, available):
        if pc_name in self.buttons:
            self.buttons[pc_name].update_style(available)

    def update_search(self, event=None):
        search_text = self.search_entry.get().lower()
        filtered_users = [user for user in self.users if search_text in user["name"].lower() or search_text in user["pc_name"].lower()]
        self.populate_buttons(filtered_users)
        self.canvas.yview_moveto(0)
        if len(search_text) >= 3:
            for user in filtered_users:
                self.executor.submit(self.check_pc_availability, user["pc_name"])

    def fix_all(self):
        messagebox.showerror("Ошибка", "В разработке")

    def add_user(self):
        def save_user():
            name = name_entry.get()
            pc_name = pc_name_entry.get()
            if name and pc_name:
                new_user = {"name": name, "pc_name": pc_name}
                self.user_manager.add_user(new_user)
                self.users = self.user_manager.get_users()
                self.populate_buttons()
                add_window.destroy()
            else:
                messagebox.showerror("Ошибка", "Заполните все поля")
        add_window = tk.Toplevel(self.master)
        add_window.title("Добавить пользователя")
        add_window.protocol("WM_DELETE_WINDOW", lambda w=add_window: self.on_toplevel_close(w, None))
        ttk.Label(add_window, text="Имя пользователя:").pack(pady=5)
        name_entry = ttk.Entry(add_window)
        name_entry.pack(pady=5)
        self.add_clipboard_bindings(name_entry)
        ttk.Label(add_window, text="Имя ПК:").pack(pady=5)
        pc_name_entry = ttk.Entry(add_window)
        pc_name_entry.pack(pady=5)
        self.add_clipboard_bindings(pc_name_entry)
        ttk.Button(add_window, text="Сохранить", command=save_user).pack(pady=10)

    def open_edit_window(self, user):
        edit_window = tk.Toplevel(self.master)
        edit_window.title("Редактировать пользователя")
        geom = self.settings_manager.get_setting("edit_window_geometry")
        if geom:
            edit_window.geometry(geom)
        edit_window.protocol("WM_DELETE_WINDOW", lambda w=edit_window: self.on_toplevel_close(w, "edit_window_geometry"))
        ttk.Label(edit_window, text="ФИО:").pack(pady=5)
        name_entry = ttk.Entry(edit_window)
        name_entry.insert(0, user["name"])
        name_entry.pack(pady=5, fill="x", expand=True)
        self.add_clipboard_bindings(name_entry)
        ttk.Label(edit_window, text="Имя ПК:").pack(pady=5)
        pc_name_entry = ttk.Entry(edit_window)
        pc_name_entry.insert(0, user["pc_name"])
        pc_name_entry.pack(pady=5, fill="x", expand=True)
        self.add_clipboard_bindings(pc_name_entry)
        def save_edited():
            new_name = name_entry.get().strip()
            new_pc_name = pc_name_entry.get().strip()
            if new_name and new_pc_name:
                self.user_manager.update_user(user["pc_name"], {"name": new_name, "pc_name": new_pc_name})
                self.users = self.user_manager.get_users()
                self.populate_buttons()
                self.settings_manager.set_setting("edit_window_geometry", edit_window.geometry())
                edit_window.destroy()
            else:
                messagebox.showerror("Ошибка", "Заполните все поля")
        ttk.Button(edit_window, text="Сохранить", command=save_edited).pack(pady=10)

    def delete_user_from_button(self, user):
        if messagebox.askyesno("Подтверждение", f"Удалить пользователя {user['name']}?"):
            self.user_manager.delete_user(user["pc_name"])
            self.users = self.user_manager.get_users()
            self.populate_buttons()

    def open_settings(self):
        # Создаём окно настроек большего размера
        settings_window = tk.Toplevel(self.master)
        settings_window.title("Настройки")
        # Восстанавливаем геометрию окна, если она сохранена, иначе задаём размер 600x400
        geom = self.settings_manager.get_setting("settings_window_geometry", "600x400")
        settings_window.geometry(geom)
        settings_window.configure(bg="#f0f0f5")  # светлый фон, имитирующий Apple‑style
        settings_window.protocol("WM_DELETE_WINDOW", lambda w=settings_window: self.on_toplevel_close(w, "settings_window_geometry"))
        
        # Создаём Notebook для двух вкладок
        notebook = ttk.Notebook(settings_window)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Вкладка "Учетные данные AD"
        tab_ad = ttk.Frame(notebook)
        notebook.add(tab_ad, text="Учетные данные AD")
        
        ad_label = ttk.Label(tab_ad, text="Учетные данные AD", font=("Helvetica", 14, "bold"))
        ad_label.pack(pady=10)
        
        ttk.Label(tab_ad, text="Логин:").pack(pady=5, anchor="w", padx=10)
        username_entry = ttk.Entry(tab_ad)
        username_entry.insert(0, self.settings_manager.get_setting("ad_username", ""))
        username_entry.pack(pady=5, padx=10, fill="x")
        self.add_clipboard_bindings(username_entry)
        
        ttk.Label(tab_ad, text="Пароль:").pack(pady=5, anchor="w", padx=10)
        password_entry = ttk.Entry(tab_ad, show="*")
        password_entry.insert(0, self.settings_manager.get_setting("ad_password", ""))
        password_entry.pack(pady=5, padx=10, fill="x")
        self.add_clipboard_bindings(password_entry)
        
        # Вкладка "Пароль для сброса"
        tab_reset = ttk.Frame(notebook)
        notebook.add(tab_reset, text="Пароль для сброса")

        reset_label = ttk.Label(tab_reset, text="Пароль для сброса", font=("Helvetica", 14, "bold"))
        reset_label.pack(pady=10)
        ttk.Label(tab_reset, text="Новый пароль:").pack(pady=5, anchor="w", padx=10)
        # Поле ввода с маскировкой (показываются звездочки)
        reset_entry = ttk.Entry(tab_reset, show="*")
        reset_entry.insert(0, self.settings_manager.get_setting("reset_password", "12340987"))
        reset_entry.pack(pady=5, padx=10, fill="x")
        self.add_clipboard_bindings(reset_entry)     
       
        # Кнопка для переключения отображения пароля
        toggle_button = ttk.Button(tab_reset, text="Показать", width=10)
        toggle_button.pack(pady=5, padx=10, anchor="e")

        def toggle_password():
            current = reset_entry.cget("show")
            if current == "*":
                reset_entry.config(show="")  # Убираем маску
                toggle_button.config(text="Скрыть")
            else:
                reset_entry.config(show="*")  # Восстанавливаем маску
                toggle_button.config(text="Показать")

        toggle_button.config(command=toggle_password)
    
        # Вкладка "SSH"
        tab_ssh = ttk.Frame(notebook)
        notebook.add(tab_ssh, text="SSH")
        ttk.Label(tab_ssh, text="SSH настройки", font=("Helvetica", 14, "bold")).pack(pady=10)

        ttk.Label(tab_ssh, text="SSH Login:", font=("Helvetica", 12)).pack(pady=5, anchor="w", padx=10)
        ssh_login_entry = ttk.Entry(tab_ssh)
        ssh_login_entry.insert(0, self.settings_manager.get_setting("ssh_login", ""))
        ssh_login_entry.pack(pady=5, padx=10, fill="x")
        self.add_clipboard_bindings(ssh_login_entry)

        ttk.Label(tab_ssh, text="SSH Password:", font=("Helvetica", 12)).pack(pady=5, anchor="w", padx=10)
        ssh_password_entry = ttk.Entry(tab_ssh, show="*")
        ssh_password_entry.insert(0, self.settings_manager.get_setting("ssh_password", ""))
        ssh_password_entry.pack(pady=5, padx=10, fill="x")
        self.add_clipboard_bindings(ssh_password_entry)

        ttk.Label(tab_ssh, text="Терминал для SSH:", font=("Helvetica", 12)).pack(pady=5, anchor="w", padx=10)
        ssh_terminal_var = tk.StringVar()
        ssh_terminal_combo = ttk.Combobox(tab_ssh, textvariable=ssh_terminal_var, state="readonly")
        ssh_terminal_combo["values"] = ("Windows Terminal", "CMD", "PowerShell")
        default_terminal = self.settings_manager.get_setting("ssh_terminal", "Windows Terminal")
        ssh_terminal_combo.set(default_terminal)
        ssh_terminal_combo.pack(pady=5, padx=10, fill="x")


        # Кнопка "Сохранить" для обоих вкладок
        save_button = ttk.Button(settings_window, text="Сохранить", command=lambda: save_settings())
        save_button.pack(pady=10)
    
        def save_settings():
            ad_user = username_entry.get().strip()
            ad_pass = password_entry.get().strip()
            reset_pwd = reset_entry.get().strip()
            ssh_login = ssh_login_entry.get().strip()
            ssh_pass = ssh_password_entry.get().strip()
            if not ad_user or not ad_pass or not reset_pwd or not ssh_login:
                messagebox.showerror("Ошибка", "Заполните все обязательные поля")
                return
            self.settings_manager.set_setting("ad_username", ad_user)
            self.settings_manager.set_setting("ad_password", ad_pass)
            self.settings_manager.set_setting("reset_password", reset_pwd)
            self.settings_manager.set_setting("ssh_login", ssh_login)
            self.settings_manager.set_setting("ssh_password", ssh_pass)
            self.settings_manager.set_setting("ssh_terminal", ssh_terminal_var.get())
            self.ad_credentials = {"username": ad_user, "password": ad_pass}
            self.on_toplevel_close(settings_window, "settings_window_geometry")
    

    def show_ip_window(self, ip):
        top = tk.Toplevel(self.master)
        top.title("IP адрес")
        if "ip_window_geometry" in self.settings_manager.config:
            top.geometry(self.settings_manager.config["ip_window_geometry"])
        else:
            top.geometry("300x100")
        top.protocol("WM_DELETE_WINDOW", lambda w=top: self.on_toplevel_close(w, "ip_window_geometry"))
        ttk.Label(top, text="IP адрес: " + ip).pack(padx=10, pady=10)
        ttk.Button(top, text="Скопировать", command=lambda: self.copy_to_clipboard(ip)).pack(pady=5)

    def on_toplevel_close(self, window, config_key):
        if config_key:
            self.settings_manager.set_setting(config_key, window.geometry())
        window.destroy()

    def copy_to_clipboard(self, ip):
        self.master.clipboard_clear()
        self.master.clipboard_append(ip)

    def ad_sync(self):
        if self.ad_credentials:
            self.perform_ad_sync(self.ad_credentials['username'], self.ad_credentials['password'])
        else:
            self.open_settings()

    def perform_ad_sync(self, username, password):
        ad_users = get_ad_users(AD_SERVER, username, password, AD_BASE_DN, AD_DOMAIN)
        if not ad_users:
            return
        existing_names = {user["name"].lower() for user in self.users}
        new_users = [user for user in ad_users if user["name"].lower() not in existing_names]
        if not new_users:
            messagebox.showinfo("AD Sync", "Нет новых пользователей для добавления.")
            return
        self.show_ad_sync_selection(new_users)

    def show_ad_sync_selection(self, new_users):
        selection_window = tk.Toplevel(self.master)
        selection_window.title("Новые пользователи AD")
        geom = self.settings_manager.get_setting("ad_sync_select_geometry")
        if geom:
            selection_window.geometry(geom)
        selection_window.protocol("WM_DELETE_WINDOW", lambda w=selection_window: self.on_toplevel_close(w, "ad_sync_select_geometry"))
        vars_dict = {}
        for user in new_users:
            var = tk.BooleanVar(value=True)
            vars_dict[user["name"].lower()] = var
            cb = ttk.Checkbutton(selection_window, text=f"{user['name']} ({user['pc_name']})", variable=var)
            cb.pack(anchor="w", padx=10, pady=2)
        def on_confirm():
            self.settings_manager.set_setting("ad_sync_select_geometry", selection_window.geometry())
            selected = [user for user in new_users if vars_dict[user["name"].lower()].get()]
            for user in selected:
                self.user_manager.add_user(user)
            self.users = self.user_manager.get_users()
            self.populate_buttons()
            selection_window.destroy()
        ttk.Button(selection_window, text="Добавить выбранных", command=on_confirm).pack(pady=10)

    def on_closing(self):
        self.settings_manager.set_setting("window_geometry", self.master.geometry())
        self.settings_manager.save_config()
        self.executor.shutdown(wait=False)
        self.master.destroy()

    def show_ip_window(self, ip):
        top = tk.Toplevel(self.master)
        top.title("IP адрес")
        if "ip_window_geometry" in self.settings_manager.config:
            top.geometry(self.settings_manager.config["ip_window_geometry"])
        else:
            top.geometry("300x100")
        top.protocol("WM_DELETE_WINDOW", lambda w=top: self.on_toplevel_close(w, "ip_window_geometry"))
        ttk.Label(top, text="IP адрес: " + ip).pack(padx=10, pady=10)
        ttk.Button(top, text="Скопировать", command=lambda: self.copy_to_clipboard(ip)).pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("1310x734+443+125")
    root.resizable(False, False)
    try:
        root.iconbitmap('ts-logo.ico')
    except Exception as e:
        log_message(f"Ошибка при загрузке иконки: {e}")
    app = MainWindow(root)
    root.mainloop()
