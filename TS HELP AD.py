import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import subprocess
import os
import threading
import queue
import ctypes
import platform
import json
import datetime
import locale
import re
from concurrent.futures import ThreadPoolExecutor
from PIL import Image, ImageTk  # Для иконок
import ldap3  # Для работы с Active Directory

os.chdir(os.path.dirname(os.path.abspath(__file__)))
locale.setlocale(locale.LC_COLLATE, 'ru_RU.UTF-8')

# === Константы и настройки ===
APP_NAME = "User Manager"
CONFIG_FILE = "config.json"
USERS_FILE = "users.json"
DEFAULT_CHECK_INTERVAL = 5  # секунд
LOG_FILE = "app.log"

# === Active Directory Settings ===
AD_SERVER = "DC02.pak-cspmz.ru"  # Замените на адрес вашего AD-сервера
AD_USERNAME = "login"         # Замените на имя пользователя с правами на чтение AD
AD_PASSWORD = "passs"     # Замените на пароль пользователя
AD_BASE_DN = "OU=csp,OU=Users,OU=csp,DC=pak-cspmz,DC=ru"  # Замените на базовый DN для поиска пользователей
AD_DOMAIN = "pak-cspmz.ru"        # Замените на ваш домен

def run_as_admin(command, params):
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", command, params, None, 1)
    if result <= 32:
        raise RuntimeError(f"Ошибка при запуске процесса с повышенными правами: {result}")

def log_message(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now()} - {message}\n")

def load_json(filename, default=None):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return default if default is not None else {}
    except json.JSONDecodeError:
        log_message(f"Ошибка при чтении JSON из {filename}")
        return default if default is not None else {}

def save_json(filename, data):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        log_message(f"Ошибка при записи в {filename}: {e}")

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
            "check_interval": DEFAULT_CHECK_INTERVAL,
            "window_geometry": "800x600",
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
       Дополнительно: 'Редактировать имя ПК' с предустановленным текущим значением и 'Получить IP'."""
    def __init__(self, master, user, available, app, *args, **kwargs):
        self.user = user
        self.available = available
        self.app = app
        button_text = f"{self.user['name']}\n({self.user['pc_name']})"
        self.style = "Green.TButton" if available else "Red.TButton"
        super().__init__(master, text=button_text, style=self.style, command=self.show_actions, *args, **kwargs)
        self.tooltip = tk.StringVar()
        self.update_tooltip()
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
    def update_tooltip(self):
        self.tooltip.set(f"Имя: {self.user['name']}\nПК: {self.user['pc_name']}\nДоступен: {self.available}")
    def on_enter(self, event=None):
        try:
            x, y, _, _ = self.bbox("insert")
        except:
            x, y = 0, 0
        x += self.winfo_rootx() + 25
        y += self.winfo_rooty() + 20
        self.app.tooltip_label.config(textvariable=self.tooltip)
        self.app.tooltip_label.place(x=x, y=y)
        self.app.tooltip_label.lift()
    def on_leave(self, event=None):
        self.app.tooltip_label.place_forget()
    def show_actions(self):
        menu = tk.Menu(self.master, tearoff=0)
        menu.add_command(label="RDP", command=self.rdp_connect)
        menu.add_command(label="Удаленный помощник", command=self.remote_assistance)
        menu.add_command(label="Проводник (C$)", command=self.open_explorer)
        menu.add_command(label="Редактировать имя ПК", command=self.edit_pc_name)
        menu.add_command(label="Получить IP", command=self.get_ip)
        x = self.winfo_rootx()
        y = self.winfo_rooty() + self.winfo_height()
        menu.post(x, y)
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
    def edit_pc_name(self):
        # Предустанавливаем текущее имя ПК в текстовом поле для редактирования
        new_pc_name = simpledialog.askstring("Редактировать имя ПК",
                                               "Введите новое имя ПК:",
                                               initialvalue=self.user["pc_name"])
        if new_pc_name:
            self.app.update_pc_name(self.user, new_pc_name)
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
        self.style = "Green.TButton" if available else "Red.TButton"
        self.config(style=self.style)
        self.update_tooltip()

class MainWindow:
    """Главное окно приложения."""
    def __init__(self, master):
        self.master = master
        self.master.title(APP_NAME)
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.loading = True  # данные могут еще загружаться
        self.configure_timer = None  # для дебаунса
        self.last_canvas_width = None  # для отслеживания изменения ширины

        # Менеджеры настроек и пользователей
        self.settings_manager = SettingsManager(CONFIG_FILE)
        self.user_manager = UserManager(USERS_FILE)
        # Если в файле уже есть данные, используем их – чтобы сохранить внесённые изменения.
        self.users = self.user_manager.get_users()
        if self.users:
            self.loading = False
        self.master.geometry(self.settings_manager.get_setting("window_geometry", "800x600"))

        # Загрузка иконок
        self.icons = self.load_icons()

        # Настройка стилей – современный светло-синий фон кнопок
        self.style = ttk.Style()
        self.style.configure("TButton", padding=5, relief="flat", background="#cce6ff", foreground="black")
        self.style.configure("Green.TButton", background="#cce6ff", foreground="black")
        self.style.configure("Red.TButton", background="#cce6ff", foreground="black")
        self.style.configure("TProgressbar", thickness=10, background="blue")

        # Атрибуты для проверки доступности
        self.buttons = {}
        self.availability_queue = queue.Queue()
        self.executor = ThreadPoolExecutor(max_workers=20)
        self.is_checking_availability = False

        # UI
        self.create_widgets()

        # Всплывающая подсказка
        self.tooltip_label = ttk.Label(self.master, background="#fff", relief="solid", borderwidth=1, padding=5)
        self.tooltip_label.place_forget()

        # Если список пуст, запускаем поток для загрузки из AD
        if not self.users:
            threading.Thread(target=self.load_users_thread, daemon=True).start()
        else:
            self.populate_buttons()

        # Запуск проверки доступности
        self.start_availability_check()

        # Обработчик изменения размеров окна с дебаунсом
        self.master.bind("<Configure>", self.on_configure)

    def load_users_thread(self):
        users = get_ad_users(AD_SERVER, AD_USERNAME, AD_PASSWORD, AD_BASE_DN, AD_DOMAIN)
        if not self.users:
            self.users = users
            self.user_manager.users = users
            self.user_manager.save_users()
        self.loading = False
        self.master.after(0, self.populate_buttons)

    def load_icons(self):
        icons = {}
        try:
            icons["add"] = ImageTk.PhotoImage(Image.open("icons/add.png").resize((16, 16)))
            icons["edit"] = ImageTk.PhotoImage(Image.open("icons/edit.png").resize((16, 16)))
            icons["delete"] = ImageTk.PhotoImage(Image.open("icons/delete.png").resize((16, 16)))
            icons["settings"] = ImageTk.PhotoImage(Image.open("icons/setting.png").resize((16, 16)))
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
        self.canvas.bind("<Button-4>", self.on_mousewheel)  # для Linux
        self.canvas.bind("<Button-5>", self.on_mousewheel)  # для Linux
        self.inner_frame = ttk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.inner_frame, anchor="nw")
        self.inner_frame.bind("<MouseWheel>", self.on_mousewheel)

        # === Нижняя панель ===
        self.bottom_frame = ttk.Frame(self.master, padding=10)
        self.bottom_frame.pack(side="bottom", fill="x")
        self.add_button = ttk.Button(self.bottom_frame, text="Добавить", command=self.add_user,
                                     image=self.icons.get("add"), compound="left")
        self.add_button.pack(side="left", padx=5)
        self.edit_button = ttk.Button(self.bottom_frame, text="Редактировать", command=self.edit_user,
                                      image=self.icons.get("edit"), compound="left")
        self.edit_button.pack(side="left", padx=5)
        self.delete_button = ttk.Button(self.bottom_frame, text="Удалить", command=self.delete_user,
                                        image=self.icons.get("delete"), compound="left")
        self.delete_button.pack(side="left", padx=5)
        self.account_count_label = ttk.Label(self.bottom_frame, text="Найдено аккаунтов: 0")
        self.account_count_label.pack(side="right", padx=5)
        self.progressbar = ttk.Progressbar(self.bottom_frame, orient="horizontal", mode="indeterminate")

        self.populate_buttons()

    def on_mousewheel(self, event):
        if event.delta > 0 and self.canvas.yview()[0] == 0:
            return "break"
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        return "break"

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

    def start_availability_check(self):
        if self.is_checking_availability:
            return
        self.is_checking_availability = True
        self.check_availability_threaded()

    def stop_availability_check(self):
        self.is_checking_availability = False

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

    def check_availability_threaded(self):
        if not self.is_checking_availability:
            return
        for user in self.users:
            if not self.is_checking_availability:
                break
            pc_name = user["pc_name"]
            self.executor.submit(self.check_pc_availability, pc_name)
        check_interval = self.settings_manager.get_setting("check_interval", DEFAULT_CHECK_INTERVAL) * 1000
        self.master.after(check_interval, self.check_availability_threaded)

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
                self.start_availability_check()
            else:
                messagebox.showerror("Ошибка", "Заполните все поля")
        add_window = tk.Toplevel(self.master)
        add_window.title("Добавить пользователя")
        ttk.Label(add_window, text="Имя пользователя:").pack()
        name_entry = ttk.Entry(add_window)
        name_entry.pack()
        ttk.Label(add_window, text="Имя ПК:").pack()
        pc_name_entry = ttk.Entry(add_window)
        pc_name_entry.pack()
        ttk.Button(add_window, text="Сохранить", command=save_user).pack()

    def edit_user(self):
        selected_pc_name = simpledialog.askstring("Редактировать", "Введите имя ПК пользователя для редактирования:")
        if not selected_pc_name:
            return
        user_to_edit = next((user for user in self.users if user["pc_name"] == selected_pc_name), None)
        if not user_to_edit:
            messagebox.showerror("Ошибка", "Пользователь не найден.")
            return
        def save_edited_user():
            name = name_entry.get()
            pc_name = pc_name_entry.get()
            if name and pc_name:
                new_user = {"name": name, "pc_name": pc_name}
                self.user_manager.update_user(selected_pc_name, new_user)
                self.users = self.user_manager.get_users()
                self.populate_buttons()
                edit_window.destroy()
                self.start_availability_check()
            else:
                messagebox.showerror("Ошибка", "Заполните все поля")
        edit_window = tk.Toplevel(self.master)
        edit_window.title("Редактировать пользователя")
        ttk.Label(edit_window, text="Имя пользователя:").pack()
        name_entry = ttk.Entry(edit_window)
        name_entry.insert(0, user_to_edit["name"])
        name_entry.pack()
        ttk.Label(edit_window, text="Имя ПК:").pack()
        pc_name_entry = ttk.Entry(edit_window)
        pc_name_entry.insert(0, user_to_edit["pc_name"])
        pc_name_entry.pack()
        ttk.Button(edit_window, text="Сохранить", command=save_edited_user).pack()

    def update_pc_name(self, user, new_pc_name):
        self.user_manager.update_user(user["pc_name"], {"name": user["name"], "pc_name": new_pc_name})
        self.users = self.user_manager.get_users()
        self.populate_buttons()

    def delete_user(self):
        selected_pc_name = simpledialog.askstring("Удалить", "Введите имя ПК пользователя для удаления:")
        if selected_pc_name:
            if messagebox.askyesno("Подтверждение", f"Вы уверены, что хотите удалить пользователя {selected_pc_name}?"):
                self.user_manager.delete_user(selected_pc_name)
                self.users = self.user_manager.get_users()
                self.populate_buttons()
                self.start_availability_check()

    def open_settings(self):
        def save_settings():
            try:
                check_interval = int(check_interval_entry.get())
                if check_interval <= 0:
                    raise ValueError("Интервал должен быть положительным числом")
                self.settings_manager.set_setting("check_interval", check_interval)
                settings_window.destroy()
                self.start_availability_check()
            except ValueError as e:
                messagebox.showerror("Ошибка", str(e))
        settings_window = tk.Toplevel(self.master)
        settings_window.title("Настройки")
        ttk.Label(settings_window, text="Интервал проверки (секунды):").pack()
        check_interval_entry = ttk.Entry(settings_window)
        check_interval_entry.insert(0, self.settings_manager.get_setting("check_interval", DEFAULT_CHECK_INTERVAL))
        check_interval_entry.pack()
        ttk.Button(settings_window, text="Сохранить", command=save_settings).pack()

    def show_ip_window(self, ip):
        top = tk.Toplevel(self.master)
        top.title("IP адрес")
        # Если ранее сохранялась геометрия для IP-окна, устанавливаем её
        if "ip_window_geometry" in self.settings_manager.config:
            top.geometry(self.settings_manager.config["ip_window_geometry"])
        else:
            top.geometry("300x100")
        top.protocol("WM_DELETE_WINDOW", lambda: self.on_ip_window_close(top))
        ttk.Label(top, text="IP адрес: " + ip).pack(padx=10, pady=10)
        ttk.Button(top, text="Скопировать", command=lambda: self.copy_to_clipboard(ip)).pack(pady=5)

    def on_ip_window_close(self, top):
        self.settings_manager.set_setting("ip_window_geometry", top.geometry())
        top.destroy()

    def copy_to_clipboard(self, ip):
        self.master.clipboard_clear()
        self.master.clipboard_append(ip)

    def on_closing(self):
        self.settings_manager.set_setting("window_geometry", self.master.geometry())
        self.settings_manager.save_config()
        self.stop_availability_check()
        self.executor.shutdown(wait=False)
        self.master.destroy()

# === Запуск приложения ===
if __name__ == "__main__":
    root = tk.Tk()
    try:
        root.iconbitmap('ts-logo.ico')
    except Exception as e:
        log_message(f"Ошибка при загрузке иконки: {e}")
    app = MainWindow(root)
    root.mainloop()
