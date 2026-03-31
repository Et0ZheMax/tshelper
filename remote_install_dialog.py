from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from ui_geometry import apply_persisted_geometry, bind_geometry_persistence
from remote_ops import (
    CatalogError,
    CatalogValidationError,
    SoftwareCatalog,
    delete_software_entry,
    disable_software_entry,
    upsert_software_entry,
)


class SoftwareCardDialog(tk.Toplevel):
    def __init__(self, master, catalog_path: str, item=None):
        super().__init__(master)
        self.catalog_path = catalog_path
        self.item = item
        self.result: dict | None = None

        self.title("Карточка ПО")
        self.transient(master)
        self.grab_set()
        self.resizable(True, True)
        self.settings = getattr(master, "settings", None)
        if self.settings is not None:
            apply_persisted_geometry(
                self,
                self.settings,
                "software_card_dialog_geometry",
                "620x520+300+120",
                min_width=600,
                min_height=480,
            )
            self._save_geometry = bind_geometry_persistence(self, self.settings, "software_card_dialog_geometry")
        else:
            self.geometry("620x520")
            self.minsize(600, 480)
            self._save_geometry = lambda: None
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.title_var = tk.StringVar(value=getattr(item, "title", ""))
        self.id_var = tk.StringVar(value=getattr(item, "item_id", ""))
        self.os_family_var = tk.StringVar(value=getattr(item, "os_family", "ubuntu") or "ubuntu")
        self.install_type_var = tk.StringVar(value=getattr(item, "install_type", "apt") or "apt")
        self.description_var = tk.StringVar(value=getattr(item, "description", ""))
        self.tags_var = tk.StringVar(value=", ".join(getattr(item, "tags", []) or []))
        self.timeout_var = tk.StringVar(value=str(getattr(item, "timeout_sec", 1800) or 1800))
        self.requires_sudo_var = tk.BooleanVar(value=bool(getattr(item, "requires_sudo", True)))
        self.enabled_var = tk.BooleanVar(value=bool(getattr(item, "enabled", True)))
        packages = getattr(item, "packages", []) or []
        package_name = getattr(item, "package_name", "")
        self.apt_input_var = tk.StringVar(value=" ".join(packages) if packages else package_name)
        self.local_path_var = tk.StringVar(value=getattr(item, "local_path", ""))
        self.url_var = tk.StringVar(value=getattr(item, "url", ""))

        self._build_ui()
        self._switch_install_type_ui()

    def _build_ui(self) -> None:
        container = ttk.Frame(self, padding=12)
        container.pack(fill="both", expand=True)
        container.columnconfigure(1, weight=1)

        row = 0

        def add_label(text: str):
            nonlocal row
            ttk.Label(container, text=text).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=4)

        def add_entry(var: tk.StringVar):
            nonlocal row
            entry = ttk.Entry(container, textvariable=var)
            entry.grid(row=row, column=1, sticky="ew", pady=4)
            row += 1
            return entry

        add_label("title")
        add_entry(self.title_var)

        add_label("id")
        add_entry(self.id_var)

        add_label("os_family")
        os_combo = ttk.Combobox(container, textvariable=self.os_family_var, values=["ubuntu"], state="normal")
        os_combo.grid(row=row, column=1, sticky="ew", pady=4)
        row += 1

        add_label("install_type")
        install_combo = ttk.Combobox(
            container,
            textvariable=self.install_type_var,
            values=["apt", "deb_file", "deb_url"],
            state="readonly",
        )
        install_combo.grid(row=row, column=1, sticky="ew", pady=4)
        install_combo.bind("<<ComboboxSelected>>", lambda _event: self._switch_install_type_ui())
        row += 1

        add_label("description")
        add_entry(self.description_var)

        add_label("tags")
        add_entry(self.tags_var)

        add_label("timeout_sec")
        add_entry(self.timeout_var)

        add_label("requires_sudo")
        ttk.Checkbutton(container, variable=self.requires_sudo_var).grid(row=row, column=1, sticky="w", pady=4)
        row += 1

        add_label("enabled")
        ttk.Checkbutton(container, variable=self.enabled_var).grid(row=row, column=1, sticky="w", pady=4)
        row += 1

        self.install_specific_frame = ttk.Frame(container)
        self.install_specific_frame.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        self.install_specific_frame.columnconfigure(1, weight=1)
        row += 1

        buttons = ttk.Frame(container)
        buttons.grid(row=row, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text="Сохранить", command=self._save).pack(side="right")
        ttk.Button(buttons, text="Отмена", command=self._on_close).pack(side="right", padx=(0, 8))

    def _switch_install_type_ui(self) -> None:
        for child in self.install_specific_frame.winfo_children():
            child.destroy()

        install_type = self.install_type_var.get().strip().lower()
        if install_type == "apt":
            ttk.Label(
                self.install_specific_frame,
                text="Пакеты apt (имя пакета или apt install ...):",
            ).grid(row=0, column=0, sticky="w", pady=4)
            ttk.Entry(self.install_specific_frame, textvariable=self.apt_input_var).grid(
                row=0, column=1, sticky="ew", pady=4
            )
        elif install_type == "deb_file":
            ttk.Label(self.install_specific_frame, text="Локальный путь к .deb:").grid(row=0, column=0, sticky="w", pady=4)
            ttk.Entry(self.install_specific_frame, textvariable=self.local_path_var).grid(row=0, column=1, sticky="ew", pady=4)
            ttk.Button(self.install_specific_frame, text="Выбрать…", command=self._pick_deb_file).grid(row=0, column=2, sticky="w", padx=(8, 0), pady=4)
        elif install_type == "deb_url":
            ttk.Label(self.install_specific_frame, text="URL .deb-пакета:").grid(row=0, column=0, sticky="w", pady=4)
            ttk.Entry(self.install_specific_frame, textvariable=self.url_var).grid(row=0, column=1, sticky="ew", pady=4)

    def _pick_deb_file(self) -> None:
        selected = filedialog.askopenfilename(
            title="Выберите .deb файл",
            filetypes=[("Debian package", "*.deb"), ("Все файлы", "*.*")],
            parent=self,
        )
        if selected:
            self.local_path_var.set(selected)

    def _save(self) -> None:
        payload = {
            "title": self.title_var.get().strip(),
            "id": self.id_var.get().strip(),
            "os_family": self.os_family_var.get().strip().lower(),
            "install_type": self.install_type_var.get().strip().lower(),
            "description": self.description_var.get().strip(),
            "tags": self.tags_var.get(),
            "timeout_sec": self.timeout_var.get().strip(),
            "requires_sudo": bool(self.requires_sudo_var.get()),
            "enabled": bool(self.enabled_var.get()),
            "apt_input": self.apt_input_var.get().strip(),
            "local_path": self.local_path_var.get().strip(),
            "url": self.url_var.get().strip(),
        }
        current_id = self.item.item_id if self.item else ""
        try:
            self.result = upsert_software_entry(self.catalog_path, payload, current_id=current_id)
        except (CatalogError, CatalogValidationError, ValueError) as exc:
            messagebox.showerror("Карточка ПО", str(exc), parent=self)
            return
        self._on_close()

    def _on_close(self):
        self._save_geometry()
        self.destroy()


class SoftwareInstallDialog(tk.Toplevel):
    def __init__(self, master, catalog: SoftwareCatalog, on_submit: Callable[[str, bool], None], settings=None):
        super().__init__(master)
        self.catalog = catalog
        self.on_submit = on_submit
        self.title("Установка ПО")
        self.transient(master)
        self.grab_set()
        self.resizable(True, True)
        self.settings = settings or getattr(master, "settings", None)
        if self.settings is not None:
            apply_persisted_geometry(
                self,
                self.settings,
                "software_install_dialog_geometry",
                "840x520+240+120",
                min_width=800,
                min_height=500,
            )
            self._save_geometry = bind_geometry_persistence(self, self.settings, "software_install_dialog_geometry")
        else:
            self.geometry("840x520")
            self.minsize(800, 500)
            self._save_geometry = lambda: None

        self.search_var = tk.StringVar()
        self.force_reinstall_var = tk.BooleanVar(value=False)
        self._items = []
        self._filtered_items = []

        self._build_ui()
        self._reload_catalog()
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    def _build_ui(self) -> None:
        container = ttk.Frame(self, padding=12)
        container.pack(fill="both", expand=True)

        ttk.Label(container, text="Поиск:").pack(anchor="w")
        search_entry = ttk.Entry(container, textvariable=self.search_var)
        search_entry.pack(fill="x", pady=(4, 8))
        search_entry.bind("<KeyRelease>", lambda _event: self._refresh_list())

        actions = ttk.Frame(container)
        actions.pack(fill="x", pady=(0, 8))
        ttk.Button(actions, text="Добавить", command=self._add_entry).pack(side="left")
        ttk.Button(actions, text="Редактировать", command=self._edit_entry).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Удалить/Отключить", command=self._delete_or_disable_entry).pack(side="left", padx=(8, 0))

        content = ttk.PanedWindow(container, orient="horizontal")
        content.pack(fill="both", expand=True)

        left_frame = ttk.Frame(content, padding=(0, 0, 8, 0))
        right_frame = ttk.Frame(content)
        content.add(left_frame, weight=3)
        content.add(right_frame, weight=2)

        self.listbox = tk.Listbox(left_frame, exportselection=False)
        self.listbox.pack(side="left", fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", lambda _event: self._update_description())
        scrollbar = ttk.Scrollbar(left_frame, orient="vertical", command=self.listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.listbox.config(yscrollcommand=scrollbar.set)

        ttk.Label(right_frame, text="Описание:").pack(anchor="w")
        self.description_text = tk.Text(right_frame, height=14, wrap="word", state="disabled")
        self.description_text.pack(fill="both", expand=True, pady=(4, 8))

        ttk.Checkbutton(right_frame, text="Принудительно переустановить", variable=self.force_reinstall_var).pack(anchor="w")

        buttons = ttk.Frame(container)
        buttons.pack(fill="x", pady=(10, 0))
        ttk.Button(buttons, text="Установить", command=self._submit).pack(side="right")
        ttk.Button(buttons, text="Отмена", command=self._cancel).pack(side="right", padx=(0, 8))

    def _reload_catalog(self, selected_id: str = "") -> None:
        self.catalog = SoftwareCatalog.load(self.catalog.source_path)
        self._items = sorted(self.catalog.all_enabled("ubuntu"), key=lambda item: item.title.lower())
        self._refresh_list(selected_id=selected_id)

    def _refresh_list(self, selected_id: str = "") -> None:
        query = self.search_var.get().strip().lower()
        self._filtered_items = []
        for item in self._items:
            haystack = " ".join([item.title, item.item_id, item.description, " ".join(item.tags)]).lower()
            if not query or query in haystack:
                self._filtered_items.append(item)

        self.listbox.delete(0, tk.END)
        for item in self._filtered_items:
            self.listbox.insert(tk.END, item.title)

        target_index = 0
        if selected_id:
            for index, item in enumerate(self._filtered_items):
                if item.item_id == selected_id:
                    target_index = index
                    break
        if self._filtered_items:
            self.listbox.selection_set(target_index)
            self._update_description()
        else:
            self._set_description("По вашему запросу ничего не найдено.")

    def _selected_item(self):
        selection = self.listbox.curselection()
        if not selection:
            return None
        index = selection[0]
        if index >= len(self._filtered_items):
            return None
        return self._filtered_items[index]

    def _update_description(self) -> None:
        item = self._selected_item()
        if item is None:
            self._set_description("Выберите ПО из списка.")
            return
        lines = [item.title, "", item.description or "Описание отсутствует.", "", f"id: {item.item_id}"]
        lines.append(f"install_type: {item.install_type}")
        lines.append(f"requires_sudo: {'да' if item.requires_sudo else 'нет'}")
        if item.tags:
            lines.extend(["", f"Теги: {', '.join(item.tags)}"])
        self._set_description("\n".join(lines))

    def _set_description(self, text: str) -> None:
        self.description_text.config(state="normal")
        self.description_text.delete("1.0", tk.END)
        self.description_text.insert("1.0", text)
        self.description_text.config(state="disabled")

    def _add_entry(self) -> None:
        dialog = SoftwareCardDialog(
            self,
            catalog_path=self.catalog.source_path,
            item=None,
        )
        self.wait_window(dialog)
        if dialog.result:
            self._reload_catalog(selected_id=dialog.result.get("id", ""))

    def _edit_entry(self) -> None:
        item = self._selected_item()
        if item is None:
            messagebox.showwarning("Каталог ПО", "Выберите запись для редактирования.", parent=self)
            return
        dialog = SoftwareCardDialog(
            self,
            catalog_path=self.catalog.source_path,
            item=item,
        )
        self.wait_window(dialog)
        if dialog.result:
            self._reload_catalog(selected_id=dialog.result.get("id", item.item_id))

    def _delete_or_disable_entry(self) -> None:
        item = self._selected_item()
        if item is None:
            messagebox.showwarning("Каталог ПО", "Выберите запись для удаления или отключения.", parent=self)
            return
        answer = messagebox.askyesnocancel(
            "Удалить/Отключить",
            "Да — удалить запись из каталога.\nНет — только отключить запись.\nОтмена — ничего не делать.",
            parent=self,
        )
        if answer is None:
            return
        try:
            if answer:
                delete_software_entry(self.catalog.source_path, item.item_id)
            else:
                disable_software_entry(self.catalog.source_path, item.item_id)
        except CatalogError as exc:
            messagebox.showerror("Каталог ПО", str(exc), parent=self)
            return
        self._reload_catalog()

    def _submit(self) -> None:
        item = self._selected_item()
        if item is None:
            messagebox.showwarning("Установка ПО", "Выберите элемент ПО для установки.", parent=self)
            return
        self.destroy()
        self.on_submit(item.item_id, bool(self.force_reinstall_var.get()))

    def _cancel(self) -> None:
        self._save_geometry()
        self.destroy()
