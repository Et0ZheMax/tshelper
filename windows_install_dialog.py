from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable

from windows_catalog import WindowsCatalogError, delete_windows_package, disable_windows_package, load_catalog_payload
from windows_package_card_dialog import WindowsPackageCardDialog


class WindowsInstallDialog(tk.Toplevel):
    def __init__(
        self,
        master,
        catalog_path: str,
        on_install: Callable[[str, bool, bool], None],
        on_check: Callable[[str], None],
        on_open_log: Callable[[], None],
        runtime_info_provider: Callable[[], dict[str, str]] | None = None,
    ):
        super().__init__(master)
        self.catalog_path = catalog_path
        self.on_install = on_install
        self.on_check = on_check
        self.on_open_log = on_open_log
        self.runtime_info_provider = runtime_info_provider or (lambda: {})

        self.title("Установка ПО Windows")
        self.geometry("1000x620")
        self.transient(master)
        self.grab_set()

        self.search_var = tk.StringVar()
        self.tag_var = tk.StringVar(value="all")
        self.force_var = tk.BooleanVar(value=False)
        self.skip_pre_detection_var = tk.BooleanVar(value=False)
        self._raw_items: list[dict] = []
        self._filtered_items: list[dict] = []
        self._build_ui()
        self._reload_catalog()
        self._refresh_runtime_info()

    def _build_ui(self):
        container = ttk.Frame(self, padding=12)
        container.pack(fill="both", expand=True)

        runtime_frame = ttk.LabelFrame(container, text="Контекст выполнения")
        runtime_frame.pack(fill="x", pady=(0, 8))
        runtime_frame.columnconfigure(1, weight=1)
        self.backend_label = ttk.Label(runtime_frame, text="-")
        self.target_label = ttk.Label(runtime_frame, text="-")
        self.mode_label = ttk.Label(runtime_frame, text="-")
        ttk.Label(runtime_frame, text="Backend:").grid(row=0, column=0, sticky="w", padx=(8, 4), pady=3)
        self.backend_label.grid(row=0, column=1, sticky="w", pady=3)
        ttk.Label(runtime_frame, text="Target host:").grid(row=1, column=0, sticky="w", padx=(8, 4), pady=3)
        self.target_label.grid(row=1, column=1, sticky="w", pady=3)
        ttk.Label(runtime_frame, text="Режим:").grid(row=2, column=0, sticky="w", padx=(8, 4), pady=3)
        self.mode_label.grid(row=2, column=1, sticky="w", pady=3)
        ttk.Button(runtime_frame, text="Обновить", command=self._refresh_runtime_info).grid(row=0, column=2, rowspan=3, padx=(6, 8), pady=3)

        top = ttk.Frame(container)
        top.pack(fill="x")
        ttk.Label(top, text="Поиск").pack(side="left")
        entry = ttk.Entry(top, textvariable=self.search_var)
        entry.pack(side="left", fill="x", expand=True, padx=(6, 8))
        entry.bind("<KeyRelease>", lambda _e: self._refresh_list())
        self.tag_combo = ttk.Combobox(top, textvariable=self.tag_var, state="readonly")
        self.tag_combo.pack(side="left")
        self.tag_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_list())

        actions = ttk.Frame(container)
        actions.pack(fill="x", pady=(8, 8))
        self.install_btn = ttk.Button(actions, text="Установить", command=self._install)
        self.install_btn.pack(side="left")
        self.check_btn = ttk.Button(actions, text="Проверить наличие", command=self._check)
        self.check_btn.pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Добавить", command=self._add).pack(side="left", padx=(16, 0))
        ttk.Button(actions, text="Редактировать", command=self._edit).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Отключить/Удалить", command=self._disable_delete).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Открыть лог", command=self.on_open_log).pack(side="right")

        split = ttk.PanedWindow(container, orient="horizontal")
        split.pack(fill="both", expand=True)

        left = ttk.Frame(split)
        right = ttk.Frame(split)
        split.add(left, weight=3)
        split.add(right, weight=2)

        self.listbox = tk.Listbox(left, exportselection=False)
        self.listbox.pack(side="left", fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", lambda _e: self._update_card())
        scrollbar = ttk.Scrollbar(left, orient="vertical", command=self.listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.listbox.config(yscrollcommand=scrollbar.set)

        self.card_text = tk.Text(right, wrap="word", state="disabled")
        self.card_text.pack(fill="both", expand=True)
        ttk.Checkbutton(container, text="Принудительная переустановка", variable=self.force_var).pack(anchor="w", pady=(8, 0))
        ttk.Checkbutton(
            container,
            text="Пропустить проверку перед установкой",
            variable=self.skip_pre_detection_var,
        ).pack(anchor="w", pady=(4, 0))

    def _refresh_runtime_info(self):
        info = self.runtime_info_provider() or {}
        backend = info.get("backend", "local_subprocess")
        target_host = info.get("target_host", "localhost")
        mode = info.get("mode", "local")
        self.backend_label.config(text=backend)
        self.target_label.config(text=target_host)
        self.mode_label.config(text=mode)
        invalid_remote = backend == "psexec" and not target_host.strip()
        state = "disabled" if invalid_remote else "normal"
        self.install_btn.config(state=state)
        self.check_btn.config(state=state)

    def _reload_catalog(self, selected_id: str = ""):
        payload = load_catalog_payload(self.catalog_path)
        self._raw_items = [row for row in payload.get("software", []) if isinstance(row, dict)]
        tags = sorted({tag for row in self._raw_items for tag in row.get("tags", []) if isinstance(tag, str)})
        self.tag_combo["values"] = ["all", *tags]
        self.tag_var.set(self.tag_var.get() if self.tag_var.get() in self.tag_combo["values"] else "all")
        self._refresh_list(selected_id)

    def _refresh_list(self, selected_id: str = ""):
        query = self.search_var.get().strip().lower()
        tag = self.tag_var.get().strip()
        self._filtered_items = []
        for item in self._raw_items:
            title = str(item.get("title", ""))
            item_id = str(item.get("id", ""))
            description = str(item.get("description", ""))
            tags = [str(x) for x in item.get("tags", []) if isinstance(x, str)]
            if tag != "all" and tag not in tags:
                continue
            haystack = f"{title} {item_id} {description} {' '.join(tags)}".lower()
            if query and query not in haystack:
                continue
            self._filtered_items.append(item)

        self.listbox.delete(0, tk.END)
        for row in self._filtered_items:
            title = row.get("title", "")
            if not row.get("enabled", True):
                title = f"{title} [disabled]"
            self.listbox.insert(tk.END, title)

        if not self._filtered_items:
            self._set_card("По фильтру ничего не найдено.")
            return
        index = 0
        if selected_id:
            for idx, row in enumerate(self._filtered_items):
                if str(row.get("id", "")) == selected_id:
                    index = idx
                    break
        self.listbox.selection_set(index)
        self._update_card()

    def _selected_item(self) -> dict | None:
        sel = self.listbox.curselection()
        if not sel:
            return None
        idx = sel[0]
        return self._filtered_items[idx] if idx < len(self._filtered_items) else None

    def _set_card(self, text: str):
        self.card_text.config(state="normal")
        self.card_text.delete("1.0", tk.END)
        self.card_text.insert("1.0", text)
        self.card_text.config(state="disabled")

    def _update_card(self):
        row = self._selected_item()
        if not row:
            self._set_card("Выберите пакет")
            return
        lines = [
            f"{row.get('title', '')}",
            "",
            f"id: {row.get('id', '')}",
            f"type: {row.get('install_type', '')}",
            f"source: {row.get('source', {}).get('value', '')}",
            f"description: {row.get('description', '')}",
            f"detection type: {row.get('detection', {}).get('type', '')}",
            f"requires admin: {'да' if row.get('requires_admin', True) else 'нет'}",
            f"architecture: {row.get('architecture', 'any')}",
            f"timeout: {row.get('timeout_sec', 1200)}",
            f"enabled: {'да' if row.get('enabled', True) else 'нет'}",
            f"tags: {', '.join(row.get('tags', []))}",
        ]
        self._set_card("\n".join(lines))

    def _add(self):
        dialog = WindowsPackageCardDialog(self, self.catalog_path)
        self.wait_window(dialog)
        if dialog.result:
            self._reload_catalog(selected_id=dialog.result.get("id", ""))

    def _edit(self):
        item = self._selected_item()
        if not item:
            messagebox.showwarning("Установка ПО Windows", "Выберите запись для редактирования", parent=self)
            return
        dialog = WindowsPackageCardDialog(self, self.catalog_path, item=item)
        self.wait_window(dialog)
        if dialog.result:
            self._reload_catalog(selected_id=dialog.result.get("id", item.get("id", "")))

    def _disable_delete(self):
        item = self._selected_item()
        if not item:
            return
        package_id = str(item.get("id", ""))
        answer = messagebox.askyesnocancel(
            "Отключить/Удалить",
            "Да — удалить пакет из каталога.\nНет — отключить пакет.\nОтмена — ничего не делать.",
            parent=self,
        )
        if answer is None:
            return
        try:
            if answer:
                delete_windows_package(self.catalog_path, package_id)
            else:
                disable_windows_package(self.catalog_path, package_id)
        except WindowsCatalogError as exc:
            messagebox.showerror("Установка ПО Windows", str(exc), parent=self)
            return
        self._reload_catalog()

    def _install(self):
        self._refresh_runtime_info()
        item = self._selected_item()
        if not item:
            messagebox.showwarning("Установка ПО Windows", "Выберите пакет", parent=self)
            return
        if not item.get("enabled", True):
            messagebox.showwarning("Установка ПО Windows", "Пакет отключён и не может быть установлен", parent=self)
            return
        self.on_install(
            str(item.get("id", "")),
            bool(self.force_var.get()),
            bool(self.skip_pre_detection_var.get()),
        )

    def _check(self):
        self._refresh_runtime_info()
        item = self._selected_item()
        if not item:
            return
        self.on_check(str(item.get("id", "")))
