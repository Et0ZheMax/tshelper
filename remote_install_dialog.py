from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable

from remote_ops import SoftwareCatalog


class SoftwareInstallDialog(tk.Toplevel):
    def __init__(self, master, catalog: SoftwareCatalog, on_submit: Callable[[str, bool], None]):
        super().__init__(master)
        self.catalog = catalog
        self.on_submit = on_submit
        self.title("Установка ПО")
        self.transient(master)
        self.grab_set()
        self.resizable(True, True)
        self.geometry("760x480")

        self.search_var = tk.StringVar()
        self.force_reinstall_var = tk.BooleanVar(value=False)
        self.description_var = tk.StringVar(value="Выберите ПО из списка.")
        self._items = sorted(self.catalog.all_enabled("ubuntu"), key=lambda item: item.title.lower())
        self._filtered_items = list(self._items)

        self._build_ui()
        self._refresh_list()
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    def _build_ui(self) -> None:
        container = ttk.Frame(self, padding=12)
        container.pack(fill="both", expand=True)

        ttk.Label(container, text="Поиск:").pack(anchor="w")
        search_entry = ttk.Entry(container, textvariable=self.search_var)
        search_entry.pack(fill="x", pady=(4, 8))
        search_entry.bind("<KeyRelease>", lambda _event: self._refresh_list())

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

    def _refresh_list(self) -> None:
        query = self.search_var.get().strip().lower()
        self._filtered_items = []
        for item in self._items:
            haystack = " ".join([item.title, item.item_id, item.description, " ".join(item.tags)]).lower()
            if not query or query in haystack:
                self._filtered_items.append(item)

        self.listbox.delete(0, tk.END)
        for item in self._filtered_items:
            self.listbox.insert(tk.END, item.title)

        if self._filtered_items:
            self.listbox.selection_set(0)
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
        lines = [item.title, "", item.description or "Описание отсутствует."]
        if item.tags:
            lines.extend(["", f"Теги: {', '.join(item.tags)}"])
        self._set_description("\n".join(lines))

    def _set_description(self, text: str) -> None:
        self.description_text.config(state="normal")
        self.description_text.delete("1.0", tk.END)
        self.description_text.insert("1.0", text)
        self.description_text.config(state="disabled")

    def _submit(self) -> None:
        item = self._selected_item()
        if item is None:
            messagebox.showwarning("Установка ПО", "Выберите элемент ПО для установки.", parent=self)
            return
        self.destroy()
        self.on_submit(item.item_id, bool(self.force_reinstall_var.get()))

    def _cancel(self) -> None:
        self.destroy()
