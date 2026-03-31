from __future__ import annotations

import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from windows_catalog import WindowsCatalogError, WindowsCatalogValidationError, upsert_windows_package


class WindowsPackageCardDialog(tk.Toplevel):
    def __init__(self, master, catalog_path: str, item: dict | None = None):
        super().__init__(master)
        self.catalog_path = catalog_path
        self.item = item or {}
        self.result: dict | None = None

        self.title("Карточка Windows-пакета")
        self.transient(master)
        self.grab_set()
        self.geometry("760x700")

        self.vars = {
            "id": tk.StringVar(value=self.item.get("id", "")),
            "title": tk.StringVar(value=self.item.get("title", "")),
            "install_type": tk.StringVar(value=self.item.get("install_type", "exe")),
            "description": tk.StringVar(value=self.item.get("description", "")),
            "tags": tk.StringVar(value=", ".join(self.item.get("tags", []))),
            "enabled": tk.BooleanVar(value=bool(self.item.get("enabled", True))),
            "requires_admin": tk.BooleanVar(value=bool(self.item.get("requires_admin", True))),
            "timeout_sec": tk.StringVar(value=str(self.item.get("timeout_sec", 1200))),
            "source_kind": tk.StringVar(value=self.item.get("source", {}).get("kind", "file_path")),
            "source_value": tk.StringVar(value=self.item.get("source", {}).get("value", "")),
            "silent_args": tk.StringVar(value=" ".join(self.item.get("silent_args", []))),
            "architecture": tk.StringVar(value=self.item.get("architecture", "any")),
            "package_version": tk.StringVar(value=self.item.get("package_version", self.item.get("version", ""))),
            "reboot_behavior": tk.StringVar(value=self.item.get("reboot_behavior", "auto_detect")),
            "detection_type": tk.StringVar(value=self.item.get("detection", {}).get("type", "file_exists")),
            "detection_path": tk.StringVar(value=self.item.get("detection", {}).get("path", "")),
            "detection_value_name": tk.StringVar(value=self.item.get("detection", {}).get("value_name", "")),
            "detection_operator": tk.StringVar(value=self.item.get("detection", {}).get("operator", "==")),
            "detection_value": tk.StringVar(value=self.item.get("detection", {}).get("value", "")),
            "detection_command": tk.StringVar(value=" ".join(self.item.get("detection", {}).get("command", []))),
            "detection_script": tk.StringVar(value=self.item.get("detection", {}).get("script", "")),
        }
        self._build_ui()

    def _build_ui(self):
        container = ttk.Frame(self, padding=12)
        container.pack(fill="both", expand=True)
        container.columnconfigure(1, weight=1)

        def row(label: str, key: str, values: list[str] | None = None):
            idx = row.counter
            ttk.Label(container, text=label).grid(row=idx, column=0, sticky="w", pady=3)
            if values is None:
                ttk.Entry(container, textvariable=self.vars[key]).grid(row=idx, column=1, sticky="ew", pady=3)
            else:
                ttk.Combobox(container, textvariable=self.vars[key], values=values, state="readonly").grid(row=idx, column=1, sticky="ew", pady=3)
            row.counter += 1
        row.counter = 0

        row("id", "id")
        row("title", "title")
        row("install_type", "install_type", ["exe", "msi", "msix", "powershell", "cmd", "winget"])
        row("description", "description")
        row("tags", "tags")
        row("timeout_sec", "timeout_sec")
        row("source.kind", "source_kind", ["file_path", "unc_path", "url", "winget_id"])

        src_row = row.counter
        ttk.Label(container, text="source.value").grid(row=src_row, column=0, sticky="w", pady=3)
        ttk.Entry(container, textvariable=self.vars["source_value"]).grid(row=src_row, column=1, sticky="ew", pady=3)
        ttk.Button(container, text="Файл…", command=self._pick_source).grid(row=src_row, column=2, sticky="w", padx=(6, 0))
        row.counter += 1

        row("silent_args", "silent_args")
        row("architecture", "architecture", ["x64", "x86", "any"])
        row("package_version", "package_version")
        row("reboot_behavior", "reboot_behavior", ["auto_detect", "never", "always"])
        row("detection.type", "detection_type", ["file_exists", "registry_exists", "registry_value", "uninstall_display_name", "product_code", "command_success", "powershell_script"])
        row("detection.path", "detection_path")
        row("detection.value_name", "detection_value_name")
        row("detection.operator", "detection_operator", ["==", "!=", ">=", "<=", ">", "<"])
        row("detection.value", "detection_value")
        row("detection.command", "detection_command")
        row("detection.script", "detection_script")

        check_frame = ttk.Frame(container)
        check_frame.grid(row=row.counter, column=0, columnspan=3, sticky="w", pady=(8, 4))
        ttk.Checkbutton(check_frame, text="enabled", variable=self.vars["enabled"]).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(check_frame, text="requires_admin", variable=self.vars["requires_admin"]).pack(side="left")
        row.counter += 1

        preview_frame = ttk.LabelFrame(container, text="Preview")
        preview_frame.grid(row=row.counter, column=0, columnspan=3, sticky="nsew", pady=(8, 4))
        preview_frame.columnconfigure(0, weight=1)
        self.preview = tk.Text(preview_frame, height=8, wrap="word", state="disabled")
        self.preview.grid(row=0, column=0, sticky="nsew")
        row.counter += 1

        for key, var in self.vars.items():
            if isinstance(var, tk.StringVar):
                var.trace_add("write", lambda *_args, _k=key: self._refresh_preview())
        self._refresh_preview()

        buttons = ttk.Frame(container)
        buttons.grid(row=row.counter, column=0, columnspan=3, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text="Сохранить", command=self._save).pack(side="right")
        ttk.Button(buttons, text="Отмена", command=self.destroy).pack(side="right", padx=(0, 8))

    def _pick_source(self):
        selected = filedialog.askopenfilename(parent=self, title="Выберите инсталлятор")
        if selected:
            self.vars["source_value"].set(selected)

    def _build_payload(self) -> dict:
        detection_command = self.vars["detection_command"].get().strip()
        return {
            "id": self.vars["id"].get().strip(),
            "title": self.vars["title"].get().strip(),
            "os_family": "windows",
            "install_type": self.vars["install_type"].get().strip(),
            "description": self.vars["description"].get().strip(),
            "tags": self.vars["tags"].get().strip(),
            "enabled": bool(self.vars["enabled"].get()),
            "requires_admin": bool(self.vars["requires_admin"].get()),
            "timeout_sec": self.vars["timeout_sec"].get().strip(),
            "source": {
                "kind": self.vars["source_kind"].get().strip(),
                "value": self.vars["source_value"].get().strip(),
            },
            "silent_args": [arg for arg in self.vars["silent_args"].get().split() if arg],
            "architecture": self.vars["architecture"].get().strip(),
            "package_version": self.vars["package_version"].get().strip(),
            "reboot_behavior": self.vars["reboot_behavior"].get().strip(),
            "detection": {
                "type": self.vars["detection_type"].get().strip(),
                "path": self.vars["detection_path"].get().strip(),
                "value_name": self.vars["detection_value_name"].get().strip(),
                "operator": self.vars["detection_operator"].get().strip(),
                "value": self.vars["detection_value"].get().strip(),
                "command": [arg for arg in detection_command.split() if arg],
                "script": self.vars["detection_script"].get().strip(),
            },
        }

    def _refresh_preview(self):
        payload = self._build_payload()
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        self.preview.config(state="normal")
        self.preview.delete("1.0", tk.END)
        self.preview.insert("1.0", text)
        self.preview.config(state="disabled")

    def _save(self):
        payload = self._build_payload()
        current_id = str(self.item.get("id", "")).strip()
        try:
            self.result = upsert_windows_package(self.catalog_path, payload, current_id=current_id)
        except (WindowsCatalogError, WindowsCatalogValidationError, ValueError) as exc:
            messagebox.showerror("Карточка Windows-пакета", str(exc), parent=self)
            return
        self.destroy()
