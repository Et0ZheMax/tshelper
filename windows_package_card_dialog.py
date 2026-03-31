from __future__ import annotations

import json
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ui_geometry import apply_persisted_geometry, bind_geometry_persistence
from windows_catalog import WindowsCatalogError, WindowsCatalogValidationError, upsert_windows_package
from windows_package_assistant import DetectionSuggestion, analyze_installer, normalize_package_id, suggest_detection_from_payload


class WindowsPackageCardDialog(tk.Toplevel):
    def __init__(self, master, catalog_path: str, item: dict | None = None):
        super().__init__(master)
        self.catalog_path = catalog_path
        self.item = item or {}
        self.result: dict | None = None
        self._assistant_notes: list[str] = []
        self._detection_suggestions: list[DetectionSuggestion] = []
        self._detection_suggestion_var = tk.StringVar(value="")

        self.title("Карточка Windows-пакета")
        self.transient(master)
        self.grab_set()
        self.settings = getattr(master, "settings", None)
        if self.settings is not None:
            apply_persisted_geometry(
                self,
                self.settings,
                "windows_package_card_dialog_geometry",
                "880x860+260+80",
                min_width=860,
                min_height=720,
            )
            self._save_geometry = bind_geometry_persistence(self, self.settings, "windows_package_card_dialog_geometry")
        else:
            self.geometry("880x860")
            self.minsize(860, 720)
            self._save_geometry = lambda: None
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        silent_args = self.item.get("silent_args", [])
        detection_command = self.item.get("detection", {}).get("command", [])
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
            "silent_args_json": tk.StringVar(value=json.dumps(silent_args, ensure_ascii=False)),
            "architecture": tk.StringVar(value=self.item.get("architecture", "any")),
            "package_version": tk.StringVar(value=self.item.get("package_version", self.item.get("version", ""))),
            "reboot_behavior": tk.StringVar(value=self.item.get("reboot_behavior", "auto_detect")),
            "detection_type": tk.StringVar(value=self.item.get("detection", {}).get("type", "file_exists")),
            "detection_path": tk.StringVar(value=self.item.get("detection", {}).get("path", "")),
            "detection_value_name": tk.StringVar(value=self.item.get("detection", {}).get("value_name", "")),
            "detection_operator": tk.StringVar(value=self.item.get("detection", {}).get("operator", "==")),
            "detection_value": tk.StringVar(value=self.item.get("detection", {}).get("value", "")),
            "detection_command_json": tk.StringVar(value=json.dumps(detection_command, ensure_ascii=False)),
            "detection_script": tk.StringVar(value=self.item.get("detection", {}).get("script", "")),
        }
        self._build_ui()

    def _build_ui(self):
        container = ttk.Frame(self, padding=12)
        container.pack(fill="both", expand=True)
        container.columnconfigure(1, weight=1)
        container.rowconfigure(1000, weight=1)

        def row(label: str, key: str, values: list[str] | None = None):
            idx = row.counter
            ttk.Label(container, text=label).grid(row=idx, column=0, sticky="w", pady=3)
            if values is None:
                ttk.Entry(container, textvariable=self.vars[key]).grid(row=idx, column=1, columnspan=2, sticky="ew", pady=3)
            else:
                ttk.Combobox(container, textvariable=self.vars[key], values=values, state="readonly").grid(row=idx, column=1, columnspan=2, sticky="ew", pady=3)
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
        src_actions = ttk.Frame(container)
        src_actions.grid(row=src_row, column=2, sticky="w", padx=(6, 0))
        ttk.Button(src_actions, text="Файл…", command=self._pick_source).pack(side="left")
        self.autofill_btn = ttk.Button(src_actions, text="Автозаполнить по файлу", command=self._autofill_by_source)
        self.autofill_btn.pack(side="left", padx=(6, 0))
        row.counter += 1

        helper_row = row.counter
        helper_actions = ttk.Frame(container)
        helper_actions.grid(row=helper_row, column=0, columnspan=3, sticky="ew", pady=(3, 6))
        ttk.Button(helper_actions, text="Сгенерировать id", command=self._generate_id_from_title).pack(side="left")
        ttk.Button(helper_actions, text="Подобрать detection", command=self._pick_detection_suggestions).pack(side="left", padx=(8, 0))
        self.detection_combo = ttk.Combobox(helper_actions, textvariable=self._detection_suggestion_var, state="readonly", width=46)
        self.detection_combo.pack(side="left", padx=(8, 0), fill="x", expand=True)
        ttk.Button(helper_actions, text="Применить вариант", command=self._apply_selected_detection).pack(side="left", padx=(8, 0))
        row.counter += 1

        row("silent_args (JSON-массив)", "silent_args_json")
        row("architecture", "architecture", ["x64", "x86", "any"])
        row("package_version", "package_version")
        row("reboot_behavior", "reboot_behavior", ["auto_detect", "never", "always"])
        row("detection.type", "detection_type", ["file_exists", "registry_exists", "registry_value", "uninstall_display_name", "product_code", "command_success", "powershell_script"])
        row("detection.path", "detection_path")
        row("detection.value_name", "detection_value_name")
        row("detection.operator", "detection_operator", ["==", "!=", ">=", "<=", ">", "<"])
        row("detection.value", "detection_value")
        row("detection.command (JSON-массив)", "detection_command_json")
        row("detection.script", "detection_script")

        check_frame = ttk.Frame(container)
        check_frame.grid(row=row.counter, column=0, columnspan=3, sticky="w", pady=(8, 4))
        ttk.Checkbutton(check_frame, text="enabled", variable=self.vars["enabled"]).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(check_frame, text="requires_admin", variable=self.vars["requires_admin"]).pack(side="left")
        row.counter += 1

        self.assistant_label = ttk.Label(container, text="", foreground="#005a9e", justify="left")
        self.assistant_label.grid(row=row.counter, column=0, columnspan=3, sticky="w", pady=(4, 0))
        row.counter += 1

        self.warning_label = ttk.Label(container, text="", foreground="#b56d00")
        self.warning_label.grid(row=row.counter, column=0, columnspan=3, sticky="w", pady=(4, 0))
        row.counter += 1

        preview_frame = ttk.LabelFrame(container, text="Нормализованный preview")
        preview_frame.grid(row=row.counter, column=0, columnspan=3, sticky="nsew", pady=(8, 4))
        preview_frame.columnconfigure(0, weight=1)
        preview_frame.rowconfigure(0, weight=1)
        self.preview = tk.Text(preview_frame, height=12, wrap="word", state="disabled")
        self.preview.grid(row=0, column=0, sticky="nsew")
        container.rowconfigure(row.counter, weight=1)
        row.counter += 1

        for key, var in self.vars.items():
            if isinstance(var, tk.StringVar):
                var.trace_add("write", lambda *_args, _k=key: self._refresh_preview())
        self.vars["detection_type"].trace_add("write", lambda *_args: self._refresh_preview())
        self._refresh_preview()

        buttons = ttk.Frame(container)
        buttons.grid(row=row.counter, column=0, columnspan=3, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text="Сохранить", command=self._save).pack(side="right")
        ttk.Button(buttons, text="Отмена", command=self.destroy).pack(side="right", padx=(0, 8))

    def _pick_source(self):
        selected = filedialog.askopenfilename(parent=self, title="Выберите инсталлятор")
        if selected:
            self.vars["source_value"].set(selected)

    def _autofill_by_source(self):
        source_value = self.vars["source_value"].get().strip()
        if not source_value:
            selected = filedialog.askopenfilename(parent=self, title="Выберите инсталлятор для автозаполнения")
            if not selected:
                return
            self.vars["source_value"].set(selected)
            source_value = selected
        self.autofill_btn.configure(state="disabled")
        self.warning_label.config(text="Идёт анализ инсталлятора…")

        def worker():
            try:
                result = analyze_installer(source_value)
            except Exception as exc:
                self.after(0, lambda: self._on_autofill_error(exc))
                return
            self.after(0, lambda: self._on_autofill_success(result))

        threading.Thread(target=worker, daemon=True).start()

    def _on_autofill_success(self, result):
        self.autofill_btn.configure(state="normal")
        self._assistant_notes = list(result.notes)
        self._apply_autofill_fields(result.fields)
        self._detection_suggestions = result.detection_suggestions
        self._refresh_detection_combo()
        if self._detection_suggestions:
            self._apply_detection_suggestion(self._detection_suggestions[0])
        self.warning_label.config(text="")
        self._refresh_preview()

    def _on_autofill_error(self, error: Exception):
        self.autofill_btn.configure(state="normal")
        self.warning_label.config(text="")
        messagebox.showerror("Карточка Windows-пакета", f"Не удалось проанализировать инсталлятор: {error}", parent=self)

    def _generate_id_from_title(self):
        base_text = self.vars["title"].get().strip() or self.vars["source_value"].get().strip()
        self.vars["id"].set(normalize_package_id(base_text))

    def _pick_detection_suggestions(self):
        payload = self._build_payload()
        self._detection_suggestions = suggest_detection_from_payload(payload)
        self._assistant_notes = ["Detection-предложения пересчитаны по текущим полям карточки."]
        self._refresh_detection_combo()
        if self._detection_suggestions:
            self._apply_detection_suggestion(self._detection_suggestions[0])
        self._refresh_preview()

    def _refresh_detection_combo(self):
        options = [f"{idx + 1}. {item.title} [{item.confidence}]" for idx, item in enumerate(self._detection_suggestions)]
        self.detection_combo["values"] = options
        if options:
            self._detection_suggestion_var.set(options[0])
        else:
            self._detection_suggestion_var.set("")

    def _apply_selected_detection(self):
        selected = self._detection_suggestion_var.get().strip()
        if not selected:
            return
        index = int(selected.split(".", 1)[0]) - 1
        if index < 0 or index >= len(self._detection_suggestions):
            return
        self._apply_detection_suggestion(self._detection_suggestions[index])
        self._refresh_preview()

    def _apply_autofill_fields(self, fields: dict):
        for key in ("id", "title", "install_type", "package_version", "architecture", "reboot_behavior"):
            if key in fields and key in self.vars and isinstance(self.vars[key], tk.StringVar):
                self.vars[key].set(str(fields[key]))
        if "requires_admin" in fields:
            self.vars["requires_admin"].set(bool(fields["requires_admin"]))
        source = fields.get("source", {}) if isinstance(fields.get("source", {}), dict) else {}
        if "kind" in source:
            self.vars["source_kind"].set(str(source["kind"]))
        if "value" in source:
            self.vars["source_value"].set(str(source["value"]))
        if "silent_args" in fields:
            self.vars["silent_args_json"].set(json.dumps(fields["silent_args"], ensure_ascii=False))

    def _apply_detection_suggestion(self, suggestion: DetectionSuggestion):
        detection = suggestion.detection
        self.vars["detection_type"].set(str(detection.get("type", "file_exists")))
        self.vars["detection_path"].set(str(detection.get("path", "")))
        self.vars["detection_value_name"].set(str(detection.get("value_name", "")))
        self.vars["detection_operator"].set(str(detection.get("operator", "==")))
        self.vars["detection_value"].set(str(detection.get("value", "")))
        self.vars["detection_command_json"].set(json.dumps(detection.get("command", []), ensure_ascii=False))
        self.vars["detection_script"].set(str(detection.get("script", "")))
        self._assistant_notes = [f"Применён detection-вариант: {suggestion.title}.", suggestion.reason]

    def _parse_json_args(self, raw_text: str, field_name: str) -> list[str]:
        try:
            data = json.loads(raw_text.strip() or "[]")
        except json.JSONDecodeError as exc:
            raise ValueError(f"{field_name}: ожидается JSON-массив строк") from exc
        if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
            raise ValueError(f"{field_name}: ожидается JSON-массив строк")
        return [item for item in data if item.strip()]

    def _build_payload(self) -> dict:
        silent_args = self._parse_json_args(self.vars["silent_args_json"].get(), "silent_args")
        detection_command = self._parse_json_args(self.vars["detection_command_json"].get(), "detection.command")
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
            "silent_args": silent_args,
            "architecture": self.vars["architecture"].get().strip(),
            "package_version": self.vars["package_version"].get().strip(),
            "reboot_behavior": self.vars["reboot_behavior"].get().strip(),
            "detection": {
                "type": self.vars["detection_type"].get().strip(),
                "path": self.vars["detection_path"].get().strip(),
                "value_name": self.vars["detection_value_name"].get().strip(),
                "operator": self.vars["detection_operator"].get().strip(),
                "value": self.vars["detection_value"].get().strip(),
                "command": detection_command,
                "script": self.vars["detection_script"].get().strip(),
            },
        }

    def _refresh_preview(self):
        warning_text = ""
        try:
            payload = self._build_payload()
            text = json.dumps(payload, ensure_ascii=False, indent=2)
            detection_type = payload.get("detection", {}).get("type")
            if detection_type == "powershell_script":
                warning_text = "Внимание: powershell_script — доверенный сценарий, используйте только проверенные команды."
            elif detection_type == "product_code":
                warning_text = "Detection по ProductCode выбран: path/value_name/operator не используются."
            elif detection_type == "file_exists":
                warning_text = "Detection file_exists требует корректный путь к файлу."
        except Exception as exc:
            text = f"Ошибка preview: {exc}"

        notes = "\n".join(f"• {note}" for note in self._assistant_notes)
        self.assistant_label.config(text=notes)
        self.warning_label.config(text=warning_text)
        self.preview.config(state="normal")
        self.preview.delete("1.0", tk.END)
        self.preview.insert("1.0", text)
        self.preview.config(state="disabled")

    def _save(self):
        try:
            payload = self._build_payload()
        except ValueError as exc:
            messagebox.showerror("Карточка Windows-пакета", str(exc), parent=self)
            return
        current_id = str(self.item.get("id", "")).strip()
        try:
            self.result = upsert_windows_package(self.catalog_path, payload, current_id=current_id)
        except (WindowsCatalogError, WindowsCatalogValidationError, ValueError) as exc:
            messagebox.showerror("Карточка Windows-пакета", str(exc), parent=self)
            return
        self._on_close()

    def _on_close(self):
        self._save_geometry()
        self.destroy()
