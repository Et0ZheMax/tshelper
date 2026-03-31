from __future__ import annotations

import re
import tkinter as tk
from typing import Callable


_GEOMETRY_RE = re.compile(r"^(\d+)x(\d+)([+-]\d+)([+-]\d+)$")


def _parse_geometry(raw: str) -> tuple[int, int, int, int] | None:
    if not raw:
        return None
    match = _GEOMETRY_RE.match(raw.strip())
    if not match:
        return None
    try:
        width = int(match.group(1))
        height = int(match.group(2))
        pos_x = int(match.group(3))
        pos_y = int(match.group(4))
    except Exception:
        return None
    return width, height, pos_x, pos_y


def _coerce_on_screen(
    root: tk.Misc,
    width: int,
    height: int,
    pos_x: int,
    pos_y: int,
    min_width: int,
    min_height: int,
) -> tuple[int, int, int, int]:
    root.update_idletasks()
    screen_w = max(640, int(root.winfo_screenwidth() or 0))
    screen_h = max(480, int(root.winfo_screenheight() or 0))

    safe_w = min(max(width, min_width), screen_w)
    safe_h = min(max(height, min_height), screen_h)

    max_x = max(0, screen_w - safe_w)
    max_y = max(0, screen_h - safe_h)
    safe_x = min(max(pos_x, 0), max_x)
    safe_y = min(max(pos_y, 0), max_y)
    return safe_w, safe_h, safe_x, safe_y


def apply_persisted_geometry(
    window: tk.Misc,
    settings,
    key: str,
    fallback_geometry: str,
    *,
    min_width: int = 480,
    min_height: int = 320,
) -> None:
    if hasattr(window, "minsize"):
        window.minsize(min_width, min_height)

    raw_value = str(settings.get_setting(key, "") or "").strip()
    parsed = _parse_geometry(raw_value) if raw_value else None
    if parsed is None:
        parsed = _parse_geometry(fallback_geometry)

    if parsed is None:
        width = max(min_width, 640)
        height = max(min_height, 420)
        pos_x = 120
        pos_y = 80
    else:
        width, height, pos_x, pos_y = parsed

    safe_w, safe_h, safe_x, safe_y = _coerce_on_screen(window, width, height, pos_x, pos_y, min_width, min_height)
    window.geometry(f"{safe_w}x{safe_h}+{safe_x}+{safe_y}")


def bind_geometry_persistence(
    window: tk.Misc,
    settings,
    key: str,
    *,
    debounce_ms: int = 500,
) -> Callable[[], None]:
    state = {"job": None, "closed": False}

    def _save_now() -> None:
        if state["closed"]:
            return
        try:
            settings.set_setting(key, window.geometry())
        except Exception:
            pass

    def _on_configure(_event=None):
        if state["closed"]:
            return
        prev = state.get("job")
        if prev:
            try:
                window.after_cancel(prev)
            except Exception:
                pass
        state["job"] = window.after(debounce_ms, _save_now)

    def _on_close() -> None:
        if state["closed"]:
            return
        job = state.get("job")
        if job:
            try:
                window.after_cancel(job)
            except Exception:
                pass
        _save_now()
        state["closed"] = True

    window.bind("<Configure>", _on_configure, add="+")
    return _on_close
