from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes


class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob_from_bytes(data: bytes) -> DataBlob:
    buffer = ctypes.create_string_buffer(data)
    blob = DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    blob._buffer = buffer  # type: ignore[attr-defined]
    return blob


def _bytes_from_blob(blob: DataBlob) -> bytes:
    return ctypes.string_at(blob.pbData, blob.cbData)


def protect_text(value: str) -> str:
    if not value:
        return ""
    if not hasattr(ctypes, "windll"):
        raise RuntimeError("DPAPI доступен только в Windows")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    source = _blob_from_bytes(value.encode("utf-16-le"))
    target = DataBlob()
    if not crypt32.CryptProtectData(ctypes.byref(source), None, None, None, None, 0, ctypes.byref(target)):
        raise ctypes.WinError()
    try:
        return base64.b64encode(_bytes_from_blob(target)).decode("ascii")
    finally:
        kernel32.LocalFree(target.pbData)


def unprotect_text(token: str) -> str:
    if not token:
        return ""
    if not hasattr(ctypes, "windll"):
        raise RuntimeError("DPAPI доступен только в Windows")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    source = _blob_from_bytes(base64.b64decode(token))
    target = DataBlob()
    if not crypt32.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 0, ctypes.byref(target)):
        raise ctypes.WinError()
    try:
        return _bytes_from_blob(target).decode("utf-16-le")
    finally:
        kernel32.LocalFree(target.pbData)
