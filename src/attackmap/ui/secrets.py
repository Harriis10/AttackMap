"""LLM API keys: Windows Credential Manager / DPAPI, never report files."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".attackmap")
    path = Path(base) / "AttackMap"
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_llm_key() -> str | None:
    env = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if env:
        return env
    blob = _data_dir() / "llm.key"
    if not blob.is_file():
        return None
    raw = blob.read_bytes()
    if sys.platform == "win32":
        try:
            import ctypes
            import ctypes.wintypes

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

            crypt = ctypes.windll.crypt32  # type: ignore[attr-defined]
            kernel = ctypes.windll.kernel32  # type: ignore[attr-defined]
            inn = DATA_BLOB(len(raw), ctypes.create_string_buffer(raw, len(raw)))
            out = DATA_BLOB()
            if not crypt.CryptUnprotectData(ctypes.byref(inn), None, None, None, None, 0, ctypes.byref(out)):
                return None
            try:
                return ctypes.string_at(out.pbData, out.cbData).decode("utf-8")
            finally:
                kernel.LocalFree(out.pbData)
        except (OSError, ValueError, AttributeError):
            return None
    return raw.decode("utf-8")


def save_llm_key(value: str) -> None:
    data = value.encode("utf-8")
    path = _data_dir() / "llm.key"
    if sys.platform == "win32":
        import ctypes
        import ctypes.wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        crypt = ctypes.windll.crypt32  # type: ignore[attr-defined]
        kernel = ctypes.windll.kernel32  # type: ignore[attr-defined]
        inn = DATA_BLOB(len(data), ctypes.create_string_buffer(data, len(data)))
        out = DATA_BLOB()
        if crypt.CryptProtectData(ctypes.byref(inn), "AttackMap LLM", None, None, None, 0, ctypes.byref(out)):
            try:
                path.write_bytes(ctypes.string_at(out.pbData, out.cbData))
            finally:
                kernel.LocalFree(out.pbData)
            return
    path.write_bytes(data)


def child_llm_env(provider: str) -> dict[str, str]:
    if not provider or provider in {"none", "None (heuristic only)"}:
        return {}
    key = load_llm_key()
    if not key:
        return {}
    if provider.lower().startswith("openai"):
        return {"OPENAI_API_KEY": key}
    return {"ANTHROPIC_API_KEY": key}
