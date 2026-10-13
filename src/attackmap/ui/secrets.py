"""LLM API keys: separate Anthropic / OpenAI blobs via DPAPI, never report files."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".attackmap")
    path = Path(base) / "AttackMap"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _key_path(provider: str) -> Path:
    name = "openai" if provider.lower().startswith("openai") else "anthropic"
    return _data_dir() / f"llm-{name}.key"


def load_llm_key(provider: str = "claude") -> str | None:
    env_name = "OPENAI_API_KEY" if provider.lower().startswith("openai") else "ANTHROPIC_API_KEY"
    env = os.environ.get(env_name)
    if env:
        return env
    blob = _key_path(provider)
    if not blob.is_file():
        return None
    return _unprotect(blob.read_bytes())


def save_llm_key(value: str, provider: str = "claude") -> None:
    path = _key_path(provider)
    path.write_bytes(_protect(value.encode("utf-8")))


def child_llm_env(provider: str, base_url: str | None = None) -> dict[str, str]:
    if not provider or provider in {"none", "None (heuristic only)"}:
        return {}
    if provider.lower().startswith("openai"):
        out: dict[str, str] = {}
        key = load_llm_key(provider)
        # LM Studio / OpenAI-compatible local endpoints accept any non-empty key.
        if base_url:
            out["OPENAI_BASE_URL"] = base_url
            out["OPENAI_API_KEY"] = key or "lm-studio"
            return out
        if not key:
            return {}
        out["OPENAI_API_KEY"] = key
        return out
    key = load_llm_key(provider)
    if not key:
        return {}
    return {"ANTHROPIC_API_KEY": key}


def has_llm_key(provider: str) -> bool:
    return bool(load_llm_key(provider))


def _protect(data: bytes) -> bytes:
    if sys.platform != "win32":
        return data
    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt = ctypes.windll.crypt32  # type: ignore[attr-defined]
    kernel = ctypes.windll.kernel32  # type: ignore[attr-defined]
    crypt.CryptProtectData.restype = ctypes.wintypes.BOOL
    inn = DATA_BLOB(len(data), ctypes.create_string_buffer(data, len(data)))
    out = DATA_BLOB()
    if crypt.CryptProtectData(ctypes.byref(inn), "AttackMap LLM", None, None, None, 0, ctypes.byref(out)):
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            kernel.LocalFree(out.pbData)
    raise OSError("Windows DPAPI could not protect the API key.")


def _unprotect(raw: bytes) -> str | None:
    if sys.platform != "win32":
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
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
