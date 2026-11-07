"""LLM API keys: separate Anthropic / OpenAI blobs via DPAPI, never report files."""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit


def _data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".attackmap")
    path = Path(base) / "AttackMap"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _key_path(provider: str) -> Path:
    name = "openai" if provider.lower().startswith("openai") else "anthropic"
    return _data_dir() / f"llm-{name}.key"


def load_llm_key(provider: str = "claude", *, allow_environment: bool = True) -> str | None:
    env_name = "OPENAI_API_KEY" if provider.lower().startswith("openai") else "ANTHROPIC_API_KEY"
    env = os.environ.get(env_name)
    if env and allow_environment:
        return env
    blob = _key_path(provider)
    if not blob.is_file():
        return None
    if blob.is_symlink() or blob.stat().st_size > 65536:
        raise OSError("Protected credential storage is redirected or oversized.")
    return _unprotect(blob.read_bytes())


def save_llm_key(value: str, provider: str = "claude") -> None:
    protected = _protect(value.encode("utf-8"))
    path = _key_path(provider)
    def validate_path() -> None:
        for candidate in (path, *path.parents):
            if candidate.is_symlink() or (hasattr(candidate, "is_junction") and candidate.is_junction()):
                raise OSError("Protected credential storage refuses redirected paths.")
    validate_path()
    temporary = path.with_name(f".credential-{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(protected)
            stream.flush()
            os.fsync(stream.fileno())
        validate_path()
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def child_llm_env(provider: str, base_url: str | None = None, *, allow_environment: bool = True) -> dict[str, str]:
    if not provider or provider in {"none", "None (heuristic only)"}:
        return {}
    if provider.lower().startswith("openai"):
        out: dict[str, str] = {}
        if base_url and is_loopback_endpoint(base_url):
            # Never forward a cloud credential to a local compatibility server.
            return {"OPENAI_BASE_URL": base_url, "OPENAI_API_KEY": "lm-studio"}
        key = load_llm_key(provider) if allow_environment else load_llm_key(provider, allow_environment=False)
        # LM Studio / OpenAI-compatible local endpoints accept any non-empty key.
        if base_url:
            out["OPENAI_BASE_URL"] = base_url
            out["OPENAI_API_KEY"] = key or "lm-studio"
            return out
        if not key:
            return {}
        out["OPENAI_API_KEY"] = key
        return out
    if base_url and is_loopback_endpoint(base_url):
        return {"ANTHROPIC_BASE_URL": base_url, "ANTHROPIC_API_KEY": "lm-studio"}
    key = load_llm_key(provider) if allow_environment else load_llm_key(provider, allow_environment=False)
    if not key:
        return {}
    return {"ANTHROPIC_API_KEY": key}


def has_llm_key(provider: str) -> bool:
    return bool(load_llm_key(provider))


def is_loopback_endpoint(base_url: str) -> bool:
    """Recognize literal loopback destinations without resolving untrusted DNS."""
    try:
        parsed = urlsplit(base_url)
        return (
            parsed.scheme in {"http", "https"}
            and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


def _protect(data: bytes) -> bytes:
    if sys.platform != "win32":
        raise OSError("Secure API key storage is unavailable on this platform.")
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
