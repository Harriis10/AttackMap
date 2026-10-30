"""Explicit desktop provider settings/actions; credentials never enter JSON."""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

from .provider_options import ProviderOptions
from .safe_fs import ensure_output_dir


def _replace_configuration(path: Path, text: str) -> None:
    """Keep the last configuration intact until a complete replacement exists."""
    def validate() -> None:
        for entry in (path, *path.absolute().parents):
            if entry.is_symlink() or (hasattr(entry, "is_junction") and entry.is_junction()):
                raise OSError("Provider settings refuse redirected paths")
    validate()
    ensure_output_dir(path.parent)
    temporary = path.with_name(f".provider-{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        validate()
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def configuration_path() -> Path:
    return Path(os.environ.get("LOCALAPPDATA") or str(Path.home() / ".attackmap")) / "AttackMap" / "NativePreview" / "provider.json"


def load_configuration() -> ProviderOptions:
    path = configuration_path()
    if not path.exists():
        return ProviderOptions()
    if path.stat().st_size > 16_384:
        raise ValueError("Provider settings exceed size limit")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("Unsupported provider settings version")
    return ProviderOptions.model_validate(data["configuration"])


def execute_provider_action(operation: str, payload: dict) -> dict:
    options = ProviderOptions.model_validate(payload["configuration"])
    credential = os.environ.pop("ATTACKMAP_ACTION_CREDENTIAL", "")
    from .ui.secrets import is_loopback_endpoint, load_llm_key, save_llm_key
    if operation == "provider_save":
        if credential:
            save_llm_key(credential, options.provider)
        path = configuration_path()
        _replace_configuration(path, json.dumps({
            "schema_version": 1, "configuration": options.model_dump(mode="json")}, indent=2))
        return {"status": "saved", "configuration": options.model_dump(mode="json"),
                "credential_saved": bool(credential), "message": "Provider settings saved. Credentials use Windows protected storage. No connection was made."}
    if operation != "provider_check":
        raise ValueError("Unknown provider action")
    if options.provider == "openai":
        from openai import OpenAI, DefaultHttpxClient
        local = bool(options.endpoint and is_loopback_endpoint(options.endpoint))
        key = "lm-studio" if local else credential or load_llm_key("openai")
        if not key:
            raise ValueError("A protected provider credential is required")
        client = OpenAI(api_key=key, base_url=options.endpoint, timeout=min(10, options.timeout_seconds), max_retries=0,
                        **({"http_client": DefaultHttpxClient(trust_env=False, follow_redirects=False)} if local else {}))
        try:
            models = client.models.list()
            available = {model.id for model in models.data}
            selected_available = options.model is None or options.model in available
        finally:
            client.close()
    else:
        from anthropic import Anthropic, DefaultHttpxClient
        local = bool(options.endpoint and is_loopback_endpoint(options.endpoint))
        key = "lm-studio" if local else credential or load_llm_key("claude")
        if not key:
            raise ValueError("A protected provider credential is required")
        client = Anthropic(api_key=key, base_url=options.endpoint, timeout=min(10, options.timeout_seconds), max_retries=0,
                           **({"http_client": DefaultHttpxClient(trust_env=False, follow_redirects=False)} if local else {}))
        try:
            models = client.models.list(limit=1)
            selected_available = options.model is None or any(model.id == options.model for model in models.data)
        finally:
            client.close()
    message = "Provider model listing succeeded; no repository evidence was sent. Model listing does not prove generation or model availability."
    if not selected_available:
        message = "Selected model was NOT listed by the provider. Check the exact model ID (including case) before scanning. " + message
    return {"status": "connected", "selected_model_listed": selected_available, "message": message}
