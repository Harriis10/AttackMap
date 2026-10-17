"""Credential-free optional desktop provider configuration; validation performs no I/O."""
from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

LOCAL_ENDPOINT = "http://127.0.0.1:1234/v1"
LOCAL_MODEL = "cyberstag-security-26b-a4b-v1"


class ProviderOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)

    enable_ai: bool = False
    provider: Literal["openai", "claude"] = "openai"
    endpoint: str | None = LOCAL_ENDPOINT
    model: str | None = LOCAL_MODEL
    max_calls: int = Field(default=8, ge=1, le=64)
    timeout_seconds: int = Field(default=600, ge=1, le=3600)
    output_token_limit: int = Field(default=32000, ge=1, le=256000)

    @field_validator("endpoint")
    @classmethod
    def valid_endpoint(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        value = value.strip()
        if len(value) > 2048 or any(ord(c) < 32 for c in value):
            raise ValueError("Provider endpoint is invalid")
        try:
            parsed = urlsplit(value)
            _ = parsed.port
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None
                    or parsed.query or parsed.fragment):
                raise ValueError
            if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError
        except ValueError:
            raise ValueError("Use HTTPS, or literal loopback HTTP; no URL credentials, query or fragment") from None
        return value.rstrip("/")

    @field_validator("model")
    @classmethod
    def valid_model(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        value = value.strip()
        if len(value) > 200 or any(ord(c) < 32 for c in value):
            raise ValueError("Provider model must be at most 200 characters without control characters")
        return value
