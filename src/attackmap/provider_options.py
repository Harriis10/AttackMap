"""Credential-free optional desktop provider configuration; validation performs no I/O."""
from __future__ import annotations

import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

LOCAL_ENDPOINT = "http://127.0.0.1:1234/v1"
LOCAL_MODEL = "cyberstag-security-26b-a4b-v1"


class ProviderOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)

    enable_ai: bool = False
    provider: Literal["openai", "claude"] = "openai"
    endpoint: str | None = LOCAL_ENDPOINT
    model: str | None = LOCAL_MODEL
    max_calls: int = Field(default=8, ge=1, le=64)
    timeout_seconds: int = Field(default=600, ge=1, le=7200)
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

    @model_validator(mode="after")
    def local_extended_allowance(self) -> ProviderOptions:
        if self.timeout_seconds <= 3600:
            return self
        endpoint = urlsplit(self.endpoint or "")
        if (self.provider != "openai" or endpoint.scheme != "http"
                or endpoint.hostname not in {"localhost", "127.0.0.1", "::1"}
                or endpoint.username is not None or endpoint.password is not None
                or endpoint.query or endpoint.fragment
                or "?" in (self.endpoint or "") or "#" in (self.endpoint or "")
                or (endpoint.port is not None and endpoint.port <= 0)
                or re.match(r"\Ahttp://(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]+)?(?:/|\Z)",
                            self.endpoint or "", re.IGNORECASE) is None):
            raise ValueError("AI allowances above 3600 seconds require local OpenAI HTTP")
        return self

    @field_validator("model")
    @classmethod
    def valid_model(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        value = value.strip()
        if len(value) > 200 or any(ord(c) < 32 for c in value):
            raise ValueError("Provider model must be at most 200 characters without control characters")
        return value


class ProviderOptionsV13(ProviderOptions):
    """Additive AI controls; the legacy provider payload and defaults stay unchanged."""

    mode: Literal["none", "review", "hunt", "hunt_verify", "remediate", "triage"] | None = None
    jury_votes: int | None = Field(default=None, ge=1, le=7)
    effort: Literal["low", "medium", "high", "xhigh", "max"] | None = None
    speed: Literal["standard", "fast"] = "standard"
    backend: Literal["api", "cli"] = "api"

    @property
    def effective_mode(self) -> str:
        return self.mode or ("review" if self.enable_ai else "none")

    @model_validator(mode="after")
    def supported_combinations(self) -> ProviderOptionsV13:
        mode = self.effective_mode
        if self.enable_ai != (mode != "none"):
            raise ValueError("AI mode must agree with explicit AI enablement")
        if self.backend != "api":
            raise ValueError("Strict output-token allowance cannot be enforced by the CLI backend; use API")
        if self.jury_votes is not None and mode != "hunt_verify":
            raise ValueError("Jury votes require Hunt+verify")
        if mode == "none" and (self.effort is not None or self.speed != "standard"):
            raise ValueError("AI tuning requires an enabled AI mode")
        if self.speed == "fast":
            from .llm_review import DEFAULT_MODEL, FAST_CAPABLE_MODELS
            if self.provider != "claude" or (self.model or DEFAULT_MODEL) not in FAST_CAPABLE_MODELS:
                raise ValueError("Fast speed requires a supported Claude API model")
        return self
