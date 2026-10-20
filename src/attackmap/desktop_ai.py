"""Desktop AI options map to existing service paths; no provider implementation or new findings."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .provider_options import ProviderOptions, ProviderOptionsV13

MODES = ("none", "review", "hunt", "hunt_verify", "remediate", "triage")
ARTIFACTS = {
    "review": ("defensive-review-llm.md", "defensive-review-llm.meta.json"),
    "hunt": ("vulnerability-hypotheses.md", "vulnerability-hypotheses.meta.json"),
    "hunt_verify": ("vulnerability-hypotheses.md", "vulnerability-hypotheses.meta.json"),
    "remediate": ("remediation.md", "remediation.meta.json"),
    "triage": ("triage.md", "triage.meta.json"),
}


def provider_mode(provider: ProviderOptions) -> str:
    return provider.effective_mode if isinstance(provider, ProviderOptionsV13) else "review" if provider.enable_ai else "none"


def service_ai_options(provider: ProviderOptions) -> dict[str, Any]:
    # Revalidate even a model_construct/model_copy caller before service dispatch.
    provider = type(provider).model_validate(provider.model_dump())
    mode = provider_mode(provider)
    return {"llm": mode == "review", "hunt": mode in {"hunt", "hunt_verify"},
            "verify": mode == "hunt_verify", "verify_votes": getattr(provider, "jury_votes", None) or 3,
            "remediate": mode == "remediate", "triage": mode == "triage",
            "llm_provider": provider.provider, "llm_model": provider.model,
            "llm_effort": getattr(provider, "effort", None), "llm_speed": getattr(provider, "speed", "standard"),
            "llm_backend": "api", "desktop_ai_mode": mode if isinstance(provider, ProviderOptionsV13) else None}


def manifest_ai_result(mode: str, output: Path, allowance: dict | None, produced: dict[str, bool]) -> dict:
    """Describe existing artifacts in the stable run manifest; never synthesize missing AI output."""
    result: dict[str, Any] = {"schema_version": "1.0", "mode": mode,
        "status": "not_requested" if mode == "none" else "unavailable",
        "model_output_available": False, "allowance": allowance,
        "notice": "Model output is separate from deterministic findings and is not a validated vulnerability or runtime acceptance."}
    if mode == "none":
        return result
    markdown_name, metadata_name = ARTIFACTS[mode]
    result.update(artifact=None, metadata_artifact=None)
    if mode not in produced:
        result["reason"] = "requested_output_unavailable; inspect run diagnostics and allowance"
        return result
    try:
        metadata = json.loads((output / metadata_name).read_text(encoding="utf-8"))
        text = (output / markdown_name).read_text(encoding="utf-8")
    except (OSError, ValueError):
        result["reason"] = "requested_output_unavailable; inspect run diagnostics and allowance"
        return result
    if not isinstance(metadata, dict):
        result["reason"] = "requested_metadata_unavailable"
        return result
    result.update(artifact=markdown_name, metadata_artifact=metadata_name,
                  backend=metadata.get("backend"), model=metadata.get("model"),
                  usage_status=metadata.get("usage_status", "unknown"))
    if mode == "triage" and metadata.get("backend") == "deterministic":
        result["status"] = "fallback"
        return result
    if not produced[mode] or metadata.get("backend") not in {"api", "cli"} or not metadata.get("model") or not text.strip():
        result["reason"] = "no_completed_model_output_established"
        return result
    partial = ((allowance or {}).get("output_limit_violations", 0) != 0
               or metadata.get("stop_reason") not in (None, "stop", "end_turn", "completed")
               or metadata.get("failed_passes", 0) != 0 or metadata.get("abstained_votes", 0) != 0)
    result.update(status="partial" if partial else "completed", model_output_available=True)
    return result
