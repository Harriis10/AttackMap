"""Anthropic-powered narrative review generator.

Wraps the existing prompt scaffolding (`review_prompts.render_review_prompts`)
in a real Claude call so users can produce a story-bearing defensive review
without copy-pasting JSON into a chat client.

Auth resolution (in order):
  1. Explicit `client=` (tests / programmatic override)
  2. `ANTHROPIC_API_KEY` env  → SDK with api_key  (per-token API billing)
  3. `ANTHROPIC_AUTH_TOKEN` env → SDK with auth_token (OAuth bearer)
  4. `claude` CLI on PATH      → shell out to `claude -p --output-format=json`
                                 (uses whatever auth `claude login` configured —
                                 typically the user's Pro/Max subscription)

The user can force a backend via the `backend` argument or the CLI's
`--llm-backend` flag; "auto" walks the order above and picks the first one
that resolves.

Optional dependency: `pip install "attackmap[llm] @ git+https://github.com/mlaify/AttackMap.git"` installs the anthropic SDK.
The CLI backend only requires the `claude` binary on PATH (no SDK install).
"""

from __future__ import annotations

import json
import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from functools import lru_cache
from typing import Any, Literal
from urllib.parse import urlsplit

from .ai_budget import (AiBudget, AiBudgetExhausted, current_budget,
                        current_reservation, reservation_scope)

from .models import AttackPath, AttackSurface, Finding, ScanResult
from .review_prompts import (
    render_critic_prompts,
    render_hunt_generate_prompts,
    render_hunt_prompts,
    render_hunt_verify_prompts,
    render_remediation_prompts,
    render_review_prompts,
    render_skeptic_prompts,
    render_triage_prompts,
)

_LLM_INSTALL = 'pip install "attackmap[llm] @ git+https://github.com/mlaify/AttackMap.git"'

DEFAULT_MODEL = "claude-opus-4-8"
DEFAULT_EFFORT: Literal["low", "medium", "high", "xhigh", "max"] = "high"
DEFAULT_MAX_TOKENS = 32000

# Fast mode (2.5x output speed, premium price) is a research-preview beta and
# only runs on the Opus 4.8 / 4.7 tiers via the API backend — the `claude` CLI
# backend and other models silently fall back to standard speed.
FAST_MODE_BETA = "fast-mode-2026-02-01"
FAST_CAPABLE_MODELS = frozenset({"claude-opus-4-8", "claude-opus-4-7"})
CLAUDE_CLI_TIMEOUT_SECONDS = 600

# OpenAI / Codex provider. `gpt-5-codex` is the code-optimized GPT-5 (Responses
# API only) and the safe default; any other model ID is passed through verbatim
# so we never have to chase OpenAI's point-release churn. Reasoning effort maps
# onto the Responses API's `reasoning.effort` — OpenAI exposes low/medium/high,
# so our extended tiers (xhigh/max) clamp down to "high".
OPENAI_DEFAULT_MODEL = "gpt-5-codex"
OPENAI_API_TIMEOUT_SECONDS = 900
LOCAL_OPENAI_API_TIMEOUT_SECONDS = 3600
CODEX_CLI_TIMEOUT_SECONDS = 900
OPENAI_EFFORT_MAP = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "xhigh": "high",
    "max": "high",
}

LlmProvider = Literal["claude", "openai"]
LlmBackend = Literal["auto", "api", "cli"]


class LlmReviewError(RuntimeError):
    """Raised when the LLM-backed review cannot be produced."""


@dataclass(frozen=True)
class LlmReviewResult:
    markdown: str
    model: str
    stop_reason: str | None
    usage: dict[str, int]
    backend: Literal["api", "cli"]
    reference_validation: dict | None = None

    @property
    def usage_status(self) -> Literal["reported", "partial", "unknown"]:
        if all(type(self.usage.get(key)) is int and self.usage[key] >= 0
               for key in ("input_tokens", "output_tokens")):
            return "reported"
        return "partial" if self.usage else "unknown"



def _claim_support_assessments(markdown: str, candidates: list[str]) -> list[dict]:
    """Per-claim closed-set support assessment for narrative review output.

    The selected narrative prompt supplies no captured snapshot spans, so every
    cited claim honestly stays 'not_assessed'. Reference validity never implies
    support, and this never reads live source files to manufacture it.
    """
    from .citations import reference_tokens

    candidate_set = set(candidates)
    assessments: list[dict] = []
    for line in markdown.splitlines():
        cited = [token for token in reference_tokens(line, allowed_ids=candidate_set) if token in candidate_set]
        if not cited:
            continue
        if len(assessments) >= 40:
            break
        claim = line.strip()[:160]
        for reference in cited:
            assessments.append({"claim": claim, "reference": reference,
                                "claim_support": "not_assessed",
                                "reason": "no captured source spans in the selected narrative prompt"})
    return assessments


def _validate_narrative_references(result: LlmReviewResult, rendered) -> LlmReviewResult:
    """Check producer IDs in precisely the selected, sanitized prompt, not claims."""
    import hashlib
    from .citations import CitationContext, EvidenceReference, reference_tokens, validate_references

    payload = json.loads(rendered.evidence_json)
    prefixes = {"findings": "finding", "attack_surfaces": "surface", "attack_paths": "path",
                "assets": "asset", "controls": "control", "notable_observations": "insight",
                "detection_opportunities": "detect"}
    records = {}
    duplicates = set()
    for collection, prefix in prefixes.items():
        for entry in payload.get(collection, []):
            identity = entry.get("id") if isinstance(entry, dict) else None
            if not isinstance(identity, str) or not re.fullmatch(re.escape(prefix) + r":[A-Za-z0-9][A-Za-z0-9_.:+/-]*", identity):
                continue
            if identity in records:
                duplicates.add(identity)
            records[identity] = EvidenceReference(identity, hashlib.sha256(
                json.dumps(entry, sort_keys=True, ensure_ascii=True).encode()).hexdigest())
    context = CitationContext("", tuple(value for key, value in records.items() if key not in duplicates), ())
    candidates = [token for token in reference_tokens(result.markdown, allowed_ids=records)
                  if token.lower().split(":", 1)[0] in {*prefixes.values(), "find"} and ":" in token]
    # This status covers producer IDs only. File/line and snapshot support are
    # separate questions and must not be implied by this check.
    validated = validate_references(" ".join(candidates), context)
    allowed = {record.evidence_id for record in context.records}
    invalid = tuple(dict.fromkeys([*validated.invalid_references,
                                  *(token for token in candidates if token not in allowed)]))
    valid = tuple(token for token in candidates if token in allowed)
    status = "invalid" if invalid else "valid" if valid else "missing"
    source_tokens = [token for token in reference_tokens(result.markdown, allowed_ids=records)
                     if token not in candidates and not token.lower().startswith(("http://", "https://"))]
    source_check = validate_references(" ".join(source_tokens), context)
    unresolved_sources = list(source_check.invalid_references)
    metadata = {"reference_validity": status, "scope": "selected_prompt_producer_evidence_ids",
                "claim_support": "not_assessed",
                "claim_support_assessments": _claim_support_assessments(result.markdown, candidates),
                "claim_support_basis": "Reference validity never implies claim support. The "
                "selected narrative prompt supplies no captured snapshot spans, so every cited "
                "claim remains not_assessed; this check never reads live source files to "
                "manufacture support.",
                "source_location_validation": "unvalidated" if unresolved_sources else "not_assessed",
                "source_reference_validity": "unresolved" if unresolved_sources else "missing",
                "source_references": unresolved_sources,
                "unresolved_source_references": unresolved_sources,
                "source_reference_scope": "No captured snapshot spans supplied by the selected narrative prompt; live files are not consulted.",
                "context_sha256": hashlib.sha256(rendered.evidence_json.encode()).hexdigest(),
                "valid_references": list(dict.fromkeys(valid)), "invalid_references": list(invalid),
                "allowed_reference_count": len(allowed)}
    notice = "> Evidence reference check: " + status + ". Claim support and source-location validity are not assessed."
    if invalid:
        notice += " Unresolved evidence IDs are present; inspect reference_validation metadata. IDs have not been corrected."
    if unresolved_sources:
        notice += " Source file/line references are unresolved: no selected snapshot spans establish their validity."
    return replace(result, markdown=notice + "\n\n" + result.markdown, reference_validation=metadata)


def _provider_call(call, *, max_tokens: int, timeout: float,
                   budget: AiBudget | None, cli: bool = False) -> LlmReviewResult:
    if current_budget() is not None and budget is not None and budget is not current_budget():
        raise LlmReviewError("Cannot replace the active shared AI allowance")
    ledger = budget or current_budget() or AiBudget(max_calls=1, max_seconds=timeout)
    if cli and ledger.output_token_limit is not None:
        raise LlmReviewError("A strict output-token allowance requires the API backend; CLI output limits are unverified.")
    inherited = current_reservation()
    owns = inherited is None or inherited.ledger is not ledger
    reservation = None
    result = None
    try:
        reservation = (ledger.reserve(max_output_tokens=max_tokens, timeout_seconds=timeout)
                       if owns else inherited)
        reservation.claim_dispatch()
        with reservation_scope(reservation):
            result = call(min(max_tokens, reservation.output_tokens))
        return result
    except AiBudgetExhausted as exc:
        raise LlmReviewError(str(exc)) from exc
    finally:
        if owns and reservation is not None:
            reservation.finish(getattr(result, "usage", None))


def _provider_timeout(default: float) -> float:
    reservation = current_reservation()
    if reservation is None:
        return default
    reservation.check_dispatch()
    return min(default, reservation.timeout_seconds, reservation.ledger.remaining_seconds)


def _controlled_client(client, *, timeout: float = OPENAI_API_TIMEOUT_SECONDS):
    reservation = current_reservation()
    if reservation is not None and hasattr(client, "with_options"):
        return client.with_options(max_retries=0, timeout=_provider_timeout(timeout))
    return client


def _literal_loopback_url(value: str | None) -> bool:
    if not value:
        return False
    try:
        parsed = urlsplit(value)
        if parsed.scheme in {"http", "https"} and parsed.hostname == "localhost":
            return True
        return (parsed.scheme in {"http", "https"} and parsed.hostname is not None
                and ipaddress.ip_address(parsed.hostname).is_loopback)
    except ValueError:
        return False


def _openai_timeout_ceiling(client=None, *, budget: AiBudget | None = None) -> float:
    """Honor an existing local allowance; never create or reset its deadline."""
    reservation = current_reservation()
    ledger = budget or current_budget() or (reservation.ledger if reservation else None)
    endpoint = str(getattr(client, "base_url", "") if client is not None
                   else os.environ.get("OPENAI_BASE_URL", ""))
    if ledger is not None and _literal_loopback_url(endpoint):
        parsed = urlsplit(endpoint)
        try:
            port = parsed.port
        except ValueError:
            return OPENAI_API_TIMEOUT_SECONDS
        if (parsed.scheme == "http" and parsed.username is None and parsed.password is None
                and (port is None or port > 0)):
            return LOCAL_OPENAI_API_TIMEOUT_SECONDS
    return OPENAI_API_TIMEOUT_SECONDS


def _normalize_local_endpoint(value: str | None) -> str | None:
    """Pin the explicitly local hostname to a numeric address without DNS."""
    if not _literal_loopback_url(value):
        return value
    parsed = urlsplit(value)
    if parsed.username is not None or parsed.password is not None:
        raise LlmReviewError("Local endpoint URLs cannot contain embedded credentials")
    if parsed.hostname == "localhost":
        authority = "127.0.0.1" + (f":{parsed.port}" if parsed.port is not None else "")
        return parsed._replace(netloc=authority).geturl()
    return value


def _loopback_transport(sdk, base_url: str | None) -> dict:
    audit_options = {}
    if getattr(sdk, "__name__", None) == "openai" and os.environ.get("ATTACKMAP_QA_HTTP_AUDIT_DIR"):
        from .ai_http_audit import client_audit_options
        audit_options = client_audit_options(base_url)
    if not _literal_loopback_url(base_url):
        return {}
    parsed = urlsplit(base_url)
    if parsed.username or parsed.password:
        raise LlmReviewError("Local endpoint URLs cannot contain embedded credentials")
    factory = getattr(sdk, "DefaultHttpxClient", None)
    if factory is None:
        raise LlmReviewError("The SDK cannot isolate the local endpoint from proxy settings; upgrade the SDK.")
    return {"http_client": factory(trust_env=False, follow_redirects=False, **audit_options)}


# ---------- Auth + SDK backend ----------


def _resolve_sdk_client(api_key: str | None, client: Any | None) -> tuple[Any, str]:
    """Return (anthropic client, auth_kind). auth_kind ∈ {'api_key', 'auth_token'}."""
    if client is not None:
        return client, "explicit"
    try:
        import anthropic
    except ImportError as exc:
        raise LlmReviewError(
            "The anthropic SDK is not installed. Install with "
            f"`{_LLM_INSTALL}` "
            "to use the API backend, or ensure the `claude` CLI is on PATH for the CLI backend."
        ) from exc

    resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    base_url = _normalize_local_endpoint(os.environ.get("ANTHROPIC_BASE_URL"))
    if _literal_loopback_url(base_url):
        return anthropic.Anthropic(api_key="attackmap-local", base_url=base_url,
            max_retries=0, **_loopback_transport(anthropic, base_url)), "local"
    if resolved_key:
        return anthropic.Anthropic(api_key=resolved_key, max_retries=0), "api_key"

    auth_token = os.environ.get("ANTHROPIC_AUTH_TOKEN")
    if auth_token:
        return anthropic.Anthropic(auth_token=auth_token, max_retries=0), "auth_token"

    raise LlmReviewError(
        "No API credentials found. Set ANTHROPIC_API_KEY (per-token API billing) or "
        "ANTHROPIC_AUTH_TOKEN (OAuth bearer), or install the `claude` CLI and run "
        "`claude login` to use your Claude subscription."
    )


def _extract_text(blocks: list[Any]) -> str:
    parts: list[str] = []
    for block in blocks:
        if getattr(block, "type", None) == "text":
            text = getattr(block, "text", "")
            if text:
                parts.append(text)
    return "\n".join(parts).strip()


def _usage_dict(usage: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for field in (
        "input_tokens",
        "output_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
    ):
        value = getattr(usage, field, None)
        if type(value) is int and value >= 0:
            out[field] = value
    return out


def _run_via_sdk(
    rendered_system: str,
    rendered_user: str,
    *,
    model: str,
    effort: str,
    max_tokens: int,
    api_key: str | None,
    client: Any | None,
    speed: str = "standard",
) -> LlmReviewResult:
    sdk_client, _ = _resolve_sdk_client(api_key, client)
    sdk_client = _controlled_client(sdk_client)

    request_kwargs: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "timeout": _provider_timeout(CLAUDE_CLI_TIMEOUT_SECONDS),
        "system": [
            {"type": "text", "text": rendered_system, "cache_control": {"type": "ephemeral"}}
        ],
        "messages": [{"role": "user", "content": rendered_user}],
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": effort},
    }

    # Fast mode needs the beta endpoint + flag + top-level speed, and only on
    # the Opus 4.8/4.7 tiers. Anything else runs at standard speed.
    fast = speed == "fast" and model in FAST_CAPABLE_MODELS
    messages_api = sdk_client.messages
    if fast:
        request_kwargs["speed"] = "fast"
        request_kwargs["betas"] = [FAST_MODE_BETA]
        messages_api = sdk_client.beta.messages

    try:
        with messages_api.stream(**request_kwargs) as stream:
            final_message = stream.get_final_message()
    except LlmReviewError:
        raise
    except Exception as exc:  # pragma: no cover - surface SDK errors verbatim
        raise LlmReviewError(f"Claude API call failed: {exc}") from exc

    markdown = _extract_text(getattr(final_message, "content", []) or [])
    if not markdown:
        raise LlmReviewError("Claude returned no text content for the review.")

    stop_reason = getattr(final_message, "stop_reason", None)
    return LlmReviewResult(
        markdown=markdown,
        model=model,
        stop_reason=stop_reason if isinstance(stop_reason, str) else None,
        usage=_usage_dict(getattr(final_message, "usage", None)),
        backend="api",
    )


# ---------- CLI backend isolation (#232) ----------
#
# The CLI backends hand an *agent* the evidence pack, which is derived from an
# untrusted repository and may carry prompt injection. They are spawned so that
# nothing from that repository can configure the agent and the agent has as
# little reach as its CLI allows:
#   * cwd is a fresh empty temp dir, never the scan root or the caller's cwd,
#     so project-scoped `.claude/settings.json` (hooks, permissions),
#     `.mcp.json`, `CLAUDE.md` and `AGENTS.md` are never discovered;
#   * claude: no built-in tools, user-level settings only, no MCP servers, no
#     session persistence;
#   * codex: read-only sandbox rooted at the temp dir, no execpolicy rules,
#     ephemeral session. Codex has no tool-less mode, so its model can still
#     run read-only commands as the user; `--llm-backend api` is the only fully
#     tool-less path for OpenAI (documented in the README);
#   * the environment is scrubbed of credentials unrelated to the provider.
# If the installed CLI lacks the hardening flags we refuse to run it rather
# than fall back to an unhardened invocation.

CLAUDE_CLI_HARDENING_ARGS = (
    "--tools",
    "",
    "--setting-sources",
    "user",
    "--strict-mcp-config",
    "--mcp-config",
    '{"mcpServers":{}}',
    "--no-session-persistence",
)
_CLAUDE_REQUIRED_FLAGS = ("--tools", "--setting-sources", "--strict-mcp-config", "--no-session-persistence")
_CODEX_REQUIRED_FLAGS = ("--cd", "--ephemeral", "--ignore-rules", "--sandbox")

# Environment variables whose names look like credentials are not forwarded to
# the agent, except the ones the selected provider needs to authenticate.
_SENSITIVE_ENV_RE = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|API_KEY|ACCESS_KEY|SESSION_KEY|AUTH)",
    re.IGNORECASE,
)
_CLOUD_ENV_PREFIXES = ("AWS_", "AZURE_", "GOOGLE_", "GCP_", "GCLOUD_", "CLOUDSDK_", "ANTHROPIC_VERTEX_")
_PROVIDER_ENV_ALLOW = {
    "claude": frozenset(
        {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_BASE_URL"}
    ),
    "openai": frozenset({"OPENAI_API_KEY", "OPENAI_BASE_URL", "CODEX_API_KEY"}),
}
# Claude Code on Bedrock / Vertex / Foundry authenticates with cloud
# credentials, so those are kept when the user has opted into a 3P provider.
_CLAUDE_3P_SWITCHES = ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY")


def scrub_cli_env(env: dict[str, str], provider: LlmProvider) -> dict[str, str]:
    """Return a copy of ``env`` without credentials the agent doesn't need."""
    allow = _PROVIDER_ENV_ALLOW[provider]
    keep_cloud = provider == "claude" and any(env.get(k) for k in _CLAUDE_3P_SWITCHES)
    scrubbed: dict[str, str] = {}
    for name, value in env.items():
        upper = name.upper()
        if upper in allow:
            scrubbed[name] = value
            continue
        if upper.startswith(_CLOUD_ENV_PREFIXES):
            if keep_cloud:
                scrubbed[name] = value
            continue
        if _SENSITIVE_ENV_RE.search(upper):
            continue
        scrubbed[name] = value
    return scrubbed


@contextmanager
def isolated_cli_workdir() -> Iterator[str]:
    """A throwaway empty working directory for an agent CLI subprocess."""
    with tempfile.TemporaryDirectory(prefix="attackmap-llm-") as tmp:
        yield tmp


@lru_cache(maxsize=None)
def _cli_help_text(argv: tuple[str, ...]) -> str:
    try:
        with isolated_cli_workdir() as cwd:
            completed = subprocess.run(
                list(argv), capture_output=True, text=True, check=False, timeout=30, cwd=cwd
            )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (completed.stdout or "") + (completed.stderr or "")


def _require_hardening_flags(name: str, help_argv: tuple[str, ...], flags: tuple[str, ...]) -> None:
    help_text = _cli_help_text(help_argv)
    missing = [flag for flag in flags if flag not in help_text]
    if missing:
        raise LlmReviewError(
            f"The installed `{name}` CLI does not support {', '.join(missing)}, which AttackMap "
            f"needs to run it isolated from the scanned repository. Upgrade `{name}`, or use "
            "`--llm-backend api`."
        )


# ---------- Claude CLI backend ----------


def _claude_cli_available() -> bool:
    return shutil.which("claude") is not None


def _anthropic_sdk_available() -> bool:
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


def _run_via_claude_cli(
    rendered_system: str,
    rendered_user: str,
    *,
    model: str,
    runner: Any | None = None,
) -> LlmReviewResult:
    """Invoke `claude -p --output-format=json` and return the result.

    The `runner` argument is only used by tests to inject a fake subprocess
    runner; in production we go straight to subprocess.run.
    """
    if runner is None and not _claude_cli_available():
        raise LlmReviewError(
            "`claude` CLI was not found on PATH. Install Claude Code (https://claude.com/claude-code) "
            "and run `claude login`, or set ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN to use the SDK backend."
        )

    cmd = [
        "claude",
        "-p",
        "--output-format=json",
        *CLAUDE_CLI_HARDENING_ARGS,
        "--model",
        model,
        "--system-prompt",
        rendered_system,
    ]

    try:
        if runner is None:
            _require_hardening_flags("claude", ("claude", "--help"), _CLAUDE_REQUIRED_FLAGS)
            with isolated_cli_workdir() as cwd:
                completed = subprocess.run(
                    cmd,
                    input=rendered_user,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=_provider_timeout(CLAUDE_CLI_TIMEOUT_SECONDS),
                    cwd=cwd,
                    env=scrub_cli_env(dict(os.environ), "claude"),
                )
        else:
            completed = runner(cmd, rendered_user)
    except FileNotFoundError as exc:
        raise LlmReviewError("`claude` CLI was not found on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise LlmReviewError(
            f"`claude` CLI did not respond within {CLAUDE_CLI_TIMEOUT_SECONDS}s."
        ) from exc

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode != 0 and not stdout:
        raise LlmReviewError(
            f"`claude` CLI exited with status {completed.returncode}: {stderr or '<no stderr>'}"
        )
    if not stdout:
        raise LlmReviewError("`claude` CLI produced no output.")

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise LlmReviewError(
            f"`claude` CLI returned non-JSON output: {stdout[:200]}..."
        ) from exc

    if payload.get("is_error"):
        # The CLI returns an unhelpful mix here:
        #  - `subtype` is often the literal "success" even when is_error=true
        #  - `result` carries the human-readable message ("Not logged in · Please run /login")
        #  - `errors` is sometimes absent
        # Prefer `result` when it looks like a message; fall back to `errors`,
        # then to `subtype`. Never show "success" — it just confuses users.
        detail: str | None = None
        result_text = payload.get("result")
        if isinstance(result_text, str) and result_text.strip():
            detail = result_text.strip()
        elif payload.get("errors"):
            detail = "; ".join(str(e) for e in payload["errors"])
        else:
            subtype = payload.get("subtype")
            if isinstance(subtype, str) and subtype and subtype != "success":
                detail = subtype
        detail = detail or "unknown error"
        hint = ""
        low = detail.lower()
        if "not logged in" in low or "/login" in low:
            hint = (
                " Run `claude login` (or `claude /login` inside the CLI), "
                "or use --llm-backend api with ANTHROPIC_API_KEY set."
            )
        raise LlmReviewError(f"`claude` CLI reported an error: {detail}.{hint}")

    markdown = payload.get("result")
    if not isinstance(markdown, str) or not markdown.strip():
        raise LlmReviewError("`claude` CLI returned no `result` text.")

    usage_payload = payload.get("usage") or {}
    usage: dict[str, int] = {}
    for field in (
        "input_tokens",
        "output_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
    ):
        value = usage_payload.get(field)
        if type(value) is int and value >= 0:
            usage[field] = value

    cli_model = model
    model_usage = payload.get("modelUsage")
    if isinstance(model_usage, dict) and model_usage:
        cli_model = next(iter(model_usage.keys()), model)

    stop_reason = payload.get("stop_reason")
    return LlmReviewResult(
        markdown=markdown.strip(),
        model=cli_model,
        stop_reason=stop_reason if isinstance(stop_reason, str) else None,
        usage=usage,
        backend="cli",
    )


# ---------- OpenAI SDK backend ----------


def _resolve_openai_client(api_key: str | None, client: Any | None) -> Any:
    if client is not None:
        return client
    try:
        import openai
    except ImportError as exc:
        raise LlmReviewError(
            "The openai SDK is not installed. Install with "
            f"`{_LLM_INSTALL}` "
            "to use the OpenAI API backend, or install the `codex` CLI for the CLI backend."
        ) from exc

    base_url = _normalize_local_endpoint(os.environ.get("OPENAI_BASE_URL"))
    local = _literal_loopback_url(base_url)
    resolved_key = "attackmap-local" if local else api_key or os.environ.get("OPENAI_API_KEY")
    if not resolved_key:
        raise LlmReviewError(
            "No OpenAI API credentials found. Set OPENAI_API_KEY, or install the `codex` "
            "CLI and run `codex login` to use --llm-backend cli."
        )
    kwargs: dict[str, Any] = {"api_key": resolved_key,
        "timeout": _provider_timeout(_openai_timeout_ceiling()), "max_retries": 0}
    if base_url:
        kwargs["base_url"] = base_url
    kwargs.update(_loopback_transport(openai, base_url))
    return openai.OpenAI(**kwargs)


def _openai_output_text(response: Any) -> str:
    text = getattr(response, "output_text", None)
    if isinstance(text, str) and text.strip():
        return text.strip()
    # Fallback: walk output items → content blocks → text, for SDK/response
    # shapes where the `output_text` convenience isn't populated.
    parts: list[str] = []
    for item in getattr(response, "output", None) or []:
        if getattr(item, "type", None) != "message":
            continue
        for block in getattr(item, "content", None) or []:
            if getattr(block, "type", None) != "output_text":
                continue
            value = getattr(block, "text", None)
            if isinstance(value, str) and value:
                parts.append(value)
    return "\n".join(parts).strip()


def _openai_usage(usage: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    for field in ("input_tokens", "output_tokens"):
        value = getattr(usage, field, None)
        if type(value) is int and value >= 0:
            out[field] = value
    return out


def _openai_uses_chat_completions(client: Any) -> bool:
    """Custom remote OpenAI-compatible endpoints default to Chat Completions.

    Keep the established OpenAI and local LM Studio Responses API behavior.
    Select before sending; never retry evidence through a second API or host.
    """
    endpoint = str(getattr(client, "base_url", "") or os.environ.get("OPENAI_BASE_URL", ""))
    if not endpoint or _literal_loopback_url(endpoint):
        return False
    return urlsplit(endpoint).hostname != "api.openai.com"


def _run_via_openai_sdk(
    rendered_system: str,
    rendered_user: str,
    *,
    model: str,
    effort: str,
    max_tokens: int,
    api_key: str | None,
    client: Any | None,
) -> LlmReviewResult:
    resolved = _resolve_openai_client(api_key, client)
    timeout = _openai_timeout_ceiling(resolved)
    oi = _controlled_client(resolved, timeout=timeout)
    reasoning_effort = OPENAI_EFFORT_MAP.get(effort, "high")

    try:
        chat = _openai_uses_chat_completions(resolved)
        if chat:
            response = oi.chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": rendered_system},
                          {"role": "user", "content": rendered_user}],
                max_tokens=max_tokens,
                timeout=_provider_timeout(timeout),
            )
        else:
            response = oi.responses.create(
                model=model,
                instructions=rendered_system,
                input=rendered_user,
                reasoning={"effort": reasoning_effort},
                max_output_tokens=max_tokens,
                timeout=_provider_timeout(timeout),
            )
    except LlmReviewError:
        raise
    except Exception as exc:  # pragma: no cover - surface SDK errors verbatim
        raise LlmReviewError(f"OpenAI API call failed: {exc}") from exc

    choice = next(iter(getattr(response, "choices", None) or []), None) if chat else None
    content = getattr(getattr(choice, "message", None), "content", None)
    markdown = content.strip() if chat and isinstance(content, str) else "" if chat else _openai_output_text(response)
    if not markdown:
        raise LlmReviewError("OpenAI returned no text content for the review.")

    status = getattr(choice, "finish_reason", None) if chat else getattr(response, "status", None)
    reported_usage = getattr(response, "usage", None)
    if chat:
        usage = {}
        for source, target in (("prompt_tokens", "input_tokens"), ("completion_tokens", "output_tokens")):
            value = getattr(reported_usage, source, None)
            if type(value) is int and value >= 0:
                usage[target] = value
    else:
        usage = _openai_usage(reported_usage)
    if '"scope": "partial selected evidence review"' in rendered_user:
        notice = "> Partial selected-evidence review. Omitted evidence and controls are unknown, not absent. Provider completion does not establish review completeness."
        if usage.get("output_tokens", 0) >= max_tokens * 0.95:
            notice += " Output allowance nearly exhausted; this review may be truncated."
        markdown = notice + "\n\n" + markdown
    return LlmReviewResult(
        markdown=markdown,
        model=str(getattr(response, "model", None) or model),
        stop_reason=status if isinstance(status, str) else None,
        usage=usage,
        backend="api",
    )


# ---------- Codex CLI backend ----------


def _codex_cli_available() -> bool:
    return shutil.which("codex") is not None


def _openai_sdk_available() -> bool:
    try:
        import openai  # noqa: F401
    except ImportError:
        return False
    return True


def _run_via_codex_cli(
    rendered_system: str,
    rendered_user: str,
    *,
    model: str,
    effort: str,
    runner: Any | None = None,
) -> LlmReviewResult:
    """Invoke `codex exec` non-interactively and return the final message.

    `codex exec` treats the positional prompt as the instruction and piped
    stdin as additional context, so we pass the rendered system prompt as the
    argument and stream the (large) evidence pack in on stdin. It prints only
    the final agent message to stdout. Runs read-only so it can never mutate the
    working tree, and `--skip-git-repo-check` lets it run outside a git repo.

    The `runner` argument is only used by tests to inject a fake subprocess
    runner; in production we go straight to subprocess.run.
    """
    if runner is None and not _codex_cli_available():
        raise LlmReviewError(
            "`codex` CLI was not found on PATH. Install it (npm install -g @openai/codex) "
            "and run `codex login`, or set OPENAI_API_KEY to use --llm-backend api."
        )

    reasoning_effort = OPENAI_EFFORT_MAP.get(effort, "high")

    def build_cmd(cwd: str) -> list[str]:
        return [
            "codex",
            "exec",
            "--model",
            model,
            "-c",
            f'model_reasoning_effort="{reasoning_effort}"',
            "--sandbox",
            "read-only",
            "--cd",
            cwd,
            "--ephemeral",
            "--ignore-rules",
            "--skip-git-repo-check",
            rendered_system,
        ]

    try:
        with isolated_cli_workdir() as cwd:
            cmd = build_cmd(cwd)
            if runner is None:
                _require_hardening_flags("codex", ("codex", "exec", "--help"), _CODEX_REQUIRED_FLAGS)
                completed = subprocess.run(
                    cmd,
                    input=rendered_user,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=_provider_timeout(CODEX_CLI_TIMEOUT_SECONDS),
                    cwd=cwd,
                    env=scrub_cli_env(dict(os.environ), "openai"),
                )
            else:
                completed = runner(cmd, rendered_user)
    except FileNotFoundError as exc:
        raise LlmReviewError("`codex` CLI was not found on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise LlmReviewError(
            f"`codex` CLI did not respond within {CODEX_CLI_TIMEOUT_SECONDS}s."
        ) from exc

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode != 0:
        hint = ""
        low = stderr.lower()
        if "not logged in" in low or "login" in low or "auth" in low:
            hint = (
                " Run `codex login`, or use --llm-backend api with OPENAI_API_KEY set."
            )
        raise LlmReviewError(
            f"`codex` CLI exited with status {completed.returncode}: "
            f"{stderr or '<no stderr>'}.{hint}"
        )
    if not stdout:
        raise LlmReviewError("`codex` CLI produced no output.")

    return LlmReviewResult(
        markdown=stdout,
        model=model,
        stop_reason=None,
        usage={},
        backend="cli",
    )


# ---------- Public entry point ----------


def _resolve_openai_backend(
    backend: LlmBackend,
    *,
    api_key: str | None,
    client: Any | None,
    codex_runner: Any | None,
) -> Literal["api", "cli"]:
    if backend == "api":
        return "api"
    if backend == "cli":
        if codex_runner is None and not _codex_cli_available():
            raise LlmReviewError(
                "`--llm-backend cli` was requested but the `codex` CLI is not on PATH."
            )
        return "cli"
    # auto
    if client is not None:
        return "api"
    if _literal_loopback_url(os.environ.get("OPENAI_BASE_URL")):
        return "api"  # Never fall back from an explicit local endpoint to a cloud CLI.
    has_key = bool(api_key or os.environ.get("OPENAI_API_KEY"))
    # Prefer the API backend only when the openai SDK is importable; otherwise
    # fall back to the `codex` CLI (needs no SDK) so a key set against an
    # SDK-less install still works via subscription auth.
    if has_key and _openai_sdk_available():
        return "api"
    if _codex_cli_available():
        return "cli"
    if has_key:
        return "api"  # no SDK and no CLI — surface the actionable SDK-missing error
    raise LlmReviewError(
        "No OpenAI backend available. Set OPENAI_API_KEY, or install the `codex` "
        "CLI and run `codex login`."
    )


def _resolve_backend(
    backend: LlmBackend,
    *,
    api_key: str | None,
    client: Any | None,
) -> Literal["api", "cli"]:
    if backend == "api":
        return "api"
    if backend == "cli":
        if not _claude_cli_available():
            raise LlmReviewError(
                "`--llm-backend cli` was requested but the `claude` CLI is not on PATH."
            )
        return "cli"
    # auto
    if client is not None:
        return "api"
    if _literal_loopback_url(os.environ.get("ANTHROPIC_BASE_URL")):
        return "api"
    has_key = bool(
        api_key
        or os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("ANTHROPIC_AUTH_TOKEN")
    )
    # Prefer the API backend only when the SDK is actually importable. Otherwise
    # fall back to the `claude` CLI (needs no SDK), so a key set against an
    # SDK-less install (one without the `llm` extra)
    # still works via subscription auth instead of erroring.
    if has_key and _anthropic_sdk_available():
        return "api"
    if _claude_cli_available():
        return "cli"
    if has_key:
        return "api"  # no SDK and no CLI — surface the actionable SDK-missing error
    raise LlmReviewError(
        "No LLM backend available. Set ANTHROPIC_API_KEY, set ANTHROPIC_AUTH_TOKEN, "
        "or install the `claude` CLI and run `claude login`."
    )


def generate_llm_review(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
    *,
    model: str | None = None,
    effort: Literal["low", "medium", "high", "xhigh", "max"] | None = None,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    api_key: str | None = None,
    client: Any | None = None,
    backend: LlmBackend = "auto",
    cli_runner: Any | None = None,
    mode: Literal[
        "review", "hunt", "hunt_verify", "hunt_generate", "hunt_skeptic",
        "hunt_critic", "remediate", "triage",
    ] = "review",
    speed: Literal["standard", "fast"] = "standard",
    provider: LlmProvider = "claude",
    openai_client: Any | None = None,
    codex_runner: Any | None = None,
    hypotheses: list[dict] | None = None,
    lens: str | None = None,
    avoid_titles: list[str] | None = None,
    critic_hint: str | None = None,
    budget: AiBudget | None = None,
) -> LlmReviewResult:
    """Produce a narrative defensive review — or, with ``mode="hunt"``, ranked
    vulnerability hypotheses (#80) — by calling an LLM.

    ``provider`` selects Claude (default) or OpenAI/Codex. For each provider,
    the backend resolves to an API SDK or a subscription CLI based on available
    auth, then runs the appropriate prompt pack through it. The Claude SDK path
    streams so we never hit HTTP timeouts on long reviews; the `claude` CLI path
    runs `claude -p --output-format=json`. The OpenAI path uses the Responses
    API; the `codex` CLI path runs `codex exec`. All modes share the same
    evidence grounding contract (every claim cites evidence IDs). ``speed`` (Fast
    mode) is Claude/API-only and ignored for OpenAI.
    """
    resolved_effort = effort or DEFAULT_EFFORT

    if mode == "hunt_skeptic":
        # The skeptic pass needs the fixed hypothesis list (#147a).
        rendered = render_skeptic_prompts(
            scan, attack_surfaces, findings, attack_paths, hypotheses or []
        )
    elif mode == "hunt_generate":
        # Generation can be primed with a lens (#147b) and prior-round context (#147c).
        rendered = render_hunt_generate_prompts(
            scan, attack_surfaces, findings, attack_paths,
            lens=lens, avoid_titles=avoid_titles, critic_hint=critic_hint,
        )
    elif mode == "hunt_critic":
        # The completeness critic names untried angles from the leads so far (#147c).
        rendered = render_critic_prompts(
            scan, attack_surfaces, findings, attack_paths, hypotheses or []
        )
    else:
        render = {
            "hunt": render_hunt_prompts,
            "hunt_verify": render_hunt_verify_prompts,
            "remediate": render_remediation_prompts,
            "triage": render_triage_prompts,
        }.get(mode, render_review_prompts)
        endpoint = (str(getattr(openai_client, "base_url", "") or os.environ.get("OPENAI_BASE_URL", ""))
                    if provider == "openai" else str(getattr(client, "base_url", "") or os.environ.get("ANTHROPIC_BASE_URL", "")))
        if mode == "review" and backend != "cli" and _literal_loopback_url(endpoint):
            rendered = render_review_prompts(scan, attack_surfaces, findings, attack_paths,
                                             max_evidence_chars=14000)
        else:
            rendered = render(scan, attack_surfaces, findings, attack_paths)

    def review_call(*args, **kwargs):
        result = _provider_call(*args, **kwargs)
        return _validate_narrative_references(result, rendered) if mode in {"review", "remediate", "triage"} else result

    if provider == "openai":
        resolved_model = (
            model or os.environ.get("ATTACKMAP_OPENAI_MODEL") or OPENAI_DEFAULT_MODEL
        )
        if backend == "cli" and codex_runner is not None:
            chosen: Literal["api", "cli"] = "cli"
        else:
            chosen = _resolve_openai_backend(
                backend, api_key=api_key, client=openai_client, codex_runner=codex_runner
            )
        if chosen == "api":
            return review_call(lambda limit: _run_via_openai_sdk(
                rendered.system,
                rendered.user,
                model=resolved_model,
                effort=resolved_effort,
                max_tokens=limit,
                api_key=api_key,
                client=openai_client,
            ), max_tokens=max_tokens, timeout=_openai_timeout_ceiling(openai_client, budget=budget), budget=budget)
        return review_call(lambda limit: _run_via_codex_cli(
            rendered.system,
            rendered.user,
            model=resolved_model,
            effort=resolved_effort,
            runner=codex_runner,
        ), max_tokens=max_tokens, timeout=CODEX_CLI_TIMEOUT_SECONDS, budget=budget, cli=True)

    resolved_model = model or os.environ.get("ATTACKMAP_LLM_MODEL") or DEFAULT_MODEL
    if backend == "cli" and cli_runner is not None:
        chosen_backend: Literal["api", "cli"] = "cli"
    else:
        chosen_backend = _resolve_backend(backend, api_key=api_key, client=client)

    if chosen_backend == "api":
        return review_call(lambda limit: _run_via_sdk(
            rendered.system,
            rendered.user,
            model=resolved_model,
            effort=resolved_effort,
            max_tokens=limit,
            api_key=api_key,
            client=client,
            speed=speed,
        ), max_tokens=max_tokens, timeout=CLAUDE_CLI_TIMEOUT_SECONDS, budget=budget)
    return review_call(lambda limit: _run_via_claude_cli(
        rendered.system,
        rendered.user,
        model=resolved_model,
        runner=cli_runner,
    ), max_tokens=max_tokens, timeout=CLAUDE_CLI_TIMEOUT_SECONDS, budget=budget, cli=True)


__all__ = [
    "generate_llm_review",
    "LlmReviewError",
    "LlmReviewResult",
    "LlmBackend",
    "LlmProvider",
    "DEFAULT_MODEL",
    "OPENAI_DEFAULT_MODEL",
    "DEFAULT_EFFORT",
    "DEFAULT_MAX_TOKENS",
]
