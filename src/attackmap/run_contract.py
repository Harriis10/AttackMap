"""Versioned, transport-neutral run envelopes; independent of process exit codes."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from .provider_options import ProviderOptions

CURRENT_SCHEMA_VERSION = "1.1"
SUPPORTED_SCHEMA_VERSIONS = ("1.0", "1.1")
RunState = Literal["queued", "running", "cancelling", "completed", "failed", "cancelled"]
PolicyOutcome = Literal["not_evaluated", "passed", "failed"]
ArtifactReadiness = Literal["pending", "ready", "unavailable"]


class RunEnvelope(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)
    schema_version: str = CURRENT_SCHEMA_VERSION
    run_id: str = Field(min_length=1)
    repository_id: str = Field(min_length=1)
    generation: int = Field(ge=1)
    revision: int = Field(ge=0)

    @field_validator("schema_version")
    @classmethod
    def supported_version(cls, value: str) -> str:
        if value not in SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError(
                f"Unsupported run schema {value!r}; supported range is 1.0–1.1. "
                "Upgrade the consumer or export using a supported schema. "
                "Schema-less reports require import_legacy_report()."
            )
        return value


class ScanOptions(BaseModel):
    """Desktop analysis options; optional network features remain opt-in."""

    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)
    recall: bool = False
    strict_analyzers: bool = False
    no_suppress: bool = False
    cve: bool = False
    secrets_history: int = Field(default=0, ge=0, le=10_000)
    timeout_seconds: int = Field(default=600, ge=1, le=86_400)
    provider: ProviderOptions = Field(default_factory=ProviderOptions)


class RunRequest(RunEnvelope):
    kind: Literal["request"] = "request"
    repository_path: str = Field(min_length=1)
    output_path: str = Field(min_length=1)
    modules: list[str] = Field(default_factory=list)
    options: ScanOptions = Field(default_factory=ScanOptions)


class RunProgress(RunEnvelope):
    kind: Literal["progress"] = "progress"
    state: Literal["queued", "running", "cancelling"]
    stage: str = ""
    completed_units: int | None = Field(default=None, ge=0)
    total_units: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def valid_units(self) -> RunProgress:
        if self.total_units is not None and (
            self.completed_units is None or self.completed_units > self.total_units
        ):
            raise ValueError("Bounded progress needs completed_units <= total_units")
        return self


class RunTerminal(RunEnvelope):
    kind: Literal["terminal"] = "terminal"
    state: Literal["completed", "failed", "cancelled"]
    execution_outcome: Literal["succeeded", "failed", "cancelled"]
    policy_outcome: PolicyOutcome = "not_evaluated"
    artifact_readiness: ArtifactReadiness = "unavailable"
    error: str | None = None
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def consistent_outcome(self) -> RunTerminal:
        expected = {"completed": "succeeded", "failed": "failed", "cancelled": "cancelled"}
        if self.execution_outcome != expected[self.state]:
            raise ValueError("Terminal state must match execution_outcome")
        if self.state != "completed" and self.policy_outcome != "not_evaluated":
            raise ValueError("Only a completed analysis has a policy outcome")
        if self.state != "completed" and self.artifact_readiness == "ready":
            raise ValueError("Failed/cancelled runs cannot publish ready analysis artifacts")
        return self


class RunArtifact(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True, frozen=True)
    path: str = Field(min_length=1)
    media_type: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)

    @field_validator("path")
    @classmethod
    def relative_path(cls, value: str) -> str:
        from pathlib import PurePosixPath, PureWindowsPath
        if (PurePosixPath(value).is_absolute() or PureWindowsPath(value).drive
                or "\\" in value or ".." in PurePosixPath(value).parts):
            raise ValueError("Artifact paths must be relative POSIX paths without traversal")
        return value


class RunArtifactManifest(RunEnvelope):
    kind: Literal["manifest"] = "manifest"
    artifact_readiness: Literal["ready"] = "ready"
    artifacts: list[RunArtifact] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_paths(self) -> RunArtifactManifest:
        paths = [item.path for item in self.artifacts]
        if len(paths) != len(set(paths)):
            raise ValueError("Artifact paths must be unique")
        return self


def parse_run_message(payload: dict[str, Any]) -> RunEnvelope:
    """Decode explicit versioned envelopes; never infer a version for legacy data."""
    if "schema_version" not in payload:
        raise ValueError("Missing schema_version; use import_legacy_report() for legacy reports")
    models = {"request": RunRequest, "progress": RunProgress,
              "terminal": RunTerminal, "manifest": RunArtifactManifest}
    model = models.get(payload.get("kind"))
    if model is None:
        raise ValueError("Unknown run message kind; expected request, progress, terminal, or manifest")
    return model.model_validate(payload)


def accepts_update(current: RunEnvelope, incoming: RunEnvelope) -> bool:
    """Reject duplicates, reordered events, cross-run identity and terminal regression."""
    return (
        (current.run_id, current.repository_id, current.generation)
        == (incoming.run_id, incoming.repository_id, incoming.generation)
        and incoming.revision > current.revision
        and not isinstance(current, RunTerminal)
        and not (isinstance(current, RunProgress) and current.state == "cancelling"
                 and isinstance(incoming, RunProgress) and incoming.state != "cancelling")
        and not (isinstance(current, RunProgress) and current.state == "running"
                 and isinstance(incoming, RunProgress) and incoming.state == "queued")
    )


def import_legacy_report(payload: dict[str, Any], *, run_id: str,
                         repository_id: str, generation: int) -> tuple[RunTerminal, dict[str, Any]]:
    """Wrap a recognized saved report without inventing provenance or publication proof."""
    if "schema_version" in payload:
        raise ValueError("Legacy adapter accepts only schema-less reports")
    scan = payload.get("scan")
    if not isinstance(scan, dict) or not isinstance(scan.get("root"), str):
        raise ValueError("Unsupported legacy report: expected scan object with root")
    terminal = RunTerminal(
        run_id=run_id, repository_id=repository_id, generation=generation, revision=0,
        state="completed", execution_outcome="succeeded", artifact_readiness="unavailable",
        limitations=["Imported legacy report: identity supplied by caller; policy and artifact integrity unverified."],
    )
    return terminal, payload
