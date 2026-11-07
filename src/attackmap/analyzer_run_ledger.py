"""Per-run analyzer decisions and observed outcomes, separate from discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
import time
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from .analyzer_contracts import AnalyzerProtocol


def safe_error_type(value: str) -> str:
    return value if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", value) else "Exception"


class AnalyzerRunError(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stage: Literal["detect", "analysis", "isolated_host", "captured_input"]
    error_type: str


class AnalyzerSignalCounts(BaseModel):
    model_config = ConfigDict(extra="forbid")
    routes: int = Field(ge=0)
    external_calls: int = Field(ge=0)
    databases: int = Field(ge=0)
    auth_hints: int = Field(ge=0)
    secret_hints: int = Field(ge=0)


class AnalyzerLifecycleEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stage: Literal["detect", "selection", "analysis"]
    state: Literal["started", "requested", "applicable", "unmatched", "detect_error", "selected", "skipped", "succeeded", "failed"]
    elapsed_ms: float = Field(ge=0, allow_inf_nan=False)
    error_type: str | None = None


class AnalyzerRunRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    version: str | None = None
    priority: int = 100
    origin: Literal["builtin", "plugin", "supplied"]
    implementation: dict[str, str | None]
    implementation_sha256: str
    package: dict[str, str | None] | None = None
    entry_point: dict[str, str | None] | None = None
    provenance: dict[str, object] = Field(default_factory=dict)
    selection: Literal["selected", "skipped"] = "skipped"
    applicability: Literal["not_evaluated", "applicable", "unmatched", "detect_error"] = "not_evaluated"
    execution: Literal["not_started", "succeeded", "failed", "skipped"] = "not_started"
    analysis_started: bool | None = False
    execution_mode: Literal["in_process", "isolated"] | None = None
    skip_reason: Literal["unmatched", "detect_error", "opt_in", "pipeline_deadline"] | None = None
    error: AnalyzerRunError | None = None
    detect_duration_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    analysis_duration_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    signal_counts: AnalyzerSignalCounts | None = None
    lifecycle_events: list[AnalyzerLifecycleEvent] = Field(default_factory=list, max_length=16)

    def failed(self, stage: str, error_type: str) -> None:
        self.execution = "failed"
        self.error = AnalyzerRunError(stage=stage, error_type=safe_error_type(error_type))


class AnalyzerRunLedger(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0", "1.1"] = "1.1"
    scope: Literal["analyzer_selection_and_execution"] = "analyzer_selection_and_execution"
    inventory_scope: Literal["registered_candidates", "supplied_candidates"] = "registered_candidates"
    selection_mode: Literal["automatic", "explicit"]
    profile_id: str | None = None
    resolution_complete: bool = False
    execution_complete: bool = False
    entries: list[AnalyzerRunRecord] = Field(default_factory=list)


def analyzer_run_identity(analyzer: AnalyzerProtocol) -> dict[str, object]:
    """Observe this instance; never rediscover or infer package identity by name.

    Paths and URLs are deliberately omitted from the report/manifest identity.
    A class-source digest is a bounded observation, not a dependency attestation.
    """
    from .analyzer_catalog import AnalyzerDiscoveryCollector, _implementation
    from .analyzers import _BUILTIN_ANALYZER_TYPES, _entry_point_distribution

    implementation = _implementation(analyzer)
    implementation.pop("source_file", None)
    entry_point = getattr(analyzer, "_attackmap_entry_point", None)
    # A caller-defined subclass is its own implementation even when the legacy
    # isolation policy treats it as a built-in through isinstance().
    origin = "builtin" if type(analyzer) in _BUILTIN_ANALYZER_TYPES else "supplied"
    package = None
    entry_point_data = None
    provenance: dict[str, object] = {"pin_status": "unverified", "content_verified": False}
    if entry_point is not None:
        collector = AnalyzerDiscoveryCollector(trusted_only=False)
        row = collector.entry_point(entry_point, _entry_point_distribution(entry_point), "attackmap.analyzers")
        origin = "plugin"
        package = row["package"]
        entry_point_data = row["entry_point"]
        observed = row["provenance"]
        source = observed["installed_source"]
        provenance = {
            "declared_pin": observed["declared_pin"],
            "installed_source": {key: source[key] for key in ("kind", "evidence", "vcs", "commit_id") if key in source},
            "pin_status": observed["pin_status"],
            "content_verified": False,
            "errors": observed["errors"],
        }
    elif origin == "builtin":
        package = {"name": "attackmap", "version": None}
        provenance = {"pin_status": "not_applicable", "content_verified": False}
    identity = {"origin": origin, "implementation": implementation, "package": package,
                "entry_point": entry_point_data, "provenance": provenance}
    return {**identity, "implementation_sha256": hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()}


@dataclass
class AnalyzerRunPlan:
    """One-use selection tied to the actual capture, never a reusable name cache."""

    repository_root: Path
    index: object
    ledger: AnalyzerRunLedger
    analyzers: tuple[AnalyzerProtocol, ...] = ()
    _selected_records: tuple[AnalyzerRunRecord, ...] = field(default=(), repr=False)
    _claimed: bool = field(default=False, repr=False)
    _started_monotonic: float = field(default_factory=lambda: time.monotonic(), repr=False)

    @staticmethod
    def mark() -> float:
        return time.monotonic()

    @staticmethod
    def duration_ms(started: float) -> float:
        return max(0.0, (time.monotonic() - started) * 1000)

    def observe(self, row: AnalyzerRunRecord, stage: str, state: str, *, error_type: str | None = None) -> None:
        if len(row.lifecycle_events) < 16:
            row.lifecycle_events.append(AnalyzerLifecycleEvent(stage=stage, state=state,
                elapsed_ms=self.duration_ms(self._started_monotonic),
                error_type=safe_error_type(error_type) if error_type is not None else None))

    def claim(self, root: Path, index: object) -> None:
        if root != self.repository_root or index is not self.index:
            raise ValueError("Analyzer run plan does not belong to this repository capture")
        if self._claimed or not self.ledger.resolution_complete:
            raise ValueError("Analyzer run plan is unresolved or already consumed")
        self._claimed = True

    def skip_for_deadline(self) -> None:
        self._claimed = True
        for row in self._selected_records:
            if row.execution == "not_started":
                row.execution = "skipped"
                row.skip_reason = "pipeline_deadline"
                self.observe(row, "selection", "skipped")
        self.ledger.execution_complete = True
