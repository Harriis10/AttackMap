"""Bounded, source-free local diagnostic context. No presentation dependencies."""
from __future__ import annotations

from typing import Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .models import ResourceLimitEvent
from .redact import redact_text

Status = Literal["not_started", "unknown", "partial", "complete"]
Outcome = Literal["completed", "failed", "cancelled", "unknown"]
StageId = Literal["request_validation", "select_analyzers", "scan_and_merge", "secrets_history",
                  "cve", "translate", "suppress", "publish", "publication", "fleet", "worker", "analysis_pipeline",
                  "baseline", "pr_comment", "llm", "hunt", "remediate", "triage", "unknown"]
ResourceScope = Literal["repo_index.file_bytes", "repo_index.index_bytes", "config_scanner.file_bytes"]


class _ContextModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)


class DiagnosticStage(_ContextModel):
    stage_id: StageId
    outcome: Outcome
    duration_milliseconds: int | float | None = Field(default=None, ge=0)


class DiagnosticAnalyzer(_ContextModel):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$")
    version_status: Literal["declared", "unknown"] = "unknown"


class DiagnosticAnalyzers(_ContextModel):
    status: Status = "unknown"
    requested_count: int | None = Field(default=None, ge=0)
    items: list[DiagnosticAnalyzer] = Field(default_factory=list, max_length=128)
    truncated: bool = False


class DiagnosticCoverage(_ContextModel):
    status: Status = "unknown"
    accepted_file_count: int | None = Field(default=None, ge=0)
    legacy_files_scanned_count: int | None = Field(default=None, ge=0)
    analyzer_error_count: int | None = Field(default=None, ge=0)
    limitation_count: int | None = Field(default=None, ge=0)
    scope_notice: Literal["Accepted-path enumeration only; not language, rule, runtime or completeness coverage."] = "Accepted-path enumeration only; not language, rule, runtime or completeness coverage."


class DiagnosticResources(_ContextModel):
    status: Status = "unknown"
    scopes: list[ResourceScope] = Field(default_factory=list, max_length=3)
    items: list[ResourceLimitEvent] = Field(default_factory=list, max_length=256)
    truncated: bool = False
    scope_notice: Literal["Only listed instrumented byte-limit scopes; other limits remain unknown."] = "Only listed instrumented byte-limit scopes; other limits remain unknown."


class DiagnosticChild(_ContextModel):
    index: int = Field(ge=0)
    outcome: Outcome = "unknown"
    coverage: DiagnosticCoverage = Field(default_factory=DiagnosticCoverage)
    resource_events: DiagnosticResources = Field(default_factory=DiagnosticResources)


class DiagnosticFleet(_ContextModel):
    status: Status = "not_started"
    requested_count: int | None = Field(default=None, ge=0)
    completed_count: int | None = Field(default=None, ge=0)
    failed_count: int | None = Field(default=None, ge=0)
    cancelled_count: int | None = Field(default=None, ge=0)
    children: list[DiagnosticChild] = Field(default_factory=list, max_length=128)
    truncated: bool = False


class DiagnosticContext(_ContextModel):
    context_version: Literal["1.0"] = "1.0"
    outcome: Outcome = "unknown"
    policy_outcome: Literal["not_evaluated", "passed", "failed", "unknown"] = "unknown"
    stages: list[DiagnosticStage] = Field(default_factory=list, max_length=128)
    analyzers: DiagnosticAnalyzers = Field(default_factory=DiagnosticAnalyzers)
    coverage: DiagnosticCoverage = Field(default_factory=DiagnosticCoverage)
    resource_events: DiagnosticResources = Field(default_factory=DiagnosticResources)
    fleet: DiagnosticFleet = Field(default_factory=DiagnosticFleet)


def _analyzers(metadata: Iterable[dict], *, requested_count: int | None = None,
               status: Status = "complete") -> DiagnosticAnalyzers:
    items = []
    invalid = False
    for entry in metadata:
        if not isinstance(entry, dict):
            invalid = True
            continue
        try:
            version = entry.get("version") if entry.get("version_status") == "declared" else None
            items.append(DiagnosticAnalyzer(name=redact_text(entry["name"]),
                         version=redact_text(version) if version is not None else None,
                         version_status="declared" if version is not None else "unknown"))
        except (KeyError, TypeError, ValidationError):
            invalid = True
    return DiagnosticAnalyzers(status="partial" if invalid or len(items) > 128 else status,
                              requested_count=requested_count, items=items[:128], truncated=len(items) > 128)


def startup_diagnostic(stage_id: StageId, *, duration_milliseconds: int | float | None = None,
                       outcome: Outcome = "failed", requested_analyzers: Iterable[str] = (),
                       analyzer_metadata: Iterable[dict] = ()) -> DiagnosticContext:
    # Requested strings can contain user input: retain only their count, never their text.
    requested_count = sum(1 for _ in requested_analyzers)
    metadata = list(analyzer_metadata)
    analyzers = _analyzers(metadata, requested_count=requested_count) if metadata else DiagnosticAnalyzers(
        status="not_started", requested_count=requested_count)
    return DiagnosticContext(outcome=outcome,
        policy_outcome="not_evaluated",
        stages=[DiagnosticStage(stage_id=stage_id, outcome=outcome, duration_milliseconds=duration_milliseconds)],
        analyzers=analyzers, coverage=DiagnosticCoverage(status="not_started"),
        resource_events=DiagnosticResources(status="not_started"))


def unknown_diagnostic(stage_id: StageId = "unknown", *, outcome: Outcome = "failed") -> DiagnosticContext:
    return DiagnosticContext(outcome=outcome, stages=[DiagnosticStage(stage_id=stage_id, outcome="unknown")])


def scan_diagnostic(scan: object | None) -> tuple[DiagnosticCoverage, DiagnosticResources]:
    if scan is None:
        return DiagnosticCoverage(), DiagnosticResources()
    files = getattr(scan, "scanned_files", None)
    analyzer_errors = list(getattr(scan, "analyzer_errors", []) or [])
    # Analyzer errors mean the accepted files were not fully analyzed: the run
    # completed but coverage is degraded, not complete.
    coverage = DiagnosticCoverage(status="complete" if files is not None and not analyzer_errors else "partial",
        accepted_file_count=len(set(files)) if files is not None else None,
        legacy_files_scanned_count=getattr(scan, "files_scanned", None),
        analyzer_error_count=len(analyzer_errors),
        limitation_count=len(getattr(scan, "limitations", [])))
    events = list(getattr(scan, "resource_limit_events", []))
    scopes = list(getattr(scan, "resource_limit_scopes", []))
    status = getattr(scan, "resource_limit_reporting", "unknown")
    resources = DiagnosticResources(status="partial" if len(events) > 256 else status,
        scopes=sorted(set(scopes)), items=events[:256], truncated=len(events) > 256)
    return coverage, resources


def context_from_run_manifest(manifest: dict, *, outcome: Outcome) -> DiagnosticContext:
    """Project only validated context or bounded known legacy numeric metadata."""
    if "diagnostic_context" in manifest:
        try:
            context = DiagnosticContext.model_validate(manifest["diagnostic_context"])
            return context.model_copy(update={"outcome": outcome})
        except ValidationError:
            pass
    stages = []
    for entry in manifest.get("stages", [])[:128] if isinstance(manifest.get("stages"), list) else []:
        try:
            stages.append(DiagnosticStage(stage_id=entry["name"], outcome="completed",
                                          duration_milliseconds=entry["milliseconds"]))
        except (KeyError, TypeError, ValidationError):
            continue
    # Legacy run manifests do not establish declared-version provenance or enumerated coverage.
    metadata = manifest.get("analyzers", [])
    analyzers = _analyzers(metadata, status="partial") if isinstance(metadata, list) else DiagnosticAnalyzers()
    return DiagnosticContext(outcome=outcome, stages=stages, analyzers=analyzers)


def fleet_diagnostic(*, duration_milliseconds: int, outcome: Outcome, requested_count: int,
                     children: Iterable[dict]) -> DiagnosticContext:
    records = []
    counts = {"completed": 0, "failed": 0, "cancelled": 0}
    for child in children:
        child_outcome = child.get("outcome", "unknown")
        if child_outcome in counts:
            counts[child_outcome] += 1
        coverage, resources = scan_diagnostic(child.get("scan"))
        records.append(DiagnosticChild(index=child["index"], outcome=child_outcome,
                                      coverage=coverage, resource_events=resources))
    return DiagnosticContext(outcome=outcome,
        stages=[DiagnosticStage(stage_id="fleet", outcome=outcome, duration_milliseconds=duration_milliseconds)],
        fleet=DiagnosticFleet(status="partial" if len(records) != requested_count or len(records) > 128 or any(child.outcome == "unknown" for child in records) else "complete",
            requested_count=requested_count, completed_count=counts["completed"], failed_count=counts["failed"],
            cancelled_count=counts["cancelled"], children=records[:128], truncated=len(records) > 128))


def merge_diagnostic_context(previous: DiagnosticContext | None, incoming: DiagnosticContext) -> DiagnosticContext:
    """Retain reported sections when a broker later has only an unknown fallback."""
    if previous is None:
        return incoming
    rank = {"unknown": 0, "not_started": 1, "partial": 2, "complete": 3}
    sections = {}
    for name in ("analyzers", "coverage", "resource_events", "fleet"):
        old, new = getattr(previous, name), getattr(incoming, name)
        sections[name] = new if rank[new.status] >= rank[old.status] else old
    old, new = previous.coverage, incoming.coverage
    sections["coverage"] = DiagnosticCoverage(status=sections["coverage"].status, **{
        field: getattr(new, field) if getattr(new, field) is not None else getattr(old, field)
        for field in ("accepted_file_count", "legacy_files_scanned_count", "analyzer_error_count", "limitation_count")})
    old, new = previous.analyzers, incoming.analyzers
    analyzers = {(item.name, item.version): item for item in [*old.items, *new.items]}
    sections["analyzers"] = DiagnosticAnalyzers(status="partial" if len(analyzers) > 128 else sections["analyzers"].status,
        requested_count=new.requested_count if new.requested_count is not None else old.requested_count,
        items=list(analyzers.values())[:128], truncated=old.truncated or new.truncated or len(analyzers) > 128)
    old, new = previous.resource_events, incoming.resource_events
    events = {item.event_id: item for item in [*old.items, *new.items]}
    sections["resource_events"] = DiagnosticResources(
        status="partial" if len(events) > 256 else sections["resource_events"].status,
        scopes=sorted(set(old.scopes) | set(new.scopes)), items=list(events.values())[:256],
        truncated=old.truncated or new.truncated or len(events) > 256)
    old, new = previous.fleet, incoming.fleet
    children = {child.index: child for child in old.children}
    for child in new.children:
        if child.index in children:
            prior = children[child.index]
            merged = merge_diagnostic_context(
                DiagnosticContext(coverage=prior.coverage, resource_events=prior.resource_events),
                DiagnosticContext(coverage=child.coverage, resource_events=child.resource_events))
            child = DiagnosticChild(index=child.index, outcome=prior.outcome if child.outcome == "unknown" else child.outcome,
                                    coverage=merged.coverage, resource_events=merged.resource_events)
        children[child.index] = child
    sections["fleet"] = DiagnosticFleet(status="partial" if len(children) > 128 else sections["fleet"].status,
        **{field: getattr(new, field) if getattr(new, field) is not None else getattr(old, field)
           for field in ("requested_count", "completed_count", "failed_count", "cancelled_count")},
        children=list(children.values())[:128], truncated=old.truncated or new.truncated or len(children) > 128)
    if children:
        fleet = sections["fleet"]
        observed_counts = {outcome: sum(child.outcome == outcome for child in children.values())
                           for outcome in ("completed", "failed", "cancelled")}
        sections["fleet"] = fleet.model_copy(update={
            outcome + "_count": max(observed_counts[outcome], getattr(fleet, outcome + "_count") or 0)
            for outcome in observed_counts})
    stages = {stage.stage_id: stage for stage in previous.stages}
    for stage in incoming.stages:
        old = stages.get(stage.stage_id)
        if old is None or stage.duration_milliseconds is not None or old.duration_milliseconds is None:
            stages[stage.stage_id] = stage
    return DiagnosticContext(outcome=incoming.outcome,
        policy_outcome=previous.policy_outcome if incoming.policy_outcome == "unknown" else incoming.policy_outcome,
        stages=list(stages.values())[:128], **sections)
