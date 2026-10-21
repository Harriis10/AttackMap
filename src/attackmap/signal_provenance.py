"""Lossless provenance for the existing normalized Signal view.

Typed hints retain their legacy merge policy. The normalized view preserves
corroborating origins and contradictory property values independently of which
legacy representative wins. This is static analyzer provenance, not runtime proof.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import TYPE_CHECKING

from .models import Signal, SignalConflict, SignalOrigin
from .evidence import classify_source_path

if TYPE_CHECKING:
    from .models import ScanResult

KINDS = ("routes", "external_calls", "databases", "auth_hints", "service_hints",
         "edge_hints", "entrypoint_hints", "protocol_hints", "framework_hints",
         "secret_hints", "taint_chains", "dependencies")

CLASSIFICATION_FIELDS = {"classification_version", "source_role", "evidence_kind", "classification_basis"}


def _semantic_dump(value, *, exclude=frozenset()):
    return value.model_dump(exclude=CLASSIFICATION_FIELDS | set(exclude))


def _stamp_static_classification(value) -> None:
    if value.classification_version is None:
        value.classification_version = "1.0"
        value.source_role = classify_source_path(value.file)
        value.classification_basis = "path_convention" if value.source_role != "unknown" else "unknown"
        value.evidence_kind = "static_extraction"


def _identity(signal: Signal) -> str:
    # These labels are analyzer signal values (method/path, hint, sink or
    # package identity), never human-facing finding titles or analyzer order.
    location = None if signal.kind == "route" else signal.line
    discriminator = signal.properties.get("method") if signal.kind == "external_call" else None
    return json.dumps([signal.kind, signal.label, signal.file, location, discriminator], ensure_ascii=False, separators=(",", ":"))


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def merge_normalized_signals(signals: list[Signal]) -> list[Signal]:
    groups: dict[str, list[Signal]] = defaultdict(list)
    for signal in signals:
        groups[_identity(signal)].append(signal)
    merged: list[Signal] = []
    for identity, items in sorted(groups.items()):
        ordered = sorted(items, key=lambda item: (_canonical(_semantic_dump(item, exclude={"origins", "conflicts", "observation_id"})), _canonical(item.model_dump(include=CLASSIFICATION_FIELDS))))
        representative = ordered[0].model_copy(deep=True)
        representative.observation_id = "obs-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()
        origins = {(_canonical(_semantic_dump(origin)), _canonical(origin.model_dump(include=CLASSIFICATION_FIELDS))): origin for item in items for origin in item.origins}
        representative.origins = [origins[key].model_copy(deep=True) for key in sorted(origins)]
        values: dict[str, set[str]] = defaultdict(set)
        for item in items:
            for key, value in item.properties.items():
                values[key].add(value)
            for conflict in item.conflicts:
                values[conflict.field].update(conflict.values)
        roles = set(values.get("source_role", set()))
        roles.update(item.source_role for item in items if not (
            item.source_role == "unknown" and any(c.field == "source_role" for c in item.conflicts)
        ))
        if len(roles) > 1:
            representative.source_role = "unknown"
            representative.classification_basis = "unknown"
            values["source_role"].update(roles)
        if len({item.evidence_kind for item in items}) > 1:
            representative.evidence_kind = "unknown"
        representative.conflicts = [SignalConflict(field=key, values=sorted(options))
                                    for key, options in sorted(values.items()) if len(options) > 1]
        merged.append(representative)
    return merged


def normalized_view(scan: ScanResult, synthesized: list[Signal]) -> list[Signal]:
    # Existing preserved observations win over a newly synthesized lossy typed
    # representative, while later whole-repository passes can add new signals.
    stored = { _identity(signal) for signal in scan.signals }
    additions: list[Signal] = []
    sources = [item for attr in KINDS for item in getattr(scan, attr)]
    for signal, source in zip(synthesized, sources):
        if _identity(signal) in stored:
            continue
        owned = signal.model_copy(deep=True)
        _stamp_static_classification(owned)
        analyzer = getattr(source, "source_analyzer", None)
        owned.origins = [SignalOrigin(
            classification_version=owned.classification_version, source_role=owned.source_role,
            evidence_kind=owned.evidence_kind, classification_basis=owned.classification_basis,
            analyzer=analyzer,
            # Existing typed hints identify a producer but do not carry its
            # version; do not advertise complete metadata for legacy output.
            metadata_status="legacy_unknown",
            file=signal.file or None, line=signal.line,
            location_reason=None if signal.file and signal.line is not None else "Analyzer did not provide a complete file/line location",
            evidence_text=signal.evidence_text,
            properties=dict(signal.properties),
        )]
        additions.append(owned)
    return merge_normalized_signals([*scan.signals, *additions])


def merge_scan_provenance(destination: ScanResult, sources: list[ScanResult]) -> None:
    destination.signals = merge_normalized_signals([signal for source in sources for signal in source.all_signals()])
    if all(source.scanned_files is not None for source in sources):
        destination.scanned_files = sorted({path.replace("\\", "/") for source in sources for path in source.scanned_files or []})
        destination.files_scanned = len(destination.scanned_files)
    else:
        limitation = "Unique-file coverage unavailable: one or more analyzers did not enumerate scanned_files; files_scanned is a legacy aggregate and may overlap."
        if limitation not in destination.limitations:
            destination.limitations.append(limitation)


def stamp_scan_provenance(scan: ScanResult, analyzer: str, version: str | None) -> None:
    """Preserve declared producer versions without upgrading another producer."""
    known_version = version.strip() if isinstance(version, str) and version.strip() else None
    observations = scan.all_signals()
    for signal in observations:
        if not signal.origins:
            signal.origins = [SignalOrigin(
                analyzer=analyzer, file=signal.file or None, line=signal.line,
                evidence_text=signal.evidence_text, properties=dict(signal.properties),
                location_reason=None if signal.file and signal.line is not None else "Analyzer did not provide a complete file/line location",
            )]
        for origin in signal.origins:
            if origin.analyzer is None:
                origin.analyzer = analyzer
            if origin.analyzer == analyzer and origin.analyzer_version is None and known_version:
                origin.analyzer_version = known_version
                origin.metadata_status = "known"
    scan.signals = observations


def admit_isolated_provenance(scan: ScanResult, analyzer: str, version: str | None) -> None:
    """Bind an isolated emitter to parent metadata; retain legacy claims as untrusted.

    This identifies who returned a statement. It does not authenticate its source
    locations, semantic truth, installed code or use of the cooperating SDK.
    In-process/trusted legacy stamping keeps its existing compatibility policy.
    """
    from .merge import MERGE_SCHEMA
    from .redact import redact_text

    known_version = version.strip() if isinstance(version, str) and version.strip() else None
    observations = scan.all_signals()  # capture old aliases before canonicalizing typed hints
    reserved = CLASSIFICATION_FIELDS | {"analyzer", "analyzer_version", "metadata_status", "source_analyzer", "observation_id"}

    def claim(properties, key, value):
        if value is not None:
            properties["untrusted_claimed_" + key] = str(redact_text(str(value)) or "")[:500]

    def classify(value, properties):
        # A child cannot confer detector-owned or artifact-manifest authority.
        role = classify_source_path(value.file)
        expected = {"classification_version": "1.0", "source_role": role,
                    "evidence_kind": "static_extraction",
                    "classification_basis": "path_convention" if role != "unknown" else "unknown"}
        for field, assigned in expected.items():
            original = getattr(value, field)
            if original is not None and original != "unknown" and original != assigned:
                claim(properties, field, original)
            setattr(value, field, assigned)

    for rule in MERGE_SCHEMA:
        for item in getattr(scan, rule.attr):
            item.source_analyzer = analyzer
    for signal in observations:
        for key in sorted(reserved):
            if key in signal.properties:
                claim(signal.properties, key, signal.properties.pop(key))
        for conflict in signal.conflicts:
            if conflict.field in reserved:
                claim(signal.properties, "conflict_" + conflict.field, _canonical(conflict.values))
        signal.conflicts = [conflict for conflict in signal.conflicts if conflict.field not in reserved]
        classify(signal, signal.properties)
        signal.observation_id = None
        if not signal.origins:
            signal.origins = [SignalOrigin(file=signal.file or None, line=signal.line,
                evidence_text=signal.evidence_text, properties=dict(signal.properties),
                location_reason=None if signal.file and signal.line is not None else "Analyzer did not provide a complete file/line location")]
        for origin in signal.origins:
            if origin.analyzer not in {None, analyzer}:
                claim(origin.properties, "producer", origin.analyzer)
            if origin.analyzer_version is not None and origin.analyzer_version != known_version:
                claim(origin.properties, "version", origin.analyzer_version)
            for key in sorted(reserved):
                if key in origin.properties:
                    claim(origin.properties, key, origin.properties.pop(key))
            if not known_version and origin.metadata_status == "known":
                claim(origin.properties, "metadata_status", origin.metadata_status)
            origin.analyzer = analyzer
            origin.analyzer_version = known_version
            origin.metadata_status = "known" if known_version else "legacy_unknown"
            origin.evidence_text = redact_text(origin.evidence_text) if origin.evidence_text else origin.evidence_text
            classify(origin, origin.properties)
    scan.signals = merge_normalized_signals(observations)
