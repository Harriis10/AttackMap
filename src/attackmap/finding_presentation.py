"""Precomputed, evidence-honest finding detail context for report consumers.

This is a presentation of existing core facts, never a scoring or ownership pass.
Exact source co-location yields candidates only. It cannot establish support,
control enforcement, an observed trust relationship or runtime exploitation.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from .evidence import is_low_quality_source
from .finding_identity import finding_id
from .models import Finding, ScanResult
from .redact import redact_text

CONTEXT_VERSION = "1.0"
MAX_CANDIDATES = 8


class FindingPresentationIndex:
    """Index normalized observations once per report, not once per selection."""

    def __init__(self, scan: ScanResult) -> None:
        self._by_location: dict[tuple[str, int], list] = defaultdict(list)
        for signal in scan.all_signals():
            if signal.file and signal.line is not None:
                self._by_location[(signal.file.replace("\\", "/"), signal.line)].append(signal)

    def for_finding(self, finding: Finding, *, suppression_reason: str | None = None) -> dict[str, Any]:
        locations = []
        candidates = {}
        for location in finding.locations:
            path = location.file.replace("\\", "/")
            locations.append({
                **location.model_dump(), "file": path,
                "source_role": "unknown" if not path else "low_quality" if is_low_quality_source(path) else "unclassified",
                "low_quality_source": is_low_quality_source(path),
                "evidence_kind": "structured_location_reference",
            })
            if path and location.line is not None:
                for signal in self._by_location.get((path, location.line), []):
                    candidates[signal.observation_id] = signal
        selected = [candidates[key] for key in sorted(candidates)[:MAX_CANDIDATES]]
        observation_candidates = [{
            "observation_id": signal.observation_id, "kind": signal.kind,
            "file": signal.file, "line": signal.line,
            "association": "exact_location_candidate_only", "ownership": "unknown",
            "conflicts": [{"field": str(redact_text(conflict.field)),
                           "values": [str(redact_text(value)) for value in conflict.values]}
                          for conflict in signal.conflicts],
            "origins": [{"analyzer": origin.analyzer, "analyzer_version": origin.analyzer_version,
                         "metadata_status": origin.metadata_status} for origin in signal.origins],
        } for signal in selected]
        roles = {location["source_role"] for location in locations}
        source_role = next(iter(roles)) if len(roles) == 1 else "mixed" if roles else "unknown"
        factors = [
            {"name": "severity", "value": finding.severity, "source": "finding.severity", "points": None},
            {"name": "confidence", "value": finding.confidence, "source": "finding.confidence", "points": None},
        ]
        uncertainty = [
            "Heuristic static-analysis claim; runtime reachability and exploitation are unverified.",
            "Source co-location and repository-wide controls do not establish finding ownership or control enforcement.",
            "Finding-to-control and finding-to-attack-path ID associations are not supplied.",
        ]
        if not locations:
            uncertainty.append("Structured source location is unavailable; source role is unknown.")
        if "low_quality" in roles:
            uncertainty.append("Low-quality source role is present under the existing tests/fixtures/mocks/examples policy.")
        if candidates:
            uncertainty.append("Observation cross-references are candidates only; no detector-owned observation IDs link them to this finding.")
        if any(signal.conflicts for signal in selected):
            uncertainty.append("Candidate observations contain conflicting properties; they are not resolved by this presentation.")
        if finding.score is not None or finding.exploitability is not None:
            uncertainty.append("Numeric priority is supplied by the engine; finding-owned point contributions are not supplied.")
        flows = [[step.model_dump() for step in flow] for flow in finding.code_flows]
        return {
            "context_version": CONTEXT_VERSION,
            "finding_id": finding_id(finding),
            "claim": {"kind": "heuristic_static_analysis", "text": finding.title,
                      "evidence_kind": "heuristic_static_claim", "runtime_verification": "unknown"},
            "priority": {"severity": finding.severity, "confidence": finding.confidence,
                         "score": finding.score, "exploitability_score": finding.exploitability,
                         "exploitability_tier": finding.exploitability_tier,
                         "factors": factors, "point_contributions": "not_supplied",
                         "meaning": "Heuristic prioritization; not verified exploitation."},
            "source": {"role": source_role, "locations": locations,
                       "policy": "attackmap.evidence.is_low_quality_source"},
            "evidence": {"text": list(finding.evidence), "basis": "heuristic_static",
                         "observation_links": "candidate_only" if candidates else "unknown",
                         "candidates": observation_candidates,
                         "candidates_truncated": len(candidates) > MAX_CANDIDATES},
            "observed_controls": {"status": "unknown", "items": [],
                                  "reason": "No stable finding-to-control association is supplied."},
            "trust_chain": {"status": "detector_owned_static_flow" if flows else "unknown",
                            "source": "finding.code_flows" if flows else "not_supplied",
                            "flows": flows, "trust_boundary_crossing": "unknown",
                            "meaning": "A detector-owned static data-flow trace is not a verified inter-service trust relationship."},
            "recommendation": finding.mitigation,
            "suppression": {"state": "suppressed" if suppression_reason is not None else "active",
                            "reason": suppression_reason},
            "uncertainty": uncertainty,
        }
