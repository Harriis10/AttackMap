"""Precomputed, evidence-honest finding detail context for report consumers.

This is a presentation of existing core facts, never a scoring or ownership pass.
Exact source co-location yields candidates only. It cannot establish support,
control enforcement, an observed trust relationship or runtime exploitation.

Ranking-factor exposure (C12): the priority block surfaces the ranking factors
actually used by the engine (severity band, confidence multiplier, fused
exploitability factors, source-quality filter) with their qualitative or numeric
contributions and explicit unresolved assumptions. It makes existing policy
visible; it never computes or changes a score. Scores order findings for triage
and are not calibrated probabilities.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from .evidence import is_low_quality_source
from .finding_identity import finding_id
from .models import ExploitabilityScore, ExploitabilityScoreReference, Finding, ScanResult
from .redact import redact_text
# Read-only exposure of the existing prioritization weights: one source of
# truth, so the decomposition shown to users cannot drift from the ranking.
from .threat_model import _CONFIDENCE_MULTIPLIER, _SEVERITY_WEIGHT

CONTEXT_VERSION = "1.0"
MAX_CANDIDATES = 8


class FindingPresentationIndex:
    """Index normalized observations once per report, not once per selection."""

    def __init__(
        self, scan: ScanResult, exploitability_scores: list[ExploitabilityScore] | None = None
    ) -> None:
        self._by_location: dict[tuple[str, int], list] = defaultdict(list)
        for signal in scan.all_signals():
            if signal.file and signal.line is not None:
                self._by_location[(signal.file.replace("\\", "/"), signal.line)].append(signal)
        # Deterministic order so the decomposition is stable across runs.
        self._scores_by_ref: dict[str, list[ExploitabilityScore]] = defaultdict(list)
        for score in exploitability_scores or []:
            if score.producer_reference is not None:
                self._scores_by_ref[score.producer_reference.score_id].append(score)
        snapshot = scan.scan_snapshot.snapshot_id if scan.scan_snapshot is not None else None
        self._reference_context = ExploitabilityScoreReference.context(scan.root, snapshot)
        self._chain_references = {
            reference.score_id: reference
            for chain in scan.taint_chains if not chain.sanitized and not chain.speculative
            for reference in [ExploitabilityScoreReference.from_chain(
                chain, repository_root=scan.root, snapshot_id=snapshot)]
        }

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
        reference_status, producer_score = self._resolve_score_reference(finding)
        decomposition = self._exploitability_decomposition(finding, producer_score)
        factors = [
            {"name": "severity", "value": finding.severity, "source": "finding.severity", "points": None,
             "kind": "ordering_band",
             "note": "primary ranking band: high ranks above medium above low (threat_model severity rank)"},
            {"name": "confidence", "value": finding.confidence, "source": "finding.confidence", "points": None,
             "kind": "ordering_multiplier",
             "note": f"multiplies the severity weight ({_SEVERITY_WEIGHT.get(finding.severity, 0)}) by "
                     f"{_CONFIDENCE_MULTIPLIER.get(finding.confidence, 0.5)} in threat_model.compute_finding_score; "
                     "an ordering input, not a calibrated probability"},
        ]
        if finding.exploitability is not None:
            factors.append({
                "name": "exploitability", "points": None, "kind": "additive_clamped_sum",
                "value": f"{finding.exploitability}/100 ({finding.exploitability_tier})",
                "source": "finding.exploitability (fused in attackmap.exploitability)",
                "note": "clamped 0-100 sum of the named factors; the additive contributions are in priority.decomposition",
            })
        else:
            factors.append({
                "name": "exploitability", "points": None, "kind": "not_applied", "value": "none",
                "source": "finding.exploitability",
                "note": "no fused route-to-sink score is attached; exposure, auth-at-entry, reachability and "
                        "chain-depth contributions are not decomposed for this finding",
            })
        factors.append({
            "name": "source_quality", "points": None, "kind": "qualitative_filter", "value": source_role,
            "source": "attackmap.evidence.is_low_quality_source over finding.locations",
            "note": "low-quality sources (tests/fixtures/mocks/examples) are excluded from runtime-surface and "
                    "hotspot ranking; a filter, not a numeric multiplier",
        })
        factors.append({
            "name": "trust_boundary_crossing", "points": None, "kind": "not_applied", "value": "unknown",
            "source": "engine ranking policy",
            "note": "not currently a fused ranking factor; see trust_chain.trust_boundary_crossing",
        })
        assumptions = ["Scores order findings for triage; they are not calibrated probabilities.",
                       "Trust-boundary crossing is not a fused ranking factor; no per-finding trust-boundary evidence is attached."]
        if finding.exploitability is None:
            assumptions.append("Exposure, privilege sensitivity (auth at entry), reachability and chain depth are not "
                               "decomposed for this finding: no fused exploitability score is attached.")
        elif not decomposition:
            assumptions.append("An engine exploitability score is attached but its additive factor list was not "
                               "supplied to this context.")
        if source_role == "unknown":
            assumptions.append("Source role is unknown for the cited locations; source-quality weighting cannot be applied.")
        elif source_role == "mixed":
            assumptions.append("Source roles disagree across cited locations; source-quality weighting is ambiguous.")
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
            if decomposition:
                uncertainty.append("Exploitability point contributions are engine-fused (attackmap.exploitability); "
                                   "the base prioritization score is a severity-by-confidence product, not additive.")
            else:
                uncertainty.append("Numeric priority is supplied by the engine; finding-owned point contributions are not supplied.")
        if finding.exploitability is not None and reference_status != "resolved":
            uncertainty.append(f"Exact producer score association is unavailable: {reference_status}.")
        flows = [[step.model_dump() for step in flow] for flow in finding.code_flows]
        return {
            "context_version": CONTEXT_VERSION,
            "finding_id": finding_id(finding),
            "claim": {"kind": "heuristic_static_analysis", "text": finding.title,
                      "evidence_kind": "heuristic_static_claim", "runtime_verification": "unknown"},
            "priority": {"severity": finding.severity, "confidence": finding.confidence,
                         "score": finding.score, "exploitability_score": finding.exploitability,
                         "exploitability_tier": finding.exploitability_tier,
                         "factors": factors,
                         "point_contributions": "supplied" if decomposition else "not_supplied",
                         "score_reference": {
                             "status": reference_status,
                             "reference": finding.exploitability_reference.model_dump()
                                 if finding.exploitability_reference is not None else None,
                             "scope": self._reference_context[2],
                             "meaning": "Producer identity within the selected scan; not runtime or publisher authentication.",
                         },
                         "decomposition": decomposition,
                         "unresolved_assumptions": assumptions,
                         "meaning": "Heuristic prioritization; not verified exploitation. Scores order "
                                    "findings for triage; they are not calibrated probabilities."},
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

    def _resolve_score_reference(self, finding: Finding) -> tuple[str, ExploitabilityScore | None]:
        if finding.exploitability is None:
            return "not_applied", None
        reference = finding.exploitability_reference
        if reference is None:
            return "missing_reference", None
        root, snapshot, scope = self._reference_context
        if scope != "repository_snapshot" or reference.scope != "repository_snapshot":
            return "unverified_scope", None
        if reference.repository_root != root or reference.snapshot_id != snapshot:
            return "context_mismatch", None
        if self._chain_references.get(reference.score_id) != reference:
            return "source_chain_unavailable", None
        candidates = self._scores_by_ref.get(reference.score_id, [])
        if not candidates:
            return "score_unavailable", None
        if len(candidates) != 1:
            return "ambiguous_reference", None
        score = candidates[0]
        if score.producer_reference != reference:
            return "producer_reference_mismatch", None
        if score.score != finding.exploitability or score.tier != finding.exploitability_tier:
            return "numeric_mismatch", None
        chain = reference.chain
        if (score.route, score.method, score.sink_kind, score.location) != (
            chain.route_path, chain.route_method, chain.sink_kind, f"{chain.sink_file}:{chain.sink_line}"
        ):
            return "source_chain_mismatch", None
        if sum(f.points for f in score.factors) != score.raw_score or max(0, min(100, score.raw_score)) != score.score:
            return "factor_integrity_mismatch", None
        return "resolved", score

    def _exploitability_decomposition(self, finding: Finding, score: ExploitabilityScore | None) -> list[dict[str, Any]]:
        """Expose only the unique, scoped producer record selected at fusion.

        Missing/legacy/unverified references never acquire ownership through
        equal numeric values, tiers, source co-location or presentation prose.
        """
        if score is None:
            return []
        finding_locs = {(location.file.replace("\\", "/"), location.line) for location in finding.locations}
        chain = score.producer_reference.chain
        corroborated = (chain.sink_file.replace("\\", "/"), chain.sink_line) in finding_locs
        points_sum = sum(factor.points for factor in score.factors)
        return [{
            "subject": score.subject, "route": score.route, "method": score.method,
            "sink_kind": score.sink_kind, "sink_location": score.location,
            "score": score.score, "raw_score": score.raw_score, "tier": score.tier,
            "match_basis": "exact_producer_reference",
            "producer_reference": score.producer_reference.model_dump(),
            "location_corroborated": corroborated,
            "factors": [{"name": factor.name, "points": factor.points, "detail": factor.detail} for factor in score.factors],
            "points_sum": points_sum, "sums_to_raw_score": points_sum == score.raw_score,
        }]
