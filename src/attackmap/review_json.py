from __future__ import annotations

from .models import AttackPath, AttackSurface, Finding, ScanResult
from .evidence import (
    is_low_quality_source as _is_low_quality_source,
    surface_evidence_class as _surface_evidence_class,
    surface_evidence_counts as _evidence_class_counts,
)
from .security_overlay import SecurityOverlay, build_security_overlay

SCHEMA_VERSION = "1.5.0"  # Static evidence labels and explicit route ownership uncertainty (C03).


def _severity_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def _risk_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def _strengths(scan: ScanResult, attack_surfaces: list[AttackSurface]) -> list[dict]:
    strengths: list[dict] = []
    auth_hints = sorted({hint.hint for hint in scan.auth_hints})
    if auth_hints:
        strengths.append(
            {
                "statement": "Authentication/identity indicators were observed in code signals.",
                "evidence_basis": "observed",
                "evidence": auth_hints[:8],
            }
        )
    internal_surfaces = [surface for surface in attack_surfaces if surface.exposure == "internal"]
    if internal_surfaces:
        strengths.append(
            {
                "statement": "Some inferred entry points appear internal-only, reducing direct internet exposure when network boundaries are correctly enforced.",
                "evidence_basis": "inferred",
                "evidence": [f"{surface.method} {surface.route} ({surface.location()})" for surface in internal_surfaces[:6]],
            }
        )
    if scan.secret_hints:
        strengths.append(
            {
                "statement": "Secret references appear environment-driven rather than hardcoded literals.",
                "evidence_basis": "observed",
                "evidence": [f"{hint.name} ({hint.file})" for hint in scan.secret_hints[:8]],
            }
        )
    if not strengths:
        strengths.append(
            {
                "statement": "No strong defensive indicators were detected heuristically.",
                "evidence_basis": "inferred",
                "evidence": [],
            }
        )
    return strengths[:4]


def _candidate_surfaces_for_finding(finding: Finding, attack_surfaces: list[AttackSurface]) -> list[AttackSurface]:
    """Prose overlap is a browsing hint, never detector-owned evidence."""
    combined = f"{finding.title} {' '.join(finding.evidence)}".lower()
    related = [
        surface
        for surface in attack_surfaces
        if any(value and value.lower() in combined for value in (surface.route, surface.file, surface.category))
    ]
    return related


def _finding_evidence_context(finding: Finding, attack_surfaces: list[AttackSurface]) -> dict:
    # Finding has no detector-owned surface IDs. Do not derive its basis from
    # route/category/file prose matches, even when a candidate is static observed.
    candidates = _candidate_surfaces_for_finding(finding, attack_surfaces)
    return {
        "evidence_basis": "heuristic_static",
        "surface_association": "unknown",
        "candidate_surfaces": [
            {"route": surface.route, "method": surface.method, "file": surface.file,
             "association": "prose_overlap_candidate_only"}
            for surface in candidates[:8]
        ],
        "candidate_surfaces_truncated": len(candidates) > 8,
        "uncertainty": "No detector-owned finding-to-surface IDs are supplied; prose overlap does not establish support or runtime behavior.",
    }


def _weaknesses_and_hotspots(
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
) -> tuple[list[dict], list[dict]]:
    ordered_findings = sorted(findings, key=lambda finding: (_severity_rank(finding.severity), finding.title))
    weakness_items = []
    for finding in ordered_findings[:8]:
        weakness_items.append(
            {
                "title": finding.title,
                "rule_id": finding.rule_id,
                "taxonomy": finding.taxonomy.model_dump() if finding.taxonomy else None,
                "severity": finding.severity,
                "confidence": finding.confidence,
                **_finding_evidence_context(finding, attack_surfaces),
                "evidence": finding.evidence[:10],
                "locations": [loc.model_dump() for loc in finding.locations],
                "mitigation": finding.mitigation,
                "attack_techniques": [t.model_dump() for t in finding.attack_techniques],
            }
        )

    runtime_surfaces = [surface for surface in attack_surfaces if not _is_low_quality_source(surface.file)]
    hotspot_pool = runtime_surfaces if runtime_surfaces else attack_surfaces
    hotspot_pool = sorted(
        hotspot_pool,
        key=lambda surface: (_risk_rank(surface.risk), surface.exposure != "public", surface.route),
    )
    hotspot_items = [
        {
            "surface": {
                "method": surface.method,
                "route": surface.route,
                "file": surface.file,
                "category": surface.category,
                "risk": surface.risk,
                "exposure": surface.exposure,
            },
            "evidence_class": _surface_evidence_class(surface),
            "notes": surface.rationale[:3],
        }
        for surface in hotspot_pool[:6]
    ]
    return weakness_items, hotspot_items


def _evidence_chains(attack_paths: list[AttackPath]) -> list[dict]:
    chains = []
    for path in attack_paths[:6]:
        chains.append(
            {
                "name": path.name,
                "impact": path.impact,
                "evidence_basis": "inferred",
                "steps": path.steps[:8],
            }
        )
    return chains


def _recommendations(findings: list[Finding], attack_surfaces: list[AttackSurface]) -> list[dict]:
    ordered_findings = sorted(findings, key=lambda finding: (_severity_rank(finding.severity), finding.title))
    recommendations: list[dict] = []
    seen: set[str] = set()
    for finding in ordered_findings:
        mitigation = finding.mitigation.strip()
        if not mitigation or mitigation in seen:
            continue
        seen.add(mitigation)
        recommendations.append(
            {
                "priority": finding.severity,
                **_finding_evidence_context(finding, attack_surfaces),
                "action": mitigation,
                "linked_finding": finding.title,
            }
        )
        if len(recommendations) >= 8:
            break
    return recommendations


def build_defensive_review_json(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
    overlay: SecurityOverlay | None = None,
) -> dict:
    evidence_counts = _evidence_class_counts(attack_surfaces)
    overlay = overlay or build_security_overlay(scan, attack_surfaces, findings, attack_paths)
    weaknesses, hotspots = _weaknesses_and_hotspots(attack_surfaces, overlay.findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "target_metadata": {
            "root": scan.root,
            "files_scanned": scan.files_scanned,
            "languages": scan.languages,
        },
        "system_overview": {
            "repository_type": "web/service-facing" if scan.routes else "non-web",
            "raw_inferred_entry_point_count": len(scan.routes),
            "external_call_count": len(scan.external_calls),
            "database_count": len(scan.databases),
            "auth_hint_count": len(scan.auth_hints),
            "secret_hint_count": len(scan.secret_hints),
            "asset_count": len(overlay.assets),
            "control_count_present": sum(1 for c in overlay.controls if c.strength != "absent"),
            "control_count_absent": sum(1 for c in overlay.controls if c.strength == "absent"),
            "notable_observation_count": len(overlay.insights),
            "detection_opportunity_count": len(overlay.detection_opportunities),
            "attack_techniques_observed_count": len(_flatten_attack_techniques(overlay)),
        },
        "attack_surface": {
            "total_surfaces": len(attack_surfaces),
            "evidence_class_counts": evidence_counts,
            "surfaces": [
                {
                    "method": surface.method,
                    "route": surface.route,
                    "file": surface.file,
                    "line": surface.line,
                    "category": surface.category,
                    "exposure": surface.exposure,
                    "risk": surface.risk,
                    "evidence_class": _surface_evidence_class(surface),
                    "auth_signals": surface.auth_signals,
                    "auth": surface.auth,
                    "data_store_interaction": surface.data_store_interaction,
                    "outbound_integration": surface.outbound_integration,
                    "relationship_basis": surface.relationship_basis,
                    "context_signals": surface.context_signals,
                }
                for surface in attack_surfaces[:60]
            ],
        },
        "assets": [asset.model_dump() for asset in overlay.assets],
        "controls": [control.model_dump() for control in overlay.controls],
        "notable_observations": [insight.model_dump() for insight in overlay.insights],
        "detection_opportunities": [opp.model_dump() for opp in overlay.detection_opportunities],
        "attack_techniques_observed": _flatten_attack_techniques(overlay),
        "strengths": _strengths(scan, attack_surfaces),
        "weaknesses_risk_hotspots": {
            "weaknesses": weaknesses,
            "risk_hotspots": hotspots,
        },
        "evidence_chains": _evidence_chains(attack_paths),
        "recommendations": _recommendations(overlay.findings, attack_surfaces),
        "raw_structured_signals": {
            "scan": scan.model_dump(),
            "attack_surfaces": [surface.model_dump() for surface in attack_surfaces],
            "findings": [finding.model_dump() for finding in overlay.findings],
            "attack_paths": [path.model_dump() for path in attack_paths],
            "assets": [asset.model_dump() for asset in overlay.assets],
            "controls": [control.model_dump() for control in overlay.controls],
            "notable_observations": [insight.model_dump() for insight in overlay.insights],
            "detection_opportunities": [opp.model_dump() for opp in overlay.detection_opportunities],
        },
        "limitations_meta": {
            "analysis_mode": "heuristic",
            "defensive_only": True,
            "notes": [
                "static_observed describes source declarations, never runtime reachability; exposure is inferred or unknown.",
                "Same-file context and repository counts do not establish route ownership or auth enforcement.",
                "Low-quality paths (tests/fixtures/mocks/examples) are retained in raw signals but separated in evidence class counts.",
                "Use this artifact as a triage source-of-truth; validate high-priority items with repository context and runtime controls.",
                "Assets, controls, and notable observations are heuristic overlays; absent-control entries indicate scanner did not find evidence, not necessarily that the control is missing in production.",
                "ATT&CK technique mappings and detection opportunities are derived from insight kinds and finding-title keywords; treat them as triage hooks for SIEM/detection-engineering work, not authoritative MITRE mappings.",
            ],
        },
    }


def _flatten_attack_techniques(overlay) -> list[dict]:
    """Deduplicated list of ATT&CK techniques observed across insights and findings."""
    by_id: dict[str, dict] = {}
    for insight in overlay.insights:
        for technique in insight.attack_techniques:
            by_id.setdefault(technique.technique_id, technique.model_dump())
    for finding in overlay.findings:
        for technique in finding.attack_techniques:
            by_id.setdefault(technique.technique_id, technique.model_dump())
    return sorted(by_id.values(), key=lambda t: t["technique_id"])
