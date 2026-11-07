from __future__ import annotations

import re

from .md import defang_markdown, md_code, md_text
from .models import (
    Asset,
    AttackPath,
    AttackSurface,
    Control,
    DetectionOpportunity,
    Finding,
    Insight,
    ScanResult,
)
from .security_overlay import SecurityOverlay, build_security_overlay
from .taxonomy import taxonomy_label
from .evidence import (
    is_low_quality_source as _is_low_quality_source,
    is_protocol_derived_surface as _is_protocol_derived_surface,
    surface_evidence_class as _surface_provenance,
    surface_evidence_counts as _provenance_counts,
)


def _severity_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def _surface_risk_rank(value: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(value, 3)


def _confidence_rank(value: str) -> float:
    return {"high": 3.0, "medium": 2.0, "low": 1.0}.get(value, 1.0)


def _extract_numeric_confidence(text: str) -> float | None:
    match = re.search(r"confidence=([0-9]+(?:\.[0-9]+)?)", text.lower())
    if match is None:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _contains_any(text: str, keywords: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in keywords)


def _provenance_breakdown(surfaces: list[AttackSurface]) -> str:
    counts = _provenance_counts(surfaces)
    total = max(len(surfaces), 1)
    return ", ".join(f"{key}={round(count / total * 100)}%" for key, count in counts.items())


def _top_score_reasons(factors: dict[str, float], top_n: int = 3) -> str:
    ranked = sorted(factors.items(), key=lambda item: item[1], reverse=True)
    top = [f"{name}={value:.1f}" for name, value in ranked[:top_n] if value > 0]
    return ", ".join(top)


def _surface_priority(surface: AttackSurface) -> tuple[float, dict[str, float]]:
    exposure_score = {"public": 3.0, "unknown": 2.0, "internal": 1.0}.get(surface.exposure, 1.0)
    privilege_score = {
        "admin": 3.0,
        "auth": 3.0,
        "webhook": 2.0,
        "upload": 2.0,
        "public_api": 1.5,
        "internal": 1.0,
        "health": 0.5,
    }.get(surface.category, 1.0)
    reachability_score = 2.0 if surface.exposure == "public" else 1.0
    trust_boundary_score = (2.0 if surface.data_store_interaction else 0.0) + (2.0 if surface.outbound_integration else 0.0)
    chain_depth_score = 1.0 + (1.0 if surface.data_store_interaction and surface.outbound_integration else 0.0)
    confidence_score = 2.0 if surface.auth_signals else 1.0
    weighted = {
        "exposure": 2.0 * exposure_score,
        "privilege": 2.0 * privilege_score,
        "reachability": 1.5 * reachability_score,
        "trust_boundary": 1.5 * trust_boundary_score,
        "chain_depth": 1.0 * chain_depth_score,
        "confidence": 1.0 * confidence_score,
    }
    if _is_low_quality_source(surface.file):
        weighted["source_quality_penalty"] = -8.0
    elif _is_protocol_derived_surface(surface):
        weighted["source_quality_penalty"] = -3.0
    elif surface.exposure == "public":
        weighted["source_quality_bonus"] = 1.0
    return round(sum(weighted.values()), 2), weighted


def _path_priority(path: AttackPath) -> tuple[float, dict[str, float]]:
    text = f"{path.name} {path.impact} {' '.join(path.steps)}"
    exposure_score = 3.0 if _contains_any(text, ("attacker reaches", "public", "/xrpc/")) else 2.0
    privilege_score = 1.0 + (
        2.0
        if _contains_any(text, ("admin", "privileged", "authorization", "authz", "token", "identity"))
        else 0.5
    )
    reachability_score = 2.0 if any(step.lower().startswith("entry:") for step in path.steps) else 1.0
    trust_boundary_score = 1.0 + sum(
        1.0
        for step in path.steps
        if _contains_any(step, ("propagation", "service", "edge", "external", "config risk", "sink"))
    )
    chain_depth_score = max(1.0, min(len(path.steps), 8) / 2.0)
    evidence_text = " ".join(path.steps)
    numeric_confidence = _extract_numeric_confidence(evidence_text)
    confidence_score = 1.5 + (numeric_confidence if numeric_confidence is not None else 0.5)
    weighted = {
        "exposure": 2.0 * exposure_score,
        "privilege": 2.0 * privilege_score,
        "reachability": 1.5 * reachability_score,
        "trust_boundary": 2.0 * trust_boundary_score,
        "chain_depth": 1.2 * chain_depth_score,
        "confidence": 1.5 * confidence_score,
    }
    if _is_low_quality_source(text):
        weighted["source_quality_penalty"] = -10.0
    return round(sum(weighted.values()), 2), weighted


def _finding_source_quality(finding: Finding) -> str:
    paths = [location.file for location in finding.locations if location.file]
    if not paths:
        return "unknown"
    low_quality = [_is_low_quality_source(path) for path in paths]
    return "low_quality" if all(low_quality) else "mixed" if any(low_quality) else "unclassified"


def _finding_priority(finding: Finding, attack_surfaces: list[AttackSurface], attack_paths: list[AttackPath]) -> tuple[float, dict[str, float]]:
    # Finding has no detector-owned surface/path IDs. Repository prose matches
    # cannot contribute exposure, reachability, boundary or chain scores.
    weighted = {
        "heuristic_severity": {"high": 6.0, "medium": 4.0, "low": 2.0}[finding.severity],
        "heuristic_confidence": 1.5 * _confidence_rank(finding.confidence),
    }
    quality = _finding_source_quality(finding)
    if quality in {"low_quality", "mixed"}:
        weighted["owned_source_quality_penalty"] = -10.0 if quality == "low_quality" else -3.0
    return round(sum(weighted.values()), 2), weighted


def _overview_line(scan: ScanResult) -> str:
    repo_type = "web/service-facing" if scan.routes else "non-web"
    return (
        f"- AttackMap reviewed a {repo_type} codebase with {len(scan.routes)} inferred entry point"
        f"{'s' if len(scan.routes) != 1 else ''} across {scan.files_scanned} scanned files."
    )


def _strengths(scan: ScanResult, attack_surfaces: list[AttackSurface]) -> list[str]:
    items: list[tuple[float, str]] = []
    auth_hints = sorted({hint.hint for hint in scan.auth_hints})
    secure_surfaces = [surface for surface in attack_surfaces if surface.auth_signals]
    internal_surfaces = [surface for surface in attack_surfaces if surface.exposure == "internal"]
    low_risk_surfaces = [surface for surface in attack_surfaces if surface.risk == "low"]

    if auth_hints:
        items.append(
            (
                9.0 + min(len(auth_hints), 5),
                f"- Authentication/identity indicators are present in code signals ({', '.join(auth_hints[:6])}).",
            )
        )
    if secure_surfaces:
        items.append(
            (
                8.0 + min(len(secure_surfaces), 5),
                f"- {len(secure_surfaces)} route(s) include nearby auth indicators, which may support defensive enforcement if validated at runtime.",
            )
        )
    if internal_surfaces:
        items.append((7.0, f"- {len(internal_surfaces)} route(s) were inferred as internal-only, reducing direct internet exposure if correctly segmented."))
    if low_risk_surfaces:
        items.append((6.0, f"- {len(low_risk_surfaces)} route(s) were classified as low-risk operational surfaces."))
    if scan.secret_hints:
        items.append((6.5, "- Secret usage appears environment-driven rather than hardcoded literals."))
    else:
        items.append((5.0, "- No obvious secret-like environment references were detected in executable paths."))
    if not items:
        return ["- No strong defensive indicators were detected heuristically; manual review is still recommended."]
    return [line for _, line in sorted(items, key=lambda item: item[0], reverse=True)[:4]]


def _weaknesses(attack_surfaces: list[AttackSurface], findings: list[Finding], attack_paths: list[AttackPath]) -> list[str]:
    items: list[str] = []
    finding_scores = sorted(
        (
            (_finding_priority(finding, attack_surfaces, attack_paths), finding)
            for finding in findings
        ),
        key=lambda item: (item[0][0], -_severity_rank(item[1].severity)),
        reverse=True,
    )
    for (score, factors), finding in finding_scores[:3]:
        label = taxonomy_label(finding.rule_id)
        items.append(
            f"- [{finding.severity.upper()} | score {score:.1f}] {md_text(finding.title)}"
            + (f" ({label})" if label else "")
        )
        items.append(f"- Reason: {_top_score_reasons(factors, top_n=3)}")
        items.append(f"- Provenance: heuristic_static; source quality={_finding_source_quality(finding)}; surface/path association=unknown; runtime unverified")

    hotspot_surfaces = [surface for surface in attack_surfaces if not _is_low_quality_source(surface.file)]
    if not hotspot_surfaces:
        hotspot_surfaces = list(attack_surfaces)

    hotspot_scores = sorted(
        (
            (_surface_priority(surface), surface)
            for surface in hotspot_surfaces
        ),
        key=lambda item: (item[0][0], -_surface_risk_rank(item[1].risk), item[1].route),
        reverse=True,
    )
    # Avoid duplicate hotspot rows for the same logical surface (e.g., ANY/SUBSCRIBE variants in one lexicon file).
    deduped_hotspots: list[tuple[tuple[float, dict[str, float]], AttackSurface]] = []
    seen_hotspot_keys: set[tuple[str, str, str, str]] = set()
    for scored_surface in hotspot_scores:
        (_score, _factors), surface = scored_surface
        key = (surface.route, surface.file, surface.category, surface.exposure)
        if key in seen_hotspot_keys:
            continue
        seen_hotspot_keys.add(key)
        deduped_hotspots.append(scored_surface)
        if len(deduped_hotspots) >= 2:
            break

    for (score, factors), surface in deduped_hotspots:
        items.append(
            f"- Hotspot [score {score:.1f}]: {surface.method} {md_code(surface.route)} ({md_code(surface.location())}) -> {surface.category} / {surface.risk}"
        )
        items.append(f"- Reason: {_top_score_reasons(factors, top_n=2)}")
        items.append(f"- Provenance: {_provenance_breakdown([surface])}")
    return items[:12]


def _evidence_chains(attack_paths: list[AttackPath]) -> list[str]:
    if not attack_paths:
        return ["- No explicit attack path was generated from current signals."]
    lines: list[str] = []
    scored_paths = sorted(
        ((_path_priority(path), path) for path in attack_paths),
        key=lambda item: item[0][0],
        reverse=True,
    )
    for (score, factors), path in scored_paths[:3]:
        lines.append(f"- [score {score:.1f}] {md_text(path.name)}: {md_text(path.impact)}")
        lines.append(f"- Reason: {_top_score_reasons(factors, top_n=3)}")
        if path.steps:
            lines.append(f"- Key step: {md_text(path.steps[0])}")
    return lines


def _recommendations(findings: list[Finding], attack_paths: list[AttackPath], attack_surfaces: list[AttackSurface]) -> list[str]:
    recommendations: list[str] = []
    low_quality_recommendations: list[str] = []
    scored_findings = sorted(
        (
            (_finding_priority(finding, attack_surfaces, attack_paths), finding)
            for finding in findings
        ),
        key=lambda item: item[0][0],
        reverse=True,
    )
    for (_score, _factors), finding in scored_findings:
        if not finding.mitigation:
            continue
        quality = _finding_source_quality(finding)
        line = f"- [heuristic_static] {finding.mitigation} (source quality={quality}; surface/path association=unknown)"
        if quality == "low_quality":
            if line not in low_quality_recommendations:
                low_quality_recommendations.append(line)
            continue
        if line not in recommendations:
            recommendations.append(line)
        if len(recommendations) >= 4:
            break

    for line in low_quality_recommendations:
        if len(recommendations) >= 4:
            break
        if line not in recommendations:
            recommendations.append(line)

    high_scored_path = max((_path_priority(path)[0] for path in attack_paths), default=0.0)
    if attack_paths and len(recommendations) < 5 and high_scored_path >= 22.0:
        recommendations.append(
            "- Validate every trust boundary hop in attack paths with explicit authn/authz and least-privilege service credentials."
        )

    if len(recommendations) < 5:
        recommendations.append(
            "- Add targeted tests for highest-risk routes and service edges to prevent regressions in boundary enforcement."
        )
    return recommendations[:5]


def _render_assets_section(assets: list[Asset]) -> list[str]:
    if not assets:
        return ["- No high-value assets identified from code signals."]
    lines: list[str] = []
    for asset in assets[:8]:
        head = f"- **{md_text(asset.name)}** ({asset.kind}, criticality={asset.criticality})"
        evidence_inline = "; ".join(md_code(e) for e in asset.evidence[:3]) if asset.evidence else ""
        if evidence_inline:
            head = f"{head} — {evidence_inline}"
        lines.append(head)
    if len(assets) > 8:
        lines.append(f"- …and {len(assets) - 8} more.")
    return lines


def _render_controls_section(controls: list[Control]) -> list[str]:
    if not controls:
        return ["- No defensive controls observed from code signals."]
    present = [c for c in controls if c.strength != "absent"]
    absent = [c for c in controls if c.strength == "absent"]
    lines: list[str] = []
    if present:
        lines.append("**Observed:**")
        for control in present[:8]:
            placement = f" — placements: {len(control.placements)}" if control.placements else ""
            lines.append(f"- `{control.kind}` · {control.name} (strength={control.strength}){placement}")
        if len(present) > 8:
            lines.append(f"- …and {len(present) - 8} more.")
    if absent:
        lines.append("")
        lines.append("**Expected but not observed (control absences):**")
        for control in absent[:6]:
            note = f" — {control.notes}" if control.notes else ""
            lines.append(f"- `{control.kind}` · {control.name}{note}")
    return lines


def _render_notable_observations(insights: list[Insight]) -> list[str]:
    if not insights:
        return ["- No notable cross-cutting observations were generated for this scan."]
    lines: list[str] = []
    for insight in insights[:6]:
        head = f"- **[{insight.severity.upper()}]** {md_text(insight.title)} _(confidence={insight.confidence}, kind={insight.kind})_"
        lines.append(head)
        lines.append(f"  - {insight.narrative}")
        if insight.suggested_action:
            lines.append(f"  - _Suggested action:_ {insight.suggested_action}")
        if insight.attack_techniques:
            techniques_text = ", ".join(
                f"`{t.technique_id}` {t.name}" for t in insight.attack_techniques[:4]
            )
            lines.append(f"  - _ATT&CK:_ {techniques_text}")
        if insight.evidence:
            lines.append(f"  - _Evidence:_ {'; '.join(md_code(e) for e in insight.evidence[:3])}")
    if len(insights) > 6:
        lines.append(f"- …and {len(insights) - 6} more notable observations in JSON output.")
    return lines


def _render_detection_opportunities(opportunities: list[DetectionOpportunity]) -> list[str]:
    if not opportunities:
        return ["- No detection opportunities were generated for this scan."]
    lines: list[str] = []
    for opp in opportunities[:5]:
        lines.append(f"- **{opp.title}** _(signal={opp.signal_kind})_")
        lines.append(f"  - _Why:_ {opp.rationale}")
        lines.append(f"  - _Suggested rule:_ {opp.suggested_rule}")
        if opp.attack_techniques:
            techniques_text = ", ".join(
                f"`{t.technique_id}`" for t in opp.attack_techniques[:4]
            )
            lines.append(f"  - _ATT&CK:_ {techniques_text}")
    if len(opportunities) > 5:
        lines.append(f"- …and {len(opportunities) - 5} more detection opportunities in JSON output.")
    return lines


def _render_attack_techniques_summary(overlay: SecurityOverlay) -> list[str]:
    by_id: dict[str, tuple[str, str]] = {}
    for insight in overlay.insights:
        for t in insight.attack_techniques:
            by_id.setdefault(t.technique_id, (t.name, t.tactic))
    for finding in overlay.findings:
        for t in finding.attack_techniques:
            by_id.setdefault(t.technique_id, (t.name, t.tactic))
    if not by_id:
        return ["- No ATT&CK techniques were mapped from the current findings/insights."]
    lines: list[str] = []
    for tid in sorted(by_id):
        name, tactic = by_id[tid]
        lines.append(f"- `{tid}` **{name}** — _{tactic}_")
    return lines


def render_defensive_review(
    scan: ScanResult,
    attack_surfaces: list[AttackSurface],
    findings: list[Finding],
    attack_paths: list[AttackPath],
    overlay: SecurityOverlay | None = None,
) -> str:
    evidence_counts = _provenance_counts(attack_surfaces)
    overlay = overlay or build_security_overlay(scan, attack_surfaces, findings, attack_paths)
    lines = [
        "# Defensive Review",
        "",
        "## System Overview",
        _overview_line(scan),
        f"- Raw inferred entry points: {len(scan.routes)}",
        f"- Static source surfaces (static_observed): {evidence_counts['static_observed']}",
        f"- Protocol/lexicon-derived surfaces (inferred_protocol): {evidence_counts['inferred_protocol']}",
        f"- Internal exposure candidates (static inference): {sum(s.exposure == 'internal' for s in attack_surfaces)}",
        f"- Unknown exposure: {sum(s.exposure == 'unknown' for s in attack_surfaces)}",
        f"- Test/example/mocked surfaces (low_quality): {evidence_counts['low_quality']}",
        f"- Languages: {', '.join(scan.languages) if scan.languages else 'none'}",
        f"- Datastores: {', '.join(sorted({db.kind for db in scan.databases})) if scan.databases else 'none'}",
        f"- External dependencies observed: {len(scan.external_calls)}",
        f"- Identified assets: {len(overlay.assets)} | controls observed: "
        f"{sum(1 for c in overlay.controls if c.strength != 'absent')} | "
        f"control absences: {sum(1 for c in overlay.controls if c.strength == 'absent')}",
        "",
        "## Notable Observations",
        *_render_notable_observations(overlay.insights),
        "",
        "## ATT&CK Techniques Mapped",
        *_render_attack_techniques_summary(overlay),
        "",
        "## Detection Opportunities",
        *_render_detection_opportunities(overlay.detection_opportunities),
        "",
        "## Asset Inventory",
        *_render_assets_section(overlay.assets),
        "",
        "## Defensive Controls",
        *_render_controls_section(overlay.controls),
        "",
        "## Strengths",
        *_strengths(scan, attack_surfaces),
        "",
        "## Weaknesses / Risk Hotspots",
        *_weaknesses(attack_surfaces, findings, attack_paths),
        "",
        "## Key Evidence Chains",
        *_evidence_chains(attack_paths),
        "",
        "## Recommendations",
        *_recommendations(findings, attack_paths, attack_surfaces),
        "",
        "## Analyst Notes",
        "- This defensive review is heuristic and intended as an engineering triage starting point.",
        "- Static observations establish source declarations, never runtime reachability. Repository context does not establish route ownership.",
        "- Validate top risks with repository-specific architecture context and runtime controls.",
        "- Notable observations are cross-cutting hypotheses; treat them as triage prompts, not verdicts.",
    ]
    # Every section interpolates repo-derived text (routes, files, evidence);
    # this document has no intentional links/HTML, so defang the whole thing
    # as a backstop to the per-field escaping above (#233).
    return defang_markdown("\n".join(lines))
