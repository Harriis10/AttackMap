# Defensive Review

## System Overview
- AttackMap reviewed a web/service-facing codebase with 5 inferred entry points across 19 scanned files.
- Raw inferred entry points: 5
- Static source surfaces (static_observed): 5
- Protocol/lexicon-derived surfaces (inferred_protocol): 0
- Internal exposure candidates (static inference): 0
- Unknown exposure: 0
- Test/example/mocked surfaces (low_quality): 0
- Languages: python
- Datastores: none
- External dependencies observed: 0
- Identified assets: 0 | controls observed: 0 | control absences: 1

## Notable Observations
- No notable cross-cutting observations were generated for this scan.

## ATT&CK Techniques Mapped
- No ATT&CK techniques were mapped from the current findings/insights.

## Detection Opportunities
- No detection opportunities were generated for this scan.

## Asset Inventory
- No high-value assets identified from code signals.

## Defensive Controls

**Expected but not observed (control absences):**
- `rate_limiting` · Rate limiting — Public routes observed without any rate-limiting markers.

## Strengths
- Authentication/identity indicators are present in code signals (django_auth, login_required, session_middleware).
- 5 route(s) were classified as low-risk operational surfaces.
- No obvious secret-like environment references were detected in executable paths.

## Weaknesses / Risk Hotspots
- [LOW | score 3.5] Heuristic scan found only a limited attack surface
- Reason: heuristic_severity=2.0, heuristic_confidence=1.5
- Provenance: heuristic_static; source quality=unknown; surface/path association=unknown; runtime unverified
- Hotspot [score 15.0]: ANY `/v2/item/` (`app/urls.py:4`) -> public_api / low
- Reason: exposure=6.0, privilege=3.0
- Provenance: static_observed=100%, inferred_protocol=0%, low_quality=0%
- Hotspot [score 15.0]: ANY `/v2/` (`project/urls.py:2`) -> public_api / low
- Reason: exposure=6.0, privilege=3.0
- Provenance: static_observed=100%, inferred_protocol=0%, low_quality=0%

## Key Evidence Chains
- No explicit attack path was generated from current signals.

## Recommendations
- [heuristic_static] Treat this as a weak signal, expand parser coverage, and manually validate the real entry points and trust boundaries. (source quality=unknown; surface/path association=unknown)
- Add targeted tests for highest-risk routes and service edges to prevent regressions in boundary enforcement.

## Analyst Notes
- This defensive review is heuristic and intended as an engineering triage starting point.
- Static observations establish source declarations, never runtime reachability. Repository context does not establish route ownership.
- Validate top risks with repository-specific architecture context and runtime controls.
- Notable observations are cross-cutting hypotheses; treat them as triage prompts, not verdicts.
