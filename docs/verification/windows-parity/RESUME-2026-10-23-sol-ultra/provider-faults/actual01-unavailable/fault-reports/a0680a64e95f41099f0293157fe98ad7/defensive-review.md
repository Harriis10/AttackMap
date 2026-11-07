# Defensive Review

## System Overview
- AttackMap reviewed a web/service-facing codebase with 1 inferred entry point across 2 scanned files.
- Raw inferred entry points: 1
- Static source surfaces (static_observed): 1
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
- `T1190` **Exploit Public-Facing Application** — _Initial Access_

## Detection Opportunities
- **Detection coverage for findings without a paired insight** _(signal=log)_
  - _Why:_ These findings did not generate cross-cutting insights but are still actionable with runtime telemetry.
  - _Suggested rule:_ Add per-finding logging at the affected handler with a structured `{finding_id, route, status_code}` payload, and aggregate in the SIEM.
  - _ATT&CK:_ `T1190`

## Asset Inventory
- No high-value assets identified from code signals.

## Defensive Controls

**Expected but not observed (control absences):**
- `rate_limiting` · Rate limiting — Public routes observed without any rate-limiting markers.

## Strengths
- 1 route(s) were classified as low-risk operational surfaces.
- No obvious secret-like environment references were detected in executable paths.

## Weaknesses / Risk Hotspots
- [MEDIUM | score 7.0] Debug mode or unrestricted management endpoints enabled (CWE-489 · CWE-215 · A05:2021 · API8:2023)
- Reason: heuristic_severity=4.0, heuristic_confidence=3.0
- Provenance: heuristic_static; source quality=unclassified; surface/path association=unknown; runtime unverified
- Hotspot [score 15.0]: GET `/records` (`app.py:3`) -> public_api / low
- Reason: exposure=6.0, privilege=3.0
- Provenance: static_observed=100%, inferred_protocol=0%, low_quality=0%

## Key Evidence Chains
- No explicit attack path was generated from current signals.

## Recommendations
- [heuristic_static] Never ship with debug mode on (Flask/Django `DEBUG`, Rails `consider_all_requests_local`) or Spring actuator endpoints exposed with `*`. Debug consoles leak internals and can enable RCE. (source quality=unclassified; surface/path association=unknown)
- Add targeted tests for highest-risk routes and service edges to prevent regressions in boundary enforcement.

## Analyst Notes
- This defensive review is heuristic and intended as an engineering triage starting point.
- Static observations establish source declarations, never runtime reachability. Repository context does not establish route ownership.
- Validate top risks with repository-specific architecture context and runtime controls.
- Notable observations are cross-cutting hypotheses; treat them as triage prompts, not verdicts.
