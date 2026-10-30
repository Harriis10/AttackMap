# Defensive Review

## System Overview
- AttackMap reviewed a web/service-facing codebase with 1 inferred entry point across 16 scanned files.
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
- **[INFORMATIONAL]** 1 obviously-benign route\(s\) carry auth signals — likely scanner false positives _(confidence=medium, kind=stale_or_contradictory_signal)_
  - Health, metrics, static-asset, and well-known paths normally do not require authentication. The scanner attached auth signals to these routes anyway, which usually means the auth marker is at file scope (e.g., a global middleware import) rather than route-specific. Treat the auth annotation on these surfaces with skepticism when reading the rest of the report.
  - _Suggested action:_ If the auth markers really should not apply to these routes, add per-route metadata the scanner can read (e.g., a `@public` decorator or a routes manifest) so future scans don't double-count file-scope signals.
  - _Evidence:_ `ANY /public/ (project/urls.py:4) — auth_signals present but route looks benign/public: django_auth, session_middleware`

## ATT&CK Techniques Mapped
- No ATT&CK techniques were mapped from the current findings/insights.

## Detection Opportunities
- **Annotate routes so static analysis stops contradicting itself** _(signal=config_audit)_
  - _Why:_ Stale or contradictory signals don't usually map to a runtime detection; the leverage is in raising the signal-to-noise of future scans.
  - _Suggested rule:_ Add a route-manifest test that asserts route categories (admin/public/internal/health) match a single source of truth — e.g., a decorator on the handler that the test reads. Future AttackMap runs will then trust the explicit annotation over heuristic guesses.

## Asset Inventory
- No high-value assets identified from code signals.

## Defensive Controls

**Expected but not observed (control absences):**
- `rate_limiting` · Rate limiting — Public routes observed without any rate-limiting markers.

## Strengths
- Authentication/identity indicators are present in code signals (django_auth, login_required, session_middleware).
- 1 route(s) include nearby auth indicators, which may support defensive enforcement if validated at runtime.
- 1 route(s) were classified as low-risk operational surfaces.
- No obvious secret-like environment references were detected in executable paths.

## Weaknesses / Risk Hotspots
- [LOW | score 3.5] Heuristic scan found only a limited attack surface
- Reason: heuristic_severity=2.0, heuristic_confidence=1.5
- Provenance: heuristic_static; source quality=unknown; surface/path association=unknown; runtime unverified
- Hotspot [score 16.0]: ANY `/public/` (`project/urls.py:4`) -> public_api / low
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
