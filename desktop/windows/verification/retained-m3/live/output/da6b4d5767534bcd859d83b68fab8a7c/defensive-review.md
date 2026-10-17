# Defensive Review

## System Overview
- AttackMap reviewed a web/service-facing codebase with 270 inferred entry points across 899 scanned files.
- Raw inferred entry points: 270
- Static source surfaces (static_observed): 270
- Protocol/lexicon-derived surfaces (inferred_protocol): 0
- Internal exposure candidates (static inference): 0
- Unknown exposure: 0
- Test/example/mocked surfaces (low_quality): 0
- Languages: hcl, javascript, python, typescript
- Datastores: mongodb, redis, sqlite
- External dependencies observed: 1251
- Identified assets: 13 | controls observed: 1 | control absences: 5

## Notable Observations
- **[CRITICAL]** 2 admin/role-mutation route\(s\) reachable without observed auth _(confidence=medium, kind=admin_action_without_auth)_
  - 2 public route(s) match administrative or role/permission-mutation patterns and carry no authentication signals on the surface. Privilege-mutation flows are an outsized target — an attacker who reaches them can grant themselves access to the rest of the system, so the absence of an explicit auth boundary here is a high-priority confirmation item.
  - _Suggested action:_ Add an explicit authentication and authorization guard at the route boundary for every admin/role/permission endpoint, and verify the guard is exercised in tests.
  - _ATT&CK:_ `T1078` Valid Accounts, `T1068` Exploitation for Privilege Escalation, `T1098` Account Manipulation
  - _Evidence:_ `GET /rest/admin/application-version (server.ts:634) — exposure=public, auth_signals=none`; `GET /rest/admin/application-configuration (server.ts:635) — exposure=public, auth_signals=none`
- **[CRITICAL]** Public route reaches User credentials at rest without observed auth _(confidence=medium, kind=sensitive_asset_reachability)_
  - User credentials at rest (criticality=critical) lives in modules that are reachable from 87 public route(s) with no observed authentication signals on the surface. This means an unauthenticated attacker can directly invoke handlers in the same module as a high-value asset without traversing an explicit auth boundary.
  - _Suggested action:_ Add an explicit authentication guard at the route boundary or relocate the handler out of the asset's module so the trust boundary is visible in code.
  - _ATT&CK:_ `T1190` Exploit Public-Facing Application, `T1041` Exfiltration Over C2 Channel
  - _Evidence:_ `POST /file-upload (server.ts:337) — exposure=public, auth_signals=none`; `POST /profile/image/file (server.ts:338) — exposure=public, auth_signals=none`; `POST /profile/image/url (server.ts:339) — exposure=public, auth_signals=none`
- **[CRITICAL]** Public route reaches Payment / billing records without observed auth _(confidence=medium, kind=sensitive_asset_reachability)_
  - Payment / billing records (criticality=critical) lives in modules that are reachable from 87 public route(s) with no observed authentication signals on the surface. This means an unauthenticated attacker can directly invoke handlers in the same module as a high-value asset without traversing an explicit auth boundary.
  - _Suggested action:_ Add an explicit authentication guard at the route boundary or relocate the handler out of the asset's module so the trust boundary is visible in code.
  - _ATT&CK:_ `T1190` Exploit Public-Facing Application, `T1041` Exfiltration Over C2 Channel
  - _Evidence:_ `POST /file-upload (server.ts:337) — exposure=public, auth_signals=none`; `POST /profile/image/file (server.ts:338) — exposure=public, auth_signals=none`; `POST /profile/image/url (server.ts:339) — exposure=public, auth_signals=none`
- **[CRITICAL]** Public route reaches Authentication tokens / session material without observed auth _(confidence=medium, kind=sensitive_asset_reachability)_
  - Authentication tokens / session material (criticality=critical) lives in modules that are reachable from 87 public route(s) with no observed authentication signals on the surface. This means an unauthenticated attacker can directly invoke handlers in the same module as a high-value asset without traversing an explicit auth boundary.
  - _Suggested action:_ Add an explicit authentication guard at the route boundary or relocate the handler out of the asset's module so the trust boundary is visible in code.
  - _ATT&CK:_ `T1190` Exploit Public-Facing Application, `T1041` Exfiltration Over C2 Channel
  - _Evidence:_ `POST /file-upload (server.ts:337) — exposure=public, auth_signals=none`; `POST /profile/image/file (server.ts:338) — exposure=public, auth_signals=none`; `POST /profile/image/url (server.ts:339) — exposure=public, auth_signals=none`
- **[HIGH]** User credentials at rest has gaps in expected controls: authentication \(absent\), encryption\_at\_rest \(absent\), audit\_logging \(absent\) _(confidence=medium, kind=control_strength_mismatch)_
  - User credentials at rest is criticality=critical, which would normally warrant strong controls of kind: authentication, encryption_at_rest, audit_logging. The scan observed gaps in: authentication (absent), encryption_at_rest (absent), audit_logging (absent). These may exist but are not detectable from code signals — either way, the absence in static evidence is itself worth confirming.
  - _Suggested action:_ Either add the missing controls or annotate the code path where they live so subsequent scans can pick them up.
  - _ATT&CK:_ `T1110` Brute Force, `T1552` Unsecured Credentials
  - _Evidence:_ `asset:asset:credentials → expected:authentication`; `asset:asset:credentials → expected:encryption_at_rest`; `asset:asset:credentials → expected:audit_logging`
- **[HIGH]** Payment / billing records has gaps in expected controls: authentication \(absent\), authorization \(absent\), audit\_logging \(absent\), encryption\_at\_rest \(absent\) _(confidence=medium, kind=control_strength_mismatch)_
  - Payment / billing records is criticality=critical, which would normally warrant strong controls of kind: authentication, authorization, audit_logging, encryption_at_rest. The scan observed gaps in: authentication (absent), authorization (absent), audit_logging (absent), encryption_at_rest (absent). These may exist but are not detectable from code signals — either way, the absence in static evidence is itself worth confirming.
  - _Suggested action:_ Either add the missing controls or annotate the code path where they live so subsequent scans can pick them up.
  - _ATT&CK:_ `T1110` Brute Force, `T1552` Unsecured Credentials
  - _Evidence:_ `asset:asset:payment → expected:authentication`; `asset:asset:payment → expected:authorization`; `asset:asset:payment → expected:audit_logging`
- …and 25 more notable observations in JSON output.

## ATT&CK Techniques Mapped
- `T1027` **Obfuscated Files or Information** — _Stealth_
- `T1041` **Exfiltration Over C2 Channel** — _Exfiltration_
- `T1059` **Command and Scripting Interpreter** — _Execution_
- `T1059.007` **Command and Scripting Interpreter: JavaScript** — _Execution_
- `T1068` **Exploitation for Privilege Escalation** — _Privilege Escalation_
- `T1078` **Valid Accounts** — _Stealth / Persistence / Privilege Escalation / Initial Access_
- `T1098` **Account Manipulation** — _Persistence / Privilege Escalation_
- `T1105` **Ingress Tool Transfer** — _Command and Control_
- `T1110` **Brute Force** — _Credential Access_
- `T1190` **Exploit Public-Facing Application** — _Initial Access_
- `T1195.001` **Supply Chain Compromise: Compromise Software Dependencies and Development Tools** — _Initial Access_
- `T1195.002` **Supply Chain Compromise: Compromise Software Supply Chain** — _Initial Access_
- `T1212` **Exploitation for Credential Access** — _Credential Access_
- `T1505.003` **Server Software Component: Web Shell** — _Persistence_
- `T1528` **Steal Application Access Token** — _Credential Access_
- `T1552` **Unsecured Credentials** — _Credential Access_
- `T1552.001` **Unsecured Credentials: Credentials In Files** — _Credential Access_
- `T1552.005` **Unsecured Credentials: Cloud Instance Metadata API** — _Credential Access_
- `T1600` **Weaken Encryption** — _Defense Impairment_
- `T1685` **Disable or Modify Tools** — _Defense Impairment_

## Detection Opportunities
- **Alert on any unauthenticated state change to admin/role routes** _(signal=log)_
  - _Why:_ Privilege-mutation flows are zero-tolerance for unauthenticated calls. Any successful mutating verb against them from an unauthenticated session should page on first occurrence.
  - _Suggested rule:_ On the access log: alert when method IN (POST,PUT,PATCH,DELETE) AND route IN (`/rest/admin/application-version`, `/rest/admin/application-configuration`) AND auth_subject IS NULL. Severity: page-on-first. Pair with an audit-log assertion that every successful call to these routes carries an actor + role-change record.
  - _ATT&CK:_ `T1078`, `T1068`, `T1098`
- **Alert on unauthenticated access to sensitive-asset routes** _(signal=log)_
  - _Why:_ A static-analysis gap on auth at the surface is also a runtime detection opportunity: any 2xx response for these routes from a request lacking a valid session/JWT is high signal.
  - _Suggested rule:_ On the access log: alert when status_code IN (200,201,204) AND route IN (`/file-upload`, `/profile/image/file`, `/profile/image/url`) AND request_headers.authorization IS NULL AND session_cookie IS NULL. Tighten with a low-volume baseline — this should normally be zero.
  - _ATT&CK:_ `T1190`, `T1041`
- **Add config-drift detection for missing controls on critical assets** _(signal=config_audit)_
  - _Why:_ When critical assets exist but expected controls aren't observable, drift detection on the deployed configuration (WAF rules, IAM policies, encryption-at-rest flags) gives ongoing visibility even before code-level fixes land.
  - _Suggested rule:_ Add a daily IaC/config audit step: assert that the modules holding critical assets have (a) a WAF/auth policy attached, (b) database encryption-at-rest enabled, (c) audit-log subscriptions configured. Page when any assertion regresses.
  - _ATT&CK:_ `T1110`, `T1552`
- **Add request-tracing to confirm controls actually run on this chain** _(signal=trace)_
  - _Why:_ Static analysis can't tell whether a control is invoked at runtime. Trace spans on the entry and sink confirm whether intermediate auth/validation/rate-limit middleware actually executed.
  - _Suggested rule:_ Instrument the chain's entry handler and its sink (DB call) with OpenTelemetry spans. Alert when a sink span's parent trace lacks a span tagged `middleware=auth` or `middleware=ratelimit`. This catches code paths that bypass middleware via direct invocation.
  - _ATT&CK:_ `T1190`, `T1212`
- **Detect signing-key drift across services** _(signal=config_audit)_
  - _Why:_ Shared signing material across many services means a single rotation should be visible everywhere; conversely, divergence may indicate a compromised key in use.
  - _Suggested rule:_ Periodically hash the secret material referenced by each service and alert when different services report different hashes for the same secret name (or when one service uses a key version older than N days). Pair with token-issuer telemetry: alert on tokens signed by a key version not present in the current authorized set.
  - _ATT&CK:_ `T1552`, `T1528`, `T1078`
- …and 2 more detection opportunities in JSON output.

## Asset Inventory
- **User credentials at rest** (credentials, criticality=critical) — `route:POST /rest/user/reset-password (server.ts:626)`
- **Cryptographic key material: LABEL\_PRIVATE\_KEY** (internal_secret, criticality=critical) — `secret:LABEL_PRIVATE_KEY (frontend/src/assets/i18n/ar_SA.json:481)`
- **Payment / billing records** (payment, criticality=critical) — `route:POST /rest/basket/:id/checkout (server.ts:632)`
- **Authentication tokens / session material** (session, criticality=critical) — `file:frontend/src/app/oauth/oauth.component.spec.ts`; `file:frontend/src/app/oauth/oauth.component.ts`; `route:GET /https:/www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token= (frontend/src/app/Services/user.service.ts:68)`
- **Internal service / API secrets** (internal_secret, criticality=high) — `secret:ALCHEMY_API_KEY (.github/workflows/ci.yml:163)`; `secret:ALCHEMY_API_KEY (.github/workflows/ci.yml:265)`; `secret:ALCHEMY_API_KEY (.github/workflows/ci.yml:280)`
- **API / service token: ALCHEMY\_API\_KEY** (internal_secret, criticality=high) — `secret:ALCHEMY_API_KEY (routes/nftMint.ts:18)`
- **Webhook / signing secret: E2E\_SOLUTIONS\_WEBHOOK** (internal_secret, criticality=high) — `secret:E2E_SOLUTIONS_WEBHOOK (.github/workflows/ci.yml:264)`
- **API / service token: HEROKU\_API\_KEY** (internal_secret, criticality=high) — `secret:HEROKU_API_KEY (.github/workflows/ci.yml:387)`
- …and 5 more.

## Defensive Controls
**Observed:**
- `mfa` · Multi-factor authentication (strength=strong) — placements: 1

**Expected but not observed (control absences):**
- `audit_logging` · Audit logging — Sensitive assets identified but no audit-logging markers found.
- `authentication` · Authentication enforcement — Admin or auth routes observed without any auth-middleware markers.
- `csrf_protection` · CSRF protection — Public state-changing routes observed without CSRF markers.
- `encryption_at_rest` · Encryption at rest — Sensitive assets identified but no at-rest encryption markers found.
- `rate_limiting` · Rate limiting — Public routes observed without any rate-limiting markers.

## Strengths
- Authentication/identity indicators are present in code signals (api_key, apikey, auth_middleware, bearer_token, dockerfile_no_user_directive, gha_no_top_level_permissions).
- 102 route(s) include nearby auth indicators, which may support defensive enforcement if validated at runtime.
- Secret usage appears environment-driven rather than hardcoded literals.
- 263 route(s) were classified as low-risk operational surfaces.

## Weaknesses / Risk Hotspots
- [HIGH | score 10.5] Administrative routes appear reachable from the main application surface (CWE-285 · A01:2021 · API5:2023)
- Reason: heuristic_severity=6.0, heuristic_confidence=4.5
- Provenance: heuristic_static; source quality=unclassified; surface/path association=unknown; runtime unverified
- [HIGH | score 10.5] Authorization outlier — route missing an auth check its siblings enforce (CWE-862 · A01:2021 · API5:2023)
- Reason: heuristic_severity=6.0, heuristic_confidence=4.5
- Provenance: heuristic_static; source quality=unclassified; surface/path association=unknown; runtime unverified
- [HIGH | score 10.5] Hard-coded secret literals were found in source or config (CWE-798 · A07:2021)
- Reason: heuristic_severity=6.0, heuristic_confidence=4.5
- Provenance: heuristic_static; source quality=unclassified; surface/path association=unknown; runtime unverified
- Hotspot [score 19.0]: GET `/https:/www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=` (`frontend/src/app/Services/user.service.ts:68`) -> auth / medium
- Reason: exposure=6.0, privilege=6.0
- Provenance: static_observed=100%, inferred_protocol=0%, low_quality=0%

## Key Evidence Chains
- [score 25.9] Distributed service trust-chain abuse: A public API foothold can propagate across \`juice-shop-net\` and affect database if service boundaries or downstream trust checks are weak.
- Reason: trust_boundary=8.0, exposure=6.0, confidence=3.4
- Key step: Entry: Attacker reaches EXPOSE container:80 in infrastructure/docker-compose.yml

## Recommendations
- [heuristic_static] Require strong authentication and explicit server-side authorization on every admin action, and move admin routes behind a narrower exposure boundary where possible. (source quality=unclassified; surface/path association=unknown)
- [heuristic_static] Confirm whether the flagged route is intended to be public. If not, apply the same auth/authorization guard its sibling routes use (decorator, middleware, or policy). Inconsistent enforcement across a resource cohort is a common source of broken access control. (source quality=unclassified; surface/path association=unknown)
- [heuristic_static] Rotate every detected credential immediately, purge it from git history, and move to environment-injected or vault-managed values. Anyone with read access to the repository already has these secrets. (source quality=unclassified; surface/path association=unknown)
- [heuristic_static] Never build filesystem paths from request input directly. Reduce it to a basename (secure_filename / path.basename), resolve it against a fixed base directory and verify the result stays inside it, or map an opaque id to a server-side path. (source quality=unclassified; surface/path association=unknown)
- Validate every trust boundary hop in attack paths with explicit authn/authz and least-privilege service credentials.

## Analyst Notes
- This defensive review is heuristic and intended as an engineering triage starting point.
- Static observations establish source declarations, never runtime reachability. Repository context does not establish route ownership.
- Validate top risks with repository-specific architecture context and runtime controls.
- Notable observations are cross-cutting hypotheses; treat them as triage prompts, not verdicts.
