# WP032 — fail-closed proxy invalidation — 2026-10-31

This completes one bounded config-to-contract safety slice. **WP032/C28 remain
IN_PROGRESS.** No runtime traffic, production fleet, provider response, native
UI, product frozen engine, package or release acceptance is claimed.

## Reproduced gap and resulting behavior

The config extractor already rejected two conflicting single-backend proxy
declarations. However, an unmodeled multi-backend declaration was merely
skipped: a separate single-backend declaration for the same normalized host
survived, or could be added later. Similarly, nginx could observe one known
location and ignore another location using a multi-backend, multiple-port,
unknown namespace target or variable. An Ingress service backend could hide a
resource backend in the same host. The resulting host-wide declaration could
authorize an unsupported `observed_via_proxy` HTTP contract.

`config_scanner.py` now uses a per-extraction, per-normalized-host tombstone:

- `_drop_proxy` removes the existing proxy mapping and its declaring-file
  provenance, then adds the host to the existing dropped-host set.
- `_declare_proxy` cannot restore that host during the same extraction. A later
  independent extraction starts afresh; the tombstone is not global state.
- Additive `DeploymentAliases.unresolved_proxies` carries the normalized,
  sorted negative facts into contract resolution. They block repo-name,
  host, explicit-port, namespace-suffix and positive-proxy fallbacks. A
  conflicting positive identity yields `candidate / ambiguous_identity`;
  otherwise the result is `candidate / unresolved_host`. No alias origin is
  fabricated for either result.
- `_effective_deployment_aliases` preserves negative-only extraction, unions
  negative facts deterministically during CLI merging, and keeps them when a
  separate conflict falls back to CLI positive declarations. A positive alias
  cannot override the absence of modeled host-wide routing.
- Multi-backend or unresolved Ingress paths invalidate the host. nginx checks
  every recognized `proxy_pass` directive; one unmodeled branch or more than
  one known backend invalidates every concrete name on that server block.
- Known backend protocol facts remain independent of a rejected host-wide
  proxy declaration. No scheme, TLS or mTLS is inferred from a service, port,
  hostname or namespace name.

Because these hosts have no other identity declaration in the fixture, both
matching backend routes remain **`candidate / unresolved_host`**, with no alias
provenance or proxy identity. The extractor emits an explicit reason; it does
not create a new observed or ambiguous runtime fact. Existing unrelated proxy
hosts retain their precise declaring-file provenance.

No `crossrepo.py`, topology, model, scoring, native or product packaging file was
edited by this slice. The checkout already contained earlier
datastore/messaging/Rails changes in `config_scanner.py`, protocol changes in
`contracts.py` and separately owned WP034 changes in `scan_service.py`; they
were preserved. This slice changes the four proxy-extraction helpers, the
additive negative alias representation/resolver guard, and only the three
carry-forward paths in `_effective_deployment_aliases`.

## Physical fixture and controls

`tests/fixtures/wp032_multibackend_proxy/` contains three synthetic repository
roots (`caller`, `api`, `worker`), real Kubernetes/nginx config inputs and inert
source-location anchors. Tests physically copy case configs into the caller
repository and exercise the actual config extractor. Application calls, routes
and taint chains are **supplied normalized observations**, not application
extraction or runtime network evidence.

The final new focused file has **63 cases**:

- Nine invalid configurations, each tested single-first and single-last under
  HTTP and HTTPS: nginx known+multi, known+multiple ports, known+unknown
  namespace, known+variable, two known backends, multi-only, unknown-only,
  multi-service Ingress and service+resource Ingress.
- All nine invalid configs also run alone. Rejected configs cannot create a
  partial proxy declaration even without an earlier single declaration.
- Valid nginx, repeated same-backend nginx locations/endpoints and valid
  single-service Ingress each retain HTTP/HTTPS proxy behavior. HTTP to the
  proxy remains allowed while the independently declared backend uses HTTPS.
- DNS case and a trailing dot normalize consistently. Route paths retain
  case, and an unqualified preview namespace remains unresolved.
- Invalid links produce no cross-boundary flow or trust-gap finding. The
  worker's port named `https` does not become a protocol declaration.
- The graph retains exact call/route observation IDs, repository, file, line
  and supplied analyzer origins, including the lowercase handler's own line.
  Legacy location-only references remain unknown rather than fabricated.
- Repo-name collisions, explicit listening ports and other host/port/suffix/
  proxy declarations cannot bypass the negative fact. Negative-only, normal
  CLI merge, deterministic normalized union and conflict fallback all preserve
  the guard.

The changed existing behavioral test expectation is diagnostic: the older
`test_config_alias_origins_and_negative_multi_backend_controls` now expects
two explicit host invalidation notes in addition to its two original skipped
upstream notes. Its aliases, protocols, ports and provenance are unchanged.
Its qualification helper also converts the new tuple to a JSON array, exactly
as it already did for `dns_suffixes`, preserving its JSON round-trip assertion.

[qualification.json](qualification.json) records **3 repositories, 13 links
(11 candidate, 1 direct observed, 1 observed_via_proxy), 14 HTTP graph edges and
24 evidence records**. It includes source/fixture SHA-256 values, platform and
the owning source's full dirty-diff hash. That full diff intentionally includes
preserved earlier work and must not be attributed wholly to this slice.
The graph controls contain one valid direct HTTPS service endpoint and one
valid HTTP proxy leg; invalidated hosts remain candidates. Provider calls: **0**.

## Executed verification

Base commit: `4ea5e49ade229fc0432d68ce0f7e99bcf87b545d`; final state is
uncommitted on the existing dirty checkout. Platform: Windows 10 build 19045,
Python 3.13.15. All commands ran from `C:\Projects\INPROGRESS\AttackMap`.

- The first restricted attempt failed on pytest temporary-directory Windows
  ACLs before useful verification. It is not counted as behavior evidence.
  Subsequent runs used ordinary filesystem access and unique task temp paths.
- [red-focused.xml](red-focused.xml): **31 reproduced behavior failures,
  4 positive controls PASS, 1 deselected** before the proxy fix.
- [red-resource.xml](red-resource.xml): **5 reproduced Ingress resource-backend
  failures, 45 deselected**, before extending the same invalidation rule there.
- [red-identity.xml](red-identity.xml): **6 reproduced behavior failures,
  52 deselected**. This exposed actual false direct `observed` edges for
  `https://API` and `https://API:8443` after merely dropping proxy declarations.
- [red-merge.xml](red-merge.xml): **4 reproduced behavior failures,
  58 deselected**, demonstrating guard loss in orchestration before carry-forward.
- [green-focused.xml](green-focused.xml): **124 PASS, 0 failures/errors/skips**
  for the new file, prior protocol fixture and config scanner tests. Two final
  repeated-single controls were added afterward and are included below.
- [final.xml](final.xml) is the **pre-guard** checkpoint: 409 PASS, 0 failures/
  errors/skips, 58.08 seconds. It does not qualify the later identity guard.
- The final guarded result is [final-guarded.xml](final-guarded.xml): **430 PASS,
  0 failures/errors/skips, 44.54 seconds**. This
  includes contracts, fleet, fleet graph, crossrepo, merge/provenance, ranking,
  identity, exact finding-to-score/reference and scan-service suites.
- `qualify_multibackend.py` completed and persisted the audit artifact.
  Scoped `git diff --check` passed.

The initial [red.xml](red.xml) contains 31 behavior failures plus one overly
strict fixture assertion about legacy location-only graph references (and four
positive passes); the clean behavior RED is `red-focused.xml`. The intermediate
`green01.xml` has 109 passes and the old diagnostic-note-count expectation
failure described above. Neither harness expectation issue is attributed to a
runtime regression; both remain preserved.
`guarded-intermediate.xml` has 429 passes and one fixture JSON round-trip
failure because the additive tuple had not yet been converted to an array in
the older helper. The corrected final run uses that conversion.

Exact final commands:

```powershell
.venv/Scripts/python.exe -X utf8 -m pytest tests/test_wp032_multibackend_proxy.py tests/test_wp032_protocol_fleet.py tests/test_contracts.py tests/test_fleet.py tests/test_fleet_architecture.py tests/test_crossrepo.py tests/test_merge.py tests/test_merge_conflict_matrix.py tests/test_merge_signal_provenance.py tests/test_ranking_factors.py tests/test_service_identity.py tests/test_config_scanner.py tests/test_wp032_reference_binding.py tests/test_wp032_override_origins.py tests/test_wp032_score_references.py tests/test_scan_service.py -q -p no:cacheprovider --basetemp .tmp/wp032-multibackend-final03-20261031 --junitxml docs/verification/windows-parity/WP032/agent-multibackend-20261031/final-guarded.xml
.venv/Scripts/python.exe -X utf8 docs/verification/windows-parity/WP032/agent-multibackend-20261031/qualify_multibackend.py .tmp/wp032-multibackend-qualification-final-20261031
git diff --check -- src/attackmap/config_scanner.py src/attackmap/contracts.py src/attackmap/scan_service.py tests/test_wp032_protocol_fleet.py tests/test_wp032_multibackend_proxy.py tests/fixtures/wp032_multibackend_proxy docs/verification/windows-parity/WP032/agent-multibackend-20261031
```

## Remaining boundaries

This deliberately rejects host-wide proxy identity instead of implementing
path routing, namespace discovery, endpoint/port routing, nginx configuration
evaluation, RPC or non-HTTP adapters. It does not prove every deployment grammar
or every remaining namespace/protocol identity case. Retained finding-to-score
tests pass, but this slice does not claim new score semantics or a runtime
reference-system acceptance.

Representative production/runtime fleet, whole WP032/C28, native/frozen/UI and
package/release gates remain open. WP043 global rendering acceptance remains
FAILED. No provider HTTP calls, native build, installation, ZIP or release was
performed.
