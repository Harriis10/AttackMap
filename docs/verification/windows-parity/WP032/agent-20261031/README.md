# WP032 — bounded HTTP protocol / alias / reference qualification — 2026-10-31

This closes one reproduced core protocol false-positive and supplies a stronger
three-repository identity/reference fixture. **WP032 and C28 remain open.** No
native, product frozen engine, packaging, release, runtime traffic or production
fleet acceptance is granted by this evidence.

## Reproduced defect and minimal fix

The HTTP route linker accepted `grpc://worker:9000/Api/Items/42` as a direct
`observed` HTTP contract when the destination was positively declared but the
backend protocol was unknown. It also accepted
`grpc://worker-edge.internal/Api/Items/42` as `observed_via_proxy`. Equivalent
Kafka, WSS and FTP targets reproduced the same false-positive. A direct false
positive could support a confused-deputy flow or unauthenticated-write lead.

`contracts.py` now leaves explicitly non-HTTP(S) schemes as
`candidate / unsupported_protocol` immediately before either successful
resolution. Existing reasons keep their priority: a configured backend protocol
contradiction remains `scheme_mismatch`, with its exact declaring source;
ambiguous identity, unresolved host and undeclared explicit port behavior also
remain unchanged. HTTP/HTTPS matching, and the independence of a supported
client-to-proxy protocol from the backend's declared protocol, remain unchanged.
An absent scheme receives no new restriction.

No `crossrepo.py`, model, config extractor, report, datastore/messaging or native
runtime file was edited. Existing downstream `resolution == observed` gates
continue to enforce the corrected core facts.

## Exact fixture scope

`tests/fixtures/wp032_protocol_fleet` contains three synthetic repository roots,
real Kubernetes/nginx extractor inputs and inert source-location anchors.
Application call/route/taint observations are **supplied normalized fixtures**,
not application extraction or runtime observations. The 31 focused tests cover:

- Non-HTTP direct and proxy resolution with an undeclared backend protocol;
  these cases cannot produce any observed link, flow or trust gap.
- HTTP and HTTPS positive controls with no backend protocol declaration, plus
  existing scheme-mismatch precedence when the backend is declared.
- Config-only aliases and source origins, single backend proxies, multi-service
  upstreams and one service on multiple upstream ports.
- Unqualified namespaces never shortening to a repository name; an explicitly
  opted-in production suffix does not authorize the preview suffix.
- A Kubernetes port called `https` does not establish TLS. The worker's actual
  full-fixture HTTP protocol declaration comes from nginx `proxy_pass` only.
- `/Api/Items/{id}`, `/api/items/{id}` and unmatched `/API/Items/...` remain
  distinct after DNS authority normalization; lower-case evidence uses its own
  sink line.
- Graph evidence references resolve exact supplied call/route observation IDs,
  repository, file, line and analyzer origin. Generated findings retain the
  exact producer score reference and real fixture snapshot context.

The persisted [qualification.json](qualification.json) has:

| Fact | Count |
| --- | ---: |
| Synthetic repositories | 3 |
| Core contract links | 19 |
| Direct observed / proxy / candidate links | 3 / 1 / 15 |
| HTTP graph edges (proxy has two legs) | 20 |
| Exact evidence records | 30 |
| Cross-boundary flows / trust gaps | 3 / 3 |
| Generated finding-to-score references | 2 |
| Provider calls | 0 |

Only the three direct HTTP(S) positive controls support flows and trust gaps.
The artifact also stores source/fixture SHA-256 hashes and full reference data.

## Executed verification

All commands ran from `C:\Projects\INPROGRESS\AttackMap` with the project
`.venv/Scripts/python.exe -X utf8`. Windows denied access to pytest's newly
created temporary directory in the restricted attempt; bounded test runs were
then executed with ordinary filesystem access and unique project-local temp
directories. No files outside this work package were reset or cleaned.

1. Actual pre-fix regression: **8 failures, 0 errors** in
   [red-protocol.xml](red-protocol.xml). Each failed on the original successful
   `observed` or `observed_via_proxy` resolution instead of `candidate`.
2. New focused file after fixture corrections: **31 PASS** in
   [focused-new.xml](focused-new.xml).
3. Final current source verification: **312 PASS, 0 skips, 0 failures/errors,
   34.81 seconds** in [final.xml](final.xml).
4. Artifact qualification script completed successfully; scoped
   `git diff --check -- src/attackmap/contracts.py` exited 0.

Final test command (the list is the exact final selection):

```powershell
.venv/Scripts/python.exe -X utf8 -m pytest tests/test_wp032_protocol_fleet.py tests/test_contracts.py tests/test_fleet.py tests/test_crossrepo.py tests/test_merge.py tests/test_merge_conflict_matrix.py tests/test_merge_signal_provenance.py tests/test_ranking_factors.py tests/test_service_identity.py tests/test_config_scanner.py tests/test_wp032_reference_binding.py tests/test_wp032_override_origins.py tests/test_wp032_score_references.py -q -p no:cacheprovider --basetemp .tmp/wp032-protocol-20261031-final --junitxml docs/verification/windows-parity/WP032/agent-20261031/final.xml
.venv/Scripts/python.exe -X utf8 docs/verification/windows-parity/WP032/agent-20261031/qualify_protocol_fleet.py
```

Intermediate files are preserved honestly: `red.xml` is an invalid initial
fixture setup attempt (27 errors from a missing required `hops` field), not a
behavior reproduction. `focused.xml` has 311 PASS and one assertion failure
because the first artifact fixture did not include a confirmed SQL source; no
runtime regression was attributed to either intermediate harness issue. The
final corrected fixture explicitly supplies its synthetic path-parameter source.

## Remaining boundaries

This deliberately does not introduce RPC, WebSocket or messaging HTTP adapters.
Non-HTTP candidates remain inspectable, but their names and matching paths do
not establish protocol connectivity. Namespace discovery and multi-backend
routing are not implemented; only declared existing seams are qualified here.
The artifact references are static fixture facts, not observed network traffic,
a global atomic fleet capture, native UI acceptance or a release proof.

Broader protocol/namespace/multi-backend coverage, production reference fleet,
native/frozen/UI behavior, C28 and whole-WP032 gates remain open. WP043 global
rendering acceptance remains FAILED. No model/provider HTTP calls, native build,
installation, package or release was performed.
