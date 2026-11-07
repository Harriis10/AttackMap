# WP032 — trailing-dot unresolved-proxy guard correction — 2026-10-31

This corrects a P1 bypass found during independent review of the prior proxy
invalidation slice. **WP032/C28 remain IN_PROGRESS.** Provider calls: **0**.
No runtime traffic, production fleet, native/frozen/UI, package or release
acceptance is claimed.

## Defect and bounded change

`DeploymentAliases.unresolved_proxies` already strips trailing DNS root dots,
but destination authorities and positive `hosts`, `proxies`, and `host_ports`
declarations preserve them. A declaration for `edge.production.internal.`
could therefore bypass the negative fact `edge.production.internal` and create
an unsupported `observed` or `observed_via_proxy` relation.

The production change is one comparison in `src/attackmap/contracts.py`:
`host.rstrip(".") in aliases.unresolved_proxies`. Two comment lines explain
the comparison. It uses the existing negative-fact normalization while retaining
destination spelling, positive alias matching, provenance, protocol precedence
outside the negative guard, and valid unrelated dotted declarations.

No broad authority normalization, path normalization, config extraction, merge,
model, crossrepo, scoring, or native code changed in this corrective slice.
Earlier changes in the dirty checkout remain separately owned.

`tests/test_wp032_multibackend_proxy.py` adds 21 focused cases using the existing
physical `mixed-upstream.conf` fixture and supplied normalized application
observations. The cases cover dotted direct-host, proxy, and host-port aliases
under HTTP, HTTPS, and scheme-less authorities; unrelated negative-host controls;
and actual CLI `HOST=REPO` parsing followed by effective alias merging. There is
no CLI host-port flag or claim that one was tested. Blocked links preserve the
dotted destination, become `candidate / ambiguous_identity`, carry no positive
alias/proxy provenance, and cannot support cross-boundary flows or trust gaps.
The unrelated server remains `candidate / unresolved_host`.

The existing path matcher retains a scheme-less authority as a path segment.
For those resolver-level cases, supplied route paths deliberately include that
authority segment so the existing resolver is reached. Conventional `/Api/...`
routes do not match such scheme-less targets in the existing implementation.
This slice does not add or claim general scheme-less URL support.

## Executed checks

All commands ran from `C:\Projects\INPROGRESS\AttackMap`, with the existing
`.venv/Scripts/python.exe`, on the pre-existing dirty checkout. No reset,
checkout, commit, fixture rewrite, or shared planning-document update occurred.

| Evidence | Result | Interpretation |
| --- | --- | --- |
| [red-acl.xml](red-acl.xml) | 21 setup errors, then pytest cleanup crash | Windows temporary-directory ACL failure; no behavior evidence |
| [red-initial-fixture.xml](red-initial-fixture.xml) | 15 failures, 6 passes | Initial scheme-less route reachability assumptions were wrong; superseded |
| [red-route-fixture.xml](red-route-fixture.xml) | 15 failures, 6 passes | Intermediate fixture used dataclass replacement on Pydantic routes; superseded |
| [red.xml](red.xml) | **12 behavior failures, 9 positive controls PASS** | Clean pre-fix reproduction after fixture corrections |
| [focused.xml](focused.xml) | **21 PASS** | All new cases after the comparison fix |
| [affected.xml](affected.xml) | **325 PASS, 2 FAIL** | Contracts/config/scanner/crossrepo/identity and both WP032 fixture suites |
| [scanner-prefix-pre-fix-guard.xml](scanner-prefix-pre-fix-guard.xml) | **2 FAIL** | Same unrelated scanner failures with the old comparison restored only in child-process memory |
| [final-guarded.xml](final-guarded.xml) | **451 PASS, 0 failures/errors/skips** | Exact prior 16-file guarded set plus the 21 new cases; 60.29 seconds wall-clock |

The broader affected set found two Flask blueprint-prefix expectation failures
in `tests/test_scanner.py`: `test_scan_repo_detects_flask_blueprint_routes`
expects `/api/v1/admin/users`, and
`test_scan_repo_normalizes_paths_without_leading_slash` expects
`/v1/admin/audit` while extraction gives `/v1/audit`. They reproduce identically
when this correction is removed in process memory, with source files untouched.
They remain reported failures; the guarded set does not erase them.

The earlier [430-pass guarded checkpoint](../agent-multibackend-20261031/final-guarded.xml)
and the independent review's reported **283 passes** are **pre-correction
evidence**, not final acceptance of this fix. This directory's 451-pass result
is the current bounded post-correction guarded evidence.

All behavior runs after the ACL failure used this process-local workaround:
`Path.mkdir` calls requesting mode `0o700` are converted to `0o777` only in that
test child, preserving other modes. Production code and the test harness on disk
are not modified by this workaround. Each run uses a unique temporary path.

Exact final command:

```powershell
.venv/Scripts/python.exe -X utf8 -B -c 'import pathlib,pytest; original=pathlib.Path.mkdir; pathlib.Path.mkdir=lambda self,mode=0o777,parents=False,exist_ok=False: original(self,mode=(0o777 if mode==0o700 else mode),parents=parents,exist_ok=exist_ok); raise SystemExit(pytest.main(["tests/test_wp032_multibackend_proxy.py","tests/test_wp032_protocol_fleet.py","tests/test_contracts.py","tests/test_fleet.py","tests/test_fleet_architecture.py","tests/test_crossrepo.py","tests/test_merge.py","tests/test_merge_conflict_matrix.py","tests/test_merge_signal_provenance.py","tests/test_ranking_factors.py","tests/test_service_identity.py","tests/test_config_scanner.py","tests/test_wp032_reference_binding.py","tests/test_wp032_override_origins.py","tests/test_wp032_score_references.py","tests/test_scan_service.py","-q","-p","no:cacheprovider","--basetemp=.tmp/wp032-dot-final-qualified01-20261031","--junitxml=docs/verification/windows-parity/WP032/agent-dot-host-fix-20261031/final-guarded.xml"]))'
```

The clean RED and focused GREEN use the same wrapper and the new fixture file
with `-k 'trailing_dot or cli_dotted'`, and unique `wp032-dot-red-qualified03`
and `wp032-dot-focused-qualified01` temporary paths. The affected set adds
`test_scanner.py` to contracts, config scanner, crossrepo, service identity, and
the two WP032 fixture files. Scoped `git diff --check` passed.

Remaining gates include the two broader scanner expectation failures,
WP032/C28 whole-task acceptance, representative production/runtime fleets,
remaining protocol/namespace/path/port-routing coverage, native/frozen/UI and
package/release qualification. WP043 rendering acceptance remains FAILED.
