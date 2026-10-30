# Python static mount and auth binding slice — 2026-10-23

This is a preparatory WP039 extraction correction. It does not complete WP039,
C27/C38 acceptance, the WP031/WP032/WP035/WP042 dependency gates, mounted URL
normalization, or Python ecosystem maturity. Root owns combined verification,
fresh frozen-engine checks, and any release/native acceptance. No provider or
application code was executed by these inert-source probes.

## Measured correction

`python-mounts-source-release.json` contains the exact before/after projections,
fixture hashes, and source hashes. Fixtures were created once under
`.tmp/wp039-python-20261023/python-mounts-fixtures`; all paired input hashes agree.
The captured original source is `.tmp/wp039-python-20261023/baseline-source/src`.
The installed plugin ran from `.tools/wp024-freeze-venv` with that original source
and again with current source. No lock or installed package changed.

| Immutable specimen | Original builtin service overlay | Current builtin service overlay |
| --- | --- | --- |
| Two FastAPI router objects in one file; only private mounted with auth | private and public siblings both required | private required; public receives no overlay auth upgrade |
| Two Flask blueprints in one file; hook only on private | both siblings required; mount hint `/api/v1` | private required; public receives no overlay auth upgrade; hint `/api` |
| Bare unbound child name with unique foreign repository definition | unrelated child mounted and required | explicit unresolved limitation; no mount/auth certification |
| One FastAPI router mounted privately and publicly | scanner failed to terminate; retained 20-second timeout trace | completes; both mount hints retained, no required-auth upgrade |

The installed external Python plugin emitted no routes for these four focused
specimens. An empty service-overlay route list means **no auth upgrade**, not an
absent application endpoint or a proved unauthenticated endpoint.

`python-mounts-before-mixed-timeout.log` records the original scanner loop and
exit 1. An initial unbounded baseline attempt was stopped using only its two
owned Python PIDs; both were later absent. A separate catalog-agent 90-second
original-source timeout independently corroborates the scanner defect.

The first `python-mounts-before.json` has superseded source-hash metadata: it
hashed the shared current file instead of the imported captured module. Use
`python-mounts-before-captured.json`, which records the actual imported module
path/hash. Earlier `after-source`, `after-reviewed`, and `after-final` evidence
captures intermediate source stages. The final paired outputs are
`python-mounts-after-release.json` and
`python-mounts-after-release-fastapi-mixed-mounts.json`. Originals remain retained.

## Implementation and boundaries

`python_route_binding.BindingIndex(files)` consumes captured source text and
returns exact static router objects, mount records, bound hook/decorator
definitions, decorator receivers, and unresolved limitations. It resolves unique
module/from imports, aliases, relative imports and simple re-exports. Direct
factory-local declarations are observed wiring; factory execution is not proved.
Reassignments, wildcard/conditional bindings, ambiguous module/package names,
unbound references, dynamic prefixes, opaque kwargs, and nested mount graphs
cannot certify mounts or auth. Function default-expression rebinding is included
in name ambiguity checks.

The overlay emits mount hints without manufacturing cross-file mounted Route
objects. Scanner and merge still use `(path, method, file)` identities. Auth
upgrades require the exact bound object and guard definition, every observed
direct FastAPI mount to carry a qualifying guard, and no competing receiver for
the same local merge key. An unresolved FastAPI child conservatively suppresses
include-derived upgrades. Flask hooks attach only to their bound blueprint.
Route decorator upgrades use bound wrapper definitions, not the repository-wide
same-name validation map.

Guard qualification is an intentionally small AST subset, not general control
flow analysis or proof of authentication strength. It requires caller-input
provenance from meaningful parameters/dependencies or imported Flask request/
session access. Local constants, reassigned inputs, comments/docstrings, early
returns, optional-pass branches, inverted predicates, truthy credential defaults,
disabled/opaque JWT options, conditional JWT decode, swallowed failure branches,
and foreign same-name wrappers do not certify auth. Supported wrapper shapes
return one nested function, with canonical `functools.wraps` metadata where used.
Unsupported valid guards remain unknown; no missing control is inferred.

The scanner prefix function now uses a bounded worklist. Unique acyclic chains
retain existing behavior; repeated mounts, cycles and their descendants retain
local prefixes. Flask registration overrides its blueprint default. A composed
prefix longer than 16,384 characters falls back locally and blocks descendant
composition. This remains the existing per-file regex extraction subset; it is
not a new Python route parser. The AST helper accepts the existing at-most-1 MB
captured files, rejects over 100,000 AST nodes after parsing and depth over 100,
and bounds dependency-helper propagation to eight passes. The node limit is a
post-parse work limit, not a pre-allocation guarantee.

## Verification and independent review

Final focused run: **103 passed in 8.44 seconds**, retained as
`python-mounts-tests-final-103.log` and `.xml`. Command:

```text
.venv/Scripts/python.exe -m pytest tests/test_ecosystem_python.py tests/test_ecosystem_python_mounts.py tests/test_python_route_binding.py tests/test_python_route_prefixes.py -q -p no:cacheprovider --basetemp=.tmp/wp039-python-20261023/pytest-mounts-final-103 --tb=short --junitxml=docs/verification/windows-parity/WP039/sol-ultra-20261023-python/python-mounts-tests-final-103.xml
```

The test run required targeted escalation after the normal sandbox run hit
WinError 5 on its owned pytest temporary directory. Tests cover the original
fixture positives, sibling and shared-key negatives, mixed mounts, imported
aliases, default overrides including empty/None, unsupported bindings, auth
decoys, 300-node reversed chains, cycles and output bounds. Original retained
application fixtures were not edited. The existing Flask mount expectation was
corrected from `/api/v1` to `/api`; root owns concurrent Django expectations.

Independent reviewers found real intermediate false positives; their initial
failures are retained. `python-django-mount-independent-final.json` reruns the
same positive and four constant/JWT-options/default-rebinding negatives: the
positive retains required auth and all four negatives receive no overlay
upgrade. Catalog's final independent review also passes at the release hashes:
ten guard probes, three bounded prefix probes and two decorator probes. Its
`review-final.json` and `python-decorator-profile-probe.json` retain exact inputs,
implementation origins and results. The actual installed `python@1.0` decorator
negatives both retain `/public` unknown with empty guards and all five selected
analyzers successful. These are source results, with no frozen-engine claim.

`python-mounts-installed-profile.json` resolves the actual installed effective
`python@1.0` profile and runs the normal `analyze_repository` merge. Local constant
dependency, shadowed known decorator, and foreign custom decorator collision each
produce `/public` with `auth=unknown`. Role-specific outputs, actual selected
implementation paths/hashes, ledger and analyzer errors are retained. The original
bound-wrapper fixture retains required FastAPI and Flask controls. Existing
external-plugin raw Django/local-path duplicates remain visible and unresolved;
these checks do not prove whole-profile route completeness or all-auth correctness.

## Primary semantics and upstream qualification

Flask registration options override blueprint defaults; `None` uses the default
and the empty string explicitly replaces it. This follows the
[Flask API](https://flask.palletsprojects.com/en/stable/api/#flask.Flask.register_blueprint)
and [Flask 3.1.2 BlueprintSetupState source](https://github.com/pallets/flask/blob/3.1.2/src/flask/sansio/blueprints.py#L66-L71).
Nested blueprint parent composition is a separate framework operation, outside
this overlay's supported direct-app mount hints.

FastAPI supports including the same router at several prefixes and applying
include-site dependencies. Those controls therefore cannot be reduced to one
arbitrarily selected mount. See the official
[multiple-file/router documentation](https://fastapi.tiangolo.com/tutorial/bigger-applications/#include-the-same-router-multiple-times-with-different-prefix).

Catalog qualification records that installed, immutable pinned, candidate
`478208fd`, and observed upstream main
`87e4a8ac3de74e2a6f459af41ddc7c85cc1f3be5` do not implement these FastAPI/Flask
mount bindings. See `upstream-fetch.json` and `installed-pin-byte-comparison.json`.
The installed three Python package files match the cached wheel exactly and
the pinned source after CRLF-to-LF normalization only. Updating a shadowed or
unrelated external plugin is not this local builtin correction, and no pin update
was attempted. Root retains the full upstream qualification and other ecosystem
coverage gaps.

Source release hashes: helper
`53e61053dc955ae06de865ab39307153c4ed6391f687a095f6eda34e4df549c9`, scanner
`5be41db7b72246efe048b01267bac008ed14119e65f9d1f896aa725502ead8ff`, shared Python
overlay `fc0f091d9ffc7c43eac6001e0ca4ae99d399a7e0ec48d40690b4171b1a9dc722`.
The shared overlay hash includes root's separately reviewed Django work.

## Fresh frozen CLI follow-up

Root released the fresh frozen engine at
`.tmp/wp039-python-20261023/engine-analyzers-final/dist/attackmap/attackmap.exe`,
SHA256 `6045194b77c0957166a6eb9fece45dbfd9c42441bb9e32cec6d040db6c419b05`.
The actual CLI `--analyzer-profile python@1.0` probe passed **8/8 cases** with no
AI flags, an allowlisted child environment, outputs outside every fixture, and
90-second Windows Job limits per process. Every process exited 0 without timeout;
owned tree cleanup was verified. No product source or test files changed.

| Frozen full-profile specimen | Observed expected result |
| --- | --- |
| FastAPI bound private/public siblings | `/private/item` required; `/public/item` unknown |
| Flask bound private/public siblings | `/v1/item` required; `/public/item` unknown; mount hint `/api` |
| Existing imported router alias | local `/v1/users` unknown; observed mount hint `/api/v1` |
| Shadowed known decorator | `/public` unknown with empty guards |
| Foreign custom decorator collision | `/public` unknown with empty guards |
| Local constant credential | `/public` unknown with empty guards |
| Mixed guarded/public repeated mount | `/items/item` unknown; both mount hints retained; terminates |
| Cyclic prefix graph and descendant | local `/a/item`, `/b/item`, `/c/item` unknown; terminates |

The cyclic specimen copies the retained unit cycle and adds declarations/routes
solely to observe bounded static extraction. It is an unsupported cyclic
configuration, not a valid running FastAPI application. Its exact source and unit
origin hash are retained; original fixtures were not rewritten.

`python-mounts-frozen-fixtures.json` records every input hash and expected merged
path/auth/hint projection. `python-mounts-frozen-final.json` retains full merged
routes, framework evidence, limitations, process evidence, engine hash and ledger
for each case. Each `python-mounts-frozen-final-<case>/` folder retains command,
stdout/stderr, process and verification JSON. Full generated reports and manifests
are under `.tmp/wp039-python-20261023/python-mounts-frozen-output-final/<case>/`.
Every fixture hash remained unchanged. Authoritative generation reports match
their compatibility exports. Report `scan.analyzer_run_ledger` exactly equals
`run-manifest.json`'s ledger, schema 1.1 and profile ID `python@1.0`, in all eight
runs. Analyzer errors are empty and LLM usage is empty.

Reproduction uses `python-mounts-frozen-probe.py`, which imports
`verify_python_batch.py`'s Windows Job runner via `importlib`. A rerun requires a
fresh `--run-id`; existing proof output is never silently replaced. These results
qualify the stated frozen executable and representative merged profile subset.
They do not resolve cross-file canonical URL identity, all plugin false surfaces,
whole-profile completeness, WP039 maturity, or root's separate native/package
release-input qualification.
