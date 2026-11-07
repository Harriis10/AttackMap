# WP039 / WP042 — Python routing, detailed analyzer activity and native UI

23 October 2026. User-authorized continuation with three GPT-6.1 Sol / ultra
agents and a single integrator. Base Git commit:
`507bddacd72a246a136ca2d46faad2aa661806c1` plus preserved uncommitted work.

**Implementation and scoped integration complete.** The same captured native
build and fresh engine passed real scans, visual review and packaging checks.
WP042 is IMPLEMENTED; dependency/manual acceptance remains open. WP039 remains
IN_PROGRESS for C27/C38 qualification and the explicit unsupported scope below.
This evidence concerns the captured analyzer slice, not concurrent fleet/graph
work or the entire moving checkout.

[Windows ZIP](../../../../../desktop/windows/artifacts/AttackMap-Windows-Analyzers-20261023.zip)
is an unsigned development package (119,545,901 bytes), with
[delivery identity](delivery.json) and [SBOM](package-sbom/release-sbom.json).
ZIP SHA-256: `1ea81929733bf6bd1204af0d06de82a6f625f00d83b738d772be7b7dc3299bde`.
It was not installed into the user's existing application directory.

## Implemented

- Exact bounded import/object binding for FastAPI/Flask mounts, blueprint hooks
  and custom guards. Ambiguous, mixed public/guarded, conditional or rebound
  identities cannot upgrade a sibling route. Flask registration prefixes
  override defaults. Same-file prefix cycles/repeated mounts terminate.
- Credential provenance and rejecting control flow replace auth-like names as
  proof. Local constants, truthy defaults, disabled JWT verification, swallowed
  exceptions, foreign decorators and definition-time rebindings are negative
  fixtures. These remain static signals, not runtime auth verification.
- Bound Django URLconf path/include aliases, repeated and tuple includes,
  anchored literal re_path, and class-view route surfaces. Exact Django auth
  decorators and correctly ordered middleware are scoped to resolved roots;
  opt-outs, ambiguous settings, mutations and unsupported wrappers remain unknown.
  Parser work is bounded, with a per-scan 32-module view cache.
- Ledger 1.1: detection/analysis durations, successful extraction counts before
  merge, and bounded ordered lifecycle events. Failure and skipped/pending work
  retain distinct states; legacy 1.0 remains readable with unknown measurements.
- Native profile/provenance UI now shows detailed per-analyzer records, live
  stage activity (latest 200 changes), and separate discovery failures/policy
  skips. Activity is scrollable; failure displays omit raw exception messages.

## Verification

| Gate | Evidence | Result |
| --- | --- | --- |
| Integrated deterministic Python suite | [JUnit](integrated-final-01.xml), [source/test hashes](integration-test-proof.json) | 338 PASS |
| Native captured model/contract suite | [log](native-discovery-issues-stable-20261023/stdout.log), [hashes](native-discovery-source-hashes.json) | 164 checks PASS; no GUI/provider claim |
| Immutable source Automatic Juice Shop before/after | [comparison](juice-shop-source-verification.json) | Whole report equal except three identical ledger copies; 266 routes / 18 findings |
| Native captured-source publish | [build proof](native-analyzers-03-build-proof.json) | PASS; input hashes unchanged |
| Django paired extraction | [review](python-django-review.md) | Original 14 cases improved 5 to 14; final 17/17 source cases; 8 settings negatives PASS |
| Mount/auth independent review | [handoff](python-mounts-handoff.md), [source release](python-mounts-source-release.json) | 103 focused tests; two independent reviews; installed profile negatives unknown |
| Ledger/live progress | [handoff](ledger-handoff.md) | 49 focused tests; overlaps integrated suite |
| Upstream Python plugin qualification | [decision](upstream-qualification.md) | NO-GO; 27 inert cases across installed/pinned/candidate/main implementations |
| Actual frozen Python profile | [Django summary](python-django-frozen-final/summary.json), [mount/auth summary](python-mounts-frozen-final.json) | 17/17 Django and 8/8 mount/auth cases; exact report/manifest ledger and immutable fixtures |
| Source / frozen / native Juice Shop before/after | [comparisons](juice-shop-verification.json) | All three whole-report comparisons equal except ledger copies; respectively 266 / 270 / 281 routes, each 18 findings |
| Actual native scan/profile persistence and appearance | [smoke proof](native-visual/analyzer-smoke.json), [independent review](python-django-native-visual-review.md) | 8 nonblank captures, Light/Dark at two sizes; real run, ledger, collisions and activity; separately labeled simulated discovery failures |
| Actual packaged executable and ZIP integrity | [package proof](packaged-catalog-final-verification.json), [SBOM](package-sbom/release-sbom.json) | 15 official distributions / 21 effective / 24 candidates / 3 shadowed; 4 profiles; 779 ZIP entries verified; 511 native + 265 engine payload files match tested builds |

Focused suites overlap; their counts must not be added. The three Juice Shop
lanes are compared against their own same-environment baselines, not claimed
identical across different profiles/runtimes. All real scans are deterministic
with zero provider calls. No framework application fixture was executed.
Frozen engine SHA-256: `6045194b77c0957166a6eb9fece45dbfd9c42441bb9e32cec6d040db6c419b05`.
Current checkout differences in fleet.py and desktop_fleet.py belong to the
other lane; [frozen provenance](python-django-frozen-final/freeze-provenance.json)
preserves this boundary. The native live view received 221 updates, retained
the latest 200 and displayed the omitted count. The complete selected-report
ledger remains separate. Native screenshot review is scoped to visible pixels;
small-window inventory scrolling and human accessibility remain unverified.

## Candidate provenance and commands

`baseline-captured-source.json` records 223 files from the previous verified
analyzer baseline. `candidate-python-inputs.json` and
`candidate-native-final-inputs.json` record this batch's overlay.
`.tmp/wp039-python-20261023/candidate-source` is immutable during builds/scans.
It excludes other agents' unfinished fleet/graph changes by construction.

Reproducers in this directory: `candidate.py`, `verify_native.py`,
`verify_candidate.py`, `package_candidate.py`, `python-django-frozen-oracle.py`.
Each output label must be fresh; retained failures are not overwritten.

## Remaining acceptance boundaries

The pinned Python plugin still emits some commented/foreign Django routes,
local include stubs and raw-regex duplicates with different route identities.
This overlay does not remove them. General regex normalization, arbitrary
dynamic mounting, cross-file route replacement, class/mixin/DRF authentication
and C27 human-labeled maturity remain unsupported or unqualified.
The proposed upstream pin improves extraction but adds false auth claims, so
it was not installed; the bounded local WP039 alternative is the accepted scope.

WP039 C27/C38 maturity and dependencies remain open. Automated native captures
and AI visual review cannot establish human keyboard/Narrator acceptance,
clean-host installation, signing or macOS parity. Windows M3 acceptance and the
removal of Windows C26 remain unchanged.

## Retained failed attempts

`native-ledger-unit-01` was a harness argument-routing mistake (`dotnet run`
forwarded a build argument to the app); the corrected helper builds then runs
the DLL. Native build `native-analyzers-01` overlapped initial source capture and
failed the immutable-input assertion; `02` passed and `03` contains the final
discovery/activity additions. Sandbox pytest temp ACL failures were retried in
fresh task-owned directories with the approved targeted execution permission.
The first ledger live test fake omitted a required begin hook and was corrected.
Upstream network/qualification attempts and early independent auth failures are
retained in their handoffs; none is counted as a final PASS.

The first frozen qualification attempt compared against the moving root's
newer release-lock algorithm, which additionally inventories findings.json.
[The exact one-file scope difference](qualification-input-mismatch.json) is
retained. Qualification and packaging use the hash-bound captured producer
tools; the wrapper separately verifies findings.json against its original
capture. Core and native product bytes did not change, and no retained lock or
build proof was rewritten to make the comparison pass.
