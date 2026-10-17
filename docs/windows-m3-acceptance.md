# Windows M3 acceptance ledger

**Workspace cleanup (2026-10-16):** only the latest accepted Windows package is retained. Final raw evidence was moved without changing its bytes to `desktop/windows/verification/retained-m3/`; its relocation manifest maps the historical paths below. Older builds and disposable raw QA campaigns were removed. The local .NET SDK/NuGet toolchain now lives under `.tools/`. See `desktop/windows/README.md` for current development commands.

**Scope change — 15 October 2026, user decision:** C26 performance qualification is removed from Windows M3 acceptance. A Windows 11 performance host and repeated performance campaign are not required; no replacement Windows 10 performance gate is introduced. Existing measurements remain optional diagnostics, not a performance pass. Other requirements retain their evidence status; the later Windows M3 closure moves remaining manual UX/accessibility and participant validation to M4. macOS C26 is unchanged. Historical Windows C26 blockers below are superseded by this decision.

**Windows M3 closed — 15 October 2026, explicit user acceptance:** Windows M3 is complete as a functional beta with documented limitations, delivered in `dev-20261015190038-5667bbbf`. Remaining Windows participant study (C19), manual workflow/UX validation (C21/C25), and manual accessibility validation including Narrator (C24) move to M4. They remain unverified, not passed. Windows C26 is removed. Original M0/M1/M2 evidence and limitations remain recorded; this bounded Windows acceptance does not certify every original prerequisite, macOS completion, clean-machine compatibility, or a signed public release.

Status: **accepted Windows functional beta with limitations**. Runtime evidence
is from the Windows 10 x64 development host. Manual and participant validation
remains open in [M4](roadmap-2026-2028.md#carried-forward-from-windows-m3-by-user-decision-2026-10-15).
Clean-machine compatibility, macOS and comprehensive original prerequisite
acceptance are not inferred. Historical delivery records remain in the
[implementation tracker](implementation-todo.md).

## Current package — citation and saved-report integration, 2026-10-15

Unsigned Windows x64 package `dev-20261015190038-5667bbbf` includes the compact
native shell, saved-generation report reopening (including listed AI reviews),
correct popup lifetime/naming and separate producer-ID/source-reference checks.
Original AI prose remains intact; unsupported source references are unvalidated.
ZIP SHA-256: `66b93d333e5f0342a1b1fc173e52a7d31986f9a469a44d9409ef2ab78be5003f`.
Native DLL: `65d3b7d4248696a741cc67b04d1b59023b9cedbb7c858cf2dfb4c5860e6fe690`.
Engine: `81a304b93e1b4f5ff3c762510c362b5f230749f46a522ff0156fef1c8916e870`.

GPT-6 Astra independently reviewed the changes and corrected regression evidence:
51 focused tests passed; four original expectation failures remain preserved.
The frozen build matches its immutable source inventory; all 104 core module
origins came from that snapshot. Frozen CLI, analyzer discovery, actual worker
publication and comparison action passed. Native publish/report smoke passed
with 18 findings and manifest integrity distinguished from broker origin.
The isolated installation and native report smoke passed. Its actual bundled
engine then analyzed `C:\tmp\juice-shop` with LM Studio at
`http://127.0.0.1:1234/v1`, model `cyberstag-security-26b-a4b-v1`.
Run `da6b4d5767534bcd859d83b68fab8a7c` exited 0 after 215.83 seconds;
its sole terminal was completed/succeeded/ready, revision 108, with zero protocol
errors and a validated generation. The 7,681-character final AI review persisted
reference metadata: eight valid producer IDs, ten unresolved source references,
and claim support not assessed. Source references are not validated by ID matches.
See [installed local-model proof](../desktop/windows/verification/installed-beta-lmstudio-reference-validation-2026-10-15.json).
This is an actual installed broker/API workflow, not a native button journey or
proof that model claims are true.

Actual desktop inspection exposed the native accessible tree, but two capture
timeouts prevented completion of the dialog/keyboard journey; see
`desktop/windows/verification/native-interactive-beta-attempt-2026-10-15.json`.
This immutable unsigned package is the accepted Windows M3 functional beta.
Manual C19/C21/C24/C25 validation is carried to M4 by user decision; it is not
reported as passed. Windows C26 is removed. All earlier package/checkpoint
acceptance statements below retain their historical cutoff and are superseded
for the current Windows delivery by the closure at the top of this ledger.

## Previous package — compact desktop redesign, 2026-10-15

User screenshots rejected the previous layout: oversized controls/header,
inconsistent spacing and shield branding. Package `dev-20261015182810-cb173755`
replaces these with a compact toolbar, text wordmark, neutral menus, native
options/details flyouts, grouped report actions and collapsed suppression.
History hides empty results; Settings uses a bounded, top-aligned form.
ZIP SHA-256: `e7ba809eb9d36defc2c981c84f4ea177994236129802ee1b3e9001ea53e6614a`.
Native DLL: `5e658192d8d788a200332e4101b087032d3e6b1fdb5cc0a7c5acfcf8605f331c`.
Engine remains `499215d3fd09e3208d1f2f7dc2ed7d6c52a152018b3cea91a40274e2c1c4b818`.
Publish and 32-view capture completed. The first redesign's 32 content images
were visually reviewed; final Settings, History, Architecture and Findings were
spot-reviewed after corrections. Capture roots are
`.pytest_cache/m3-native-compact-captures-2394d55fa85e4bd2b6c3af6470d63b70/`
and `.pytest_cache/m3-native-final-visual-capture-678e0280f8dc415ba168530eeaf06f03/`.
List fading/blank Inventory capture anomalies remain unresolved as live behavior;
these captures do not accept OS scaling, flyout interaction, or C24/C25 overall.
The bundled application was opened on the user's desktop. No new model call.

## Previous package — direct AI review, 2026-10-15

Unsigned package `dev-20261015181728-7bd32153` includes the Reports AI-review
card, corrected supplied-control wording, stricter static/runtime review
instructions and the API provider progress label. ZIP SHA-256:
`bfecb34ac926754a05f6c2ab448dca683456e2f67dd4de905b606f4adcac0647`.
Native DLL SHA-256:
`9eaaaed36da584dec210efe0e8770617fcf7f70cab564ce724b484e14fa5d07e`.
Engine SHA-256:
`499215d3fd09e3208d1f2f7dc2ed7d6c52a152018b3cea91a40274e2c1c4b818`.
The publish and loaded Reports check passed; the new review card has not been
visually or manually accepted. Desktop capture failed twice with timeout.
The new engine passed bounded actual worker/compare checks; no new model call
was made. The successful live AI evidence below belongs to the previous package
and does not prove compliance with the strengthened prompt. M3 remains open.

## Previous checkpoint — styled bundled workflow, 2026-10-15

**M3 remains unaccepted.** This previous immutable development package is
`dev-20261015180303-939910bd`, ZIP SHA-256
`2513063208a315b1919e0e98426f29b636434ad1afe511d0cd2d90bdc8a5d601`.
Its bundled engine SHA-256 is
`09d3984f08635e0187997858b91b3e55a324afc932e602aca3d7d2347b5a46d3`;
the native DLL is `ad93aa0a33dbd3c5fae41b2ecb15e130b9f269a1fc42c22f92e9748918d90caa`.
The user confirmed that the styled GUI is visible. This is direct confirmation
of the displayed styling, not a complete visual/accessibility acceptance.
The package manifest binds the payload; no claim that every older installed
candidate has these changes is intended.

One actual bundled `desktop-worker` request analyzed `C:\tmp\juice-shop`
with AI enabled only at `http://127.0.0.1:1234/v1`, model
`cyberstag-security-26b-a4b-v1`, empty credential, and CVE lookup disabled.
Personal provider settings were isolated. Original session 6679 / broker PID
142660 naturally exited 0 after 285.36 seconds: zero protocol errors, strictly
increasing revisions, exactly one completed/succeeded/ready terminal, a valid
generation and current pointer, and a genuine nine-section final AI review
(7,312 characters; provider metadata reports completed, 5,926 input and 6,803
output tokens). See
[actual bundled proof](../desktop/windows/verification/bundled-juice-shop-lmstudio-workflow-2026-10-15.json).
This exercised the bundled broker/API path, not a native button-click journey.
No independent HTTP/server log was captured during that run. A later read-only
inspection found the matching LM Studio completed response: its exact final
message occurs in the bundled review, and input/output usage matches. See
[server response correlation](../desktop/windows/verification/bundled-lmstudio-server-response-2026-10-15.json).
No extra model call was made.

The C15 pre-output-helper source snapshot has complete Windows Python
3.11/3.12/3.13 node coverage: each 3,290 passed and four explained skips,
using two disjoint fresh jobs whose union exactly matches the same 3,294-node
inventory. Sealed source/test/schema/fixture maps match across roots. See
[cross-version proof](../desktop/windows/verification/c15-corrective-three-python-two-phase-2026-10-15.json).
This predates the subsequent output-root helper and AI/style changes; it is
**not** a full regression result for this new package. Original failed regular
runs and the later Python 3.13 startup-readiness negative remain preserved;
the subsequent quiet pass does not establish the failure's cause. The two
ordinary atomic prewrite sites now call the canonical strict preparation
helper, so the earlier source counterexample is historical rather than an
unfixed current claim.

The demonstrated remaining product-quality issue is AI wording: this actual
final review still contains unqualified unauthorized-state-change and RCE
claims despite the deterministic partial/static scope notice. Final-message
extraction and successful delivery do not validate those claims. A focused
claim-classification improvement is needed before treating model narrative as
an evidence-qualified review. Missing detector-owned control/trust links stay
explicitly unknown; no association should be invented to fill them.

M0/M1 remain partial: the current Windows scoped results do not supply the
clean-checkout supported OS/Python matrix, macOS adapter end-to-end evidence,
or all original requirement-level proofs. Windows C21–C23 have implemented
scan, report, compare, suppression, source inspection and export paths with
bounded proofs; the live bundled AI path now adds actual final-response
evidence. C24 still needs real keyboard/dialog/Narrator/contrast/scaling
journeys. C25 still needs the full settled platform/state capture and human
review scope. Windows C26 performance qualification is no longer required.
C19 representative participants,
C20 owner effort/migration decision and macOS slices are external/manual
requirements, not demonstrated code defects. No new broader implementation
defect is established by those missing proofs.

All checkpoints below are historical, version-bound records. Their references
to pending processes, earlier candidates or absent AI proof describe their
original cutoff and do not override this checkpoint.

## Previous checkpoint (historical)


The C15 context and cross-version publisher snapshot now has complete Windows
Python 3.11/3.12/3.13 coverage: each recorded 3,290 passed and four explained
skips across two disjoint jobs. Exact full inventories of 3,294 nodes match;
all sealed source/test/schema/fixture inputs stayed unchanged. See
`c15-corrective-three-python-two-phase-2026-10-15.json`. The earlier Python
3.13 startup-readiness failure is preserved; the later quiet pass does not
establish its cause. This evidence predates the output-root preparation helper
currently being integrated and is absent from existing preview packages.

The following regression figures describe the preceding packaged snapshot.

Full Windows Python 3.11 and corrected 3.12 each pass 3,214 tests with four
explained skips. Corrected full 3.13 also passes 3,214 with four skips in
496.27s. All three green runs share identical production source inventories;
the original 3.11 test fixture predates the test-only PID publication repair.
Original failed runs remain in
`final-source-windows-matrix-2026-10-15.json`. Final-source Linux 3.12 passes
3,213 tests with five platform/opt-in skips.

Candidate `dev-20261015155320-502d45eb` pairs history-fixed native `6c10…`
with final engine `b5f8…`; installed startup/report/history/tiny timed-scan checks
and scoped uninstall pass. Neither it nor earlier packages are accepted M3
betas. Manual workflows, accessibility, settled visual review, qualifying
Windows 11 performance and original M0/M1/M2 prerequisites remain open.
The subsequent C15 structured-diagnostic implementation batch is in progress
and is outside those green regression and immutable package snapshots.
Its first integrated source check passed 272 tests in 89.02s across 19 test
files with 15 pinned official analyzers and unchanged source/test/contract
inventories. See `native-c15-integrated-focused-2026-10-15.json`. A later
source audit found uncovered early CLI/service validation diagnostics and
source-bearing analyzer warnings; their focused corrections are pending
verification. That pass does not cover these later corrections or both-client
end-to-end acceptance.

## C21 workflow status

| Workflow | Implemented and tested scope | Remaining acceptance |
| --- | --- | --- |
| Open repository | Native folder control; real repository scans | Recorded picker/keyboard journey and supported-host interactions |
| Run default scan | Actual Juice Shop scans load 18 findings without supplied analyzer errors; later legacy aggregate 899 may overlap. Installed candidates also pass tiny timed scans with all 19 artifacts verified | Native-control fault/retry/cancel journeys and clean-host proof |
| Configure advanced options | Typed options/module selection, compatible settings restore, live custom scan | Every advertised option, capability errors and keyboard journey |
| Browse/filter findings | Canonical real reports and synthetic 10k filter/selection | Qualifying reference-corpus measurements, exceptional states and accessibility |
| Inspect evidence | Precomputed finding context, supplied priority and static flows; explicit unknown controls/runtime | Native new-context and old-report journeys, source-change warnings, proven control/trust associations where required |
| Explore architecture/inventory | Supplied records only; real report 1,547 architecture / 472 inventory records | Task-based acceptance, scale/layout and full evidence semantics |
| Compare runs | Core coverage-aware comparison plus CLI/PR parity; native baseline/current action smoke matches seeded counts | Manual baseline picker, partial-coverage native journey, source-change/legacy cases |
| Manage reasoned suppression | Native preview/apply/undo action smoke; stable identity and explicit migration | Manual reason/reversal journey, rescan round trip and dialogs |
| Export selected run | Release native export smoke; exact selected JSON/Markdown bytes verified | Manual save dialogs, concurrent-run journey, legacy/error cases |
| Configure optional provider | Native settings/action integration; smoke restores AI disabled; protected-store/privacy tests | Explicit opt-in/save/restore/test journey and credential failure cases; no automatic requests |

## Early bounded evidence (historical)

- `desktop/windows/verification/native-engine-2026-10-15.json` records the live
  engine scan; settings, run-context, advanced-options and structure records
  separately establish their scoped integration. Export proof is
  `native-export-2026-10-15.json` (60 focused checks, exact bytes; manual picker
  interaction explicitly not certified).
- `.pytest_cache/m3-native-workflows/actions/native-actions-smoke.json` passes:
  comparison new=1, persisted=2, resolved=1, newly_suppressed=1,
  resolution_uncertain=0; suppression change undone; provider disabled.
  `manualDialogAcceptance=false`. Release publish log:
  `.pytest_cache/m3-ten-workflows-build.log`. Python action-focused log:
  `.pytest_cache/m3-actions-focused.log`, **99 passed in 3.82s**.
- `native-action-runner-qa-2026-10-15.json`: eight actual runner cases with a
  controlled **childless fake broker** pass identity/hash rejection, exclusive
  admission, transient credential handling, EOF cleanup and cleanup-timeout
  admission blocking. `native-engine-session-qa-2026-10-15.json`: seven controlled
  session cases pass schema 1.0/1.1 policy-failed completion, revision/terminal
  filtering, exclusive admission, cancellation/disconnect/exit races and failed
  cleanup blocking. These are not full native process-tree or manual UI proof.
- `.pytest_cache/m3-native-accessibility.json`: five loaded-view audits, zero
  scoped issues. Scope is exposed peer names/roles, enabled focusability and
  primary scan/cancel sizes; dialogs, virtualized rows, task focus order,
  Narrator, contrast and scaling remain unverified. Earlier verification-folder
  accessibility records describe source checks and pending hooks; this newer
  runtime record supersedes only that hook status, not manual acceptance.
- Finding context tests: **38 passed in 1.14s** across presentation, report,
  identity and review JSON. Saved Juice Shop yields 18 contexts, 48 exact-location
  candidate references and four detector-owned static flows; proof:
  `.pytest_cache/m3-finding-presentation-proof/juice-shop-contexts.json`.
  Candidate co-location does not establish support. Finding-to-control and
  attack-path IDs and score point contributions are not supplied; runtime and
  trust-boundary crossing remain unknown. See [context contract](finding-presentation.md).
- Last recorded complete Python baseline is **2,924 passed, 6 skipped in
  499.42s**, `.pytest_cache/m3-frozen-full.log`, before subsequent workflow,
  coverage, comparison and presentation changes. It is **not a current full
  regression pass**. Later focused passes establish only their named scope.

## Other gates and prerequisites

| Gate | Current proof | Still open |
| --- | --- | --- |
| C22 scan experience | Typed lifecycle, atomic generations, real scans, scoped session/action protocol QA | Complete client fault matrix, diagnostics reveal and native-control race journeys |
| C23 evidence experience | Stable IDs, accepted-file coverage, coverage-aware comparison, reversible suppression/export slices and precomputed context | End-to-end golden/source-change/legacy journeys; detector-owned control/trust evidence remains incomplete |
| C24 accessibility | Five bounded loaded-view audits with zero scoped issues | All ten keyboard/Narrator workflows, platform audit, contrast/focus/200% text, scaling/high contrast and dialogs |
| C25 visual quality | Native surfaces and Release build | Nine-view/theme/size captures, Windows scaling, exceptional states and live appearance switching |
| C26 performance | Historical fixture, harness and measurements retained as optional diagnostics | Removed from Windows M3 acceptance by user decision on 2026-10-15; no qualifying Windows 11 host required |

Reference fixture SHA-256:
`612d12c9b56bfa98ccb7061e81b67120bc738759e9731737ab1fe9d1ada658ba`.
[Fixture contract](desktop-reference-fixture.md) and
`native-performance-probe-2026-10-15.json` document the corpus and harness.
Windows performance measurements are optional diagnostics and do not gate M3.
Removing the criterion does not turn historical measurements into a performance pass.

M0/M1/M2 remain prerequisites: current complete regression and packaged/frozen
proof, remaining evidence ownership/citation support, complete cross-platform
supervision/contracts, C19 participant outcomes, supported-host/package evidence
and C20 technology/migration decision must not disappear behind functional M3
progress. Shared Windows supervisor 50-cycle proof does not certify macOS.

## Shortest remaining acceptance sequence

1. Freeze current integration; run current full Python regression and rebuilt
   native protocol/action/context/legacy/partial-coverage checks. Preserve logs
   tied to exact source/build identities; investigate failures without narrowing gates.
2. Record all ten Windows workflows end to end, including cancellation/faults,
   source changes, reasoned suppression/rescan/undo, selected-run export and
   explicit provider opt-in/restore. Include manual picker/dialog interactions.
3. On the available Windows host, complete C24 keyboard, Narrator,
   contrast/scaling/high-contrast checks; capture C25 views and states.
   No Windows C26 performance campaign or Windows 11 performance host is required.
4. Complete outstanding M0/M1 credibility/ownership and packaged proofs plus
   M2 study/technology decision evidence. Keep unsupported platform targets
   explicitly unaccepted; the roadmap's two-platform gates remain unchanged.

## Newer scoped checkpoint — 2026-10-15

This checkpoint supersedes only the earlier five-view accessibility count,
seven-session-case count and absence of diagnostic performance results above.
It does not supersede the open acceptance gates.

- ReportAdapter: 66 isolated checks. EngineSession: eight controlled fake-broker
  cases, including absent optional stage on policy-failed completion; evidence
  `desktop/windows/verification/native-engine-session-qa-2026-10-15.json`.
- SourceLocation: 17 isolated checks with an actual symlink, Unicode long paths,
  containment/bounded reads and whole-file hash comparisons. Actual native legacy
  report smoke loads 18 findings, shows defensive review and two valid source
  locations with unknown scan hashes and live-file-may-differ warnings. Proof:
  `desktop/windows/verification/native-review-source-runtime-2026-10-15.json`.
  Legacy identity/integrity remain unverified; no new scan is claimed.
- Actual provider runner/backend round trip: six checks pass against explicit
  local LM Studio model listing, with safe settings restore/save and AI remaining
  off. No generation, repository payload, DPAPI credential-storage or manual UI
  acceptance is claimed. Proof:
  `desktop/windows/verification/native-provider-roundtrip-2026-10-15.json`.
- Seven loaded-view audits inspect 29/29/20/20/14/21/28 controls, all with zero
  scoped issues (`.pytest_cache/m3-seven-view-accessibility.json`). Collapsed
  configuration, dialogs, virtualized rows and manual assistive/contrast/scaling
  acceptance remain unverified.
- Windows 10 single-launch quick performance diagnostic: Loaded marker 1761.13 ms,
  report 1382.82 ms, filter 15.39 ms, detail 0.98 ms; working set 323,104,768 bytes,
  private bytes 314,707,968; only one open/close cycle. Raw summary:
  `.pytest_cache/native-performance-qa-0afaf6daeef443958b58d31d44aa8568/summary.json`.
  These are insufficient-sample diagnostic values, not qualifying p95 or leak
  acceptance. Hardware qualification/counts fail; Loaded is not action readiness.
- Current full regression `.pytest_cache/m3-current-full.log` and package work
  are ongoing. Neither is recorded as passed. No complete M3 gate closes here.

## Regression correction and placement/viewport checkpoint — 2026-10-15

The earlier running `.pytest_cache/m3-current-full.log` is now **aborted**, not
passed and not a natural test failure. Exact pytest PID 58200 retained obsolete
imported citation regexes. Stack diagnosis identified quadratic hostile-input
matching; `m3-current-full-aborted.json` records the deliberate abort and reason.
The focused fix passes 68 citation tests and all 574 regex-budget tests in 36.08s.
Replacement full regression PID 59825 writes `.pytest_cache/m3-fixed-full.log`;
it is running with no result accepted at this checkpoint.

WindowPlacement has 33 pure persistence checks. Actual two-process save/restore
preserves 1100x720 geometry and reports `insideWorkArea=true`; evidence:
`.pytest_cache/placement-runtime-2a8659e83a9d4c13ae267326e8a58961/`.
Restore clamps to the startup monitor only. DPI changes, attached-monitor
selection and manual window-restoration acceptance remain unverified.

Actual viewport smokes at 1024x700 and 1600x1000 load 18 findings and show the
review. Finding content heights are respectively 332 and 632 logical units;
inspectors are stacked at the smaller viewport and split at the larger. Proof:
`desktop/windows/verification/native-viewport-1024-2026-10-15.json` and
`native-viewport-1600-2026-10-15.json`. This establishes measured layout state,
not complete visual, text-scaling or task acceptance.

An earlier unsigned development ZIP was actually installed, launched, report-smoke
tested and uninstalled in an isolated workspace target:
`desktop/windows/verification/native-development-package-2026-10-15.json`.
Its versioned payload predates the current snapshot; no clean host, bundled
engine or interactive installation acceptance is claimed. A fresh frozen-engine
build from an isolated snapshot containing the citation fix is running; no new
artifact or successful packaged execution exists at this checkpoint.

## Integrated scope and full-count diagnostic checkpoint — 2026-10-15

- Replacement baseline `.pytest_cache/m3-fixed-full.log` completed **3,127 passed,
  6 skipped in 592.27s**. It predates the newer C03 Markdown/JSON ownership,
  source-classification, C14 whole-run allowance and redirected-stdio entry
  integration; it is not current-snapshot full regression proof. Later scoped
  runs: 192 passed in 2.61s (provenance/reports), 150 passed in 42.46s (AI pipeline/
  fleet), four entry-point checks. Current PID 48828 writes
  `.pytest_cache/m3-final-integrated-full.log`; it remains running with no green
  result claimed at this checkpoint.
- Prior verified bundled development ZIP `dev-20261015124518-6a81a884` is
  119,753,126 bytes, SHA-256
  `914a8fe1e027917abfb635fdddac625b92934aa6cc58417cb17696d0cbf940fd`.
  Proof: `desktop/windows/verification/native-bundled-engine-package-2026-10-15.json`.
  Frozen production C# runner proof additionally establishes Juice Shop parity:
  18 findings, exact normalized IDs/severity/confidence/score equality with the
  same frozen CLI, verified manifest/report hash and process cleanup. Evidence:
  `native-frozen-runners-juice-current.json`. This is a prior verified revision,
  not certification of subsequent Python/entry edits. Final frozen build is
  ongoing; no fresh final artifact is available yet.
- Windows 10 full-count diagnostic completed 30 fresh launches, 30 report loads,
  100 interaction samples after warmups and 100 open/close cycles. Reported p95:
  Loaded marker 1.276s, report 0.950s, filter 27.916ms, detail 15.761ms. Loaded
  working set is 381,935,616 bytes (364.24 MiB). Retained working-set growth is
  52,723,712 bytes (**50.28 MiB, fails the 50 MiB target**). Evidence:
  `desktop/windows/verification/native-performance-full-2026-10-15.json` and raw
  campaign `.pytest_cache/native-performance-full-3c874d53547b4d86bde3de1024dc6a4d`.
  Counts are complete, but Windows 10/hardware qualification and primary-action
  readiness are not C26 acceptance. The failure remains visible despite other
  threshold comparisons passing.
- A bounded-read optimization passes 68 scoped checks; the subsequent performance
  reprobe is ongoing with no accepted result. Do not replace the measured failure
  with an optimization claim. Windows 11 host availability remains an optional
  unanswered planning question, not evidence or an acceptance waiver.

Current next proof: finish integrated regression and final frozen execution;
inspect the bounded-read reprobe; then run qualifying Windows 11 performance and
manual workflow/accessibility/visual gates. Original prerequisites stay open.

## Current integration checkpoint — 2026-10-15

This checkpoint supersedes the running-build and running-regression statements
above; historical failures and their evidence remain preserved.

- Current production Python regression: **3,174 passed, 6 skipped in 735.40s**
  (`.pytest_cache/m3-final-integrated-full.log`). Skips cover unavailable optional
  PHP analyzer in the main environment, opt-in authenticated Claude CLI, and
  Windows permission/symlink cases. They do not constitute passing coverage.
- Fresh final frozen engine built successfully from the current production
  snapshot. Proofs: `.pytest_cache/m3-frozen-final/final-build-proof.json`,
  `frozen-command-proof.json`, and `frozen-csharp-runner-proof.json`.
  Redirected UTF-8 help, version, 19 modules and eight C# runner checks pass.
- Bundled package `dev-20261015132727-c6df7c2a.zip` was installed in an isolated
  workspace target and completed an actual native-to-frozen-engine Juice Shop
  scan: 18 findings, zero scan errors, validated artifact hashes. Evidence:
  `desktop/windows/verification/native-installed-engine-composition-2026-10-15.json`.
  A subsequent native-only package revision adds core Overview projection and
  an isolated startup proof; its result is pending at this checkpoint.
- The bounded report-read optimization reprobe records loaded working set
  313.09 MiB and retained growth 30.625 MiB after 100 cycles, versus the prior
  measured 50.28 MiB failure. Report/filter/detail p95: 806.83/23.43/12.25 ms.
  Evidence: `native-performance-bounded-buffer-2026-10-15.json`. It used one
  launch and Windows 10 with concurrent Python regression; it cannot accept
  C26 or establish controlled causality. Qualifying Windows 11 remains open.
- Two fake-analyzer unit tests now use a one-file temporary repository instead
  of indexing the entire dirty checkout. Their assertions are unchanged.
  The isolated plugin environment passes all 54 focused cases in 1.71s versus
  the prior 245.41s. Production code and final frozen snapshot are unchanged.
- Reports expose manifest-listed raw artifacts and export the selected validated
  generation. Overview projects supplied strengths, actions and limitations;
  its pure adapter has 18 checks and the integrated report adapter has 68.

Remaining work is tracked by proof rather than calendar guesses: complete the
latest package startup/report checks; close native fault workflow gaps; capture
and review the Windows visual matrix; verify keyboard/Narrator/contrast/scaling;
run qualified Windows 11 performance; and preserve unmet M0–M2 prerequisites,
including participant validation. Signing and four-week beta exit belong to M4
and are not additional Windows M3 implementation tasks. No M3 completion claimed.

### Native fault correction and capture review — 2026-10-15

The standalone process fault suite found that a valid completed envelope followed
by broker exit 7 was accepted by both native runners. Historical evidence remains
in `native-fault-composition-current.json` (12 passing cases, two detected gaps).
Both runners now require exit zero before delivering the result. EngineSession
also defers completed status and import callback until verified process exit.
The correction passes 8 session, 8 action-runner and 14 fault-composition checks;
see `native-fault-composition-exitguard-current.json` and the companion runner
proofs. These establish process/host behaviour, not a complete MainWindow fault
journey. Final native republish/package verification is pending.

An app-owned RenderTargetBitmap capture hook generated 28 images (seven main
views, two themes, two sizes) with verified hashes. Evidence:
`native-capture-review-2026-10-15.json`. A second campaign waits for two rendering
frames. Spot review found excessively long source summaries consuming finding
list rows; previews are now limited to two title and three summary lines, with
full evidence retained in detail. Recapture is pending. Sampled navigation pixels
are fully transparent (alpha zero), explaining why the image viewer's black
background cannot establish a live-window theme defect. Native composition,
window chrome, all nine C18 views and exceptional states still need verification.
The user confirmed that a qualifying Windows 11 host is currently unavailable;
C26 and remaining Windows 11 gates are explicitly open.

### Initial view, evidence composition and protected store — 2026-10-15

- Actual loaded MainWindow abnormal-exit composition passes ten checks: no
  completed callback, preserved report/hash/rows/export/identity, previous-result
  label, selected diagnostic folder and enabled retry/reveal controls. Evidence:
  `native-mainwindow-exitguard-runtime-2026-10-15.json`. Programmatic composition
  does not verify manual retry/Explorer or the complete C22 fault matrix.
- Independent C23 report composition passes 17 checks for conflicting supplied
  evidence, partial/unsupported-language coverage, missing locations, Unicode
  source uncertainty and exact selected-run export after a newer current pointer.
  Evidence: `native-c23-report-composition-current.json`.
- Actual Windows DPAPI save and production-loader roundtrip pass 14 isolated
  checks using a synthetic credential; JSON excludes it and its owned protected
  blob is removed afterward. No personal store access or network requests.
  Evidence: `native-protected-provider-current.json`. Native panel/manual
  credential workflows remain separate.
- First-launch capture exposed simultaneous Overview and Findings panels with
  overlapping content. Explicit initial Overview selection and collapsed Findings
  default correct the defect. Four corrected startup captures report
  `initialViewPassed=true`; a reviewed 1024x700 image has no content overlap.
  Evidence: `native-initial-navigation-review-2026-10-15.json`.
- Overview now puts supplied next actions ahead of verbose counters/strengths,
  retaining their order, labels and all details (24 pure checks; 68 integrated
  adapter checks). Structure limitations are explicitly expandable; the visible
  summary shows supplied record counts. Actual recaptures establish these
  narrow layout improvements, not full visual acceptance.
- A new Windows content matrix contains 36 PNGs: four start-workspace states and
  32 loaded-report states. Finding detail is the production master/detail view
  focused/scrolled toward its recommendation, not an invented extra destination.
  Full review remains pending. Composition transparency, OS chrome, exceptional
  states, Windows 11 and display/text scaling remain outside this evidence.

The reviewed C22-corrected development ZIP `dev-20261015134618-c6a071da` passed
isolated installed startup/report/engine checks (SHA-256
`713242f76892498178ecca6aa03565d3c92ec605f82dc3f64ba5f85ba413f9f8`).
It predates the initial-view and action-order corrections above; a later revision
must contain them. Evidence: `native-exitguard-package-2026-10-15.json`.
A portable future host procedure is in `windows-11-beta-validation.md`.
Qualifying Windows 11 is currently unavailable. Python 3.11/3.12 exist locally;
additional isolated matrix runs are being prepared, with no outcome claimed yet.

Performance retained-memory diagnostics above use the probe's explicit forced-GC
baseline/final normalization. This limitation is present in raw results; those
numbers do not establish unnormalized daily-use retention or C26 acceptance.

### Expanded controls and provider scroll checks — 2026-10-15

Expanded actual-report audits cover seven destinations and 188 interactive control
observations, including repeated common controls, with zero scoped issues.
The QA helper does not repair names before inspection. Exact scope remains names,
roles, focusability and primary sizes in the realized tree; this is not a general
critical/serious accessibility classification, keyboard completion or Narrator.
Evidence: `native-expanded-accessibility-2026-10-15.json`.

A separate actual Settings inner/outer scroll journey at 1024x700 and 1600x1000
moves Save/Test from zero visible area to fully visible, enabled buttons. Bounds
are intersected with realized ancestor scroll viewports; Visibility alone is not
used as proof. No button action/provider request is invoked. Evidence:
`native-provider-scroll-2026-10-15.json`. Manual keyboard traversal remains open.

All 36 content captures are now independently reviewed and their hashes checked:
`native-nine-view-visual-review-2026-10-15.json` and
`native-nine-view-capture-integrity-2026-10-15.json`. Known capture fidelity,
small structure allocation, pane transition and OS/manual limitations remain
explicit; no C25 acceptance is claimed. Current criterion-by-criterion remaining
work is recorded in `windows-m3-gate-status.json`.

### Python matrix findings and coordinated corrections — 2026-10-15

Both first full Windows matrix runs completed with **3,170 passed, 6 failed,
4 skipped**: Python 3.11.9 in 503.59s and 3.12.10 in 565.95s. They are preserved
as negative evidence in `native-core-python-matrix-current.json`. The failures
revealed a genuine default run-ID collision on coarse clocks and five tests
whose fixtures assumed absent plugins or a unique legacy file-count aggregate.

The run-ID generator now retains its readable UTC prefix and uses a full UUID4
suffix. A fixed-clock 1,000-ID test plus publication/schema checks pass 65 cases
on each interpreter. Missing-plugin test states are now explicitly controlled;
the root-output unit fixture uses the enumerating built-in analyzer and checks
its exact accepted file and repository index. All 85 scoped tests pass on each
interpreter with the pinned plugins installed.

A separate actual frozen-fleet matrix verifies all/json/markdown in serial and
two-worker modes, normalized findings/coverage and parent/child hashes. Its old
malformed-lock fixture establishes fault containment, not desirable recovery.
New npm root/nested mapping validation rejects malformed graphs through the
existing per-lockfile ValueError path, retaining range manifests and valid sibling
locks. Sixty-one scoped lockfile/SBOM cases pass per interpreter. Existing invalid
lockfiles are still skipped without dedicated semantic coverage diagnostics;
that limitation is not relabeled as complete dependency coverage.

The focused proof records raw-log and import-path limitations, including an
initial old-installed-wheel invocation corrected before the authoritative npm
checks: `native-post-matrix-focused-fixes-2026-10-15.json`. The earlier 3,174-pass
baseline predates these production corrections. Refreshed full 3.11/3.12 runs are
active; a separate full 3.13 environment is being provisioned after the shared
build environment exposed missing test-only jsonschema (three collection errors,
no tests accepted). The shared build environment was not modified. A fresh
immutable frozen build includes both production fixes; no new outcome or current
package is claimed before verification.

The prior corrected native package also completed a new actual Juice Shop scan:
18 findings, zero supplied analyzer errors, 19 listed artifact hashes verified.
Evidence: `native-final-candidate-juice-scan-2026-10-15.json`. Its 899 reported files
are a legacy aggregate; no unchanged-input parity with the earlier 862 aggregate
is inferred. Its engine predates the new UUID/npm corrections and remains a
historical executable proof, not the final current-engine candidate.

### Post-matrix candidate checkpoint — 2026-10-15

The corrected full Windows suites now pass on all three supported interpreters:
Python 3.11.9: **3,195 passed, 4 skipped, 490.05s**; Python 3.12.10:
**3,195 passed, 4 skipped, 548.68s**; Python 3.13.15:
**3,195 passed, 4 skipped, 503.60s**. Each run verifies live-source imports,
15 pinned official plugins and unchanged source/test inventories. The four
skips have explicit authenticated-CLI, POSIX permission or Windows symlink
privilege reasons. This is a dirty-worktree Windows matrix, not the complete
three-OS release matrix. Earlier failed runs remain in the evidence.

Development package `dev-20261015144954-78c3f581` contains frozen engine SHA256
`ebafb3277271d6a87703e07e0c4b4b5d21d3d296a0f200990223a439be280013`
and native DLL SHA256
`ec298f52fefe3bd5a6aabc623c20ab35d799bb80b83ab3dd257e2ef809a7d68e`.
Fresh installed startup and report checks pass. One actual installed native plus
engine Juice Shop scan exited zero and loaded 18 findings, with no supplied
analyzer errors; the current-generation manifest hash and all 19 section/export
sizes and hashes were checked. Evidence:
`native-post-matrix-package-2026-10-15.json` and
`native-post-matrix-installed-juice-2026-10-15.json`. The reported 899 files remain
a potentially overlapping legacy aggregate. AI and CVE enrichment were off.
The user-open preview runs from the separate extracted development package and
must not be stopped by isolated installer cleanup.

The same frozen engine passes six serial/parallel all/json/markdown fleet cases
and a guarded, own-worker termination scenario: an explicit failed child,
preserved successful sibling, and no publication of a partial parent generation.
See `native-frozen-fleet-post-matrix-formats-2026-10-15.json` and
`native-frozen-fleet-worker-death-post-matrix-utf8-2026-10-15.json`.

Thirty fresh native launches also responded to the actual primary Scan control
with the expected missing-repository message (p95 1,575.7296ms). All observed
windows were visible and no scan started. This narrowly measures an app-owned
response on Windows 10; it does not qualify C26 or exercise the OS repository
picker. See `native-primary-readiness-2026-10-15.json`.

Linux Python 3.12 verification is being diagnosed separately; no Linux pass is
claimed here. Legacy output-copy review also identified wording requiring a
static-score/model-assessment qualifier; subsequent source changes must not be
represented as already present in this immutable package. Windows 11 hardware,
manual accessibility/appearance, participant studies and outstanding M0/M1/M2
requirements remain open. M3 is not accepted.

### Linux diagnostic and output wording follow-up — 2026-10-15

The first isolated non-root Ubuntu 24.04 / Python 3.12.3 run completed with
**3,188 passed, 6 failed, 5 skipped in 79.94s**. It used a copied dirty-source
subset and all 15 pinned plugins. Three failures were traced to omitted
`examples/` inputs in that subset, and two to Windows-only process test doubles
without a POSIX PID. The sixth unreadable-file summary failure remains under
diagnosis. The original output is preserved under
`.pytest_cache/m3-wsl-linux-qa/attempt-bc455506600d46638e7e867dfd831ede/`;
this run does not establish Linux release acceptance.

Legacy web, Markdown/console and CLI help now explicitly qualify heuristic
static risk and model assessments. Sixty focused Python tests and eight actual
JavaScript rendering assertions pass. Scoring, ordering and tiers are unchanged.
See `output-classification-copy-fix-2026-10-15.json`. These source wording updates
postdate the immutable preview package; that package is not claimed to contain
them. No exhaustive generated-model prose audit or C03/C07 completion is inferred.

The acceptance JSON was corrected from accidental locale encoding to strict
UTF-8 and parses successfully; all 47 current evidence-catalog paths exist.
That structural check does not prove the contents satisfy the 26 criteria.

The corrected Linux subset includes the omitted examples, and the two process
test doubles intercept POSIX signalling with synthetic identities while retaining
the unverified-cleanup admission invariant. A focused Linux run now reports
120 passed, one Windows-only skip and two failures in 10.52s: the outstanding
unreadable-summary expectation and an empty-state expectation made stale by the
later wording correction. All five originally assigned corrections pass.
See `native-core-wsl-linux-current.json`; this remains diagnostic evidence,
not a full green Linux matrix. The two corrected cancellation doubles also pass
on Windows (two tests, 0.77s) with an explicit isolated temporary directory;
the initial sandbox TEMP permission failure occurred before test execution.
See `native-posix-process-fakes-windows-check-2026-10-15.json`.

### Native commands checkpoint — 2026-10-15

The later native QA build adds File, Scan and View menus with eight commands
calling existing handlers. Actual loaded-app checks pass command metadata and
safe Settings/History navigation, missing-repository Scan and disabled Cancel
guards. The build and QA process both exited zero; DLL SHA256
`a279e1dae7453392a990f3911c3b0001e98872fb8b2fb37139a405d583661696`.
See `native-command-menus-runtime-2026-10-15.json`.

Folder launch returning false now reaches the existing failure message;
clipboard and picker failures are handled with actionable messages while
preserving the selected source warning or previous workspace/report. These
changes have compile and bounded handler evidence, not a manual OS dialog,
Explorer, clipboard or popup keyboard pass. They postdate the user's immutable
preview package and do not close C21 or C24.

### Green Linux snapshot — 2026-10-15

The corrected full non-root Ubuntu 24.04 WSL2 / Python 3.12.3 run completed:
**3,195 passed, 5 skipped in 98.84s, exit zero**. Its 570 copied inputs include
the example fixtures, and all 434 source/test hashes are unchanged before/after.
Raw output, JUnit, setup, plugin pins and inventories are preserved in
`.pytest_cache/m3-wsl-linux-qa/attempt-c80c1bf54ef9470bb848c6c1c5fe7295/`
and bound by `native-core-wsl-linux-current.json`.

The skips are Windows Job Object lifecycle, authenticated Claude CLI opt-in,
Windows-specific O_NOFOLLOW export, Windows DPAPI and Windows job containment.
The initial full and focused negative results remain preserved. This is one
Python version on a copied dirty-source WSL snapshot, not clean-Git release
verification or the missing Linux 3.11/3.13 and macOS matrix. Subsequent engine
scan-timing changes are outside this snapshot and require their own checks.

### Engine timing integration checkpoint — 2026-10-15

The additive engine `scan_timing` contract records real UTC start/end and
analysis outcome before publication; its scope and diagnostic limitations are
documented in `atomic-artifacts.md`. Focused Python sets pass 92, 59 and 12
checks respectively (overlapping sets, not 163 distinct tests). The later
native reader checks schema, clock, scope, UTC interval ordering and selected
artifact integrity; it never inherits timing for an unverified legacy import.

The first native timing test exposed an uncaught `InvalidDataException` for a
tampered artifact. Its failed process required identity-verified owned-process
cleanup and is not recorded as a natural successful exit. The corrected test
run passes 29 checks, including unavailable fallback and duplicate-field
rejection. Native compile/report integration and the new frozen engine are
being verified separately. No earlier full matrix or immutable package is
claimed to cover these later changes.

The durable engine timing proof subsequently records an authoritative combined
focused run of **99 passed in 51.09s**, with a live-source import guard and raw
log/exit/source hashes: `engine-scan-timing-focused-2026-10-15.json`. A preserved
tiny canonical generation verifies all listed hashes and real engine UTC timing
from `2026-10-15T15:19:47.365214+00:00` to
`2026-10-15T15:19:47.415712+00:00`, outcome completed. This strengthens the
bounded timing evidence; it is not a new full supported-matrix result.

A separate C15 audit found requested-analyzer configuration failures can occur
after writable output setup but before pipeline diagnostics. The scoped service
repair is in progress. It must preserve the existing error/exit behavior, avoid
secret-bearing exception text and leave the previous current generation intact.
The first new frozen timing candidate predates this subsequent service repair;
neither source freshness nor package promotion is inferred.

The immutable timing freeze subsequently completed with build exit zero and
eight passing actual C# EngineSession/DesktopActionRunner checks. All 123 bound
inputs stayed unchanged, and all 103 core module origins point into its copied
snapshot. The live service diagnostic change is explicitly excluded. Proofs:
`.pytest_cache/m3-frozen-timing-0a7d1e482b6c461cae713f1c5a70996a/`.

A later loaded menu-state check contradicted the initial metadata-only result:
initial, toggled and restored Scan/Cancel enabled-state bindings all failed.
The original result (`native-menu-bindings-df008ab938024b568ec8e055a4556fca.json`)
is preserved under `.pytest_cache`; its process exited zero but its `passed`
field is false. Process exit alone is therefore insufficient. The two bindings
are being corrected and independently rerun before any new package promotion.
This leaves native popup/keyboard/manual accessibility acceptance open.

The corrected x:Bind command states now pass initial, toggled and restored
loaded-app checks. The same later native build passes legacy report import
with explicit unavailable engine timing. Evidence:
`native-scan-timing-and-menu-bindings-2026-10-15.json`.

A separate real native/engine tiny-repository scan then exited zero, loaded two
findings and verified all 19 published artifacts. Displayed engine start/end
match its selected canonical run manifest, separately from client request time,
with explicit before-publication wording. Evidence:
`native-positive-scan-timing-2026-10-15.json`. This closes the bounded positive
timing integration check, not the full C22 journey or package freshness gate.

### Sealed source regression and startup diagnostics — 2026-10-15

The service repair and both ordinary/fleet CLI module preflight paths now emit
generic redacted startup diagnostics when atomic output is safe and writable.
Interactive installation prompts, existing errors and exit codes are preserved;
failed diagnostic storage does not replace the original configuration error.
Direct-generation mode does not gain diagnostic writes. Prior current reports
and secret-sentinel exclusion are covered. The final focused suite reports
57 passed and one expected skip. Evidence:
`requested-analyzer-startup-diagnostic-2026-10-15.json` and
`cli-all-analyzer-startup-diagnostic-2026-10-15.json`. The earlier ordinary-only
CLI proof has narrower scope and is retained.

All production sources are now sealed for a new immutable engine build and
complete Windows Python 3.11/3.12/3.13 source regressions. The original live
sessions are 94361, 76696 and 17406 respectively; outputs and pre/post source
inventories belong to the fresh paths in
`.pytest_cache/m3-final-source-matrix-sessions.json`. These runs are pending,
not new green evidence. Earlier packages and full matrices do not contain the
latest timing and startup-diagnostic changes.

### Final source engine and capture refresh — 2026-10-15

The sealed-source frozen engine completed with exit zero, 123 unchanged bound
inputs, 103 snapshot-only core module origins and no live-source differences.
Executable SHA256:
`b5f839a26d3f2f0bb93a77a555e75fb0b48583b89b30e85688a746f2ee43a7dd`.
Bounded command and eight C# runner checks pass, including actual ordered UTC
scan timing. Proof root:
`.pytest_cache/m3-frozen-final-source-a7cc235cfa7e41c6a465f8ed9b0e3c58/`.
Complete Windows source regressions remain pending; new candidate packaging is
separate from M3 acceptance.

All 36 refreshed native content captures were reviewed and hash-checked against
native DLL `a7201cb2ecddd9eaeabd3481566e7237ce2c4298883c383a5a38fe2f92f5dce9`.
See `native-final-content-review-2026-10-15.json` and the independent two-image
root spot review. Unresolved navigation transparency and pale/absent list rows
prevent live readability/contrast conclusions. The timing Expander is collapsed,
menu popups are absent, and these images omit OS chrome and display scaling.
No C25 acceptance is inferred from capture completion or absence of a confirmed
new main-content overlap.

### Real frozen ordinary cancellation campaign — 2026-10-15

All 50 samples completed with verified held identities and terminal cleanup;
the original campaign exited zero. API Cancel return p95 is 0.4367ms; observed
owned-process exit p95 is 3,334.4069ms and maximum 3,429.7857ms. Each observed
set contains two `attackmap.exe` and two `conhost.exe` processes. Twenty
synchronized admission requests yield one start, 19 rejections and one request.
See `native-frozen-cancellation-50-2026-10-15.json` for identities, hashes,
limits and the preserved failed/unsampled initial calibration.

This measures ordinary backend cancellation on the preceding timing engine,
not actual UI acknowledgement, an intentionally stubborn descendant, macOS or
the final candidate executable. Later changes are confined to CLI/service
startup diagnostics; unchanged cancellation source is useful review evidence,
not a substitute for execution of a different packaged binary.

The final-source Python 3.12 full run has two failure markers while still
active. Its terminal tracebacks and the other two full results are pending;
new candidate packaging and isolated checks do not override that evidence.

### Final source matrix terminal checkpoints — 2026-10-15

Python 3.11 completed with **3,214 passed, 4 skipped in 654.08s**, exit zero.
Python 3.13 completed with **3,213 passed, 1 failed, 4 skipped in 645.05s**,
exit one. Both source/test inventories remained unchanged and JUnit was
inspected. Evidence: `final-source-windows-matrix-2026-10-15.json`.

The 3.13 failure is an empty PID-file read in `test_fifty_cancel_cycles` after
waiting only for file existence, before the controlled worker finished writing.
Its process cleanup and fixture synchronization are under investigation. No
production failure is inferred from that traceback alone, and the failed run
is not treated as green. Python 3.12 remains active; diagnostic collection-order
mapping suggests three scan-limit timing cases, but terminal tracebacks are
required before diagnosing their cause. Source edits are held until that live
run finishes, preserving its inventory validity.

### Candidate installation and corrective checks — 2026-10-15

Unsigned candidate `dev-20261015153700-2ef7b386` binds native a720 and final
engine b5f8. Installed startup/default network-off, report import (18 findings),
tiny timed scan (two findings, all 19 artifacts), actual two-version rollback,
rollforward and scoped uninstall pass. The existing AppData file hash is
unchanged; the user-open preview remains untouched. Evidence:
`native-final-source-candidate-package-2026-10-15.json`. Its validation-pending
status is not upgraded by successful installer checks.

The three original 3.12 failures exceeded unchanged 5/5/25-second limits at
5.0207/5.1535/26.4768 seconds. Their isolated rerun passes all three in 23.59s
total (calls 1.69/2.40/19.23s). This supports load sensitivity but does not prove
its sole cause or algorithmic linearity. A new full 3.12 run (58170) is active
with reduced competing test campaigns. The test-only PID publication repair
retains all 50 cancellation cycles and original acknowledgement/exit bounds;
its focused 3.13 verification is pending.

Final-source Linux 3.12 completed with 3,213 passed and five explicit skips in
146.53s; copied source/test hashes stayed unchanged and all 117 non-metadata
frozen inputs match. See `final-source-linux312-full-2026-10-15.json`.

A read-only workflow audit demonstrated a separate native history defect:
changing the comparison baseline updates its label while retaining old rows,
detail and notes. The scoped presentation invalidation repair is in progress;
the immutable a720 candidate predates it. This is an actual code gap, separate
from the remaining manual, platform and participant acceptance evidence.

The baseline presentation repair subsequently compiled and passed actual loaded
History control checks: changing A to B clears rows/detail/notes, discloses the
change, preserves busy state, rejects a late A result and accepts a fresh B
result. Same-baseline selection retains valid content. See
`native-history-baseline-freshness-2026-10-15.json`; native DLL SHA256 is
`6c10d330a6d2f3f4f59a6a96b48e6d792e9d7fa49116d83b16c6c5577376ae00`.
The test uses fixture comparison envelopes in the actual control, not a core
comparison action, OS picker or manual keyboard journey. The corrected package
is still pending and the previous a720 archive remains immutable.

The repaired 3.13 PID fixture also passed all 50 cycles with the original
bounds: acknowledgement p95 5.83ms, tree-exit p95 3,083.691ms, maximum
3,121.350ms. `native-core-targeted-post-full-2026-10-15.json` binds the
test-only atomic PID publication/finally cleanup repair and preserved negatives.
The subsequent full 3.13 wrapper is prepared but not started while full 3.12
session 58170 remains live. Targeted success does not replace that full rerun.


