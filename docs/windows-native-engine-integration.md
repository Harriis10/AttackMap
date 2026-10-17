# Windows native engine integration preview

The native WinUI slice now separates two inputs: a synthetic 10,000 finding UI
fixture and a canonical saved AttackMap report. ReportAdapter accepts only the
recognized schema-less report shape with scan.root and findings. Explicit
schema_version envelopes are rejected as report documents. Imported identity is
local; policy and artifact integrity are unverified, matching the core legacy
adapter semantics. The view preserves engine order, severity, confidence, score,
locations, evidence, code flows and mitigation. It does not calculate scores.
Missing classification and controls remain unknown, never runtime verified.
Report import is bounded to 64 MiB and JSON depth 64; failed imports retain the
previous valid report.

Scan starts an absolute source Python executable or a supported frozen engine,
using EngineLaunchSpec and the typed desktop-worker request. Schema 1.1 carries
run/repository/generation identity, revision zero, selected repository, unique
output and validated options/modules. Defaults request neither AI nor CVE; optional
network features require explicit configuration and visible disclosure.
The Python broker owns core supervision; the native process never kills a worker
or descendants directly. Cancel sends `cancel` on stdin, and disconnect closes
stdin. The UI waits for terminal confirmation. Outputs live in LocalAppData,
outside the repository.

EngineSession accepts bounded NDJSON lines (64 KiB), checks supported schema and
exact identity, ignores duplicate/reordered revisions and prevents messages after
terminal from changing results. Local generation guards reject callbacks after
repository selection or report import. A ready completed terminal can identify
its canonical artifact through additive `artifact_path`; policy outcome remains
separate from successful execution. Progress uses stage text, with no invented
percentage or ETA. There is one active session per window.

Verification uses the workspace .NET 8.0.426 SDK, Windows App SDK 2.4.0 and
EnableMsixTooling PRI packaging. Build/publish and separate real-report native
smoke evidence are recorded under desktop/windows/verification. Synthetic smoke
is only a fixture interaction check. No keyboard, Narrator, clean installation,
performance, full C21 workflow parity or M3 acceptance claim follows from these
checks. The current implementation includes window/provider settings, captured
report integrity, export, suppression/history, Overview and selected artifact
text. Historical checkpoints below describe their tested revisions; the current
scope section at the end distinguishes implemented behavior from open acceptance.

## Verified native live scan, 15 October 2026

After the broker startup fix, the published native executable completed
`--scan-smoke <absolute .venv Python> C:\tmp\juice-shop <workspace output>`
under normal-user execution outside the restricted sandbox. It imported the
completed report and selected evidence/recommendation detail: 18 findings from
862 scanned files, zero analyzer errors, three reported limitations and empty
LLM usage. No AI was requested. The scan output remained outside Juice Shop.

Run `e53ed4e064a94e83b5818e54f82275fc` is the verified current-generation pointer
in `.pytest_cache/m3-native-scan`. The pointer's manifest hash and all 19
manifest-listed artifact hashes/sizes matched. The canonical report is
12,874,040 bytes, SHA-256
`1a76a4035682dd6de39a1486d98c2a2b7c0488fa11f875b2770e00ff90c6e99d`.
The native smoke exited and no Python workers remained. Detailed evidence is
`desktop/windows/verification/native-engine-2026-10-15.json`.

An earlier restricted-sandbox attempt stalled before artifacts; it is retained
as a failed attempt in the evidence. Its native process was identity-checked and
stopped to force control EOF; the broker/job cleaned all owned processes. The
passing normal-user run supersedes that attempt for this bounded journey only.
Manual keyboard/Narrator, performance and full desktop beta acceptance remain
unmeasured.

## Local settings slice

Explicit Save local settings stores only absolute Python and repository paths
in LocalAppData/AttackMap/NativePreview/settings.json. Clear saved settings removes
the stored file; the active workspace stays open. Version 1 JSON is bounded to
16 KiB and replaced atomically within the same directory. Unsupported, oversized
or malformed input is rejected with the original preserved and actionable status.
Restore populates local paths and saved advanced options without an automatic scan.
AI remains off. CVE defaults off; an explicitly saved CVE opt-in is restored with
a visible disclosure that a subsequent scan sends dependency names/versions to
OSV. Restore itself makes no network request. Provider credentials/options remain
outside this slice. No old WebView settings are
implicitly migrated or overwritten. Smoke modes bypass personal settings.

The C21â€“C26 source/evidence audit and remaining gaps are in
`desktop/windows/verification/m3-acceptance-gap-audit-2026-10-15.md`. Focused settings
checks and separate native save/restore launches do not establish manual keyboard
or Narrator acceptance.

## Advanced analysis options

The native view sends validated analyzer modules and typed options through the
same request consumed by the shared engine: recall, strict analyzer errors,
suppression disablement, CVE enrichment, Git secret-history depth and elapsed-time
limit. Missing options in old requests/settings restore the safe defaults. Module
selection never installs plugins automatically. CVE and AI default off; enabling
CVE is accompanied by the OSV dependency-data disclosure. Settings restore does
not start analysis or contact a provider.

The advanced Juice Shop scan used `javascript-web` and `config`, strict analyzers
and suppression disablement, with a 120-second limit and CVE off. It completed
with 18 findings and no analyzer errors; request and prepared engine options
matched, and all 19 artifact hashes verified. Evidence:
`desktop/windows/verification/native-advanced-options-2026-10-15.json`.
41 focused option/settings checks and native save/restore passed. Live OSV,
keyboard/Narrator and full C21 workflow parity remain unverified.

## Persistent run and report context

The persistent summary separates the selected repository, active scan request and
displayed report. Active run ID/generation and client request time come directly
from the native broker request identity. The time is labeled client-request UTC,
not engine scan time. Ready broker artifacts carry that exact run identity into
the displayed report. A schema-less manually imported report has unavailable run
identity and scan timestamp; only its client-open time is shown. No directory name
or file modification time is promoted into engine provenance.

Starting another scan retains the prior report with PREVIOUS VALID REPORT and
its own repository/time context. Cancel/failure keeps that previous label; only a
new successfully parsed ready report replaces it. Selecting a different repository
keeps the displayed report's ownership separate. Filter/navigation text does not
overwrite this summary. Coverage expands to show the canonical report's supplied
limitations/analyzer errors and a labeled legacy aggregate file count. Missing
coverage remains unknown. Stage text has no invented percentage or ETA.

Focused state tests cover rescan, cancellation, failure, new-report promotion,
repository switching and missing coverage. Native report/live smoke evidence is
recorded separately. Shared fake-engine fault coverage, manual keyboard/Narrator
and full C22 acceptance remain open.

The 24-check focused suite, native legacy report regression, synthetic 10k
regression and live Juice Shop context smoke passed. Run
`af2d132c84944a97a71698e4646904d7` appeared exactly in the native displayed report
summary with `artifacts ready`, separately labeled client-request UTC and all
three supplied limitations. Its current pointer and 19 artifact hashes/sizes
verified. Normal-user process inspection found no remaining native broker/engine.
Evidence: `desktop/windows/verification/native-run-context-2026-10-15.json`.
Previous/cancel/failure labels are covered by focused presentation state tests;
this successful live scan does not claim end-to-end cancel/failure acceptance.

## Architecture and inventory slice

Native searchable lists project supplied canonical architecture/service/edge/
entrypoint/protocol/datastore/outbound records and attack surfaces. Inventory
projects supplied routes, dependencies, datastores and frameworks. The UI does
not infer ownership, graph edges or scores. Missing relationship basis remains
unknown; supplied roles, evidence kinds, origins and conflicts stay available.

50 focused checks cover missing/malformed input, Unicode, long source paths,
conflicts and secret exclusion. Release publish and native golden/real-report
navigation passed: 1,547 architecture records, 472 inventory records and 176
filtered dependencies with ecosystem/version detail. Evidence:
`desktop/windows/verification/native-structure-2026-10-15.json`. Event-queue waits
in the smoke are synchronization, not performance measurements. Accessibility,
layout acceptance and full C21/C23 remain open.

## Current report, source and provider checkpoint â€” 2026-10-15

ReportAdapter now passes 66 isolated checks; EngineSession passes eight controlled
fake-broker cases, including policy-failed completion with a missing optional
stage. Protocol proof remains scoped, not a complete native fault/UI matrix.
SourceLocation passes 17 isolated checks including an actual created symlink,
Unicode long paths, containment, bounded reads and changed/unchanged/unknown
whole-file hashes. Excerpt hashes are never treated as file hashes.

The actual native report smoke loaded 18 findings from
`.pytest_cache/m3-juice-shop/attackmap-report.json`, displayed the defensive review,
and inspected two valid `server.ts` locations. Both have unknown scan-time hashes
and explicit live-file-may-differ warnings; the legacy report's identity/integrity
remain unverified. Evidence:
`desktop/windows/verification/native-review-source-runtime-2026-10-15.json`.
This is a report/source presentation smoke, not a new analysis scan or evidence
that source bytes match a historical scan.

The actual DesktopActionRunner/Python provider round trip passes six checks:
fresh AI-off restore, credential-free save, no credential fields on disk, exact
safe settings in a fresh process, explicit loopback model listing and AI remaining
off after the connection check. Endpoint/model were the prescribed local LM
Studio service. No generation or repository payload was sent; DPAPI credential
storage and manual provider-panel interaction are not covered. Evidence:
`desktop/windows/verification/native-provider-roundtrip-2026-10-15.json`.

Seven loaded-view accessibility audits now inspect respectively 29, 29, 20, 20,
14, 21 and 28 controls with zero scoped issues:
`.pytest_cache/m3-seven-view-accessibility.json`. Collapsed configuration controls,
dialogs, virtualized rows, manual keyboard/Narrator, contrast and scaling remain
outside this audit. It does not certify C24.

A single-process Windows 10 **quick diagnostic** measured Loaded-marker 1761.13 ms,
report load 1382.82 ms, filter 15.39 ms and detail 0.98 ms; loaded working set
323,104,768 bytes and private bytes 314,707,968. One open/close cycle retained
22,499,328 working-set bytes / 9,568,256 private bytes. These are the harness's
reported values from insufficient samples, not qualifying p95 acceptance or a
leak test. Hardware qualification failed/unknown, full protocol counts were false,
and Loaded does not establish primary-action readiness. Raw evidence:
`.pytest_cache/native-performance-qa-0afaf6daeef443958b58d31d44aa8568/summary.json`
and `launch-00.json`. C26 remains unaccepted.

Current full Python regression is running in `.pytest_cache/m3-current-full.log`;
no pass is claimed. Packaging verification is ongoing, not accepted. The original
M0/M1/M2 prerequisites and C21â€“C26 acceptance remain open as documented in the
[acceptance ledger](windows-m3-acceptance.md).


## Current implemented workflow scope — 2026-10-15

This section supersedes older statements that settings, export, history,
architecture, inventory or layout were design-only/pending implementation. It
does not retroactively certify later source revisions with earlier package tests.

- Overview uses `OverviewAdapter.Read` through ReportAdapter: supplied system
  counts, strengths, ordered actions, analyst notes and limitations, with bounded
  plaintext and explicit unknowns. Eighteen pure checks include a real immutable
  report and exact action order. No native score calculation or finding-to-control
  ownership is invented; an independently recorded Overview task remains open.
- Architecture and Inventory use searchable supplied records. Saved real-report
  smoke records 1,547 / 472 entries and dependency version/ecosystem detail
  (`native-structure-2026-10-15.json`). Missing relationships remain unknown.
- Reports displays the supplied defensive review, exports the exact selected
  JSON/Markdown and browses only captured-manifest artifacts as inert text.
  `native-artifacts-export-runtime-2026-10-15.json` records 19 listed artifacts,
  successful architecture.md preview and selected-run export, separately from a
  different-active-run presentation fixture. Optional AI review is visible only
  if actually listed; no filename guessing, other-generation fallback or HTML
  execution. Legacy imports retain JSON-only export with integrity unknown.
- History selects a baseline and compares it with the displayed current report
  through the shared Python action runner. Seeded action proof includes new,
  persisted, resolved and newly suppressed counts; missing source coverage stays
  resolution-uncertain. Reasoned suppression preview/apply/undo is integrated.
  Native picker/dialog/rescan journeys remain separate acceptance work.
- Finding detail displays precomputed static context when supplied, direct static
  flows and explicit missing-basis fallbacks. Live source inspection validates
  containment and bounded reads; missing whole-file scan hashes always warn that
  live bytes may differ. Reveal/copy actions do not prove historical source identity.
- Current-display geometry persistence has 33 pure checks plus actual two-process
  1100x720 save/restore with work-area containment
  (`native-placement-runtime-2026-10-15.json`). Unsupported/malformed saved data
  disables automatic overwrite. Startup-monitor clamping does not certify DPI or
  multiple-monitor restore. Smoke modes isolate geometry writes.
- Findings and structure inspectors stack below 850 content units. Actual
  1024x700 / 1600x1000 viewport proof shows 332 / 632 content-height units,
  stacked / split findings and visible review (`native-viewport-1024-2026-10-15.json`,
  `native-viewport-1600-2026-10-15.json`). Configuration is collapsible; exports
  live in Reports. These are layout-state checks, not complete C25 visual proof.
- Cancellation is backed by shared Windows Job Object supervision, controlled
  50-cycle tree cleanup and 20-way admission proof, plus native fake-broker
  protocol/action tests. Frozen production C# runners execute a real Juice Shop
  scan and verify manifest hashes and normalized 18-finding parity with the same
  frozen CLI (`native-frozen-runners-juice-current.json`). Manual control-driven
  cancellation/retry/error journeys remain open; macOS is not certified.
- Provider save/restore/explicit local connection-check round trip passes six
  checks without enabling AI or sending repository inputs
  (`native-provider-roundtrip-2026-10-15.json`). Settings include local diagnostic
  reveal. Appearance/analyzer-management surfaces and manual protected-credential
  failure journeys are still incomplete.

Performance evidence now includes a full-count Windows 10 diagnostic campaign:
30 launches, 30 loads, 100 interaction samples and 100 open/close cycles. It
failed the 50 MiB retained-working-set target at 50.28 MiB. A later bounded-buffer
one-launch diagnostic reports 30.63 MiB growth with full first-trial counts; it
neither replaces the 30-launch campaign nor establishes a causal improvement
under concurrent test load. See `native-performance-full-2026-10-15.json` and
`native-performance-bounded-buffer-2026-10-15.json`. Windows 11/hardware and
primary-action-ready qualification remain unaccepted.

Shortest remaining product/acceptance gaps: dated history with retention/pinning,
appearance/analyzer-status controls, complete advertised advanced/fleet/watch
capability mapping, PDF export, detector-owned control/trust links, manual
picker/dialog/keyboard/Narrator journeys, supported Windows 11 installation and
performance, C19 participant outcomes, C20 migration/rollback decision and C25
nine-view theme/scale/exceptional-state review. Seven bounded loaded-view audits
with zero scoped issues do not cover collapsed configuration, dialogs, virtualized
rows, contrast or task focus order. The capture helper captures app content only;
no OS appearance or screen-reader result follows from a PNG. Full gates remain
tracked in [Windows M3 acceptance](windows-m3-acceptance.md).
