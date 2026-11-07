# Diagram explorer integration — 24 October 2026

Status: implementation integrated; **native rendering acceptance FAILED and reopened**.
User explicitly requested parallel completion/integration after showing the standalone
Fleet explorer. This reopens the current scoped work; prior frozen handoffs remain
historical. WP043 and WP044 whole-task acceptance remain separate.

**Current valid native-only result: FAILED.** In normal process 31656
(`native-only-07-bundled`), a truthful diagnostic portable marker selected retained
engine03 and the new default AppData action `c28b0acd77d64054a55dd0f8edc54af3`
successfully returned the hash/run-bound graph: 1 repository, 40 nodes, 39
containment edges and 92 evidence records. The user confirms native menu glyph
loss after graph loading/navigation **without an initialized web host**.
[`diag07-status.json`](../../../../../artifacts/diagram-integration-20261024/diag07-status.json)
records the actual action identity and raw-trace reference; updated
[`user-live-result.json`](../../../../../artifacts/diagram-integration-20261024/user-live-result.json)
is authoritative negative visual evidence.

The trace has 12 navigation snapshots, all with initializedBrowserCores=0, and no
ProcessFailed, SurfaceContentsLost or diagnostic-error event. An uninitialized
WebView2 control was observed (browserControls up to 1); this is not a claim of
zero control objects. All 12 exact navigation-label TextBlocks in the latest
snapshot retain text, positive geometry, visibility, white foreground and opacity1.
Those state assertions do not prove that glyphs were painted. F9/F10 have not been
invoked; their manual results are pending and the user has minimized the window.
No rendering repair or exact root cause is established.

The [engine-selection audit](../../../../../artifacts/diagram-integration-20261024/engine-selection-audit.md)
supersedes graph-specific interpretations of no-marker native04/native06/first07
comparisons: they selected an old saved engine and did not prove new graph loading.
Their observed text loss remains recorded. The complete source03 package has a
marker, so its earlier failed user check remains valid. Current native-only07
is a separate valid negative graph comparison. Source07 compiled and now has a
successful normal action; earlier compile-pending notes below are historical.
The SDK2.5.1 candidate remains **not launched**, the ZIP remains withheld,
native acceptance remains FAILED, and all whole-task/release gates remain open.

**Latest diagnostic checkpoint:** native04 failed the user's normal-window check
and the same native04/engine03 binaries also failed with a fresh WebView2 user-data
folder (PID 38320). The screenshot referenced by `hardening-04-status.json` is
`codex-clipboard-b8f8747f-521f-4d03-ad78-091333191481.png`. Lazy fallback and fresh
profile isolation did not repair the observed native menu/finding-row text loss.
The precise rendering cause remains unknown; native acceptance is FAILED and
the generated source03 ZIP remains withheld.

Source05's diagnostic build failed on the `WindowEventHandler` declaration; its
failure log/result remain preserved under `native-build-05`. Root replaced that
declaration with a local handler in source06, whose native build passed with
unchanged inputs (`native-build-06/result.json`). The normal native-only06 process
PID 13192 is awaiting human comparison. Its trace so far covers startup/Findings
only and records no observed WebView2 core, process-failure or SurfaceContentsLost
event. It has **not yet exercised native graph navigation**; this is not native
graph acceptance or proof that no renderer failure can occur.

Source07 adds one-label F9 fresh-brush and F10 CharacterSpacing diagnostic probes,
observed browser/core counts and diagnostic auto-open wiring. Its compile is pending
at this checkpoint. These opt-in probes are not a production repair or a root-cause
claim; no source07 runtime/visual result is assumed.

The separate [SDK2.5.1 experiment README](../../../../../artifacts/diagram-integration-20261024/sdk251-experiment/README.md)
and [verification](../../../../../artifacts/diagram-integration-20261024/sdk251-experiment/verification.json)
record successful restore/publish and payload checks from source06, with exactly
two project SDK-reference edits. That candidate has **not been launched** and has
no visual acceptance. It did not modify the production SDK references or source06.
Whole WP043/WP044 statuses remain IN_PROGRESS; manual, clean-host and release
acceptance remain open. The earlier checkpoints below retain their original scope.

The latest authoritative user evidence is
[`user-live-result.json`](../../../../../artifacts/diagram-integration-20261024/user-live-result.json).
The user retracted the brief positive observation: after opening the new interactive
graph and navigating back, native menu text disappeared again while hosted web graph
pixels remained visible. The earlier answer identifying Vector as the trigger was
also explicitly corrected; the precise trigger is **unknown**. This negative native
shell result overrides any inference of user acceptance from the structural checks
or hosted-page screenshots below.

The generated `artifacts/AttackMap-Windows-graphs-20261024-final.zip` is **not
accepted and is withheld from delivery**, despite its `final` filename. It remains
preserved as evidence. The subsequent fresh normal source03 application
(`--show-report`, PID 38840) also **FAILED the user's native menu check**, without
QA switches, captures or the missing-asset probe. QA probing is therefore not a
necessary trigger. The precise cause remains unknown. Root closed owned processes
30628 and 38840 after checking their exact executable paths.

The newer status record is
[`hardening-04-status.json`](../../../../../artifacts/diagram-integration-20261024/hardening-04-status.json).
Native04 was built successfully with zero warnings/errors from source04 input digest
`126a6ef7c9d0c0b764c0cbc61c571cc72d97b85a3a0b1665686b7c49681c2762`.
The hardening creates full canonical fallback JSON only when needed, wraps fallback
text, disables horizontal scrolling, and replaces the one-pixel probe with a bounded
640×360 probe in a separate disposable QA process. Its missing-asset event check
passed in `fallback-runtime-04`; this is an event result, not native glyph acceptance.
At the preceding documentation checkpoint these edits were unbuilt; they are now
compiled and scoped-test verified, without a claim that rendering is repaired.

Native04 deliberately retains the source03 frozen engine, whose engine closure
hashes match source03; this is a mixed scoped diagnostic lane, **not a new combined
release**. The normal native04 application (PID 15532) subsequently failed the
user's visual comparison, and a fresh-profile process (PID 38320) failed as well;
the earlier pending state is superseded by `hardening-04-status.json`. No new
scan, provider request or screenshot was used by the separate fallback event check.
None of this changes the failed source03 user result or retroactively changes the
withheld ZIP. WP043/WP044 remain IN_PROGRESS; native rendering, manual/clean-host
and release acceptance remain open.

The last user-checked portable already contains both graph libraries, the hosted
WebView2 bridge and the complete offline Cytoscape asset closure under Fleet.
The screenshot's standalone page legitimately starts with `No graph loaded` until
a canonical file or the labelled synthetic example is selected. Diagrams used the
older artifact viewer, defaulting to prose `architecture.md` rather than the modern
explorer. Package audit is in `artifacts/diagram-integration-20261024/package-audit/`.

## Focused completion

- Diagrams now defaults to the interactive architecture of the selected verified
  report, with a native vector alternative and canonical evidence/source controls.
  The original inert report diagrams, full source, copy/export and the long-line
  wrapping correction remain available in `Report diagrams and summary`.
- `report_graph` is a local, hash-bound desktop action. It replays the stored
  `ScanResult` through the existing core graph builder for one repository, without
  scanning files, connecting to a provider or modifying the report. File/root/hash
  and post-projection identity checks prevent publishing changed inputs. The native
  host binds the result to its separately verified manifest and run selection.
- One-repository graphs initially expose their components in both renderers;
  multi-repository Fleet graphs retain their collapsed repository overview.
- A typed host fallback event replaces matching human-readable error prefixes.
  Initialization/runtime failures expose the vector alternative and clear obsolete
  layout acknowledgement. Existing context/session and offline restrictions remain.
- Hosted layout fits the native pane at narrow/wide sizes. Graph replacement resets
  filters, neighborhood selection reprojects correctly, Back restores the focus,
  and hosted ready messages no longer advertise unavailable PNG export.
- Cross-review corrected a legacy/interactive visibility race and serializes report
  graph loads so changing the report cannot collide with its previous action.
  A graph from an earlier selection cannot replace the current report.

This is a renderer and report replay integration. The actual retained Juice Shop
input has 40 nodes and 39 **containment** edges with 92 evidence records. Those
edges mean ownership, not 39 newly established service calls. The UI does not invent
relationships from prose. Unsupported non-HTTP relationships remain unanalysed.

## Parallel ownership and focused evidence

Three GPT-6.1 Sol agents worked in disjoint scopes; root owned shared shell,
Diagrams composition, source capture, combined build, runtime QA and packaging.

- Native agent: typed fallback, report mode and native initial expansion. Isolated
  initial native build passed with zero warnings/errors; existing core 316 checks
  and navigation 128 checks passed. Those model suites do not prove host fallback.
  A separate actual loaded-control missing-asset probe is included in root QA.
- Web agent: 21 focused Node tests passed; 14 deployed assets have a regenerated
  hash manifest. Evidence in `artifacts/diagram-integration-20261024/web-agent/`.
- Engine agent: 52 graph/action/fleet tests and 44 capability tests passed. Actual
  retained-report source action preserved input bytes and produced the counts above.
  Evidence in `artifacts/diagram-integration-20261024/engine-agent/`.

The zero-capture user check from the earlier rendering investigation remains
scoped to its original build. The new QA intentionally uses WebView2 page capture
for actual hosted pixels, not RenderTargetBitmap of the native shell. Page captures
exclude native chrome and are not OS/Narrator/200% text acceptance.

Both source03 candidate binaries, native and frozen engine, were built from the
same captured release inputs under `artifacts/diagram-integration-20261024/source-03`;
`source-capture-03.json` and the corresponding build evidence retain that identity.
The actual source03 runtime `report-runtime-03b/report-graph-proof.json` passed
hosted light/dark captures at 1100/1600 widths (four PNGs), 15 navigation transitions,
native vector layout, complete JSON/SVG export and the missing-asset fallback event.
These checks prove their stated scoped behavior; hosted-page PNGs exclude native
menu/chrome and do not override the later failed user-visible native rendering check.
Earlier source01/source02 attempts and their results remain historical evidence.
No signing, clean-host, representative production 16-repository or macOS acceptance
is implied. The original long-line investigation's user-checked binaries remain a
separate historical scoped result; they do not establish acceptance of this new build.
