<!-- ATTACKMAP_DOC_STATUS: HISTORICAL_REFERENCE -->
> **STARÝ DOKUMENT — pro agenty nerelevantní jako aktuální plán nebo zadání (20. 10. 2026).**
> Práci řídí pouze dokumenty v [aktuálním rozcestníku](README.md). Tento text je historická reference: neobnovovat jeho TODO, priority ani statusy dokončení. Technické podklady a kritéria použít jen v rozsahu potřebném pro aktivní WP úkol a ověřit proti aktuálnímu kódu.

# Windows native shell design â€” bounded proposal

AM020 / AM021 / AM024, updated 2026-10-15. The WinUI development preview now
imports real reports and runs the shared engine, with implemented workflow slices
below. Windows M3 is accepted as a functional beta with limitations by the
2026-10-15 user decision. Remaining manual UX/accessibility and Windows study
validation is tracked in M4; original C20 evidence limits remain recorded. The existing Python
pywebview shell has not been retired; a development ZIP is not a public release.

## Shell and nine workflows

Use NavigationView for six destinations with its standard Settings entry. Keep a
workspace selector and run identity above destination content. Use system title
bar/window behavior and native folder/save pickers. Proposed default local scan
sequence: Choose repository, confirm folder, Start scan; a selected repository
needs only Start scan. Scan options and run details open compact native flyouts;
advanced fields expand inside the options flyout. AI defaults off.

The current shell uses an inline AttackMap wordmark, a compact toolbar with
content-sized actions, 36-unit minimum button heights, and a shared spacing
rhythm. Reports groups export actions horizontally. Findings keeps suppression
collapsed until needed; History hides empty results. Settings uses a bounded,
top-aligned form. These choices replace the oversized header/button layout
rejected in user screenshots. Actual desktop/scaling acceptance remains open.

| C18 view | Native composition and useful action | Source capability / status |
| --- | --- | --- |
| Start workspace | Folder picker, recent locations, primary Start scan; options flyout | Native repository selection/default scan and typed advanced options implemented; fleet selection/recent list acceptance open |
| Overview | Supplied system summary, strengths, ordered next actions, coverage and uncertainty | OverviewAdapter projects core review fields without rescoring; 18 pure checks; integrated source, independent current-view acceptance open |
| Findings list | Search and filters, bounded ListView, priority explanation alongside severity | Canonical report and live Juice Shop findings implemented; full priority explanation/acceptance open |
| Finding detail | Persistent inspector: basis, confidence, provenance, evidence and recommendation together; reasoned suppression dialog | Precomputed static context, live source inspection/reveal/copy and reasoned preview/apply/undo implemented; detector-owned control links and full C23 acceptance remain open |
| Architecture | Searchable supplied service/edge/surface records with basis/unknown labels | Real-report smoke: 1,547 records; full graph interaction and task acceptance open |
| Inventory | Searchable supplied route/dependency/datastore/framework records | Real-report smoke: 472 records, version/ecosystem detail; broader inventory tabs and acceptance open |
| Reports | Defensive review, selected JSON/Markdown/HTML/PDF export, manifest-listed inert artifact text including AI review only if supplied | Actual selected-run export/artifact smoke: 19 listed, architecture.md read; no guessed AI output or HTML execution; rendered HTML/PDF export prints via located Edge/Chrome with browser fallback; manual dialog journeys remain open |
| History | Native baseline picker and displayed-current coverage-aware comparison | Core/native seeded action smoke; dated run browser, retention/pinning and manual picker journey remain open |
| Settings | Appearance, engine/analyzer status, provider disclosure, protected credentials, diagnostic reveal | Paths/options and provider Save/restore/test, network disclosure, local diagnostics reveal implemented; appearance/analyzer status and manual credential journeys remain open |

Watch maps to workspace advanced settings; fleet maps to workspace selector and
aggregate overview. Recall/CVE/analyzers/baseline/gates/suppressions/AI modes/jury
options map to advanced scan configuration; unavailable capabilities must be
explained, never silently changed. Implemented shell actions include shortcuts,
source copy/folder reveal and current-display geometry restore. Suppression writes
require reviewed reasons and support undo. JSON/Markdown/HTML/PDF export and
verified selected-run artifact browsing are implemented (HTML renders locally;
PDF prints through located headless Edge/Chrome, falling through candidates
that fail silently); a dated history browser, watch/fleet interaction and
advanced capability coverage remain gaps.

## Required states

Every surface retains repository, generation identity, timestamp, coverage and
freshness. Previous results are visible only with an explicit previous-result
label during a new run. Terminal status and artifact readiness are separate.

| State | Explanation and next action |
| --- | --- |
| First launch | No workspace selected; Choose repository |
| Loading | Named stage and indeterminate progress unless bounded; Cancel |
| No findings | No findings within stated coverage, not proof of safety; Inspect coverage |
| Filtered-empty | No matches to current filters; Clear filters |
| Partial/degraded | Missing stages/analyzers named; Inspect coverage and retry |
| Stale previous result | Previous generation timestamp shown; Return to active run |
| Cancelling | Termination requested; wait for worker cleanup before restart |
| Failure | Redacted actionable error; Retry and Reveal diagnostics |
| Missing analyzer | Named capability unavailable; Open analyzer settings |
| Unavailable AI provider | Local deterministic result remains visible; Configure provider or retry |
| Incompatible report | Unsupported schema shown; Preserve original and select supported report/engine |

The preview implements startup, loading, filtered-empty, previous-report,
cancel/cleanup, report-import failure and degraded-coverage presentation slices.
Protocol/session QA covers revision, policy, EOF and cleanup failure cases; it
is not a recording of every exceptional state through native controls. See
[engine integration](windows-native-engine-integration.md) and the
[acceptance ledger](windows-m3-acceptance.md) for bounded runtime evidence.

## Components, semantic tokens and accessibility

These semantic roles use system theme resources, never fixed light-only colors.
Severity, confidence and observed/inferred meaning always have text; they must not
be communicated only by color. The table specifies at least twelve reusable roles.

| Component / role | Token / native resource | Interaction and accessibility contract |
| --- | --- | --- |
| Window surface | ApplicationPageBackgroundThemeBrush | System appearance changes live; no lost selection |
| Primary text | TextFillColorPrimaryBrush | Inherits system text scaling and high contrast |
| Secondary text | TextFillColorSecondaryBrush | Essential confidence/provenance remains readable |
| Navigation | NavigationView defaults | Named destinations, selected state, keyboard traversal |
| Workspace selector | ComboBox defaults | Accessible repository name, stable focus after selection |
| Primary command | AccentButtonStyle | One clear Start scan; label states scope |
| Secondary command | Button defaults | Visible names and focus; no icon-only essential action |
| Search/filter | TextBox defaults | Explicit automation name; clear query without losing workspace |
| Finding row | ListViewItem defaults | Arrow selection, meaningful row name including severity/basis |
| Evidence inspector | TextControlThemeFontFamily / body style | Selectable text, source name/line, bounded scrolling |
| Heading | TitleTextBlockStyle / SubtitleTextBlockStyle | Semantic heading automation level in production |
| Status | InfoBar + polite live region | Announce state changes once; throttle progress announcements |
| Severity badge | Semantic critical/high/medium/low text | Theme-aware contrast; no severity scoring in UI |
| Basis badge | Semantic observed/inferred/candidate text | Separate from confidence and severity |
| Focus | System focus visual defaults | Never remove focus rectangle; restore invoking focus on dialog close |
| Layout rhythm | 4/8/12/16/24 logical-unit spacing | Reflow inspector at narrow width; no full-window horizontal scroll |
| Advanced settings | Expander defaults | Keyboard toggles and exposed expansion state |
| Suppression prompt | ContentDialog defaults | Required reason, cancel escape, no hidden destructive default |

The spike uses native default controls, automation names, a polite status region,
and selectable evidence text. These are implementation choices, not screen-reader
validation. Test tab/arrow traversal, Ctrl+F, escape/dialog focus, Narrator row and
detail announcements, high contrast, and 100/150/200% scaling on the available supported Windows host.
At 1024Ă—700 use a stacked or collapsible inspector; at 1600Ă—1000 use split view.
The preview stacks finding/structure inspectors below 720 content units. Actual
1024x700 / 1600x1000 smokes retain 332 / 632 content-height units and stacked /
split finding inspectors. Full theme/text-scale/exceptional-state captures remain open.

## Python engine adapter and cancellation design

Do not port analysis/scoring into C#. Reuse a versioned Python bridge over a
controlled subprocess. The existing ScanConfig emits analyze, repository paths,
--format all, --output, JSON progress and --run-id. Inventory records options that
the server currently fails to forward: do not assume configuration type parity
is end-to-end parity. The native adapter needs a single canonical option manifest,
schema compatibility negotiation and shared golden reports.

Launch a discovered absolute engine executable with ProcessStartInfo.ArgumentList,
UseShellExecute=false, redirected output/error, working directory under app-owned
run storage, and a per-child environment overlay. Never concatenate a shell command
or pass credentials as arguments. AI requires visible provider/data disclosure and
explicit opt-in; secure-store failures must be actionable. Use the local LM Studio
endpoint/model for any future live test per AGENTS.md.

Carry workspace ID, run ID and generation ID with every event. Parse bounded
newline-delimited JSON off the UI thread; marshal throttled updates through
DispatcherQueue. Reject stale/out-of-order generations, oversized/malformed events
and missing artifacts with a visible partial/failure state. Keep the previous
validated generation immutable until the engine promotes the new one. Exit code
alone cannot establish report readiness or policy success.

State machine: idle â†’ running â†’ succeeded/failed; running â†’ cancelling â†’ cancelled
only after owned process-tree cleanup. Cancellation request races must be serialized
with completion and promotion; keep Start disabled while cleanup is incomplete.
For Windows use an owned Job Object with kill-on-close and assignment before the
worker can spawn descendants (requires a suspended-launch native helper or the
existing Python adapter with a proven tree-ownership contract). Cooperative
cancellation then bounded escalation must satisfy C09; Process.Kill(tree=true)
alone is not proof against escaping/reparented children. Shared Windows supervisor
proof covers 50 ignoring-graceful tree cycles (ack p95 0.933ms, exit p95 3.044s),
20-way admission and blocked restart on failed cleanup. Native session/action QA
and frozen runner scans are separate integration proof; complete native-control
cancellation journeys and macOS supervision acceptance remain open.

## Performance and design validation

ItemsStackPanel inside a height-constrained Grid is the source virtualization
choice; do not wrap the list in an outer ScrollViewer. See Microsoft's
[WinUI list optimization guidance](https://learn.microsoft.com/en-us/windows/apps/develop/performance/optimize-gridview-and-listview).
The original synthetic DTO smoke is supplemented by the versioned canonical
C26 corpus: 10,000 findings, 50,000 observations and exactly 20 MiB, with generator
and checksum in [reference fixture](desktop-reference-fixture.md). Real Juice
Shop reports are imported by the native client; actual engine and frozen C#
runner evidence is recorded under `desktop/windows/verification/`.

A full-count Windows 10 diagnostic measured 30 launches, 30 loads, 100 interaction
samples and 100 open/close cycles. Retained working-set growth 50.28 MiB failed
the 50 MiB target. A later bounded-buffer diagnostic has one launch with the full
first-trial load/interaction/cycle counts and 30.63 MiB retained growth; it is not
a replacement 30-launch campaign or a controlled causal comparison. Both are
unqualified for C26 Windows 11/action-ready acceptance; raw proof is in
`native-performance-full-2026-10-15.json` and
`native-performance-bounded-buffer-2026-10-15.json`.

Before migration, complete the C20 technology/migration/rollback decision and
missing native task evidence, run C19 participant tasks, and verify supported
Windows 11 installation, keyboard/Narrator, contrast, scaling and nine-view
light/dark exceptional-state captures. NativeCaptureProbe is an app-content-only
capture helper; its existence does not prove a capture campaign or visual quality.
No participant ratings or manual assistive acceptance are claimed.
