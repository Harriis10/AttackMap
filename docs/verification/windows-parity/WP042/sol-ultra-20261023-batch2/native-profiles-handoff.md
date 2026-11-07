# WP042 native profiles handoff — 2026-10-23 batch 2

Scoped source preparation, not whole WP042/WP006 acceptance. The integrator
approved the API before edits and owns request/settings/schema negotiation,
report binding, the full application build and actual visual review.

## Leased implementation

- `desktop/windows/AttackMap.NativeSpike/AnalyzerSelectionModel.cs`
- `desktop/windows/AttackMap.NativeSpike/AnalyzerSelectionView.cs`
- `desktop/windows/ScanProgress.Tests/Program.cs`

No other implementation files were edited by this agent. The test project
already links the model; no project-file changes were necessary. Shared dirty
work was preserved; no commits, reset, installation, scan or provider call.

## Profile API and behavior

Existing `Automatic`, `Restore(modules)`, `Select`, `SetAutomatic` and
`RequestModules` preserve exact manual semantics. New properties:
`SelectedProfile`, `RequestProfile`, `ExpandedProfileModules`,
`ProfileSelectionError`, `ProfileCatalogError`, `CatalogError`, `Profiles`.

`RestoreProfile(qualifiedName, savedExpandedModules)` retains the qualified
identity and saved membership before discovery. `SelectProfile(qualifiedName)`
explicitly accepts the currently advertised revision/membership. Named mode
emits `RequestProfile` and empty `RequestModules`; saved expansion remains
available separately. Manual module clicks retain the expanded choices and
switch to exact Custom selection. Automatic sends neither named profile nor
explicit module list.

Fresh discovery must verify the saved profile version and membership. Missing
profile/version, missing required modules, same-version changed membership,
malformed profile catalog and engine changes block named requests without
fallback or substitution. Explicit reselection accepts the displayed current
definition. Older capabilities without profiles retain Automatic/Custom;
saved named profiles remain blocked until the user explicitly changes mode.

Optional profile and provenance catalogs are parsed independently of installed
inventory. Malformed optional catalogs cannot publish partial definitions or
partial implementation provenance. Bounds cover UTF-8 payload size, JSON
depth, row/profile/module counts, strings, qualified identifiers and duplicate
records. Typed availability/missing/experimental/opt-in fields are checked
against supplied installed metadata.

Rows show effective builtin/plugin origin, package and analyzer versions,
implementation class/source identity and shadowed implementations when
advertised. Missing provenance is shown as unknown. Discovery does not imply
repository applicability, execution, success or maturity.

## Report ledger API

`SetRunLedger(JsonElement? ledger, string label)` binds observations from the
selected report. `RunLedgerRows`, `RunLedgerLabel` and `RunLedgerNotice` feed a
separate native Expander. Root supplies repository/generation context in the
label and owns report selection identity checks.

Accepted schema: `1.0`, scope `analyzer_selection_and_execution`, inventory
scope `registered_candidates` or `supplied_candidates`. It displays recorded
selection, applicability, execution, analysis-start state, skip reason and
bounded error stage/type, with recorded implementation SHA-256. It never joins
report entries to the current installed inventory by name. A report may have
a different implementation of the same name. Current-engine inventory
invalidation leaves separately labelled historical report observations intact.
Repeated analyzer names from legacy direct-API invocations remain separate
rows in producer order, including different outcomes; they are never merged.
Missing/malformed ledger clears previous rows and states unknown. Isolated
host failures with `analysis_started:null` stay unknown. Terminal-outcome
completion can include failures/skips and is never labelled full coverage.

The view uses one outer vertical ScrollViewer for the profile picker, summary,
filter, report-ledger Expander and inventory. This avoids fixed-height profile
and ledger regions starving the inventory in the existing constrained host.
The integrator still must inspect actual fit, keyboard behavior and theme
appearance in the full app.

## Verification and release boundary

The PATH `dotnet` host had no SDK. Using the already available
`.tools/dotnet/dotnet.exe` with task-local DOTNET_ROOT/DOTNET_CLI_HOME and
NUGET_PACKAGES completed the focused test build with **0 warnings, 0 errors**:

```powershell
.tools/dotnet/dotnet.exe build desktop/windows/ScanProgress.Tests/ScanProgress.Tests.csproj --no-restore -p:NuGetAudit=false -p:UseSharedCompilation=false -nodeReuse:false
desktop/windows/ScanProgress.Tests/bin/Debug/net8.0/ScanProgress.Tests.exe
```

Result: **136 checks passed**, exit 0. Coverage includes all previous protocol/
progress checks plus profiles, old capabilities, missing/stale restoration,
engine invalidation, Custom override, provenance/shadowing, malformed typed
flags, report separation, null/unknown/malformed ledger, detect error versus
unmatched, opt-in/deadline skips, unknown isolated analysis-start state and
repeated-name invocations with independent succeeded/failed outcomes.
`native-profiles-verification.json` records these tool outputs, test DLL hash
and leased-source hashes. `git diff --check` passed for all three leased files.

Source freeze was sent to root before the final full application build. The
focused test project compiles the model but **does not compile the WinUI view**.
No GUI appearance, Narrator, provider integration, real scan, frozen packaging,
macOS or whole-task acceptance is claimed here. Root's final source-bound build
and captures provide their own evidence and may supersede these source hashes.
