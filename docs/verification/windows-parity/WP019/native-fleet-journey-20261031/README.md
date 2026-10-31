# Native Fleet transport QA journey (prepared, not executed)

This opt-in QA partial exercises actual `ApplyScanOptions` → `RunFleet` → capability admission → preflight action → `FleetSession` → worker → verified native terminal. It uses explicit module `config`, isolation enabled, 30-second per-repository soft budget, 180-second Fleet allowance and one worker. Inputs are the existing `tests/fixtures/shared_datastores/reader` and `writer` fixture repositories. AI and CVE lookup are disabled. Soft-budget transport is exercised; these tiny fixtures do not prove budget exhaustion or deadline fairness.

Invocation after the host hooks are integrated and a source-bound app/engine are built:

```powershell
& <absolute-native-exe> --fleet-transport-smoke <fresh-empty-absolute-output> <absolute-engine-exe> C:\Projects\INPROGRESS\AttackMap\tests\fixtures\shared_datastores
```

The caller must create the empty output directory. Output must be separate from corpus, engine and application directories. Settings, placement, recent-repository state, capability/preflight actions and Fleet reports belong there. Paths are canonical fixed-drive paths; UNC/device paths, ADS, existing state and reparse ancestors are rejected. No corpus writes or cleanup occur in the journey. Both fixture file hashes are captured and checked after completion.

## Host integration (root-owned files)

In `MainWindow.xaml.cs`, before `InitializeComponent()`:

```csharp
fleetTransportQaDirectory = ReadFleetTransportSmokeDirectory(startup);
if (fleetTransportQaDirectory is { } fleetQa)
{
    settings = new LocalSettingsStore(Path.Combine(fleetQa, "settings.json"));
    placementStore = new WindowPlacementStore(Path.Combine(fleetQa, "window.json"));
    recentStore = new HistoryPrep.RecentRepositoriesStore(Path.Combine(fleetQa, "recent.json"));
    providerRenderActionDirectory = Path.Combine(fleetQa, "actions");
}
```

In the exclusive smoke dispatch chain, before the normal restore branch:

```csharp
else if (startup.Contains("--fleet-transport-smoke"))
    ((FrameworkElement)Content).Loaded += FleetTransportSmokeLoaded;
```

In `MainWindow.Workspaces.cs`, the actual `RunFleet` preflight call receives:

```csharp
outputBase: fleetTransportQaDirectory == null ? null : Path.Combine(fleetTransportQaDirectory, "actions")
```

Immediately after that awaited preflight, capture its actual request and response:

```csharp
CaptureFleetTransportPreflight(preflightRequest.RootElement, preflight);
```

The QA journey fails if this capture hook is absent. It compares the actual persisted worker request against the actual preflight selection, verifies identity/isolation/budget/modules and requires a succeeded current terminal with two verified children. No synthetic request stands in for worker evidence.

## Verification and limits

Executed focused command:

```powershell
& .\.tools\dotnet\dotnet.exe run --project desktop/windows/FleetTransportQa.Tests/FleetTransportQa.Tests.csproj -- C:\Projects\INPROGRESS\AttackMap\tests\fixtures\shared_datastores
```

Exit 0, **19 input-admission checks PASS**. Includes the actual two fixture files, before/after file inventory and SHA256 equality, fresh output, overlap, missing fixture/engine, relative/UNC/device/ADS/noncanonical paths and preservation of existing output. No app, engine, GUI or scan launched. Reparse rejection is implemented but not independently exercised by this focused test. Initial PATH `dotnet` had no SDK; explicit local SDK was used. Initial test attempts found and fixed exception-filter and slash-canonicalization errors before the final passing run.

The native partial itself has not been compiled or run by this agent. `native-fleet-transport.json` PASS covers native transport only. `LoadFleetSummary` may fail after `Finish(succeeded)`; no summary-load, pixel or manual UI acceptance follows from this proof. Native cleanup flags and awaited broker completion are recorded; the coordinated external runner must independently record the exact owned process tree and verify its termination after window closure. No global process termination or shared-service cleanup is permitted.
