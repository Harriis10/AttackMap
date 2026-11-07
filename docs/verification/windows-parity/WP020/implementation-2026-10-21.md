# WP020 native single-repository watch preparation

Status: IMPLEMENTED component with focused policy and actual Windows filesystem verification; native product integration/manual acceptance remains pending. Base: `620210ed52dc1f20b72d4da91a6594fd45a1e6a9`. Worker: `/root/roadmap_completion_audit`. No MainWindow, shared settings, engine, legacy watcher or backlog changes.

## Implementation and host integration

`desktop/windows/AttackMap.NativeSpike/Watch/RepositoryWatchCoordinator.cs` owns one FileSystemWatcher and one timer. Start is explicit, does not scan, and does not persist settings. Events coalesce after debounce; an active scan retains one pending burst. Every request explicitly requires a full rescan and carries repository root plus subscription epoch. Error/overflow marks event uncertainty and schedules a full rescan. A completed older scan cannot clear uncertainty raised later.

Host API:

```csharp
watch.ScanRequested += request => dispatcher.TryEnqueue(() => {
    if (!watch.IsCurrent(request)) return;
    // Use the single engine scan slot, exact request.RepositoryRoot,
    // full-scan options and host policy. Display EventsUncertain/Notice.
});
watch.Start(repositoryRoot, allOwnedOutputRoots, scanRunning: engineIsRunning);
watch.SetScanRunning(true); // also for manual scans
watch.ScanCompleted(capturedEpoch, successfulFullScan: true);
watch.Stop(); // cancel, watch off, workspace/repo-set switch
watch.Dispose(); // window close
```

If dispatch cannot start, the host must release the reserved slot with `ScanCompleted(capturedEpoch)`; if the subscription is no longer wanted, stop it. Do not acknowledge an older run against a new subscription. Callbacks occur on background threads; UI dispatch must recheck `IsCurrent`.

The relative directory exclusions mirror `srcpaths.py::SKIP_DIRS`. A source file with an excluded directory basename remains input; deleted-directory type uncertainty may cause an extra conservative scan. All explicit owned output/cache/diagnostic roots must be supplied to Start. Marker-only legacy output directories are ignored. Modern manifested directories and arbitrary `reports` directories are not blindly excluded: they may contain user sources. This component does not port the engine's per-file manifest/legacy-shape classifier; output outside configured owned roots may therefore cause extra rescans, never a basename-based omission of source changes. UNC/redirected/missing roots fail explicitly; other filesystem failures surface through Error/Notice. This is not proof of every filesystem's delivery guarantees.

## Verification actually performed

Windows, bundled .NET SDK 8.0.426, standalone `WatchCoordinator.Tests` net8 harness:

`./.tools/dotnet/dotnet.exe run --project desktop/windows/WatchCoordinator.Tests -p:NuGetAudit=false -- .tmp-watch-wp020-events`

Result: **31 PASS**: 9 explicit-clock policy checks, 7 exclusion/availability checks, 15 actual local Windows filesystem/lifecycle checks. Real events covered create, edit burst while scan active, one follow-up, rename, delete, owned publication ignore, pending repo switch, stale epoch rejection, old subscription disposal and stop/dispose. The GUID test directory was containment-checked and deleted. Harness exited 0; no scan/GUI/provider processes were created.

Legacy regression:

`./.venv/Scripts/python.exe -m pytest tests/test_ui_watch.py -q --basetemp .tmp-wp020-legacy-approved`

Result: **13 PASS**. Sandbox temporary-directory restrictions required the approved focused test execution. This is the existing Python watcher regression, separate from the new .NET real-event checks.

No native shell journey, real scan, baseline comparison, GUI/accessibility review, real buffer-overflow stress or all-filesystem campaign was performed. Those remain WP020/product integration gates; this record does not close K4.

## Source identity

SHA-256 at worker handoff:

| File | SHA-256 |
| --- | --- |
| Watch/RepositoryWatchCoordinator.cs | `ECA0F4D86715569178C3BE6BBBD7618F8AA1740B743CA9702A5EC3F823AEDE61` |
| Watch/RepositoryWatchState.cs | `6A6D77BCEF51281B2CAA12CC3C9E6246608898B7B85952C0D25808D8A4151559` |
| WatchCoordinator.Tests/Program.cs | `A86EBB4A0817A1CB0C8A49A8E94489E795AA7FB409CB9A1BF6C9638455CAFF4E` |
| WatchCoordinator.Tests/WatchCoordinator.Tests.csproj | `BFF875021C253BE03DA5E5A7133182F8A63A388F550D5824C8E75A04DC096DC8` |

First two paths are relative to `desktop/windows/AttackMap.NativeSpike/`; test paths are relative to `desktop/windows/`. Final commit/diff identity and independent review remain integrator-owned.
