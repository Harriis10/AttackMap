# WP021 bounded fleet watch component

This is component evidence, not integrated native UI acceptance or roadmap
closure. No engine, GUI, provider or actual analysis was started.

`Watch/FleetRepositoryWatchCoordinator.cs` composes WP020's existing
RepositoryWatchCoordinator for each supported selected root. It adds no raw
FileSystemWatcher implementation. Start is explicit, default off, with 2–16
unique absolute selected roots. The pending collection has at most one entry
per supported root. A second debounce coalesces child requests across roots
into one full-fleet request, preserving original selected root order. Changes
during an admitted/running fleet remain pending in the child coordinators and
are coalesced after completion. Owned outputs and skip/uncertainty policy remain
WP020's policy.

API for the full existing product shell (root-owned integration):

```csharp
bool Start(IEnumerable<string> repositoryRoots,
    IEnumerable<string>? ownedOutputRoots = null,
    TimeSpan? debounce = null, bool fleetRunning = false);
event Action<FleetRepositoryWatchRequest>? ScanRequested;
bool IsCurrent(FleetRepositoryWatchRequest request);
void SetFleetRunning(bool value);
void Requeue(FleetRepositoryWatchRequest request);
bool FleetCompleted(FleetRepositoryWatchRequest request, bool successfulFullScan = false);
void FleetCompleted(long expectedEpoch, bool successfulFullScan = false);
void Stop();
void Dispose();
```

Request fields: Epoch, RequestId, RepositoryRoots, ChangedRepositoryRoots,
FullRescan, EventsUncertain. Root arrays are captured read-only snapshots.
RepositoryRoots always includes the entire selected fleet, including unsupported
watch roots; watch limitations never silently reduce full-scan scope. IsCurrent
requires the selected-set epoch and current dispatch ID. Use the request-token
completion overload for watch-triggered jobs, so an old same-epoch callback
cannot clear a newer dispatch. The epoch-only overload supports separately
tracked manual fleet runs; the host must serialize their lifecycle.

Event callbacks run on timer threads. Recheck IsCurrent after UI dispatch and
before invoking the existing full-fleet workflow. If UI dispatch fails or the
host is busy, Requeue. A throwing or missing event handler is automatically
requeued. SetFleetRunning(true) while manual fleet work is active; release that
state and complete the captured epoch/token after owned work terminates.
Set changes must restart explicitly or Stop; window closure must Dispose.
Pending callbacks from the old epoch are rejected. Host code owns all engine
admission, cleanup verification, network/AI settings and visible status.

Enabled, Pending, PendingRepositoryCount, Epoch, WatchedRoots, Limitations and
Notice expose component status. Unsupported/unavailable roots have explicit
per-root limitations; supported siblings can remain watched. No callback,
watcher or timer survives Stop/Dispose as a current subscription. As with
WP020, remote/redirected/unsupported filesystems require manual rescans and
filesystem events are hints, not complete change provenance.

The first dedicated `FleetWatchCoordinator.Tests` run passed 41 checks using
actual Windows filesystem create/edit/rename/delete events across three owned
temporary roots, including a Unicode/space path. It covers default off, set
bounds/uniqueness, second/third repository events, cross-root burst follow-up,
changes while running, output/dependency ignores, busy requeue, thrown dispatch
retry, stale completion rejection, repository-set switch, unavailable sibling,
Stop/Dispose and no callbacks from removed subscriptions. Temporary GUID-root
cleanup validates its resolved path before recursive deletion. It does not
exercise a full native fleet run or manual UI/accessibility interaction.

The final-source rerun passed the same 41 checks. The original WP020
WatchCoordinator.Tests harness passed all 34 checks, including its actual Windows
filesystem matrix, with the new component present in its shared Watch source
glob. `component-checks-2026-10-21.json` binds these outcomes to the three new
source/project files. Scoped diff check passed. Both used SDK 8.0.426 through
`.tools/dotnet/dotnet.exe`, task-owned CLI/package paths and NuGetAudit=false;
the final runs used --no-restore. No historical evidence or authoritative
backlog was modified for this component.
