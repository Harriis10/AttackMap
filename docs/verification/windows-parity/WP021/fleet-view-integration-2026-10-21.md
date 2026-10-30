# Fleet view watch control — component integration

The existing full-product FleetView retains Add/Remove/Scan/Cancel, selected root
ordering, child results and summary projection. It now includes the native
"Watch selected repositories" CheckBox, off by default, and an independent
wrapping watch notice. No provider, engine admission or filesystem subscription
is owned by this view.

Root-owned MainWindow wiring API:

- `bool WatchRequested { get; set; }`: setting the existing value does nothing;
  actual native checked/unchecked changes emit `Action<bool> WatchRequestedChanged`.
- `IReadOnlyList<FleetRoot> SelectedRoots`: captured read-only snapshot in the
  existing workspace order, including repository ID and normalized path.
- `Action<IReadOnlyList<FleetRoot>> RepositorySetChanged`: emitted after successful
  AddRepository/RemoveRepository only when the ordered ID/path sequence changed.
  Duplicate/rejected additions and no-op removals emit no set change. Refresh
  and ShowSummary never emit it; result updates do not restart subscriptions.
- `RemoveRepository(string id)` exposes the same mutation route as the existing
  Remove selected button. Existing AddRepository stays available.
- `SetWatchNotice(string)` changes only the independent wrapping watch text,
  preserving the main fleet outcome status.

The host restarts its coordinator on set changes only while WatchRequested is
true, and may explicitly set it false for an unsupported set. Start/Stop,
dispatch admission, busy requeue, completion and window disposal remain with the
host and the existing coordinator. The checkbox is not silently persisted or
enabled by result refreshes.

Focused actual WinUI compilation: `.tmp/FleetView.BuildCheck` links the exact
production FleetView, FleetWorkspace and FleetAdapter against cached
Microsoft.WindowsAppSDK 2.4.0. SDK `.tools/dotnet/dotnet.exe` 8.0.426 completed
the library build with exit 0, zero warnings and zero errors in 67.50 seconds.
Scoped diff check passed. This compiled library was not launched. No GUI,
provider or engine process was started, and no MainWindow, coordinator or shared
resource was edited. Actual checkbox interaction, appearance and full-shell
coordinator wiring remain root's native runtime/capture verification.
