# WP016 shutdown hardening — 21 October 2026

Root observed a full native smoke whose UI assertions passed, followed by native process exit `0xC0000005` at close without a managed UnhandledException. A pending AI/diagram continuation was a plausible hypothesis, not an established cause. This patch must not be described as fixing that native crash until root's full-shell reproduction verifies it.

The AI view previously invalidated reads when selection changed, but had no terminal lifetime state. Its async `SetSelection` could still update XAML after the window's owner lifetime ended if the owner never cleared/invalidated it. The smallest component change adds `AiArtifactsView.Stop()`: it marks the view stopped, increments its revision, stops the workspace and drops the managed snapshot. **Stop accesses no XAML properties or methods.** Repeated calls are safe. It is terminal: subsequent Clear/SetSelection/Show paths do not mutate controls.

Root wiring API:

```csharp
// Before/at window teardown; do not use Clear as the close-time API.
AiArtifacts.Stop();
// During normal report binding, await rather than fire-and-forget.
await AiArtifacts.SetSelection(selected);
```

The workspace has terminal Stop semantics and checks its stopped/epoch/selection state before and after every artifact I/O await. Its I/O awaits use `ConfigureAwait(false)` so internal file-reading continuations do not require the UI dispatcher. An existing in-flight read may finish; the component does not dispatch additional reads after observing Stop. The outer view retains the UI context needed for live rendering and checks stopped/revision after await, in its catch path and before Show. Root owns MainWindow/diagram lifetime wiring and actual native close validation; this worker changed neither.

Verification: `.tools/dotnet/dotnet.exe run --no-restore --project desktop/windows/AiArtifacts.Tests/AiArtifacts.Tests.csproj -p:NuGetAudit=false`, with repository-local DOTNET_ROOT, CLI home and NuGet cache: **45 checks PASS**, exit 0. The meaningful new deterministic test gates the first manifest listing, stops while it is pending, changes metadata bytes before releasing the listing, and asserts the load returns null without reading the changed metadata or doing final revalidation. It also verifies terminal Stop, rejected restart, idempotent Stop/Cancel and no I/O for subsequent missing-file selections. The internal constructor seam only replaces listing scheduling for this test; actual artifact text always retains SelectedArtifacts validation.

`git diff --check` for AI components/harness passed. No GUI launch, native app build, live provider request or native-crash acceptance was performed by this worker. WP024 final freeze remains on standby until root releases stable core/native sources.
