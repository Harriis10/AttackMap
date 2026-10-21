# WP016 component preparation — 21 October 2026

Scope: additive components for the existing full native product Reports surface. The standalone WP015 preview is not the product basis. This evidence does not close shell, visual, accessibility, export, or live-model acceptance.

Implemented `desktop/windows/AttackMap.NativeSpike/AI/AiArtifactProjection.cs` and `AI/AiArtifactsView.cs`. `AiArtifactsView` lives in `AttackMap.NativeSpike`; root integrates it into existing Reports without replacing its AI review or artifact browser. Its content has no nested ScrollViewer: use the existing Reports scrolling surface.

Integration API:

- `await view.SetSelection(capturedExportSelection)` after selected-report publication.
- `view.Clear()` immediately on reset, repository/report switch, or close. This invalidates pending reads and clears previous prose/metadata.
- `SetSelection(null)` clears and shows unavailable state. No method initiates provider traffic, opens links, executes prose, writes files, or changes the analyzed repository.

All file reads use existing `SelectedArtifacts.List` / `ReadText`, including `run-manifest.json` when manifest-listed. Every output requires both its manifest-listed Markdown and metadata. Legacy adjacent files are not read. Hash/manifest changes fail closed; a late load returns no result after cancellation or selection change. Invalid metadata clears the view with an unavailable notice.

Five mode sections map directly to `src/attackmap/desktop_ai.py` artifact pairs. Hunt and Hunt+verify intentionally share the core hypotheses file; the display distinguishes requested mode from selected section and does not invent verification. Completed status requires the matching run manifest's supplied completed status and model-output flag. Metadata-only historical output remains completion unknown. Deterministic triage explicitly states no completed model response. Missing usage is unknown; reference validity and claim support are separate, jury abstentions/failed passes and consensus are shown. Complete supplied metadata remains selectable for detailed inspection. Judgements are not presented as confirmed vulnerabilities.

Verification command (repository-local .NET SDK 8.0.426; repository-local CLI home and NuGet cache):

```powershell
& .tools/dotnet/dotnet.exe run --project desktop/windows/AiArtifacts.Tests/AiArtifacts.Tests.csproj -p:NuGetAudit=false
```

Result: **39 checks PASS**, exit 0. These are deterministic projection and captured-generation fixture checks: five-mode mapping/status/unknown usage/inert text, missing metadata/output, malformed JSON/object/count, fallback, abstentions, generation-bound reads, missing sections, delayed cancellation, changed output and changed report. No provider HTTP, GUI launch, native app build or visual acceptance performed by this component worker. Root owns full-app build, integration and actual UI review. Existing safety suites remain independent evidence; these checks do not substitute for WP017 live LM Studio acceptance.

Initial attempt with system `dotnet` failed because that installation has no SDK. Successful verification used `.tools/dotnet/dotnet.exe`; no SDK was downloaded or installed.
