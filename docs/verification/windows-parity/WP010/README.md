# WP010 native offline diagram slice

Status: IMPLEMENTED / MANUAL_PENDING for this owned slice. This adds only new owned files; it does not register a product navigation item or edit shared adapters/project/resources. Compilation, parser checks and a standalone preview are distinct from actual visual, keyboard, Narrator, contrast or network-disabled runtime acceptance.

## Decision

Current core emits `architecture.md`, `attackmap-paths.md` and `attackmap-topology.md`. Core attack-path Mermaid declares steps/impact then an explicit chain; topology declares ordered nodes and explicit labeled solid/dashed/undirected/thick edges. `src/attackmap/ui/web/src/mermaid-lite.js` is an existing offline JavaScript renderer, but using it would require active script execution and a browser surface. This slice uses framework-native Canvas/TextBlock/Polyline controls and a bounded inert Mermaid subset instead. No external renderer, package, CDN, web runtime, remote resource, SVG image loading or new license dependency is introduced. Repository-owned code remains under the repository license.

The parser retains supplied node and edge order, edge direction/operator, labels, parallel edges and self edges. Explicit chains expand only their supplied adjacent links. It refuses duplicate IDs and undeclared endpoints instead of inventing nodes/joins. Unknown syntax—including arbitrary Mermaid click/init directives—falls back to complete accepted source text. Only the exact core style annotations are accepted; arbitrary CSS is not interpreted. Labels remain native literal text, including hostile HTML, scripts and URLs. The fixed declaration-order grid is deterministic presentation, with no ranking/rescoring/reachability heuristics. Text includes all original accepted source plus the complete parsed node/edge lists, even when visual labels are shortened.

Bounds: selected artifact read ≤4 MiB, report validation ≤64 MiB, line ≤8192 characters, label ≤2048 characters, visual graph ≤120 nodes/240 edges. Unsupported or excessive visual structure retains its full accepted source as inert text. An artifact over the read bound is explicitly unavailable in this control and must be inspected/exported through the existing raw-artifact workflow; no truncated graph is presented as complete. A report with supplied limitations/resource events carries a completeness warning. Empty/missing/invalid states never imply a clean or complete system.

## Exact integration additions for the integrator

The primary project already uses SDK source globbing; new `AttackMap.NativeSpike/Diagram/*.cs` are included automatically. Do not add package references, script assets, resources or a WebView. Add a `DiagramView` instance to the existing navigation/content host using the same lifetime as the selected report. After obtaining the displayed report's existing captured `ExportSelection`, call:

```csharp
await diagramView.SetSelection(capturedSelection);
```

Call `await diagramView.SetSelection(null)` when clearing/replacing the report. Revision checks reject stale async results. Loading/error states clear the prior graph to avoid displaying another repository's diagram. `DiagramSelectionReader` delegates selected report/manifest/path/hash checks to the existing `SelectedArtifacts.List/ReadText` and never probes sibling diagram files by naming convention. Legacy unverified imports are refused.

Subscribe to `ExportTextRequested` before `SetSelection` to enable the export button. The event carries complete displayed text including snapshot notice; host must use its existing save picker/explicit path flow, enforce `capturedSelection.EnsureExportDestination(destination, sourceArtifactPath)`, and write inert UTF-8 `.txt` outside the selected generation. No destination is inferred by the control. Revalidate the captured selection through `DiagramSelectionReader.Read` before export if the host promises current on-disk integrity. The built-in copy button copies the displayed captured text only. Export is disabled until a host handler is present. Zoom, reset, touch/scroll pan and explicit keyboard-focusable directional buttons are local native operations.

The raw-source preview bypass is behind `DIAGRAM_STANDALONE_PREVIEW` and exists only in the isolated preview project; product builds expose only manifest-bound selection loading.

## Isolated verification commands

Use the bundled SDK and the repository's documented DOTNET_CLI_HOME/NUGET_PACKAGES directories:

```powershell
.tools/dotnet/dotnet.exe build desktop/windows/Diagram.Tests/Diagram.Tests.csproj --artifacts-path docs/verification/windows-parity/WP010/test-build
.tools/dotnet/dotnet.exe docs/verification/windows-parity/WP010/test-build/bin/Diagram.Tests/debug/Diagram.Tests.dll
.tools/dotnet/dotnet.exe build desktop/windows/Diagram.Tests/Preview/Diagram.Preview.csproj --artifacts-path docs/verification/windows-parity/WP010/preview-build --ignore-failed-sources
```

The standalone preview accepts `--dark`, `--empty`, `--hostile` and `--large`. Its data is explicitly synthetic. Run the built preview EXE for review; it does not access a repository, invoke an engine or change the selected installation. Product navigation integration is intentionally left to the integrator. Real visual/keyboard/accessibility and network-disabled runtime review remain acceptance gates, not inferred from compilation or tests.

## Actual bounded verification

The isolated contract executable passed **20 checks**, and both its build and the standalone WinUI preview build passed with zero warnings/errors. Initial builds lacked the existing RunPresentation identity source reference; this was corrected only in the new isolated projects.

Startup is not accepted: the first preview process (21184) had no window handle after its bounded launch check and had exited before a later recheck. A second launch with explicit bundled DOTNET_ROOT (15084) likewise had no window handle and later exited; redirected stderr was empty. A third bounded lifecycle check (17268) recorded the process alive after 20 seconds with window handle zero; no exit code was available in that check. See `preview-launch.json`, `preview-launch-runtime.json` and `preview-lifecycle.json`. No rendered window was observed, and the cause is unresolved; it is not attributed to CUA. Diagnostic-only exception logging was added solely to the preview project, without further launch attempts after the coordinator's stop instruction. Cleanup evidence is in `preview-cleanup.json`.

Native CUA APIs are unavailable here. Actual visual, keyboard, Narrator, contrast/scaling, network-disabled runtime and integrated navigation/export acceptance therefore remain open. No fixture/unit check or compilation result is presented as those acceptance results.
