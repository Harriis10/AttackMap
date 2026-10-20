# WP015 native AI preferences

This slice adds native None/Review/Hunt/Hunt+verify/Remediate/Triage choices, optional jury/effort/speed/backend preferences, and explicit capability negotiation. It performs no HTTP request or authenticated CLI dispatch. Native visual and keyboard acceptance remain separate from compilation and model tests.

## Compatibility and preservation

`ProviderConfiguration` retains its original seven constructor fields and exact default JSON bytes. Optional 1.3 fields are omitted when null. Untouched profiles continue to serialize 1.1 requests; WP005 extended options still select 1.2. An explicit advanced preference selects 1.3 and must pass the selected engine's exact per-schema provider-field and six-mode declarations. Global capability lists cannot establish advanced compatibility. Existing identity, executable selection, unknown-option and analyzer checks remain active.

Stored preferences undergo structural validation. Request validation additionally rejects unsupported combinations: jury outside Hunt+verify or 1–7, CLI backend, conflicting None enablement, and tuning without AI. Engine declarations gate effort, speed, jury bounds and Fast's provider/backend/model allowlist. The UI explains requested effort separately from the advertised mapped effort. Fast availability never proves model availability, response completion or pricing; its premium cost disclosure remains visible.

AI is off on a new profile. The AI-off wire projection removes all advanced fields while preserving the stored preference, so unsupported advanced preferences do not prevent a deterministic scan using a legacy 1.1/1.2 engine. Switching engine/provider, restoring or resetting controls does not invoke Save or Test handlers. Unsupported saved values remain stored and explained; re-enabling an unsupported preference fails before dispatch. The API-only backend control is disabled with the strict-output-cap reason. Endpoint/model remain editable local fields, with existing HTTPS/literal-loopback and URL-credential guards.

`LocalSettingsStore` retains schema 1, recursive unknown-field preservation, duplicate-key rejection, atomic save and backup behavior. Advanced nulls are written explicitly only when replacing an advanced saved configuration so reset actually clears old tuning. Unknown provider properties remain marked and block requests, including attempts to write calculated native-only properties. Existing legacy settings do not gain null advanced fields on save.

Credentials stay in `PasswordBox` and the existing transient `ProviderAccessRequest`; JSON and diagnostic string exclude credentials. Save/Test continue to use the existing protected-store/action seam. This slice adds no credential setting or alternate store. The standalone preview intercepts both actions and performs no persistence or network I/O.

## Shell integration owned by root

No MainWindow, shared project, resource or tracker file was edited here. The native product SDK project automatically includes its C# files; isolated test/preview projects link the changed source directly.

1. Pass the selected `EngineCapabilities` to `Provider.ApplyCapabilities(...)` after explicit discovery and null on invalidation/switch. No discovery/provider action should run merely because a preference changes.
2. Retain `Provider.ReadConfiguration()` even while AI is off when saving preferences. MainWindow's previous `provider.EnableAi ? provider : null` drops those disabled preferences.
3. Before an explicit scan, use `Provider.ReadRequestConfiguration()` (or the equivalent `EngineCapabilities.RequireSupport` gate), retaining the original stored configuration. Request serialization uses the safe AI-off projection.
4. EngineProtocol 1.3 acceptance belongs to WP006. No EngineProtocol or EngineSession code was edited by this slice.
5. Protected provider actions should continue to store credentials through their current secret-store seam; ordinary local settings never receive the transient credential. `ProviderAccessRequest.Configuration` deliberately projects the established seven-field provider action contract; `Preferences` is JSON-ignored and contains the advanced configuration to retain in LocalSettings on explicit Save. Test uses only the legacy provider configuration and never persists preferences automatically.

## Standalone preview

Build `desktop/windows/WP015Preview/WP015Preview.csproj`, then launch its executable with the optional absolute path to `synthetic-capabilities.json`. Without a capability fixture advanced controls remain unavailable and saved values remain visible. The view has vertical scrolling and stacked action buttons for a small window; this design intent does not prove 200% text or keyboard acceptance. Native CUA access is unavailable in this session, so no visual or keyboard acceptance is claimed.

Focused verification and actual startup results are recorded separately in this folder. WP017 owns live LM Studio requests and real model response acceptance.

## Actual verification and STOP boundary

- Final `NativeAiOptions.Tests` run: **49 PASS**, zero engine/provider dispatches. Existing `NativeOptions.Tests`: **54 PASS**; existing `ProviderConfiguration.Tests`: **16 PASS**.
- The older `ProviderRoundtrip.Tests` was mistakenly invoked without arguments and failed immediately at `args[0]` with `IndexOutOfRangeException`. Its source then showed an explicit live `/models` call, so it was not rerun. It proves no roundtrip or HTTP acceptance. The unhandled exception may have produced the error popup reported by the user.
- The first standalone WinUI build succeeded with **0 errors**, **2 NU1900 warnings** (NuGet vulnerability-feed metadata unavailable), elapsed **8:32.86**. The final rebuild after the last small preview/metadata edits was interrupted by the user's STOP request, so it is not a final-source compilation claim.
- No preview executable was launched. No visual, keyboard, 200% text, native control journey or live HTTP acceptance was performed.
- On STOP, only the owned WP015 project process tree was terminated: dotnet PIDs **21884**, **26560**, and descendant conhost **20028**. Cleanup verification is retained in `cleanup.json`. No further native executable/test/preview launch is authorized in this turn.

Final UI compilation and manual acceptance remain pending. Keep WP015 in progress; do not infer full completion from the isolated model checks.

## Resumed verification — 2026-10-20

The resumed final-source preview build succeeded with **0 warnings, 0 errors** in **12:43.92** (`resume-preview-build.log`). Restore used only the existing `.tools/nuget-packages` cache and an empty local feed; NuGet audit was disabled. A fresh isolated `NativeAiOptions.Tests` build had **0 warnings, 0 errors**, and the managed DLL run passed **49 offline settings/capability/secret checks**, with zero engine/provider dispatches (`resume-native-ai-build.log`, `resume-native-ai-tests.log`). The earlier 54 NativeOptions and 16 ProviderConfiguration checks were not rerun in this resumed slice.

An optional capture seam was then added to the standalone preview. Its final-source incremental build succeeded with **0 warnings, 0 errors** in **4:37.85** (`resume-capture-build.log`), using `--no-restore` and inherited per-process `SetErrorMode(0x8003)` with the previous mode restored afterward. Root owns the preview launch and actual pixel review.

After a successful capture build, invoke the generated `WP015Preview.exe` with four arguments: the absolute synthetic capability fixture path, an absolute trace log path, `--capture`, and a **new absolute output directory**; append `--close` to exit after capture. Keep the first two positional paths present. The output directory must not already exist. No Save, Test, engine, provider, or local-settings action is dispatched. This optional journey renders a clean AI-off profile and overlapping viewport pages of supported Hunt+verify / max effort / three jury votes, then the same retained configuration after capability invalidation. It verifies supported request validation, unsupported request rejection, retained preferences, and inert AI-off reset. It writes `result.json` on success or `error.txt` on failure. Root must bound the launched process externally and inspect the generated PNGs; capture alone does not establish visual acceptance.

With the fixture, all six modes are enabled; jury is available only for Hunt+verify, within 1–7 votes. OpenAI requested xhigh/max maps to high. Fast is accepted only for the fixture's `claude` / `api` / `advertised-local-model` combination; that synthetic allowance does not demonstrate a provider/model exists or sends a request. Without capabilities, advanced mode/effort/speed/jury controls are disabled and retained values remain visible. CLI is always disabled with the strict-output-cap explanation. Provider endpoint/model and existing allowance fields remain editable. AI is off by default; Save/Test are intercepted in the standalone preview.

Still required: root's capture execution and actual visual review of every page, keyboard traversal, small-window/200% text acceptance, protected-store integration acceptance, and shell integration. WP017 separately owns live local-provider HTTP and completed model responses. WP015 remains in progress.

The first resumed root capture (`root-visual-resume-20261020/images/`) completed its inert journey and produced seven PNGs. Root's actual pixel inspection found a visual failure on scrolled supported/unsupported pages: content escaped the provider view and overlapped the fixed preview header. Those images remain retained as failed visual evidence. The standalone preview now sets a `RectangleGeometry` clip to the provider view's actual width/height on `SizeChanged`, preserving scrolling within its bounds. Its final-source offline build passed with **0 warnings, 0 errors**, exit **0**, elapsed **7:45.16** (`resume-clip-build.log`), with inherited per-process error-mode suppression restored afterward. A fresh root capture and review must establish whether this resolves the observed overlap. No product model or provider behavior changed.
