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
