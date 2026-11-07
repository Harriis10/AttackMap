# Root integration additions (shared shell remains root-owned)

No application project/resource changes are required: SDK default compile inclusion
already includes `EngineCapabilities.cs`. This agent did not edit MainWindow or
EngineProtocol. The standalone `WP005Preview` is an isolated WinUI host, not a new
engine/package or release.

1. Keep a `LocalSettings loadedSettings = new();` snapshot and an
   `EngineCapabilitiesCache capabilityCache = new();` field. Restore with
   `loadedSettings = settings.Load()`; apply every supported option/provider field
   to controls. Reopen/restore/save/text changes must not call an engine action,
   provider check or model. Empty saved `PythonPath` means bundled default;
   resolve it with `EngineCapabilities.ResolveEngine(savedPath, AppContext.BaseDirectory)`
   only when the user chooses/checks/scans. Explicit paths use the existing
   EngineLaunchSpec static self-exe/Python-layout guard. No PATH lookup/download.

2. Add native controls named `BaselineOption`, `SuppressFileOption`,
   `FailOnNewHighOption`, `FailOnNewSuppressionOption`, `StrictSuppressionsOption`,
   `IsolatedAnalyzersOption`, and `TimeBudgetOption`. The preview shows the native
   layout and accessible labels. Budget is optional whole seconds, strictly below
   the existing hard timeout. File paths are fully absolute local paths. Extend
   ApplyScanOptions with all seven values; never clear a saved value merely because
   its control is disabled. Offer an explicit Reset advanced options button that
   clears just these seven values; normal Save persists that user decision.

3. Read preferences by starting from `loadedSettings.EffectiveOptions with { ... }`,
   updating the legacy controls plus these exact property mappings:

```csharp
Baseline = NullIfBlank(BaselineOption.Text),
SuppressFile = NullIfBlank(SuppressFileOption.Text),
FailOnNewHigh = FailOnNewHighOption.IsChecked == true,
FailOnNewSuppression = FailOnNewSuppressionOption.IsChecked == true,
StrictSuppressions = StrictSuppressionsOption.IsChecked == true,
IsolatedAnalyzers = IsolatedAnalyzersOption.IsChecked == true,
TimeBudgetSeconds = ParseOptionalWholeSeconds(TimeBudgetOption.Text),
Provider = Provider.ReadConfiguration()
```

   Validate with `Validate()` and `ParseModules`. Starting from the snapshot retains
   unknown option metadata/provider markers; `ValidateForRequest` then blocks
   unsupported saved fields instead of dropping them. Save preferences with
   `settings.Save(loadedSettings with { PythonPath = explicitPathOrEmpty,
   RepositoryPath = repositoryPath ?? "", Options = preferences,
   Modules = ModulesOption.Text.Trim() })`; refresh the snapshot with `settings.Load()`.
   The store merges unknown top-level/nested JSON, writes atomically, refuses
   corrupt/unknown-major overwrite and retains first original bytes beside the file
   as `.before-wp005.json`. Explicit Clear deletes both settings and that backup.

4. Keep disabled provider configuration in saved preferences. For the existing
   request path, preserve the previous default wire behavior by projecting
   `preferences with { Provider = preferences.Provider?.EnableAi == true ?
   preferences.Provider : null }`. The unknown-provider marker remains on that
   record and still blocks unsupported requests. `NativeScanRequest.Serialize`
   retains exact existing 1.1 default bytes and emits 1.2 only when one of the seven
   new properties is nondefault. Update the root-owned settings smoke expectation
   to distinguish saved disabled provider preferences from the unchanged off request.

5. Engine text/selection changes call `capabilityCache.Invalidate()` and show
   "Compatibility needs checking". On explicit Check compatibility or Scan:

```csharp
string executable = EngineCapabilities.ResolveEngine(explicitPathOrEmpty, AppContext.BaseDirectory);
capabilityCache.SelectEngine(executable); // hashes file again; catches same-path replacement
if (capabilityCache.Current == null)
{
    var result = await DesktopActionRunner.Run(executable, "capabilities", new { },
        cancellationToken: actionLifetime.Token);
    capabilityCache.Store(executable, EngineCapabilities.Parse(result.GetRawText()));
}
var capabilities = capabilityCache.Current!;
capabilities.RequireSupport(requestOptions, ModulesOption.Text);
```

   This discovery runs only the known action broker and never probes by launching
   a different executable or invoking help/GUI fallback. Existing DesktopActionRunner
   strips credentials for non-provider actions. Use `Option(name, requestedSchema)`
   and `Mode(name)` for disabled state/reason text. Advanced fields use schema1.2;
   legacy fields use1.1. Unsupported modes remain disabled even if a future engine
   advertises them. Analyzer names must exist in the returned installed inventory;
   applicability remains unknown until repository analysis.

6. Immediately before EngineSession.Run, also issue the read-only `preflight`
   action using a proposed request JSON object from NativeScanRequest.Serialize and
   `expected_identity = capabilities.ExpectedIdentity`. A dummy preflight run ID
   is fine because preflight does not admit/reserve/execute scans. If status is
   `engine_changed`, invalidate and require compatibility review again; all other
   unsupported states stop before dispatch. This catches source/module identity
   changes even when the Python host executable stayed the same. Do not silently
   drop options, retry with a lower schema or launch a fallback command.

7. Actual request dispatch uses the same resolved executable and request options.
   Preserve existing EngineSession/EngineProtocol process and identity checks. Root
   owns those shared composition tests plus visible/keyboard journey acceptance.
   Component model tests and synthetic preview control assertions are narrower.
