using System.Text.Json;
using System.Text.Json.Nodes;
using System.Security.Cryptography;
using AttackMap.NativeSpike;

int checks = 0;
void Check(bool value, string reason) { if (!value) throw new Exception(reason); checks++; }
void Rejected(Action action, string reason) { bool rejected = false; try { action(); } catch (Exception error) when (error is InvalidDataException or JsonException) { rejected = true; } Check(rejected, reason); }
string folder = Path.Combine(Path.GetTempPath(), "attackmap-wp005-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(folder);
try
{
    var defaults = new NativeScanOptions();
    string original = JsonSerializer.Serialize(new { schema_version = "1.1", kind = "request", run_id = "r", repository_id = folder,
        generation = 1L, revision = 0, repository_path = folder, output_path = folder,
        modules = Array.Empty<string>(), options = new { recall = false, strict_analyzers = false, no_suppress = false, cve = false, secrets_history = 0, timeout_seconds = 600 } });
    Check(NativeScanRequest.Serialize("r", folder, folder, 1, defaults, "") == original, "Existing 1.1 default wire bytes must remain exact");
    var advanced = new NativeScanOptions(Recall: true, StrictAnalyzers: true, Cve: true, SecretsHistory: 12, TimeoutSeconds: 37,
        Provider: new ProviderConfiguration(EnableAi: false, Provider: "claude", Endpoint: "http://localhost:4321/v1", Model: "fixture-local-model", MaxCalls: 5, TimeoutSeconds: 333, OutputTokenLimit: 1234), Baseline: Path.Combine(folder, "baseline.json"),
        SuppressFile: Path.Combine(folder, "suppressions.yml"), FailOnNewHigh: true, FailOnNewSuppression: true,
        StrictSuppressions: true, IsolatedAnalyzers: true, TimeBudgetSeconds: 17);
    var wire = JsonNode.Parse(NativeScanRequest.Serialize("r", folder, folder, 1, advanced, "config"))!.AsObject();
    Check(wire["schema_version"]!.GetValue<string>() == "1.2", "Used extended options require 1.2");
    var sentinels = new Dictionary<string, object?> { ["baseline"] = advanced.Baseline, ["suppress_file"] = advanced.SuppressFile,
        ["fail_on_new_high"] = true, ["fail_on_new_suppression"] = true, ["strict_suppressions"] = true,
        ["isolated_analyzers"] = true, ["time_budget_seconds"] = 17 };
    foreach (var entry in sentinels) Check(wire["options"]![entry.Key]!.ToJsonString() == JsonSerializer.Serialize(entry.Value), "Nondefault sentinel lost: " + entry.Key);
    foreach (var value in new[] { "relative.json", "C:relative.json", "\\\\server\\share\\a.json", "https://host/a.json", "C:\\a\n.json" })
        Rejected(() => (defaults with { Baseline = value }).Validate(), "Relative/network/control paths rejected");
    Rejected(() => (defaults with { FailOnNewHigh = true }).Validate(), "Policy needs baseline");
    Rejected(() => (advanced with { NoSuppress = true }).Validate(), "Conflicting suppression choices rejected");
    foreach (int seconds in new[] { 0, -1, 600, 86401 }) Rejected(() => (defaults with { TimeBudgetSeconds = seconds }).Validate(), "Soft budget range/hard timeout enforced");

    string settingsPath = Path.Combine(folder, "settings.json");
    var store = new LocalSettingsStore(settingsPath);
    Check(store.Load() == new LocalSettings(), "Missing settings stay local/default");
    string old = "{\"SchemaVersion\":1,\"PythonPath\":\"\",\"RepositoryPath\":\"\",\"future_ui\":{\"x\":42}}";
    File.WriteAllText(settingsPath, old);
    var loaded = store.Load();
    Check(loaded.EffectiveOptions == defaults && File.ReadAllText(settingsPath) == old, "Old path-only settings load without rewrite");
    store.Save(loaded with { PythonPath = Path.Combine(folder, "engine", "attackmap.exe"), Options = advanced, Modules = "config", RepositoryPath = folder });
    var reopened = new LocalSettingsStore(settingsPath).Load();
    Check(reopened.EffectiveOptions == advanced && reopened.Modules == "config", "All supported settings roundtrip on reopen");
    Check(reopened.PythonPath == Path.Combine(folder, "engine", "attackmap.exe") && reopened.RepositoryPath == folder, "Explicit engine/repository paths roundtrip without execution");
    Check(JsonNode.Parse(File.ReadAllText(settingsPath))!["future_ui"]!["x"]!.GetValue<int>() == 42, "Unknown top-level settings retained");
    Check(File.ReadAllText(settingsPath + ".before-wp005.json") == old, "Original old bytes preserved before migration/save");
    store.Save(reopened with { Options = defaults });
    Check(store.Load().EffectiveOptions == defaults, "Resetting known values actually clears prior true/non-null fields");
    string unknown = "{\"SchemaVersion\":1,\"PythonPath\":\"\",\"RepositoryPath\":\"\",\"Options\":{\"future_knob\":13,\"provider\":{\"future_provider_knob\":7}}}";
    File.WriteAllText(settingsPath, unknown);
    var future = store.Load();
    Rejected(() => NativeScanRequest.Serialize("r", folder, folder, 1, future.EffectiveOptions, ""), "Unknown options cannot disappear into a request");
    store.Save(future with { Modules = "config" });
    var retained = JsonNode.Parse(File.ReadAllText(settingsPath))!;
    Check(retained["Options"]!["future_knob"]!.GetValue<int>() == 13 && retained["Options"]!["provider"]!["future_provider_knob"]!.GetValue<int>() == 7, "Unknown nested options preserved losslessly across save");
    foreach (string bad in new[] { "{broken", "{\"SchemaVersion\":99}", "{\"SchemaVersion\":1,\"SchemaVersion\":1}" })
    {
        File.WriteAllText(settingsPath, bad);
        Rejected(() => store.Load(), "Corrupt/unknown-major/duplicate settings rejected");
        Rejected(() => store.Save(new()), "Unloaded corrupt/future settings cannot be overwritten");
        Check(File.ReadAllText(settingsPath) == bad, "Invalid original remains exact");
    }
    store.Clear();
    Check(store.Load() == new LocalSettings(), "Explicit clear re-enables defaults");

    string engineDir = Path.Combine(folder, "engine"); Directory.CreateDirectory(engineDir);
    string executable = Path.Combine(engineDir, "attackmap.exe"); File.WriteAllText(executable, "first-engine");
    Check(EngineCapabilities.ResolveEngine("", folder) == executable, "Bundled path is the simple default; no PATH search");
    string legacyDirectory = Path.Combine(folder, "legacy"); Directory.CreateDirectory(legacyDirectory);
    string legacyEngine = Path.Combine(legacyDirectory, "attackmap.exe"); File.WriteAllText(legacyEngine, "legacy-engine");
    Check(EngineCapabilities.RestoreEngineSelection(legacyEngine, folder) == legacyEngine, "Nonportable startup preserves an existing explicit engine");
    Check(EngineCapabilities.RestoreEngineSelection(Path.Combine(folder, "removed.exe"), folder) == executable, "Missing saved engine retains bundled fallback");
    string portableMarker = Path.Combine(folder, "portable-manifest.json");
    string validMarker = "{\"schema_version\":1,\"kind\":\"portable-development-preview\",\"runtime\":{\"engine\":\"engine/attackmap.exe\"}}";
    File.WriteAllText(portableMarker, validMarker);
    store.Save(new LocalSettings(PythonPath: legacyEngine, RepositoryPath: folder, Options: advanced, Modules: "config"));
    string retainedSettings = File.ReadAllText(settingsPath);
    Check(EngineCapabilities.RestoreEngineSelection(legacyEngine, folder) == executable, "Portable startup ignores a legacy global engine even while that executable exists");
    Check(EngineCapabilities.RestoreEngineSelection("", folder) == executable, "Fresh portable startup selects the same bundle");
    Check(File.ReadAllText(settingsPath) == retainedSettings, "Startup selection never rewrites user settings");
    Check(EngineCapabilities.ResolveEngine(legacyEngine, folder) == legacyEngine, "Explicit runtime selection after startup still wins");
    File.WriteAllText(portableMarker, "{broken");
    Rejected(() => EngineCapabilities.RestoreEngineSelection(legacyEngine, folder), "Malformed portable metadata never silently selects legacy engine");
    File.WriteAllText(portableMarker, validMarker.Replace("\"schema_version\":1", "\"schema_version\":2"));
    Rejected(() => EngineCapabilities.RestoreEngineSelection(legacyEngine, folder), "Unsupported portable schema reports incomplete package");
    File.WriteAllText(portableMarker, validMarker);
    File.Move(executable, executable + ".retained");
    Rejected(() => EngineCapabilities.RestoreEngineSelection(legacyEngine, folder), "Missing portable bundle never falls back to a legacy global engine");
    File.Move(executable + ".retained", executable);
    File.Delete(portableMarker);
    Rejected(() => EngineCapabilities.ResolveEngine("missing.exe", folder), "Advanced engine must be an explicit existing absolute path");
    Rejected(() => EngineCapabilities.ResolveEngine(Environment.ProcessPath!, folder), "Existing self-exe guard preserved");
    string Hash() { using var stream = File.OpenRead(executable); return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant(); }
    string[] common = new[] { "recall", "strict_analyzers", "no_suppress", "cve", "secrets_history", "timeout_seconds", "provider" };
    JsonObject Document() => JsonSerializer.SerializeToNode(new { schema = 1, commands = new[] { "desktop-worker", "desktop-action" },
        engine_identity = new { path = executable, sha256 = Hash(), size_bytes = new FileInfo(executable).Length, runtime_kind = "Frozen" },
        modules = new[] { new { name = "config", display_name = "Configuration", experimental = false } },
        desktop = new { schema_versions = new[] { "1.0", "1.1", "1.2" }, scan_options = common.Concat(sentinels.Keys).ToArray(),
            scan_options_by_schema = new Dictionary<string, string[]> { ["1.0"] = common, ["1.1"] = common, ["1.2"] = common.Concat(sentinels.Keys).ToArray() },
            provider_options = new[] { "enable_ai", "provider", "endpoint", "model", "max_calls", "timeout_seconds", "output_token_limit" }, modes = new[] { "none", "review", "hunt" }, providers = new[] { "openai", "claude" } } })!.AsObject();
    var caps = EngineCapabilities.Parse(Document().ToJsonString());
    Check(caps.Compatible && caps.Option("baseline").Enabled && !caps.Option("baseline", "1.1").Enabled, "Per-schema options consumed");
    caps.RequireSupport(advanced, "config"); checks++;
    Check(!caps.Mode("hunt").Enabled && caps.Mode("hunt").Reason.Length > 20, "Unsupported desktop modes disabled even if engine advertises them");
    Check(!caps.Option("invented").Enabled, "Unknown desktop field disabled");
    Rejected(() => caps.RequireSupport(defaults, "missing-analyzer"), "Unavailable explicit analyzer never replaced");
    var older = Document(); older["desktop"]!["schema_versions"] = JsonSerializer.SerializeToNode(new[] { "1.0", "1.1" });
    Rejected(() => EngineCapabilities.Parse(older.ToJsonString()).RequireSupport(advanced, ""), "Old engine rejects new schema/options");
    Check(!EngineCapabilities.Parse("{\"schema\":99}").Compatible && !EngineCapabilities.Parse("{\"schema\":1}").Compatible, "Future major and legacy engine disabled explicitly");
    Rejected(() => EngineCapabilities.Parse("{\"schema\":1,\"desktop\":null}"), "Malformed capabilities rejected");
    var cache = new EngineCapabilitiesCache(); cache.Store(executable, caps);
    var fleetDocument = Document();
    fleetDocument["desktop"]!["schema_versions"] = JsonSerializer.SerializeToNode(new[] { "1.0", "1.1", "1.2", "1.4" });
    string[] fleetFields = new[] { "timeout_seconds", "isolated_analyzers", "time_budget_seconds", "analyzer_profile" };
    fleetDocument["desktop"]!["scan_options_by_schema"]!["1.4"] = JsonSerializer.SerializeToNode(fleetFields);
    fleetDocument["desktop"]!["fleet_by_schema"] = JsonSerializer.SerializeToNode(new { v = 0 });
    fleetDocument["desktop"]!["fleet_by_schema"]!["1.4"] = JsonSerializer.SerializeToNode(new { multi_repo = true, maximum_workers = 4 });
    var fleetWire = JsonSerializer.SerializeToElement(new { timeout_seconds = 600, isolated_analyzers = true });
    EngineCapabilities.Parse(fleetDocument.ToJsonString()).RequireFleetSupport(fleetWire, "config", 2); checks++;
    var profileWire = JsonSerializer.SerializeToElement(new { timeout_seconds = 600, analyzer_profile = "node-atproto@1.0" });
    Rejected(() => EngineCapabilities.Parse(fleetDocument.ToJsonString()).RequireFleetSupport(profileWire, "", 1), "Legacy fleet declaration cannot silently ignore named profiles");
    fleetDocument["desktop"]!["fleet_by_schema"]!["1.4"]!["scan_options"] = JsonSerializer.SerializeToNode(fleetFields);
    fleetDocument["analyzer_profiles"] = JsonSerializer.SerializeToNode(new { schema_version = "1.0", profiles = new[] { new { qualified_name = "node-atproto@1.0", available = true } } });
    EngineCapabilities.Parse(fleetDocument.ToJsonString()).RequireFleetSupport(profileWire, "", 4); checks++;
    Rejected(() => EngineCapabilities.Parse(fleetDocument.ToJsonString()).RequireFleetSupport(profileWire, "config", 1), "Profile and explicit modules are exclusive");
    Rejected(() => EngineCapabilities.Parse(fleetDocument.ToJsonString()).RequireFleetSupport(fleetWire, "missing", 1), "Fleet cannot replace unavailable explicit analyzers");
    fleetDocument["analyzer_profiles"]!["profiles"]![0]!["available"] = false;
    Rejected(() => EngineCapabilities.Parse(fleetDocument.ToJsonString()).RequireFleetSupport(profileWire, "", 1), "Unavailable fleet profile is rejected before launch");
    Check(cache.Current == caps, "Capabilities cached only for selected identity");
    File.WriteAllText(executable, "other-engine"); cache.SelectEngine(executable);
    Check(cache.Current == null, "Same path/version/length changed executable invalidates cache");
    Rejected(() => cache.Store(executable, caps), "Stale discovery identity rejected");
    string otherDir = Path.Combine(folder, "other"); Directory.CreateDirectory(otherDir);
    string otherExe = Path.Combine(otherDir, "attackmap.exe"); File.WriteAllText(otherExe, "other-engine");
    cache.Store(executable, EngineCapabilities.Parse(Document().ToJsonString())); cache.SelectEngine(otherExe);
    Check(cache.Current == null, "Engine switch invalidates cached options");
    Console.WriteLine($"NativeOptions: {checks} checks passed; settings/model/capability seams only, no engine/provider process.");
}
finally { Directory.Delete(folder, recursive: true); }
