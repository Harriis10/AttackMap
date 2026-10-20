using AttackMap.NativeSpike;
using System.Text.Json;
using System.Text.Json.Nodes;

int checks = 0;
void Check(bool value, string name) { if (!value) throw new Exception(name); checks++; }
void Reject(Action action, string name) { try { action(); } catch (InvalidDataException) { checks++; return; } throw new Exception(name); }
var legacy = new ProviderConfiguration();
const string expected = "{\"enable_ai\":false,\"provider\":\"openai\",\"endpoint\":\"http://127.0.0.1:1234/v1\",\"model\":\"cyberstag-security-26b-a4b-v1\",\"max_calls\":8,\"timeout_seconds\":600,\"output_token_limit\":32000}";
Check(JsonSerializer.Serialize(legacy) == expected, "legacy provider bytes");
Check(new NativeScanOptions(Provider: legacy).RequestSchema == "1.1", "legacy 1.1");
Check(new NativeScanOptions(Provider: legacy, IsolatedAnalyzers: true).RequestSchema == "1.2", "WP005 1.2");
Check(!legacy.EnableAi, "AI off default");
var fields = new[] { "enable_ai", "provider", "endpoint", "model", "max_calls", "timeout_seconds", "output_token_limit", "mode", "jury_votes", "effort", "speed", "backend" };
var modes = new[] { "none", "review", "hunt", "hunt_verify", "remediate", "triage" };
JsonObject Fixture() => JsonSerializer.SerializeToNode(new {
    schema = 1, commands = new[] { "desktop-worker", "desktop-action" }, modules = Array.Empty<object>(),
    engine_identity = new { sha256 = new string('a', 64), path = Path.GetFullPath("engine.exe"), size_bytes = 1, runtime_kind = "Frozen" },
    desktop = new { schema_versions = new[] { "1.1", "1.2", "1.3" }, scan_options = new[] { "recall", "strict_analyzers", "no_suppress", "cve", "secrets_history", "timeout_seconds", "provider" },
        provider_options = fields, providers = new[] { "openai", "claude" }, modes,
        provider_options_by_schema = new Dictionary<string, string[]> { ["1.1"] = fields[..7], ["1.2"] = fields[..7], ["1.3"] = fields },
        modes_by_schema = new Dictionary<string, string[]> { ["1.1"] = modes[..2], ["1.2"] = modes[..2], ["1.3"] = modes },
        provider_tuning = new { minimum_schema = "1.3", backends = new[] { "api" }, speed = new[] { "standard", "fast" }, effort = new[] { "low", "medium", "high", "xhigh", "max" },
            jury_votes = new { minimum = 1, maximum = 7, mode = "hunt_verify", @default = 3 },
            openai_effort_mapping = new { low = "low", medium = "medium", high = "high", xhigh = "high", max = "high" },
            fast_speed = new { provider = "claude", backend = "api", models = new[] { "advertised-local-model" } } }
    }
})!.AsObject();
var fixture = Fixture();
if (args.Length == 1) File.WriteAllText(Path.GetFullPath(args[0]), fixture.ToJsonString());
var caps = EngineCapabilities.Parse(fixture.ToJsonString());
Check(caps.AdvancedAiAvailable, "exact advanced contract");
foreach (string mode in modes)
{
    var provider = legacy with { EnableAi = mode != "none", Mode = mode, Backend = "api", Speed = "standard" };
    Check(caps.Mode(mode).Enabled && caps.AiConfiguration(provider).Enabled, "mapped mode " + mode);
    var options = new NativeScanOptions(Provider: provider);
    caps.RequireSupport(options, "");
    using var wire = JsonDocument.Parse(NativeScanRequest.Serialize("id", "repo", "out", 1, options, ""));
    Check(wire.RootElement.GetProperty("schema_version").GetString() == (mode == "none" ? "1.1" : "1.3"), "explicit enabled 1.3; off remains legacy");
    Check(JsonSerializer.Deserialize<ProviderConfiguration>(JsonSerializer.Serialize(provider)) == provider, "mode roundtrip");
}
var jury = legacy with { EnableAi = true, Mode = "hunt_verify", JuryVotes = 7, Effort = "max", Backend = "api" };
Check(caps.AiConfiguration(jury).Enabled && caps.MappedEffort(jury) == "high", "requested max maps high");
Check(!caps.AiConfiguration(jury with { JuryVotes = 8 }).Enabled, "jury high bound");
Check(!caps.AiConfiguration(jury with { JuryVotes = 0 }).Enabled, "jury low bound");
Check(!caps.AiConfiguration(jury with { Mode = "review" }).Enabled, "jury mode guard");
Check(!caps.AiConfiguration(jury with { Backend = "cli" }).Enabled, "CLI fail closed");
Check(!caps.AiConfiguration(jury with { JuryVotes = null, Speed = "fast" }).Enabled, "OpenAI fast refused");
Check(caps.AiConfiguration(jury with { JuryVotes = null, Provider = "claude", Model = "advertised-local-model", Speed = "fast" }).Enabled, "advertised fast model");
foreach (string missing in new[] { "provider_options_by_schema", "modes_by_schema", "provider_tuning" })
{
    var partial = Fixture(); partial["desktop"]!.AsObject().Remove(missing);
    var unsupported = EngineCapabilities.Parse(partial.ToJsonString());
    Check(!unsupported.AdvancedAiAvailable && !unsupported.AiConfiguration(jury).Enabled, "no global inference " + missing);
    Check(unsupported.AiConfiguration(jury with { EnableAi = false }).Enabled, "disabled advanced preference does not block legacy " + missing);
}
var missingField = Fixture(); missingField["desktop"]!["provider_options_by_schema"]!["1.3"]!.AsArray().RemoveAt(11);
Check(!EngineCapabilities.Parse(missingField.ToJsonString()).AdvancedAiAvailable, "every exact field required");
var malformed = Fixture(); malformed["desktop"]!["provider_tuning"] = 1;
Check(!EngineCapabilities.Parse(malformed.ToJsonString()).AdvancedAiAvailable, "malformed tuning disabled");
var narrower = Fixture(); narrower["desktop"]!["modes_by_schema"]!["1.3"]!.AsArray().RemoveAt(5);
Check(!EngineCapabilities.Parse(narrower.ToJsonString()).AdvancedAiAvailable, "every exact mode required");
string root = Path.Combine(Path.GetTempPath(), "attackmap-wp015-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
try
{
    string path = Path.Combine(root, "settings.json"); var store = new LocalSettingsStore(path);
    store.Save(new LocalSettings(Options: new NativeScanOptions(Provider: jury)));
    Check(store.Load().EffectiveOptions.Provider == jury, "advanced settings roundtrip");
    var disabled = jury with { EnableAi = false, Backend = "cli", Speed = "fast" };
    store.Save(new LocalSettings(Options: new NativeScanOptions(Provider: disabled)));
    Check(store.Load().EffectiveOptions.Provider == disabled, "disabled unsupported preference retained");
    Check(caps.AiConfiguration(disabled).Enabled, "off projection strips unsupported tuning");
    using (var off = JsonDocument.Parse(NativeScanRequest.Serialize("id", "repo", "out", 1, new NativeScanOptions(Provider: disabled), "")))
    {
        var provider = off.RootElement.GetProperty("options").GetProperty("provider");
        Check(!provider.GetProperty("enable_ai").GetBoolean() && !provider.TryGetProperty("mode", out _) && !provider.TryGetProperty("jury_votes", out _), "off means no tuned dispatch");
    }
    store.Save(new LocalSettings(Options: new NativeScanOptions(Provider: legacy)));
    Check(store.Load().EffectiveOptions.Provider == legacy, "explicit reset clears old tuning");
    var original = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
    original["future"] = "retained"; original["Options"]!["provider"]!["future_provider"] = "retained";
    File.WriteAllText(path, original.ToJsonString());
    var unknown = store.Load(); store.Save(unknown);
    Check(File.ReadAllText(path).Contains("future_provider"), "unknown provider fields retained");
    Reject(() => unknown.EffectiveOptions.ValidateForRequest(), "unknown fields block request");
    store.Clear();
    var access = new ProviderAccessRequest(legacy, "CREDENTIAL_SENTINEL_WP015");
    Check(!JsonSerializer.Serialize(access).Contains("CREDENTIAL_SENTINEL_WP015") && !access.ToString().Contains("CREDENTIAL_SENTINEL_WP015"), "secret sentinel excluded");
    var advancedAccess = new ProviderAccessRequest(jury, "CREDENTIAL_SENTINEL_WP015");
    Check(advancedAccess.Preferences == jury && !advancedAccess.Configuration.RequiresSchema13 && !JsonSerializer.Serialize(advancedAccess).Contains("jury_votes"), "protected action contract remains legacy; preferences separate");
    Check(!Directory.EnumerateFiles(root).Any(), "isolated settings clear");
}
finally { Directory.Delete(root, true); }
Console.WriteLine($"PASS {checks} WP015 offline settings/capability/secret checks; zero engine/provider dispatches");
