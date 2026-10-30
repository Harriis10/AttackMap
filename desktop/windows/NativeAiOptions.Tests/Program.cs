using AttackMap.NativeSpike;
using System.Text.Json;
using System.Text.Json.Nodes;

int checks = 0;
void Check(bool value, string name) { if (!value) throw new Exception(name); checks++; }
void Reject(Action action, string name) { try { action(); } catch (InvalidDataException) { checks++; return; } throw new Exception(name); }
var qaDefaults = ParitySmokeTimeouts.Parse([]);
Check(qaDefaults == new ParitySmokeTimeouts(900, 1200, 1500), "QA default timeouts unchanged");
var qaLong = ParitySmokeTimeouts.Parse(["--qa-provider-timeout", "3600", "--qa-scan-timeout", "4200", "--qa-harness-timeout", "4500"]);
Check(qaLong == new ParitySmokeTimeouts(3600, 4200, 4500), "explicit long local QA timeouts");
using (var longWire = JsonDocument.Parse(NativeScanRequest.Serialize("qa", "repo", "out", 1,
    new NativeScanOptions(TimeoutSeconds: qaLong.ScanTimeoutSeconds,
        Provider: new ProviderConfiguration(true, TimeoutSeconds: qaLong.ProviderTimeoutSeconds) with { Mode = "hunt_verify", Backend = "api", Speed = "standard" }), "")))
{
    var options = longWire.RootElement.GetProperty("options");
    var provider = options.GetProperty("provider");
    Check(options.GetProperty("timeout_seconds").GetInt32() == 4200 && provider.GetProperty("timeout_seconds").GetInt32() == 3600, "long QA timeouts reach request exactly");
    Check(provider.GetProperty("max_calls").GetInt32() == 8 && provider.GetProperty("output_token_limit").GetInt32() == 32000 && !provider.TryGetProperty("jury_votes", out _), "QA timeouts preserve calls/tokens/default jury");
}
Check(JsonSerializer.Serialize(qaLong) == "{\"provider_timeout_seconds\":3600,\"scan_timeout_seconds\":4200,\"harness_timeout_seconds\":4500}", "QA proof timeout triplet");
ParitySmokeTimeouts.Parse(["--qa-provider-timeout", "3600", "--qa-scan-timeout", "3600", "--qa-harness-timeout", "3601"]);
Check(true, "provider may equal scan");
ParitySmokeTimeouts.Parse(["--qa-scan-timeout", "7199", "--qa-harness-timeout", "7200"]);
Check(true, "previous QA harness bound remains accepted");
ParitySmokeTimeouts.Parse(["--qa-scan-timeout", "10799", "--qa-harness-timeout", "10800"]);
Check(true, "new QA harness upper bound accepted");
var qaExtended = ParitySmokeTimeouts.Parse(["--qa-provider-timeout", "7200", "--qa-scan-timeout", "7800", "--qa-harness-timeout", "8100"]);
Check(qaExtended == new ParitySmokeTimeouts(7200, 7800, 8100), "explicit shared local allowance triplet");
Reject(() => new ParitySmokeTimeouts(7201, 7800, 8100).Validate(), "provider upper bound rejected independently of ordering");
Check(JsonSerializer.Serialize(qaExtended) == "{\"provider_timeout_seconds\":7200,\"scan_timeout_seconds\":7800,\"harness_timeout_seconds\":8100}", "extended QA proof triplet");
using (var extendedWire = JsonDocument.Parse(NativeScanRequest.Serialize("qa", "repo", "out", 1,
    new NativeScanOptions(TimeoutSeconds: qaExtended.ScanTimeoutSeconds,
        Provider: new ProviderConfiguration(true, TimeoutSeconds: qaExtended.ProviderTimeoutSeconds) with { Mode = "hunt_verify", Backend = "api", Speed = "standard" }), "")))
{
    var options = extendedWire.RootElement.GetProperty("options");
    var provider = options.GetProperty("provider");
    Check(options.GetProperty("timeout_seconds").GetInt32() == 7800 && provider.GetProperty("timeout_seconds").GetInt32() == 7200, "extended timeouts serialize exactly");
    Check(provider.GetProperty("max_calls").GetInt32() == 8 && provider.GetProperty("output_token_limit").GetInt32() == 32000 && !provider.TryGetProperty("jury_votes", out _), "extended allowance preserves calls/tokens/default jury");
}
new NativeScanOptions(TimeoutSeconds: 86400).Validate();
Check(true, "product scan upper bound unchanged");
foreach (string[] invalid in new[] {
    new[] { "--qa-provider-timeout", "0" }, new[] { "--qa-provider-timeout", "7201" },
    new[] { "--qa-scan-timeout", "0" }, new[] { "--qa-scan-timeout", "86401", "--qa-harness-timeout", "7200" },
    new[] { "--qa-harness-timeout", "10801" }, new[] { "--qa-harness-timeout", "1200" },
    new[] { "--qa-provider-timeout", "1201" }, new[] { "--qa-provider-timeout" },
    new[] { "--qa-provider-timeout", "1.5" }, new[] { "--qa-provider-timeout", "2147483648" },
    new[] { "--qa-provider-timeout", "900", "--qa-provider-timeout", "901" },
    new[] { "--qa-provider-timeout=3600" } })
    Reject(() => ParitySmokeTimeouts.Parse(invalid), "invalid QA timeouts rejected: " + string.Join(" ", invalid));
var legacy = new ProviderConfiguration();
const string expected = "{\"enable_ai\":false,\"provider\":\"openai\",\"endpoint\":\"http://127.0.0.1:1234/v1\",\"model\":\"cyberstag-security-26b-a4b-v1\",\"max_calls\":8,\"timeout_seconds\":600,\"output_token_limit\":32000}";
Check(JsonSerializer.Serialize(legacy) == expected, "legacy provider bytes");
Check(new NativeScanOptions(Provider: legacy).RequestSchema == "1.1", "legacy 1.1");
Check(new NativeScanOptions(Provider: legacy, IsolatedAnalyzers: true).RequestSchema == "1.2", "WP005 1.2");
Check(!legacy.EnableAi, "AI off default");
foreach (string endpoint in new[] { "http://localhost/v1", "http://127.0.0.1:1234/v1", "http://[::1]:1234/v1", "HTTP://LOCALHOST:1234/v1", "  http://localhost:1234/v1  ", "http://[::1]", "http://localhost:65535/v1" })
foreach (int seconds in new[] { 3601, 7200 })
{
    (legacy with { Endpoint = endpoint, TimeoutSeconds = seconds }).Validate();
    Check(true, "explicit local allowance accepted: " + endpoint + "/" + seconds);
}
foreach (var restricted in new[] {
    legacy with { Endpoint = null }, legacy with { Endpoint = "" },
    legacy with { Endpoint = "https://api.openai.com/v1" },
    legacy with { Endpoint = "https://localhost/v1" }, legacy with { Provider = "claude" },
    legacy with { Endpoint = "http://127.0.0.1.evil.invalid/v1" },
    legacy with { Endpoint = "http://127.1/v1" }, legacy with { Endpoint = "http://2130706433/v1" },
    legacy with { Endpoint = "http://0177.0.0.1/v1" }, legacy with { Endpoint = "http://0x7f000001/v1" },
    legacy with { Endpoint = "http://[0:0:0:0:0:0:0:1]/v1" }, legacy with { Endpoint = "http://[::01]/v1" },
    legacy with { Endpoint = "http://localhost:0/v1" }, legacy with { Endpoint = "http://localhost:/v1" },
    legacy with { Endpoint = "http://localhost:invalid/v1" }, legacy with { Endpoint = "http://localhost:65536/v1" },
    legacy with { Endpoint = "http://user@localhost/v1" }, legacy with { Endpoint = "http://localhost/v1?x=1" },
    legacy with { Endpoint = "http://localhost/v1#fragment" }, legacy with { Endpoint = "http://localhost/v1?" },
    legacy with { Endpoint = "http://localhost/v1#" }, legacy with { Backend = "cli" } })
    Reject(() => (restricted with { TimeoutSeconds = 3601 }).Validate(), "extended allowance refused outside explicit local API: " + restricted.Endpoint);
(legacy with { Endpoint = "https://api.openai.com/v1", TimeoutSeconds = 3600 }).Validate();
Check(true, "remote 3600 bound preserved");
Reject(() => (legacy with { TimeoutSeconds = 0 }).Validate(), "zero local allowance refused");
Reject(() => (legacy with { TimeoutSeconds = 7201 }).Validate(), "local allowance upper bound");
Reject(() => (legacy with { EnableAi = true, TimeoutSeconds = 7200, Backend = "cli" }).ValidateForRequest(), "extended CLI request refused");
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
var profileDocument = Fixture();
profileDocument["desktop"]!["schema_versions"] = JsonSerializer.SerializeToNode(new[] { "1.1", "1.2", "1.3", "1.5" });
profileDocument["desktop"]!["scan_options_by_schema"] = JsonSerializer.SerializeToNode(new Dictionary<string, string[]> {
    ["1.5"] = new[] { "recall", "strict_analyzers", "no_suppress", "cve", "secrets_history", "timeout_seconds", "provider", "analyzer_profile" } });
profileDocument["desktop"]!["provider_options_by_schema"]!["1.5"] = JsonSerializer.SerializeToNode(fields);
profileDocument["desktop"]!["modes_by_schema"]!["1.5"] = JsonSerializer.SerializeToNode(modes);
var profileCaps = EngineCapabilities.Parse(profileDocument.ToJsonString());
var profileRequest = new NativeScanOptions(Provider: jury, AnalyzerProfile: "node-atproto@1.0");
profileCaps.RequireSupport(profileRequest, "");
Check(profileRequest.RequestSchema == "1.5" && profileCaps.AiConfiguration(jury, "1.5").Enabled, "Profile schema explicitly preserves advanced provider mapping");
Reject(() => caps.RequireSupport(profileRequest, ""), "Old schema cannot silently ignore named profile");
Reject(() => profileCaps.RequireSupport(profileRequest, "config"), "Named profile cannot combine modules at capability admission");
profileDocument["desktop"]!["provider_options_by_schema"]!.AsObject().Remove("1.5");
Check(!EngineCapabilities.Parse(profileDocument.ToJsonString()).AiConfiguration(jury, "1.5").Enabled, "Profile schema cannot infer provider fields from global inventory");
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
    var extendedPreference = jury with { TimeoutSeconds = 7200 };
    store.Save(new LocalSettings(Options: new NativeScanOptions(Provider: extendedPreference)));
    Check(store.Load().EffectiveOptions.Provider == extendedPreference, "explicit local allowance settings roundtrip");
    Reject(() => (extendedPreference with { Endpoint = "https://api.openai.com/v1" }).ValidateForRequest(), "retained local allowance rejects remote switch without clamping");
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
