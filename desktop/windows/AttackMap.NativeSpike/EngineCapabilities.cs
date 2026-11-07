using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AttackMap.NativeSpike;

public sealed record CapabilityAvailability(bool Enabled, string Reason);
public sealed record AnalyzerCapability(string Name, string DisplayName, bool Experimental);

/// <summary>Inert capability data. Parsing/validation never launches an engine or provider.</summary>
public sealed class EngineCapabilities
{
    private readonly JsonElement document;
    private readonly HashSet<string> commands = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HashSet<string>> optionsBySchema = new(StringComparer.Ordinal);
    private readonly HashSet<string> providerOptions = new(StringComparer.Ordinal);
    private readonly HashSet<string> modes = new(StringComparer.Ordinal);
    private readonly HashSet<string> providers = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HashSet<string>> providerBySchema = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HashSet<string>> modesBySchema = new(StringComparer.Ordinal);
    public IReadOnlySet<string> SchemaVersions { get; private set; } = new HashSet<string>();
    public IReadOnlyList<AnalyzerCapability> Analyzers { get; private set; } = Array.Empty<AnalyzerCapability>();
    public bool Compatible { get; private set; }
    public string Reason { get; private set; } = "Engine compatibility has not been checked.";
    public string? EngineSha256 { get; private set; }
    public JsonElement? ExpectedIdentity => document.TryGetProperty("engine_identity", out var identity) ? identity.Clone() : null;

    private EngineCapabilities(JsonElement document) { this.document = document.Clone(); }
    public static EngineCapabilities Parse(string json)
    {
        try
        {
            if (System.Text.Encoding.UTF8.GetByteCount(json) > 4 * 1024 * 1024) throw new InvalidDataException();
            using var parsed = JsonDocument.Parse(json);
            var root = parsed.RootElement;
            UniqueKeys(root);
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("schema", out var schema) || !schema.TryGetInt32(out int number)) throw new InvalidDataException();
            var result = new EngineCapabilities(root);
            if (number != 1) { result.Reason = "Unsupported capability document version. Choose a compatible engine; no request was sent."; return result; }
            if (!root.TryGetProperty("desktop", out var desktop)) { result.Reason = "Legacy engine does not advertise desktop schema/options. Choose a compatible bundled or explicit engine."; return result; }
            if (desktop.ValueKind != JsonValueKind.Object) throw new InvalidDataException();
            result.commands.UnionWith(Strings(root.GetProperty("commands")));
            result.SchemaVersions = Strings(desktop.GetProperty("schema_versions"));
            var common = Strings(desktop.GetProperty("scan_options"));
            foreach (string version in result.SchemaVersions)
                result.optionsBySchema[version] = desktop.TryGetProperty("scan_options_by_schema", out var bySchema) && bySchema.TryGetProperty(version, out var selected) ? Strings(selected) : common;
            result.providerOptions.UnionWith(Strings(desktop.GetProperty("provider_options")));
            result.modes.UnionWith(Strings(desktop.GetProperty("modes")));
            result.providers.UnionWith(Strings(desktop.GetProperty("providers")));
            foreach (string version in result.SchemaVersions)
            {
                // Advanced negotiation requires explicit per-schema declarations; never infer 1.3 from global lists.
                if (desktop.TryGetProperty("provider_options_by_schema", out var providerSchemas) && providerSchemas.TryGetProperty(version, out var providerFields)) result.providerBySchema[version] = Strings(providerFields);
                else if (version is not ("1.3" or "1.5")) result.providerBySchema[version] = result.providerOptions;
                if (desktop.TryGetProperty("modes_by_schema", out var modeSchemas) && modeSchemas.TryGetProperty(version, out var modeFields)) result.modesBySchema[version] = Strings(modeFields);
                else if (version is not ("1.3" or "1.5")) result.modesBySchema[version] = result.modes;
            }
            var identity = root.GetProperty("engine_identity");
            string hash = identity.GetProperty("sha256").GetString()!;
            if (hash == null || hash.Length != 64 || hash.Any(c => !"0123456789abcdef".Contains(c))) throw new InvalidDataException();
            string? identityPath = identity.GetProperty("path").GetString();
            if (identityPath == null || !Path.IsPathFullyQualified(identityPath) || identity.GetProperty("size_bytes").GetInt64() < 1 ||
                identity.GetProperty("runtime_kind").GetString() is not ("Python" or "Frozen")) throw new InvalidDataException();
            result.EngineSha256 = hash;
            var modules = root.GetProperty("modules");
            if (modules.ValueKind != JsonValueKind.Array || modules.GetArrayLength() > 1024) throw new InvalidDataException();
            result.Analyzers = modules.EnumerateArray().Select(item => new AnalyzerCapability(
                item.GetProperty("name").GetString() ?? throw new InvalidDataException(),
                item.TryGetProperty("display_name", out var display) ? display.GetString() ?? "Unnamed analyzer" : item.GetProperty("name").GetString()!,
                item.TryGetProperty("experimental", out var experimental) && experimental.GetBoolean())).ToArray();
            if (result.Analyzers.Select(item => item.Name).Distinct(StringComparer.Ordinal).Count() != result.Analyzers.Count) throw new InvalidDataException();
            result.Compatible = result.commands.Contains("desktop-worker") && result.commands.Contains("desktop-action") && result.SchemaVersions.Overlaps(new[] { "1.0", "1.1", "1.2" });
            result.Reason = result.Compatible ? "Compatibility data loaded; no scan or provider request started." : "Selected engine lacks supported desktop commands or run schemas.";
            return result;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException or InvalidDataException or ArgumentException)
        { throw new InvalidDataException("Engine returned malformed capabilities. Previous settings are preserved; no scan was started."); }
    }
    private static void UniqueKeys(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in value.EnumerateObject()) { if (!seen.Add(item.Name)) throw new InvalidDataException(); UniqueKeys(item.Value); }
        }
        else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) UniqueKeys(item);
    }
    private static HashSet<string> Strings(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > 1024) throw new InvalidDataException();
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in value.EnumerateArray())
            if (item.ValueKind != JsonValueKind.String || item.GetString() is not string text || text.Length is < 1 or > 4096 || !result.Add(text)) throw new InvalidDataException();
        return result;
    }
    public CapabilityAvailability Option(string name, string schema = "1.2")
    {
        if (!Compatible) return new(false, Reason);
        bool known = typeof(NativeScanOptions).GetProperties().Any(property => property.GetCustomAttributes(typeof(JsonPropertyNameAttribute), false).Cast<JsonPropertyNameAttribute>().Any(attribute => attribute.Name == name));
        bool enabled = known && optionsBySchema.TryGetValue(schema, out var options) && options.Contains(name);
        return new(enabled, enabled ? "Supported by the selected engine and run schema." : "Unavailable for the selected engine/schema. The saved value is retained; choose a compatible engine or reset it explicitly.");
    }
    public CapabilityAvailability Mode(string name)
    {
        bool enabled = Compatible && ((name is "none" or "review") && modes.Contains(name) || AdvancedAiAvailable && modesBySchema["1.3"].Contains(name));
        return new(enabled, enabled ? "Supported by the current desktop contract." : "This desktop does not dispatch that mode. No substitute or provider request will be sent.");
    }
    public bool AdvancedAiAvailable
    {
        get
        {
            try { return HasAdvancedAi(); }
            catch (Exception error) when (error is InvalidOperationException or KeyNotFoundException or FormatException) { return false; }
        }
    }
    private bool HasAdvancedAi() => Compatible && SchemaVersions.Contains("1.3") &&
        providerBySchema.TryGetValue("1.3", out var fields) && new[] { "enable_ai", "provider", "endpoint", "model", "max_calls", "timeout_seconds", "output_token_limit", "mode", "jury_votes", "effort", "speed", "backend" }.All(fields.Contains) &&
        modesBySchema.TryGetValue("1.3", out var advertised) && new[] { "none", "review", "hunt", "hunt_verify", "remediate", "triage" }.All(advertised.Contains) &&
        document.GetProperty("desktop").TryGetProperty("provider_tuning", out var tuning) && tuning.TryGetProperty("minimum_schema", out var minimum) && minimum.GetString() == "1.3";
    public string MappedEffort(ProviderConfiguration configuration)
    {
        string requested = configuration.Effort ?? "high";
        if (configuration.Provider != "openai") return requested;
        try
        {
            if (document.GetProperty("desktop").TryGetProperty("provider_tuning", out var tuning) && tuning.TryGetProperty("openai_effort_mapping", out var map) && map.TryGetProperty(requested, out var mapped) && mapped.ValueKind == JsonValueKind.String) return mapped.GetString()!;
        }
        catch (Exception error) when (error is InvalidOperationException or KeyNotFoundException) { }
        return "Not advertised";
    }
    public CapabilityAvailability AiConfiguration(ProviderConfiguration configuration, string? requestSchema = null)
    {
        try
        {
            var wire = configuration.ForRequest();
            wire.ValidateForRequest();
            string schema = requestSchema ?? (wire.RequiresSchema13 ? "1.3" : SchemaVersions.Contains("1.1") ? "1.1" : "1.2");
            if (!Compatible || !SchemaVersions.Contains(schema) || !providers.Contains(wire.Provider)) throw new InvalidDataException();
            if (schema is "1.3" or "1.5" && !AdvancedAiAvailable) throw new InvalidDataException();
            if (!modesBySchema.TryGetValue(schema, out var supportedModes) || !supportedModes.Contains(wire.EffectiveMode) ||
                !providerBySchema.TryGetValue(schema, out var fields) || JsonSerializer.SerializeToElement(wire).EnumerateObject().Any(field => !fields.Contains(field.Name))) throw new InvalidDataException();
            if (schema is "1.3" or "1.5")
            {
                var tuning = document.GetProperty("desktop").GetProperty("provider_tuning");
                if (!Strings(tuning.GetProperty("backends")).Contains(wire.Backend ?? "api") || !Strings(tuning.GetProperty("speed")).Contains(wire.Speed ?? "standard")) throw new InvalidDataException();
                if (wire.Effort != null && !Strings(tuning.GetProperty("effort")).Contains(wire.Effort)) throw new InvalidDataException();
                if (wire.JuryVotes != null)
                {
                    var jury = tuning.GetProperty("jury_votes");
                    if (jury.GetProperty("mode").GetString() != wire.EffectiveMode || wire.JuryVotes < jury.GetProperty("minimum").GetInt32() || wire.JuryVotes > jury.GetProperty("maximum").GetInt32()) throw new InvalidDataException();
                }
                if (wire.Speed == "fast")
                {
                    var fast = tuning.GetProperty("fast_speed");
                    if (fast.GetProperty("provider").GetString() != wire.Provider || fast.GetProperty("backend").GetString() != (wire.Backend ?? "api") || wire.Model == null || !Strings(fast.GetProperty("models")).Contains(wire.Model)) throw new InvalidDataException();
                }
            }
            return new(true, "Supported; no provider request has been sent.");
        }
        catch (Exception error) when (error is InvalidDataException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException)
        { return new(false, "AI preference unavailable for the selected engine, mode or provider/model. Saved values are retained; no substitute or request will be sent. CLI cannot enforce strict output caps."); }
    }
    public void RequireSupport(NativeScanOptions options, string modules)
    {
        options.ValidateForRequest();
        if (options.AnalyzerProfile != null && NativeScanOptions.ParseModules(modules).Length > 0)
            throw new InvalidDataException("Analyzer profiles cannot be combined with an explicit module list.");
        if (!Compatible || !SchemaVersions.Contains(options.RequestSchema)) throw new InvalidDataException(Compatible ? "Selected engine does not support the requested run schema. Saved options are retained." : Reason);
        var serialized = JsonSerializer.SerializeToElement(options);
        foreach (var field in serialized.EnumerateObject())
            if (!Option(field.Name, options.RequestSchema).Enabled) throw new InvalidDataException("Selected engine does not support a requested scan option. Saved options are retained.");
        if (options.Provider != null)
        {
            var ai = AiConfiguration(options.Provider, options.RequestSchema);
            if (!ai.Enabled) throw new InvalidDataException(ai.Reason);
        }
        var installed = Analyzers.Select(item => item.Name).ToHashSet(StringComparer.Ordinal);
        if (NativeScanOptions.ParseModules(modules).Any(name => !installed.Contains(name))) throw new InvalidDataException("An explicitly selected analyzer is unavailable in this engine. No automatic replacement was chosen.");
    }
    public void RequireFleetSupport(JsonElement options, string modules, int maxWorkers)
    {
        if (!Compatible || !SchemaVersions.Contains("1.4")) throw new InvalidDataException("Selected engine does not support fleet schema 1.4.");
        try
        {
            var fleet = document.GetProperty("desktop").GetProperty("fleet_by_schema").GetProperty("1.4");
            if (!fleet.GetProperty("multi_repo").GetBoolean() || maxWorkers > fleet.GetProperty("maximum_workers").GetInt32()) throw new InvalidDataException();
            var supported = fleet.TryGetProperty("scan_options", out var fields) ? Strings(fields) :
                optionsBySchema["1.4"].Where(name => name != "analyzer_profile").ToHashSet(StringComparer.Ordinal);
            if (options.EnumerateObject().Any(field => !supported.Contains(field.Name))) throw new InvalidDataException();
            var installed = Analyzers.Select(item => item.Name).ToHashSet(StringComparer.Ordinal);
            if (NativeScanOptions.ParseModules(modules).Any(name => !installed.Contains(name))) throw new InvalidDataException();
            if (options.TryGetProperty("analyzer_profile", out var profile))
            {
                if (NativeScanOptions.ParseModules(modules).Length != 0) throw new InvalidDataException();
                var catalog = document.GetProperty("analyzer_profiles");
                if (catalog.GetProperty("schema_version").GetString() != "1.0") throw new InvalidDataException();
                var matches = catalog.GetProperty("profiles").EnumerateArray().Where(item => item.GetProperty("qualified_name").GetString() == profile.GetString()).ToArray();
                if (matches.Length != 1 || !matches[0].GetProperty("available").GetBoolean()) throw new InvalidDataException();
            }
        }
        catch (Exception error) when (error is InvalidDataException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException)
        { throw new InvalidDataException("Selected engine does not advertise the requested fleet options or analyzer selection. Settings are preserved; no fleet was started."); }
    }
    public static string RestoreEngineSelection(string savedPath, string applicationDirectory)
    {
        string bundled = Path.Combine(applicationDirectory, "engine", "attackmap.exe");
        string marker = Path.Combine(applicationDirectory, "portable-manifest.json");
        if (File.Exists(marker))
        {
            try
            {
                using var stream = File.OpenRead(marker);
                if (stream.Length > 1024 * 1024) throw new InvalidDataException();
                using var document = JsonDocument.Parse(stream);
                var root = document.RootElement;
                if (root.GetProperty("schema_version").GetInt32() != 1 ||
                    root.GetProperty("kind").GetString() != "portable-development-preview" ||
                    root.GetProperty("runtime").GetProperty("engine").GetString() != "engine/attackmap.exe")
                    throw new InvalidDataException();
            }
            catch (Exception error) when (error is JsonException or InvalidDataException or KeyNotFoundException or InvalidOperationException or FormatException or OverflowException)
            { throw new InvalidDataException("Portable package metadata is invalid or unsupported. Extract the complete package again; saved settings are preserved."); }
            if (!File.Exists(bundled))
                throw new InvalidDataException("The portable engine is missing. Extract the complete package including engine/attackmap.exe; saved settings are preserved.");
            // Global preferences can name an older installed engine. A portable
            // startup belongs to its adjacent bundle; a later explicit choice
            // in Scan options still uses ResolveEngine without substitution.
            return ResolveEngine("", applicationDirectory);
        }
        return File.Exists(bundled) && !File.Exists(savedPath.Trim()) ? bundled : savedPath.Trim();
    }
    public static string ResolveEngine(string explicitPath, string applicationDirectory)
    {
        string selected = string.IsNullOrWhiteSpace(explicitPath) ? Path.Combine(applicationDirectory, "engine", "attackmap.exe") : explicitPath.Trim();
        return new EngineLaunchSpec(selected).ExecutablePath; // existing self-exe and static Python-layout guards
    }
}

/// <summary>Explicit engine-selection cache; never performs discovery or network I/O.</summary>
public sealed class EngineCapabilitiesCache
{
    public string? SelectedExecutable { get; private set; }
    public string? ExecutableSha256 { get; private set; }
    public EngineCapabilities? Current { get; private set; }
    public void Invalidate() { Current = null; }
    public void SelectEngine(string executable)
    {
        try
        {
            string selected = new EngineLaunchSpec(executable).ExecutablePath;
            using var stream = File.OpenRead(selected);
            string hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            if (!string.Equals(selected, SelectedExecutable, StringComparison.OrdinalIgnoreCase) || hash != ExecutableSha256) Invalidate();
            SelectedExecutable = selected; ExecutableSha256 = hash;
        }
        catch { Invalidate(); SelectedExecutable = null; ExecutableSha256 = null; throw; }
    }
    public void Store(string executable, EngineCapabilities capabilities)
    {
        SelectEngine(executable);
        if (capabilities.Compatible)
        {
            string? advertisedPath = capabilities.ExpectedIdentity is { } identity ? identity.GetProperty("path").GetString() : null;
            if (capabilities.EngineSha256 != ExecutableSha256 || advertisedPath == null ||
                !string.Equals(Path.GetFullPath(advertisedPath), SelectedExecutable, StringComparison.OrdinalIgnoreCase))
            { Invalidate(); throw new InvalidDataException("Engine changed during capability discovery. Check compatibility again."); }
        }
        Current = capabilities;
    }
}
