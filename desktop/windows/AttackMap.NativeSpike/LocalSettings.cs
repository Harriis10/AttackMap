using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
namespace AttackMap.NativeSpike;

public sealed record LocalSettings(int SchemaVersion = 1, string PythonPath = "", string RepositoryPath = "", NativeScanOptions? Options = null, string Modules = "")
{
    [JsonExtensionData] public Dictionary<string, JsonElement>? AdditionalProperties { get; init; }
    [JsonIgnore]
    public NativeScanOptions EffectiveOptions => Options ?? new();
}
public sealed class LocalSettingsStore(string path)
{
    public static string DefaultPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AttackMap", "NativePreview", "settings.json");
    public LocalSettings Load()
    {
        if (!File.Exists(path)) return new();
        return Decode(ReadOriginal());
    }
    private string ReadOriginal()
    {
        if (new FileInfo(path).Length > 16384) throw new InvalidDataException("Local settings exceed 16 KiB. Original file preserved.");
        return File.ReadAllText(path);
    }
    private static LocalSettings Decode(string raw)
    {
        using var document = JsonDocument.Parse(raw);
        RejectDuplicateKeys(document.RootElement);
        if (document.RootElement.ValueKind != JsonValueKind.Object || !document.RootElement.TryGetProperty("SchemaVersion", out _)) throw new InvalidDataException("Missing local settings version. Original file preserved.");
        var settings = document.RootElement.Deserialize<LocalSettings>() ?? throw new InvalidDataException("Local settings are empty.");
        if (document.RootElement.TryGetProperty("Options", out var options) && options.ValueKind == JsonValueKind.Object &&
            options.TryGetProperty("provider", out var provider) && provider.ValueKind == JsonValueKind.Object && settings.Options != null)
        {
            var known = typeof(ProviderConfiguration).GetProperties().Select(property => property.GetCustomAttributes(typeof(JsonPropertyNameAttribute), false).Cast<JsonPropertyNameAttribute>().SingleOrDefault()?.Name).Where(name => name != null).ToHashSet(StringComparer.Ordinal);
            string[] unknown = provider.EnumerateObject().Select(item => item.Name).Where(name => !known.Contains(name)).ToArray();
            if (unknown.Length > 0) settings = settings with { Options = settings.Options with { UnrecognizedProviderFields = unknown } };
        }
        Validate(settings);
        return settings;
    }
    public void Save(LocalSettings settings)
    {
        Validate(settings);
        string? original = File.Exists(path) ? ReadOriginal() : null;
        LocalSettings? previous;
        try { previous = original == null ? null : Decode(original); }
        catch (JsonException) { throw new InvalidDataException("Existing settings are malformed. Original file preserved; reopen or explicitly clear them."); }
        if (previous?.Options?.AdditionalProperties?.Count > 0 && settings.Options == null ||
            previous?.Options?.UnrecognizedProviderFields?.Count > 0 && settings.Options?.Provider == null)
            throw new InvalidDataException("Unknown saved options must be retained. Use a compatible client or explicitly clear saved settings.");
        var updated = JsonSerializer.SerializeToNode(settings)!.AsObject();
        if (settings.Options != null)
        {
            // Request serialization omits new default fields. Settings must explicitly
            // replace an old true/non-null value when the user resets it to default.
            var options = updated["Options"]!.AsObject();
            options["provider"] = JsonSerializer.SerializeToNode(settings.Options.Provider);
            if ((settings.Options.Provider?.RequiresSchema13 == true || previous?.Options?.Provider?.RequiresSchema13 == true) && options["provider"] is JsonObject provider)
            {
                // Explicit nulls clear prior tuning while recursive merge retains unknown fields.
                provider["mode"] = settings.Options.Provider!.Mode;
                provider["jury_votes"] = settings.Options.Provider.JuryVotes;
                provider["effort"] = settings.Options.Provider.Effort;
                provider["speed"] = settings.Options.Provider.Speed;
                provider["backend"] = settings.Options.Provider.Backend;
            }
            options["baseline"] = settings.Options.Baseline;
            options["suppress_file"] = settings.Options.SuppressFile;
            options["fail_on_new_high"] = settings.Options.FailOnNewHigh;
            options["fail_on_new_suppression"] = settings.Options.FailOnNewSuppression;
            options["strict_suppressions"] = settings.Options.StrictSuppressions;
            options["isolated_analyzers"] = settings.Options.IsolatedAnalyzers;
            options["time_budget_seconds"] = settings.Options.TimeBudgetSeconds;
        }
        JsonObject merged = original == null ? new() : JsonNode.Parse(original)!.AsObject();
        Merge(merged, updated);
        string json = merged.ToJsonString();
        if (System.Text.Encoding.UTF8.GetByteCount(json) > 16384) throw new InvalidDataException("Local settings exceed 16 KiB.");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, json);
            if (original != null)
            {
                if (ReadOriginal() != original) throw new IOException("Settings changed during save; reopen them before saving.");
                if (!File.Exists(path + ".before-wp005.json")) File.Copy(path, path + ".before-wp005.json");
            }
            else if (File.Exists(path)) throw new IOException("Settings appeared during save; reopen them before saving.");
            File.Move(temporary, path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    public void Clear() { if (File.Exists(path)) File.Delete(path); if (File.Exists(path + ".before-wp005.json")) File.Delete(path + ".before-wp005.json"); }
    private static void Merge(JsonObject target, JsonObject update)
    {
        foreach (var item in update)
            if (item.Value is JsonObject child && target[item.Key] is JsonObject existing) Merge(existing, child);
            else target[item.Key] = item.Value?.DeepClone();
    }
    private static void RejectDuplicateKeys(JsonElement node)
    {
        if (node.ValueKind == JsonValueKind.Object)
        {
            var keys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in node.EnumerateObject())
            {
                if (!keys.Add(property.Name)) throw new InvalidDataException("Duplicate settings fields; original file preserved.");
                RejectDuplicateKeys(property.Value);
            }
        }
        else if (node.ValueKind == JsonValueKind.Array) foreach (var child in node.EnumerateArray()) RejectDuplicateKeys(child);
    }
    private static void Validate(LocalSettings settings)
    {
        if (settings.SchemaVersion != 1) throw new InvalidDataException("Unsupported local settings version. Original file preserved; clear or use a compatible preview.");
        settings.EffectiveOptions.Validate();
        if (settings.Modules is null) throw new InvalidDataException("Module selection must be text.");
        NativeScanOptions.ParseModules(settings.Modules);
        foreach (string? value in new[] { settings.PythonPath, settings.RepositoryPath })
            if (value is null || (value.Length > 0 && !Path.IsPathFullyQualified(value))) throw new InvalidDataException("Local paths must be absolute or empty.");
    }
}
