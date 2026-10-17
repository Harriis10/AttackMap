using System.Text.Json;
namespace AttackMap.NativeSpike;

public sealed record LocalSettings(int SchemaVersion = 1, string PythonPath = "", string RepositoryPath = "", NativeScanOptions? Options = null, string Modules = "")
{
    [System.Text.Json.Serialization.JsonIgnore]
    public NativeScanOptions EffectiveOptions => Options ?? new();
}
public sealed class LocalSettingsStore(string path)
{
    public static string DefaultPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AttackMap", "NativePreview", "settings.json");
    public LocalSettings Load()
    {
        if (!File.Exists(path)) return new();
        if (new FileInfo(path).Length > 16384) throw new InvalidDataException("Local settings exceed 16 KiB. Original file preserved.");
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        if (document.RootElement.ValueKind != JsonValueKind.Object || !document.RootElement.TryGetProperty("SchemaVersion", out _)) throw new InvalidDataException("Missing local settings version. Original file preserved.");
        var settings = document.RootElement.Deserialize<LocalSettings>() ?? throw new InvalidDataException("Local settings are empty.");
        Validate(settings);
        return settings;
    }
    public void Save(LocalSettings settings)
    {
        Validate(settings);
        string json = JsonSerializer.Serialize(settings);
        if (System.Text.Encoding.UTF8.GetByteCount(json) > 16384) throw new InvalidDataException("Local settings exceed 16 KiB.");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { File.WriteAllText(temporary, json); File.Move(temporary, path, overwrite: true); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    public void Clear() { if (File.Exists(path)) File.Delete(path); }
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
