using System.Text.Json;
using System.Text.RegularExpressions;
namespace AttackMap.NativeSpike;

public sealed record AnalyzerSelectionItem(string Name, string DisplayName, bool Experimental, bool? EnabledByDefault, bool Missing, bool Selected, string? Error)
{
    public string Status => Missing ? "Missing from selected engine" : Error != null ? "Analyzer error" : Experimental ? (EnabledByDefault == false ? "Experimental · Opt-in" : "Experimental") : EnabledByDefault == false ? "Opt-in" : EnabledByDefault == true ? "Available · Automatic eligible (detection still applies)" : "Available · default eligibility unknown";
}

/// <summary>Installed discovery inventory, not repository applicability. No install or discovery side effects.</summary>
public sealed class AnalyzerSelectionModel
{
    private Dictionary<string, AnalyzerSelectionItem> installed = new(StringComparer.Ordinal);
    private readonly HashSet<string> selected = new(StringComparer.Ordinal);
    private Dictionary<string, string> errors = new(StringComparer.Ordinal);
    public bool Automatic { get; private set; } = true;
    public string? DiscoveryError { get; private set; } = "Analyzer discovery has not been loaded.";
    public string RequestModules => Automatic ? "" : string.Join(",", selected.Order(StringComparer.Ordinal));
    public void SetAutomatic(bool value) => Automatic = value;
    public void Restore(string modules)
    {
        var names = ParseNames(modules); selected.Clear(); selected.UnionWith(names); Automatic = names.Length == 0;
    }
    public void Select(string name, bool value)
    {
        if (ParseNames(name) is not [var parsed] || parsed != name) throw new InvalidDataException("One analyzer name required.");
        if (value && selected.Count >= 32 && !selected.Contains(name)) throw new InvalidDataException("Select at most 32 analyzers.");
        if (value) selected.Add(name); else selected.Remove(name);
        Automatic = false;
    }
    public void LoadDiscovery(string json)
    {
        try
        {
            if (System.Text.Encoding.UTF8.GetByteCount(json) > 4 * 1024 * 1024) throw new InvalidDataException();
            using var document = JsonDocument.Parse(json); var root = document.RootElement;
            if (root.GetProperty("schema").GetInt32() != 1) throw new InvalidDataException();
            var modules = root.GetProperty("modules"); if (modules.ValueKind != JsonValueKind.Array || modules.GetArrayLength() > 1024) throw new InvalidDataException();
            var next = new Dictionary<string, AnalyzerSelectionItem>(StringComparer.Ordinal);
            foreach (var item in modules.EnumerateArray())
            {
                string name = item.GetProperty("name").GetString() ?? throw new InvalidDataException(); if (ParseNames(name) is not [var parsed] || parsed != name) throw new InvalidDataException();
                string display = item.TryGetProperty("display_name", out var title) ? title.GetString() ?? name : name;
                if (display.Length > 2048) throw new InvalidDataException();
                bool experimental = item.TryGetProperty("experimental", out var exp) && exp.GetBoolean();
                bool? enabled = item.TryGetProperty("enabled_by_default", out var def) ? def.GetBoolean() : null;
                if (!next.TryAdd(name, new(name, display, experimental, enabled, false, false, null))) throw new InvalidDataException();
            }
            installed = next; errors.Clear(); DiscoveryError = null;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or InvalidDataException or FormatException)
        { installed.Clear(); errors.Clear(); DiscoveryError = "Analyzer discovery unavailable or incompatible. Saved selections retained; retry explicit discovery. Nothing was installed."; }
    }
    public void EngineChanged() { installed.Clear(); errors.Clear(); DiscoveryError = "Engine changed; refresh analyzer discovery before scanning. Saved selections retained."; }
    public void SetAnalyzerErrors(IReadOnlyDictionary<string, string> values)
    {
        if (values.Count > 1024) throw new InvalidDataException("Too many analyzer errors.");
        errors = values.ToDictionary(item => item.Key, item => item.Value.Length <= 2048 ? item.Value : item.Value[..2048] + "…", StringComparer.Ordinal);
    }
    public IReadOnlyList<AnalyzerSelectionItem> Rows(string filter = "")
    {
        filter = filter.Trim();
        return installed.Values.Select(item => item with { Selected = selected.Contains(item.Name), Error = errors.GetValueOrDefault(item.Name) })
            .Concat(selected.Where(name => !installed.ContainsKey(name)).Select(name => new AnalyzerSelectionItem(name, name, false, null, true, true, null)))
            .Where(item => item.Missing || filter.Length == 0 || item.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) || item.DisplayName.Contains(filter, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(item => item.Missing).ThenBy(item => item.Name, StringComparer.Ordinal).ToArray();
    }
    public void ValidateForScan()
    {
        if (DiscoveryError != null) throw new InvalidDataException(DiscoveryError);
        if (!Automatic && selected.Any(name => !installed.ContainsKey(name))) throw new InvalidDataException("Selected analyzers are missing. Retain or explicitly remove them; no substitute or installation was performed.");
        if (!Automatic && selected.Count == 0) throw new InvalidDataException("Select an analyzer or choose Automatic.");
    }
    private static string[] ParseNames(string text)
    {
        if (text.Length > 4096) throw new InvalidDataException("Analyzer selection too long.");
        var names = text.Split(new[] { ',', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).ToArray();
        if (names.Length > 32 || names.Any(name => !Regex.IsMatch(name, "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"))) throw new InvalidDataException("Invalid analyzer name.");
        return names;
    }
}


