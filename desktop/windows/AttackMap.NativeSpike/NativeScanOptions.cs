using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
namespace AttackMap.NativeSpike;

public sealed record NativeScanOptions(
    [property: JsonPropertyName("recall")] bool Recall = false,
    [property: JsonPropertyName("strict_analyzers")] bool StrictAnalyzers = false,
    [property: JsonPropertyName("no_suppress")] bool NoSuppress = false,
    [property: JsonPropertyName("cve")] bool Cve = false,
    [property: JsonPropertyName("secrets_history")] int SecretsHistory = 0,
    [property: JsonPropertyName("timeout_seconds")] int TimeoutSeconds = 600,
    [property: JsonPropertyName("provider"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProviderConfiguration? Provider = null)
{
    public void Validate()
    {
        if (SecretsHistory is < 0 or > 10000) throw new InvalidDataException("Secret history must be 0 to 10000 commits (0 disables it).");
        if (TimeoutSeconds is < 1 or > 86400) throw new InvalidDataException("Timeout must be 1 to 86400 seconds.");
        Provider?.Validate();
    }
    public static string[] ParseModules(string text)
    {
        if (text.Length > 4096) throw new InvalidDataException("Module selection exceeds 4096 characters.");
        var names = text.Split(new[] { ',', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).ToArray();
        if (names.Length > 32 || names.Any(name => !Regex.IsMatch(name, "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", RegexOptions.CultureInvariant)))
            throw new InvalidDataException("Use at most 32 installed analyzer names, separated by commas or spaces; letters, digits, dot, underscore and hyphen only.");
        return names;
    }
}
public static class NativeScanRequest
{
    public static string Serialize(string runId, string repository, string output, long generation, NativeScanOptions options, string modules)
    {
        options.Validate();
        return JsonSerializer.Serialize(new { schema_version = "1.1", kind = "request", run_id = runId, repository_id = repository,
            generation, revision = 0, repository_path = repository, output_path = output, modules = NativeScanOptions.ParseModules(modules), options });
    }
}
