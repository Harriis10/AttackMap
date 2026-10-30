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
    [property: JsonPropertyName("provider"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProviderConfiguration? Provider = null,
    [property: JsonPropertyName("baseline"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Baseline = null,
    [property: JsonPropertyName("suppress_file"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? SuppressFile = null,
    [property: JsonPropertyName("fail_on_new_high"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool FailOnNewHigh = false,
    [property: JsonPropertyName("fail_on_new_suppression"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool FailOnNewSuppression = false,
    [property: JsonPropertyName("strict_suppressions"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool StrictSuppressions = false,
    [property: JsonPropertyName("isolated_analyzers"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] bool IsolatedAnalyzers = false,
    [property: JsonPropertyName("time_budget_seconds"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? TimeBudgetSeconds = null,
    [property: JsonPropertyName("analyzer_profile"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? AnalyzerProfile = null)
{
    [JsonExtensionData] public Dictionary<string, JsonElement>? AdditionalProperties { get; init; }
    [JsonIgnore] public IReadOnlyList<string>? UnrecognizedProviderFields { get; init; }
    [JsonIgnore] public bool RequiresSchema12 => Baseline != null || SuppressFile != null || FailOnNewHigh || FailOnNewSuppression || StrictSuppressions || IsolatedAnalyzers || TimeBudgetSeconds != null;
    [JsonIgnore] public string RequestSchema => AnalyzerProfile != null ? "1.5" : Provider?.ForRequest().RequiresSchema13 == true ? "1.3" : RequiresSchema12 ? "1.2" : "1.1";
    public void Validate()
    {
        if (SecretsHistory is < 0 or > 10000) throw new InvalidDataException("Secret history must be 0 to 10000 commits (0 disables it).");
        if (TimeoutSeconds is < 1 or > 86400) throw new InvalidDataException("Timeout must be 1 to 86400 seconds.");
        Provider?.Validate();
        if (AnalyzerProfile != null && (AnalyzerProfile.Length > 160 || !Regex.IsMatch(AnalyzerProfile, "^[a-z][a-z0-9-]*@[0-9]+\\.[0-9]+\\z", RegexOptions.CultureInvariant)))
            throw new InvalidDataException("Analyzer profile must include its supported version.");
        foreach (string? value in new[] { Baseline, SuppressFile })
            if (value != null && (!Path.IsPathFullyQualified(value) || value.StartsWith("\\\\", StringComparison.Ordinal) || value.StartsWith("//", StringComparison.Ordinal) || value.Any(char.IsControl)))
                throw new InvalidDataException("Baseline and suppression files require absolute local paths.");
        if ((FailOnNewHigh || FailOnNewSuppression) && Baseline == null) throw new InvalidDataException("Baseline policies require a baseline file.");
        if (NoSuppress && (SuppressFile != null || StrictSuppressions)) throw new InvalidDataException("Suppression options conflict with suppression disablement.");
        if (TimeBudgetSeconds is < 1 or > 86400 || TimeBudgetSeconds >= TimeoutSeconds) throw new InvalidDataException("Soft time budget must be a positive whole number of seconds below the hard timeout (maximum 86400).");
    }
    public void ValidateForRequest()
    {
        Validate();
        Provider?.ForRequest().ValidateForRequest();
        if (AdditionalProperties?.Count > 0 || UnrecognizedProviderFields?.Count > 0)
            throw new InvalidDataException("Saved options contain unsupported fields. Original settings are preserved; use a compatible client or explicitly clear saved settings.");
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
        options.ValidateForRequest();
        if (options.AnalyzerProfile != null && NativeScanOptions.ParseModules(modules).Length != 0)
            throw new InvalidDataException("Choose a named analyzer profile or an explicit module list.");
        return JsonSerializer.Serialize(new { schema_version = options.RequestSchema, kind = "request", run_id = runId, repository_id = repository,
            generation, revision = 0, repository_path = repository, output_path = output, modules = NativeScanOptions.ParseModules(modules), options = options with { Provider = options.Provider?.ForRequest() } });
    }
}
