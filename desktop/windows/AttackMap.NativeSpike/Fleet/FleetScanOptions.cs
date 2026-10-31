using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace AttackMap.NativeSpike;

/// <summary>Only options supported by the native fleet workflow. No provider credentials enter this transport.</summary>
public sealed record FleetScanOptions(
    [property: JsonPropertyName("timeout_seconds")] int TimeoutSeconds = 600,
    [property: JsonPropertyName("recall")] bool Recall = false,
    [property: JsonPropertyName("strict_analyzers")] bool StrictAnalyzers = false,
    [property: JsonPropertyName("no_suppress")] bool NoSuppress = false,
    [property: JsonPropertyName("cve")] bool Cve = false,
    [property: JsonPropertyName("strict_suppressions")] bool StrictSuppressions = false,
    [property: JsonPropertyName("isolated_analyzers")] bool IsolatedAnalyzers = false,
    [property: JsonPropertyName("time_budget_seconds"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? TimeBudgetSeconds = null,
    [property: JsonPropertyName("analyzer_profile"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? AnalyzerProfile = null)
{
    public void Validate()
    {
        if (TimeoutSeconds is < 1 or > 86400) throw new InvalidDataException("Fleet allowance must be 1–86400 seconds.");
        if (TimeBudgetSeconds is < 1 or > 86400 || TimeBudgetSeconds >= TimeoutSeconds)
            throw new InvalidDataException("The per-repository soft budget must be below the whole fleet allowance.");
        if (NoSuppress && StrictSuppressions) throw new InvalidDataException("Strict suppression conflicts with suppression disablement.");
        if (AnalyzerProfile != null && (AnalyzerProfile.Length > 160 || !Regex.IsMatch(AnalyzerProfile, "^[a-z][a-z0-9-]*@[0-9]+\\.[0-9]+\\z", RegexOptions.CultureInvariant)))
            throw new InvalidDataException("Fleet analyzer profile requires its supported version.");
    }
    public static string[] ParseModules(string text)
    {
        if (text.Length > 4096) throw new InvalidDataException("Fleet module selection exceeds 4096 characters.");
        var names = text.Split(new[] { ',', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.Ordinal).ToArray();
        if (names.Length > 32 || names.Any(name => !Regex.IsMatch(name, "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", RegexOptions.CultureInvariant)))
            throw new InvalidDataException("Choose at most 32 installed analyzer names.");
        return names;
    }
}

public static class NativeFleetRequest
{
    public static string Serialize(FleetGeneration identity, IReadOnlyList<FleetRoot> repositories, string output,
        FleetScanOptions options, int maxWorkers = 1, string modules = "")
    {
        options.Validate();
        var validation = new FleetWorkspace(); foreach (var root in repositories) validation.Add(root.RepositoryId, root.RepositoryPath);
        var roots = validation.Repositories.ToArray();
        var names = FleetScanOptions.ParseModules(modules);
        if (roots.Length < 2 || identity.Generation < 1 || string.IsNullOrWhiteSpace(identity.RunId) ||
            identity.RepositorySetId != FleetSession.RepositorySetId(roots) || maxWorkers is < 1 or > 4 ||
            !Path.IsPathFullyQualified(output) || output.StartsWith("\\\\", StringComparison.Ordinal) || output.StartsWith("//", StringComparison.Ordinal) || output.Any(char.IsControl))
            throw new InvalidDataException("Invalid fleet identity, limits or output path.");
        if (options.AnalyzerProfile != null && names.Length != 0) throw new InvalidDataException("Choose a fleet analyzer profile or explicit modules.");
        return JsonSerializer.Serialize(new { schema_version = "1.4", kind = "fleet_request", run_id = identity.RunId,
            repository_id = identity.RepositorySetId, generation = identity.Generation, revision = 0,
            repositories = roots.Select(root => new { repository_id = root.RepositoryId, repository_path = root.RepositoryPath }),
            output_path = output, max_workers = maxWorkers, modules = names, options });
    }
}
