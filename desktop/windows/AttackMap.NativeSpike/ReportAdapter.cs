using System.Text.Json;

namespace AttackMap.NativeSpike;

public sealed record ImportedReport(string Repository, List<FixtureFinding> Findings, string Limitation, string Coverage, StructureData Structure, string ReadHash)
{
    public List<JsonElement> FindingRecords { get; init; } = [];
    public string Review { get; init; } = "No defensive review supplied in this report.";
    public string ArchitectureSummary { get; init; } = "No architecture summary supplied in this report.";
    public string Overview { get; init; } = "No review overview supplied in this report.";
}
public static class ReportAdapter
{
    public const string LegacyLimitation = "Imported legacy report: local import identity only; policy and artifact integrity unverified. Missing evidence classifications remain unknown; static evidence is not runtime verification.";
    public static async Task<ImportedReport> Load(string path)
    {
        if (new FileInfo(path).Length > 64 * 1024 * 1024) throw new InvalidDataException("Report exceeds the 64 MiB preview limit.");
        using var stream = File.OpenRead(path);
        long length = stream.Length;
        if (length > 64 * 1024 * 1024) throw new InvalidDataException("Report exceeds the 64 MiB preview limit.");
        byte[] bytes = new byte[(int)length];
        await stream.ReadExactlyAsync(bytes);
        if (await stream.ReadAsync(new byte[1]) != 0) throw new InvalidDataException("Report changed while being read. Reopen it before continuing.");
        string readHash = ExportSelection.Hash(bytes);
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 64 });
        return Read(document.RootElement, readHash);
    }
    public static ImportedReport Read(JsonElement root, string readHash)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Report must be an object.");
        if (root.TryGetProperty("schema_version", out _)) throw new InvalidDataException("Versioned run envelopes are not saved reports. Open the canonical report artifact.");
        if (!root.TryGetProperty("scan", out var scan) || scan.ValueKind != JsonValueKind.Object || !scan.TryGetProperty("root", out var repository) || repository.ValueKind != JsonValueKind.String ||
            !root.TryGetProperty("findings", out var findings) || findings.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Expected a canonical legacy report with scan.root and findings.");
        var rows = new List<FixtureFinding>();
        foreach (var item in findings.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Finding must be an object.");
            string locations = item.TryGetProperty("locations", out var source) && source.ValueKind == JsonValueKind.Array
                ? string.Join("; ", source.EnumerateArray().Select(p => $"{Text(p, "file") }:{Text(p, "line")}")) : "Location unavailable";
            string evidence = item.TryGetProperty("evidence", out var observations) && observations.ValueKind == JsonValueKind.Array
                ? string.Join("\n", observations.EnumerateArray().Select(p => p.ToString())) : "Evidence unavailable";
            string score = Text(item, "score", "unknown");
            string context = item.TryGetProperty("context", out var suppliedContext) && suppliedContext.ValueKind == JsonValueKind.Object
                ? "\n\n" + FindingContextFormatter.Format(suppliedContext)
                : "\nFinding context unavailable in this saved report.";
            bool controlsSupplied = suppliedContext.ValueKind == JsonValueKind.Object &&
                suppliedContext.TryGetProperty("context_version", out var contextVersion) && contextVersion.ValueKind == JsonValueKind.String && contextVersion.GetString() == "1.0" &&
                suppliedContext.TryGetProperty("observed_controls", out var controls) && controls.ValueKind is JsonValueKind.Object or JsonValueKind.Array;
            string controlsLabel = controlsSupplied
                ? "Observed controls: see core-supplied finding context below. Controls are observations, not proof that the claim is mitigated."
                : "Observed controls: not separately supplied for this finding.";
            rows.Add(new FixtureFinding(Text(item, "id"), Text(item, "title"), Text(item, "severity"),
                Text(item, "evidence_basis", "unknown (legacy classification absent)"), Text(item, "confidence", "unknown"),
                locations, $"{evidence}\n\nPriority supplied by engine: {score}\n{controlsLabel}\nTrust chain: {Text(item, "code_flows", "not supplied")}\nUncertainty: {LegacyLimitation}{context}",
                Text(item, "mitigation", "Recommendation unavailable")));
        }
        var limitations = scan.TryGetProperty("limitations", out var supplied) && supplied.ValueKind == JsonValueKind.Array
            ? supplied.EnumerateArray().Select(p => p.ToString()).ToList() : new List<string>();
        string errors = scan.TryGetProperty("analyzer_errors", out var failures) ? failures.ToString() : "not supplied";
        string coverage = $"Reported file count (legacy aggregate; may overlap): {Text(scan, "files_scanned", "unknown")}\nCoverage limitations:\n" +
            (limitations.Count == 0 ? "None supplied; completeness is unverified." : string.Join("\n", limitations)) + $"\nAnalyzer errors (as supplied): {errors}";
        if (scan.TryGetProperty("scanned_files", out var accepted) && accepted.ValueKind == JsonValueKind.Array)
            coverage = $"Distinct accepted source paths enumerated by analyzers: {accepted.EnumerateArray().Where(p => p.ValueKind == JsonValueKind.String).Select(p => p.GetString()).Distinct(StringComparer.Ordinal).Count()}\nEnumeration does not establish complete language or runtime coverage.\n" + coverage;
        return new ImportedReport(repository.GetString()!, rows, LegacyLimitation, coverage, StructureAdapter.Read(root, scan), readHash)
        { FindingRecords = findings.EnumerateArray().Select(item => item.Clone()).ToList(),
          Review = Text(root, "defensive_review", "No defensive review supplied in this report."),
          ArchitectureSummary = Text(root, "architecture_summary", "No architecture summary supplied in this report."),
          Overview = OverviewAdapter.Read(root) };
    }
    private static string Text(JsonElement item, string key, string fallback = "unknown") =>
        item.ValueKind == JsonValueKind.Object && item.TryGetProperty(key, out var value) && value.ValueKind != JsonValueKind.Null ? value.ToString() : fallback;
}
