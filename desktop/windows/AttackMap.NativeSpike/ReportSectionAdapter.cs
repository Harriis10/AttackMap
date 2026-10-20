using System.Security.Cryptography;
using System.Text.Json;
namespace AttackMap.NativeSpike;

/// <summary>Read-only supplied values; no ranking, association or generation inference.</summary>
public static class ReportSectionAdapter
{
    public const int MaxBytes = 64 * 1024 * 1024;
    public const int MaxRows = 10000;
    // Core fleet_summary_json is a separate index, never a single-repo report.
    public static FleetSections ReadFleet(JsonElement root, string readHash, string? generationId = null)
    {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("repos",out var repos) || repos.ValueKind != JsonValueKind.Array
            || !root.TryGetProperty("repo_count",out var count) || count.ValueKind != JsonValueKind.Number)
            throw new InvalidDataException("Expected the core fleet summary index.");
        return new(readHash,generationId,Rows(root,"repos",(r,i)=>new FleetRepositoryRow(i,Text(r,"repo_id"),Text(r,"root"),Text(r,"report_dir"),r.Clone())),
            Rows(root,"cross_repo_links",Evidence),Clone(root,"failed"),"Core-supplied fleet index only; links retain candidate/observed provenance in source. No UI-created edges or aggregate scoring.");
    }
    public static async Task<ReportSections> Load(string path, string? expectedHash = null, string? generationId = null)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > MaxBytes) throw new InvalidDataException("Report exceeds the 64 MiB preview limit.");
        byte[] bytes = new byte[(int)stream.Length];
        await stream.ReadExactlyAsync(bytes);
        if (await stream.ReadAsync(new byte[1]) != 0) throw new InvalidDataException("Report changed while being read.");
        string hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        if (expectedHash != null && !string.Equals(hash, expectedHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Report hash changed; reselect a verified generation.");
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 64 });
        return Read(document.RootElement, hash, generationId);
    }
    public static ReportSections Read(JsonElement root, string readHash, string? generationId = null)
    {
        if (root.ValueKind != JsonValueKind.Object || root.TryGetProperty("schema_version", out _)
            || !root.TryGetProperty("scan", out var scan) || scan.ValueKind != JsonValueKind.Object
            || Text(scan,"root") is not string repository || !root.TryGetProperty("findings",out var findings) || findings.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Expected a canonical saved report with scan.root and findings, not a run envelope.");
        return new(repository, readHash, generationId,
            Rows(root,"exploitability",(r,i) => new ExploitabilityRow(Evidence(r,i),Text(r,"subject"),Text(r,"route"),Text(r,"method"),Text(r,"sink_kind"),Number(r,"score"),Text(r,"tier"))),
            Rows(root,"attack_paths",(r,i) => new PathRow(Evidence(r,i),Text(r,"impact"),Clone(r,"steps"))),
            Rows(root,"attack_surfaces",(r,i) => new SurfaceRow(Evidence(r,i),Text(r,"method"),Text(r,"route"),Text(r,"exposure"))),
            Rows(scan,"routes",(r,i) => new SurfaceRow(Evidence(r,i),Text(r,"method"),Text(r,"path"),Text(r,"exposure"))),
            Rows(scan,"dependencies",(r,i) => new DependencyRow(Evidence(r,i),Text(r,"version"),Text(r,"ecosystem"))),
            Rows(scan,"vulnerabilities",Evidence),
            Rows(scan,"secret_hints",(r,i) => new SecretRow(i,Text(r,"id"),Text(r,"name"),Text(r,"kind"),Text(r,"file"),Integer(r,"line"))),
            Rows(scan,"workflow_issues",Evidence), Rows(scan,"taint_chains",Evidence),
            Rows(scan,"analyzers",Evidence), Rows(scan,"analyzer_errors",Evidence),
            Rows(root,"suppressed_findings",(r,i) => new SuppressedRow(Evidence(r,i),Text(r,"title"),Text(r,"reason"),Clone(r,"suppressed_by"),Text(r,"expiry"))),
            new ReportSection<EvidenceRow>(SectionAvailability.Missing,null,Array.Empty<EvidenceRow>(),"Fleet summary is a separate core index; use ReadFleet. No fleet result inferred from a single-repo report."), Clone(scan,"resource_limit_events"), Clone(scan,"resource_limit_scopes"), Clone(scan,"resource_limit_reporting"), Clone(scan,"limitations"),
            "Supplied static records only. Missing fields remain unknown. Generation identity is caller-supplied and is not proof of manifest integrity.");
    }
    private static ReportSection<T> Rows<T>(JsonElement parent,string key,Func<JsonElement,int,T> project)
    {
        if (!parent.TryGetProperty(key,out var rows)) return new(SectionAvailability.Missing,null,Array.Empty<T>(),$"{key}: unavailable; completeness unknown.");
        if (rows.ValueKind != JsonValueKind.Array) return new(SectionAvailability.Malformed,null,Array.Empty<T>(),$"{key}: malformed section; completeness unknown.");
        var result = new List<T>(); int count = rows.GetArrayLength(), malformed = 0;
        int index = 0;
        foreach (var row in rows.EnumerateArray())
        {
            if (index >= MaxRows) break;
            if (row.ValueKind == JsonValueKind.Object) result.Add(project(row,index)); else malformed++;
            index++;
        }
        bool partial = malformed > 0 || count > MaxRows;
        return new(partial ? SectionAvailability.Partial : SectionAvailability.Present,count,result.AsReadOnly(),
            $"{key}: {count} supplied; {result.Count} displayed; {malformed} malformed in inspected rows; truncated: {count > MaxRows}. Missing evidence is unknown; empty is not a security assurance.");
    }
    private static EvidenceRow Evidence(JsonElement row,int index) => new(index,Text(row,"id"),Text(row,"name"),Text(row,"file"),Integer(row,"line"),Text(row,"evidence_basis"),row.Clone());
    private static string? Text(JsonElement row,string key) => row.TryGetProperty(key,out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    private static int? Integer(JsonElement row,string key) => row.TryGetProperty(key,out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int number) ? number : null;
    private static double? Number(JsonElement row,string key) => row.TryGetProperty(key,out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out double number) ? number : null;
    private static JsonElement? Clone(JsonElement row,string key) => row.TryGetProperty(key,out var value) ? value.Clone() : null;
}
