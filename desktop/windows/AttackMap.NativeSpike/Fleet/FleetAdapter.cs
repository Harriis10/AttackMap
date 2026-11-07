using System.Text.Json;

namespace AttackMap.NativeSpike;

public sealed record FleetRepositorySummary(string RepositoryId, string Root, int? Findings, JsonElement SeverityCounts);
public sealed record FleetContractLink(string Client, string Server, string Method, string Route, string Resolution, string Reason, string? Proxy, JsonElement Source)
{
    public bool IsCandidate => Resolution != "observed" && Resolution != "observed_via_proxy";
    public string Description => IsCandidate ? "Candidate lead; destination is unconfirmed" : Resolution == "observed_via_proxy" ? "Observed via declared proxy; no direct service edge" : "Observed contract link";
}
public sealed record FleetSummary(IReadOnlyList<FleetRepositorySummary> Repositories, IReadOnlyList<FleetContractLink> Links, IReadOnlyList<JsonElement> Failures,
    IReadOnlyList<JsonElement> Flows, IReadOnlyList<JsonElement> Gaps, IReadOnlyList<JsonElement> Anomalies);

/// <summary>Projects supplied core records in original order. Never scores or synthesizes edges.</summary>
public static class FleetAdapter
{
    public static FleetSummary Read(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("repos", out var repos) || repos.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Expected a core fleet summary index.");
        var rows = Rows(root, "repos").Select(r => new FleetRepositorySummary(Required(r, "repo_id"), Required(r, "root"),
            r.TryGetProperty("findings", out var n) && n.ValueKind == JsonValueKind.Number && n.TryGetInt32(out int count) && count >= 0 ? count : null,
            r.TryGetProperty("severity_counts", out var counts) ? counts.Clone() : default)).ToArray();
        if (rows.Select(r => r.RepositoryId).Distinct(StringComparer.Ordinal).Count() != rows.Length) throw new InvalidDataException("Duplicate fleet repository identity.");
        var links = Rows(root, "cross_repo_links").Select(r => new FleetContractLink(Required(r,"client_repo"), Required(r,"server_repo"), Text(r,"method") ?? "unknown",
            Text(r,"server_route_path") ?? Text(r,"path_template") ?? "unknown", Text(r,"resolution") ?? "unknown", Text(r,"resolution_reason") ?? "unspecified", Text(r,"proxy_host"), r.Clone())).ToArray();
        return new(rows, links, Rows(root,"failed"), Rows(root,"cross_boundary_flows"), Rows(root,"trust_gaps"), Rows(root,"cross_repo_anomalies"));
    }
    private static JsonElement[] Rows(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var rows)) return Array.Empty<JsonElement>();
        if (rows.ValueKind != JsonValueKind.Array || rows.GetArrayLength() > 10000) throw new InvalidDataException($"Invalid or oversized fleet section: {name}.");
        return rows.EnumerateArray().Select(r => r.ValueKind == JsonValueKind.Object ? r.Clone() : throw new InvalidDataException($"Malformed fleet record in {name}.")).ToArray();
    }
    private static string? Text(JsonElement root,string key) => root.TryGetProperty(key,out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    private static string Required(JsonElement root,string key) => Text(root,key) is string text && text.Length > 0 ? text : throw new InvalidDataException($"Fleet record lacks {key}.");
}
