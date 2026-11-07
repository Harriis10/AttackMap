using System.Collections.Immutable;
using System.Text.Json;
using AttackMap.GraphExplorer;

namespace AttackMap.NativeSpike;

public sealed record FleetGraphSelection(GraphContext Context, string PresentationId, bool IsEdge,
    ImmutableArray<string> NodeIds, ImmutableArray<string> EdgeIds);

public sealed record FleetGraphSourceRequest(GraphContext Context, FleetGraphSelection Selection,
    string EvidenceId, string GraphRepositoryId, string RequestedRepositoryId, string RepositoryRoot,
    string RelativePath, int? Line, string? SnapshotId, string? SnapshotAt);

public sealed record FleetGraphEvidenceItem(string Id, string Side, string RepositoryLabel,
    string? RepositoryId, GraphEvidence? Record, ImmutableArray<string> EdgeIds, bool EndpointOnly)
{
    public string DisplayName => $"{Side} · {RepositoryLabel} · {Record?.File ?? "source unknown"} · {Id}";
}

public sealed record FleetGraphEvidenceDetail(FleetGraphSelection Selection,
    ImmutableArray<GraphEdge> Edges, ImmutableArray<FleetGraphEvidenceItem> Items);

/// <summary>Projects canonical evidence only. The host still verifies the child and inspects live source.</summary>
public static class FleetGraphEvidenceNavigation
{
    public static bool TryDescribe(GraphDocument graph, GraphContext current, FleetGraphSelection selection,
        out FleetGraphEvidenceDetail? detail, out string reason)
    {
        detail = null;
        if (graph.Context != current || selection.Context != current)
        { reason = "The graph selection belongs to an older run or generation."; return false; }
        var nodes = graph.Nodes.ToDictionary(node => node.Id, StringComparer.Ordinal);
        var edges = graph.Edges.ToDictionary(edge => edge.Id, StringComparer.Ordinal);
        if (selection.NodeIds.IsDefault || selection.EdgeIds.IsDefault || selection.NodeIds.Length + selection.EdgeIds.Length == 0 ||
            selection.NodeIds.Any(id => !nodes.ContainsKey(id)) || selection.EdgeIds.Any(id => !edges.ContainsKey(id)))
        { reason = "The selected canonical node or relationship is unavailable."; return false; }
        var selectedEdges = selection.EdgeIds.Distinct(StringComparer.Ordinal).Select(id => edges[id]).ToImmutableArray();
        var references = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        var direct = new HashSet<string>(StringComparer.Ordinal);
        void Add(string id, string? edge, bool isDirect)
        {
            if (!references.TryGetValue(id, out var owners)) references[id] = owners = new(StringComparer.Ordinal);
            if (edge != null) owners.Add(edge);
            if (isDirect) direct.Add(id);
        }
        foreach (var edge in selectedEdges)
        {
            foreach (string id in edge.EvidenceRefs) Add(id, edge.Id, true);
            foreach (string id in nodes[edge.Source].EvidenceRefs.Concat(nodes[edge.Target].EvidenceRefs)) Add(id, edge.Id, false);
        }
        foreach (string node in selection.NodeIds)
            foreach (string id in nodes[node].EvidenceRefs) Add(id, null, true);
        var registry = graph.Evidence.ToDictionary(item => item.Id, StringComparer.Ordinal);
        var repositories = graph.Repositories.ToDictionary(repo => repo.Id, StringComparer.Ordinal);
        var items = references.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair =>
        {
            registry.TryGetValue(pair.Key, out var record);
            var repo = record?.RepoId is { } repoId && repositories.TryGetValue(repoId, out var owner) ? owner : null;
            bool source = record?.RepoId != null && pair.Value.Any(id => nodes[edges[id].Source].RepoId == record.RepoId);
            bool target = record?.RepoId != null && pair.Value.Any(id => nodes[edges[id].Target].RepoId == record.RepoId);
            string side = source && target ? "Source and target repository" : source ? "Source repository" : target ? "Target repository" : "Side unknown";
            return new FleetGraphEvidenceItem(pair.Key, side, repo == null ? "Repository unknown" : $"{repo.Label} [{repo.Id}] · {repo.Root}",
                record?.RepoId, record, pair.Value.Order(StringComparer.Ordinal).ToImmutableArray(), !direct.Contains(pair.Key));
        }).ToImmutableArray();
        detail = new(selection, selectedEdges, items); reason = ""; return true;
    }

    public static FleetGraphSourceRequest? BuildSourceRequest(GraphDocument graph, GraphContext current,
        FleetGraphSelection selection, string evidenceId, out string reason)
    {
        if (!TryDescribe(graph, current, selection, out var detail, out reason)) return null;
        var item = detail!.Items.SingleOrDefault(item => item.Id == evidenceId);
        if (item?.Record is not { } record)
        { reason = item == null ? "This evidence is not referenced by the selected canonical facts." : "The referenced evidence record is unavailable; its source is unknown."; return null; }
        var repo = graph.Repositories.SingleOrDefault(repo => repo.Id == record.RepoId);
        if (repo == null || string.IsNullOrWhiteSpace(repo.RequestedId) || repo.Status is not ("completed" or "partial"))
        { reason = "A verified completed child repository is unavailable for this evidence."; return null; }
        if (graph.Repositories.Any(row => !TryCanonicalRoot(row.Root, out _)) || !TryCanonicalRoot(repo.Root, out string root) ||
            graph.Repositories.Count(row => TryCanonicalRoot(row.Root, out string other) && string.Equals(other, root, StringComparison.OrdinalIgnoreCase)) != 1 ||
            graph.Repositories.Count(row => row.RequestedId == repo.RequestedId) != 1)
        { reason = "The evidence repository root or child identity is ambiguous or unsafe."; return null; }
        if (!TryRelativeSource(root, record.File, out string relative))
        { reason = record.File == null ? "No source file was supplied for this evidence." : "The supplied source reference is not a safe bounded repository-relative path."; return null; }
        int? line = record.Data.TryGetProperty("line", out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int number) && number > 0 ? number : null;
        reason = "";
        return new(current, selection, record.Id, repo.Id, repo.RequestedId!, root, relative, line, repo.SnapshotId, repo.SnapshotAt);
    }

    public static bool TryValidate(GraphDocument graph, GraphContext current, FleetGraphSourceRequest request, out string reason)
    {
        var expected = BuildSourceRequest(graph, current, request.Selection, request.EvidenceId, out reason);
        if (expected == null) return false;
        if (request.Context != current || request.GraphRepositoryId != expected.GraphRepositoryId ||
            request.RequestedRepositoryId != expected.RequestedRepositoryId || request.RepositoryRoot != expected.RepositoryRoot ||
            request.RelativePath != expected.RelativePath || request.Line != expected.Line || request.SnapshotId != expected.SnapshotId || request.SnapshotAt != expected.SnapshotAt)
        { reason = "The source request no longer matches the selected captured evidence and child identity."; return false; }
        return true;
    }

    public static bool SameSelection(FleetGraphSelection left, FleetGraphSelection right) => left.Context == right.Context &&
        left.PresentationId == right.PresentationId && left.IsEdge == right.IsEdge &&
        left.NodeIds.SequenceEqual(right.NodeIds, StringComparer.Ordinal) && left.EdgeIds.SequenceEqual(right.EdgeIds, StringComparer.Ordinal);

    private static bool TryCanonicalRoot(string value, out string root)
    {
        root = "";
        try
        {
            if (value.Length > 4096 || value.Any(char.IsControl) || !Path.IsPathFullyQualified(value) || value.StartsWith("\\\\") || value.StartsWith("//")) return false;
            string prefix = Path.GetPathRoot(value)!;
            string tail = value[prefix.Length..].Replace('\\', '/').TrimEnd('/');
            if (tail.Length > 0 && tail.Split('/').Any(segment => !SafeWindowsSegment(segment))) return false;
            root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(value)); return true;
        }
        catch (Exception error) when (error is ArgumentException or IOException or NotSupportedException) { return false; }
    }

    private static bool TryRelativeSource(string root, string? value, out string relative)
    {
        relative = "";
        if (string.IsNullOrWhiteSpace(value) || value.Length > 2048 || value.Any(char.IsControl) || value.IndexOfAny([':', '*', '?', '"', '<', '>', '|']) >= 0 || Path.IsPathRooted(value)) return false;
        var segments = value.Replace('\\', '/').Split('/');
        if (segments.Any(segment => !SafeWindowsSegment(segment))) return false;
        try
        {
            string candidate = Path.GetFullPath(Path.Combine(root, Path.Combine(segments)));
            string prefix = Path.EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar;
            if (!candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
            relative = string.Join('/', segments); return true;
        }
        catch (Exception error) when (error is ArgumentException or IOException or NotSupportedException) { return false; }
    }

    private static bool SafeWindowsSegment(string segment)
    {
        if (segment is "" or "." or ".." || segment.Length > 255 || segment != segment.Trim() || segment.EndsWith('.') ||
            segment.Any(char.IsControl) || segment.IndexOfAny([':', '*', '?', '"', '<', '>', '|']) >= 0) return false;
        string stem = segment.Split('.')[0].ToUpperInvariant();
        return stem is not ("CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$" or "CLOCK$") &&
            !(stem.Length == 4 && (stem[3] is >= '1' and <= '9' or '¹' or '²' or '³') && (stem.StartsWith("COM") || stem.StartsWith("LPT")));
    }
}
