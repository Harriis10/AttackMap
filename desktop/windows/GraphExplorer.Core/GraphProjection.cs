using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;

namespace AttackMap.GraphExplorer;

public enum GraphResolutionFilter { All, Observed, Candidate, Inferred }
public enum GraphNeighborhood { All, Upstream, Downstream }
public sealed record GraphFilter(GraphResolutionFilter Resolution = GraphResolutionFilter.All,
    bool InterRepositoryOnly = false, GraphNeighborhood Neighborhood = GraphNeighborhood.All, string? FocusNodeId = null);

public sealed record ProjectedNode(string Id, GraphNode Original, string? ParentId, bool Collapsed,
    ImmutableArray<string> UnderlyingNodeIds, ImmutableArray<string> InternalEdgeIds);
public sealed record ProjectedEdge(string Id, string Source, string Target, string Kind, bool Directed,
    string Resolution, bool Proxy, string Basis, ImmutableArray<string> UnderlyingEdgeIds)
{
    public int Count => UnderlyingEdgeIds.Length;
}
public sealed record GraphProjection(GraphDocument Document, ImmutableArray<ProjectedNode> Nodes,
    ImmutableArray<ProjectedEdge> Edges, ImmutableHashSet<string> CollapsedIds,
    ImmutableDictionary<string, string> VisibleNodeForOriginal, GraphFilter Filter,
    ImmutableArray<string> FilteredEdgeIds)
{
    public int HiddenNodeCount => Document.Nodes.Length - Nodes.Length;
    public int HiddenInternalEdgeCount => Nodes.Sum(x => x.InternalEdgeIds.Length);
    public int FilteredEdgeCount => FilteredEdgeIds.Length;
    public string PathNotice => GraphDocument.AggregatePathWarning;

    /// <summary>Collapse never edits the source document; expanding recreates exact canonical facts.</summary>
    public static GraphProjection Create(GraphDocument document, IEnumerable<string>? collapsedIds = null, GraphFilter? filter = null)
    {
        filter ??= new();
        if (!Enum.IsDefined(filter.Resolution) || !Enum.IsDefined(filter.Neighborhood)) throw new ArgumentException("Unsupported presentation filter.", nameof(filter));
        var byId = document.Nodes.ToDictionary(x => x.Id, StringComparer.Ordinal);
        if (filter.FocusNodeId is not null && !byId.ContainsKey(filter.FocusNodeId)) throw new ArgumentException("Neighborhood focus is not in the captured graph.", nameof(filter));
        if (filter.Neighborhood != GraphNeighborhood.All && filter.FocusNodeId is null) throw new ArgumentException("Neighborhood filter requires a canonical node ID.", nameof(filter));
        var collapsed = (collapsedIds ?? []).ToImmutableHashSet(StringComparer.Ordinal);
        if (collapsed.Any(x => !byId.ContainsKey(x))) throw new ArgumentException("Collapse ID is not in this graph.", nameof(collapsedIds));
        var visible = ImmutableDictionary.CreateBuilder<string, string>(StringComparer.Ordinal);
        foreach (var node in document.Nodes)
        {
            string representative = node.Id;
            if (!node.IsProxy)
                for (string? parent = node.ParentId; parent is not null; parent = byId[parent].ParentId)
                {
                    if (collapsed.Contains(parent)) representative = parent;
                    // Explicit intermediaries remain visible even when an owning repository collapses.
                    if (byId[parent].IsProxy) break;
                }
            visible.Add(node.Id, representative);
        }
        var internals = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var buckets = new Dictionary<string, List<GraphEdge>>(StringComparer.Ordinal);
        var filtered = ImmutableArray.CreateBuilder<string>();
        var focusNodes = new HashSet<string>(StringComparer.Ordinal);
        if (filter.FocusNodeId is not null)
            foreach (var node in document.Nodes)
                for (string? id = node.Id; id is not null; id = byId[id].ParentId)
                    if (id == filter.FocusNodeId) { focusNodes.Add(node.Id); break; }
        foreach (var edge in document.Edges)
        {
            bool resolutionMatches = filter.Resolution switch {
                GraphResolutionFilter.Observed => edge.Resolution is "observed" or "observed_via_proxy",
                GraphResolutionFilter.Candidate => edge.Resolution == "candidate",
                GraphResolutionFilter.Inferred => edge.Resolution == "inferred",
                _ => true };
            bool interRepository = edge.Metadata.TryGetProperty("scope", out var scope) && scope.ValueKind == System.Text.Json.JsonValueKind.String && scope.GetString() == "cross_repository"
                || byId[edge.Source].RepoId is { } sourceRepo && byId[edge.Target].RepoId is { } targetRepo && sourceRepo != targetRepo;
            bool neighborhoodMatches = filter.Neighborhood == GraphNeighborhood.All
                || edge.Kind is not ("containment" or "ownership" or "deployment") &&
                (filter.Neighborhood == GraphNeighborhood.Upstream ? focusNodes.Contains(edge.Target) : focusNodes.Contains(edge.Source));
            if (!resolutionMatches || filter.InterRepositoryOnly && !interRepository || !neighborhoodMatches)
            { filtered.Add(edge.Id); continue; }
            string source = visible[edge.Source], target = visible[edge.Target];
            if (source == target && (source != edge.Source || target != edge.Target))
            {
                if (!internals.TryGetValue(source, out var list)) internals[source] = list = [];
                list.Add(edge.Id);
                continue;
            }
            // Typed tuple serialization avoids delimiter collisions and preserves proxy leg semantics.
            string key = System.Text.Json.JsonSerializer.Serialize(new[] {
                source, target, edge.Kind, edge.Directed.ToString(), edge.Resolution, edge.Basis,
                edge.Proxy.ToString(), edge.Proxy ? Semantic(edge, "relation_id") : "direct", Semantic(edge, "endpoint_resolution"),
                Semantic(edge, "proxy"), Semantic(edge, "proxy_leg"), Semantic(edge, "leg") });
            if (!buckets.TryGetValue(key, out var bucket)) buckets[key] = bucket = [];
            bucket.Add(edge);
        }
        var underlying = visible.GroupBy(x => x.Value, StringComparer.Ordinal).ToDictionary(x => x.Key,
            x => x.Select(pair => pair.Key).Order(StringComparer.Ordinal).ToImmutableArray(), StringComparer.Ordinal);
        var nodes = document.Nodes.Where(x => visible[x.Id] == x.Id).Select(x => new ProjectedNode(
            x.Id, x, x.ParentId is null ? null : visible[x.ParentId], collapsed.Contains(x.Id),
            underlying[x.Id],
            internals.TryGetValue(x.Id, out var list) ? list.Order(StringComparer.Ordinal).ToImmutableArray() : []))
            .OrderBy(x => x.Id, StringComparer.Ordinal).ToImmutableArray();
        var edges = buckets.OrderBy(x => x.Key, StringComparer.Ordinal).Select(pair =>
        {
            var first = pair.Value[0];
            var ids = pair.Value.Select(x => x.Id).Order(StringComparer.Ordinal).ToImmutableArray();
            string id = ids.Length == 1 && visible[first.Source] == first.Source && visible[first.Target] == first.Target
                ? first.Id : "aggregate:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(pair.Key + System.Text.Json.JsonSerializer.Serialize(ids)))).ToLowerInvariant();
            return new ProjectedEdge(id, visible[first.Source], visible[first.Target], first.Kind, first.Directed,
                first.Resolution, first.Proxy, first.Basis, ids);
        }).ToImmutableArray();
        return new(document, nodes, edges, collapsed, visible.ToImmutable(), filter, filtered.Order(StringComparer.Ordinal).ToImmutableArray());
    }

    private static string Semantic(GraphEdge edge, string name) => edge.Metadata.TryGetProperty(name, out var value) ? value.GetRawText() : "null";

    /// <summary>Non-containment model endpoint continuity only; this is not runtime reachability or execution proof.</summary>
    public bool IsContinuousCanonicalPath(IEnumerable<string> edgeIds)
    {
        var byId = Document.Edges.ToDictionary(x => x.Id, StringComparer.Ordinal);
        string? previous = null;
        bool any = false;
        foreach (string id in edgeIds)
        {
            if (!byId.TryGetValue(id, out var edge) || !edge.Directed || edge.Kind is "containment" or "ownership" or "deployment"
                || edge.Resolution is not ("resolved" or "observed" or "inferred" or "via_proxy")
                || (previous is not null && previous != edge.Source)) return false;
            previous = edge.Target;
            any = true;
        }
        return any;
    }
}
