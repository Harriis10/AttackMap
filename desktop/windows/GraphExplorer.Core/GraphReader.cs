using System.Collections.Immutable;
using System.Text;
using System.Text.Json;

namespace AttackMap.GraphExplorer;

/// <summary>Bounded inert JSON input. Unknown additive properties are preserved in SourceJson.</summary>
public static class GraphReader
{
    public static GraphDocument Read(ReadOnlyMemory<byte> utf8, GraphContext context, GraphReadLimits? limits = null)
    {
        limits ??= new();
        if (limits.MaxBytes < 1 || limits.MaxNodes < 1 || limits.MaxEdges < 0 || limits.MaxRepositories < 1
            || limits.MaxEvidence < 0 || limits.MaxStringCharacters < 1 || limits.MaxDepth < 1)
            throw new ArgumentOutOfRangeException(nameof(limits));
        if (utf8.Length > limits.MaxBytes) throw new GraphReadException("Graph exceeds the byte budget; no truncated graph was accepted.");
        if (string.IsNullOrWhiteSpace(context.RunId) || string.IsNullOrWhiteSpace(context.GenerationId)
            || string.IsNullOrWhiteSpace(context.ReportHash) || context.SelectionRevision < 0)
            throw new GraphReadException("Verified run/generation/report identity and revision are required.");
        try
        {
            using var json = JsonDocument.Parse(utf8, new JsonDocumentOptions { MaxDepth = limits.MaxDepth });
            var root = json.RootElement;
            ValidateJson(root, limits.MaxStringCharacters);
            if (root.ValueKind != JsonValueKind.Object) throw new GraphReadException("Graph root must be an object.");
            if (Required(root, "schema_version") != "1.0" || Required(root, "kind") != "fleet_architecture")
                throw new GraphReadException("Unsupported graph schema/kind; expected 1.0 fleet_architecture.");
            var repos = Array(root, "repositories", limits.MaxRepositories).Select(x => new GraphRepository(
                Required(x, "id"), Text(x, "repo_id"), Text(x, "requested_id"), Required(x, "root"),
                Text(x, "label") ?? Required(x, "id"), Required(x, "status"),
                Text(x, "snapshot_id"), Text(x, "snapshot_at"))).ToImmutableArray();
            var nodes = Array(root, "nodes", limits.MaxNodes).Select(x => new GraphNode(
                Required(x, "id"), Required(x, "kind"), Text(x, "label") ?? Required(x, "id"),
                Text(x, "repo_id"), Text(x, "parent_id"), Refs(x), x.Clone())).ToImmutableArray();
            var edges = Array(root, "edges", limits.MaxEdges).Select(x => new GraphEdge(
                Required(x, "id"), Required(x, "source"), Required(x, "target"), Required(x, "kind"),
                Boolean(x, "directed"), Required(x, "resolution"), Text(x, "basis") ?? "unknown",
                Scalar(x, "confidence"), IsProxy(x), Refs(x), x.Clone())).ToImmutableArray();
            var evidence = Array(root, "evidence", limits.MaxEvidence).Select(x => new GraphEvidence(
                Required(x, "id"), Text(x, "repo_id"), x.Clone())).ToImmutableArray();
            var repoIds = Unique(repos.Select(x => x.Id), "repository");
            var nodeIds = Unique(nodes.Select(x => x.Id), "node");
            Unique(edges.Select(x => x.Id), "edge");
            var evidenceIds = Unique(evidence.Select(x => x.Id), "evidence");
            var byId = nodes.ToDictionary(x => x.Id, StringComparer.Ordinal);
            foreach (var repo in repos)
                if (!byId.TryGetValue(repo.Id, out var group) || group.Kind != "repository" || group.ParentId is not null || group.RepoId != repo.Id)
                    throw new GraphReadException($"Repository {repo.Id} requires its own root repository group node.");
            foreach (var node in nodes)
            {
                if (node.RepoId is not null && !repoIds.Contains(node.RepoId)) throw new GraphReadException($"Node {node.Id} has dangling repo_id.");
                if (node.ParentId is not null && !nodeIds.Contains(node.ParentId)) throw new GraphReadException($"Node {node.Id} has dangling parent_id.");
                if (node.ParentId is not null && node.RepoId is not null && byId[node.ParentId].RepoId != node.RepoId)
                    throw new GraphReadException($"Node {node.Id} has a parent in a different repository.");
            }
            foreach (var item in evidence)
            {
                if (item.RepoId is not null && !repoIds.Contains(item.RepoId)) throw new GraphReadException($"Evidence {item.Id} has dangling repo_id.");
                if (item.Data.TryGetProperty("file", out var file) && file.ValueKind is not (JsonValueKind.String or JsonValueKind.Null))
                    throw new GraphReadException($"Evidence {item.Id} file must be a string or null.");
                if (item.Data.TryGetProperty("line", out var line) && line.ValueKind != JsonValueKind.Null
                    && (line.ValueKind != JsonValueKind.Number || !line.TryGetInt32(out int number) || number < 1))
                    throw new GraphReadException($"Evidence {item.Id} line must be a positive integer or null.");
            }
            foreach (var edge in edges)
                if (!nodeIds.Contains(edge.Source) || !nodeIds.Contains(edge.Target)) throw new GraphReadException($"Edge {edge.Id} has dangling endpoint.");
            ValidateParents(nodes);
            var unknown = nodes.SelectMany(x => x.EvidenceRefs).Concat(edges.SelectMany(x => x.EvidenceRefs))
                .Where(x => !evidenceIds.Contains(x)).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToImmutableArray();
            if (!root.TryGetProperty("coverage", out var c)) throw new GraphReadException("coverage is required.");
            var coverage = c.Clone();
            if (coverage.ValueKind != JsonValueKind.Object) throw new GraphReadException("coverage must be an object.");
            var limitations = StringArray(root, "limitations", optional: false);
            if (unknown.Length > 0) limitations = limitations.Add($"{unknown.Length} evidence reference(s) unavailable; evidence is unknown, not absent.");
            return new(context, repos, nodes, edges, evidence, coverage, limitations, unknown, Encoding.UTF8.GetString(utf8.Span));
        }
        catch (JsonException error) { throw new GraphReadException($"Malformed graph JSON: {error.Message}"); }
    }

    private static void ValidateParents(ImmutableArray<GraphNode> nodes)
    {
        var parents = nodes.ToDictionary(x => x.Id, x => x.ParentId, StringComparer.Ordinal);
        var done = new HashSet<string>(StringComparer.Ordinal);
        foreach (var node in nodes)
        {
            var path = new HashSet<string>(StringComparer.Ordinal);
            string? current = node.Id;
            while (current is not null && !done.Contains(current))
            {
                if (!path.Add(current)) throw new GraphReadException("Containment parent cycle is invalid; semantic edge cycles remain supported.");
                current = parents[current];
            }
            done.UnionWith(path);
        }
    }

    private static void ValidateJson(JsonElement element, int maxString)
    {
        if (element.ValueKind == JsonValueKind.String && element.GetString()!.Length > maxString)
            throw new GraphReadException("Graph string exceeds the character budget.");
        if (element.ValueKind == JsonValueKind.Array) foreach (var item in element.EnumerateArray()) ValidateJson(item, maxString);
        if (element.ValueKind != JsonValueKind.Object) return;
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!names.Add(property.Name)) throw new GraphReadException($"Duplicate JSON property {property.Name}.");
            if (property.Name.Length > maxString) throw new GraphReadException("Graph property name exceeds the character budget.");
            ValidateJson(property.Value, maxString);
        }
    }
    private static HashSet<string> Unique(IEnumerable<string> ids, string kind)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (string id in ids) if (!set.Add(id)) throw new GraphReadException($"Duplicate {kind} ID: {id}.");
        return set;
    }
    private static IEnumerable<JsonElement> Array(JsonElement owner, string name, int maximum, bool optional = false)
    {
        if (!owner.TryGetProperty(name, out var value))
        {
            if (optional) return [];
            throw new GraphReadException($"Required array {name} missing.");
        }
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > maximum)
            throw new GraphReadException($"Invalid or oversized {name} array (limit {maximum}).");
        return value.EnumerateArray().ToArray();
    }
    private static string Required(JsonElement owner, string name) => Text(owner, name) is { Length: > 0 } value
        && !string.IsNullOrWhiteSpace(value) ? value : throw new GraphReadException($"Required string {name} missing.");
    private static string? Text(JsonElement owner, string name)
    {
        if (owner.ValueKind != JsonValueKind.Object) throw new GraphReadException("Graph collection items must be objects.");
        if (!owner.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind != JsonValueKind.String) throw new GraphReadException($"{name} must be a string.");
        return value.GetString();
    }
    private static string? Scalar(JsonElement owner, string name)
    {
        if (!owner.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        if (value.ValueKind is not (JsonValueKind.String or JsonValueKind.Number)) throw new GraphReadException($"{name} must be string or number.");
        return value.ValueKind == JsonValueKind.String ? value.GetString() : value.GetRawText();
    }
    private static bool Boolean(JsonElement owner, string name)
    {
        if (!owner.TryGetProperty(name, out var value)) throw new GraphReadException($"Required boolean {name} missing.");
        if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new GraphReadException($"{name} must be boolean.");
        return value.GetBoolean();
    }
    private static bool IsProxy(JsonElement owner) => owner.TryGetProperty("proxy", out var value)
        && value.ValueKind is not (JsonValueKind.Null or JsonValueKind.False)
        || owner.TryGetProperty("proxy_leg", out _)
        || owner.TryGetProperty("leg", out var leg) && leg.ValueKind == JsonValueKind.String && leg.GetString() is "client_to_proxy" or "proxy_to_service" or "proxy_to_server";
    private static ImmutableArray<string> Refs(JsonElement owner) => StringArray(owner, "evidence_refs", optional: true);
    private static ImmutableArray<string> StringArray(JsonElement owner, string name, bool optional)
    {
        if (!owner.TryGetProperty(name, out var value) && optional) return [];
        if (value.ValueKind != JsonValueKind.Array || value.EnumerateArray().Any(x => x.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(x.GetString())))
            throw new GraphReadException($"{name} must be an array of nonempty strings.");
        return value.EnumerateArray().Select(x => x.GetString()!).ToImmutableArray();
    }
}
