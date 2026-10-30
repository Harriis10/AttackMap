using System.Collections.Immutable;
using System.Text.Json;

namespace AttackMap.GraphExplorer;

/// <summary>Identity is supplied by the verified artifact envelope, never inferred from labels.</summary>
public sealed record GraphContext(string RunId, string GenerationId, string ReportHash, long SelectionRevision)
{
    public bool IsCurrent(GraphContext current) => this == current;
}

public sealed record GraphRepository(string Id, string? RepoId, string? RequestedId, string Root,
    string Label, string Status, string? SnapshotId, string? SnapshotAt);
public sealed record GraphEvidence(string Id, string? RepoId, JsonElement Data)
{
    public string? File => Data.TryGetProperty("file", out var file) && file.ValueKind == JsonValueKind.String ? file.GetString() : null;
    public int? Line => Data.TryGetProperty("line", out var line) && line.ValueKind == JsonValueKind.Number ? line.GetInt32() : null;
}
public sealed record GraphNode(string Id, string Kind, string Label, string? RepoId,
    string? ParentId, ImmutableArray<string> EvidenceRefs, JsonElement Metadata)
{
    public bool IsProxy => Metadata.TryGetProperty("component_role", out var role) && role.ValueKind == JsonValueKind.String && role.GetString() == "proxy";
}
public sealed record GraphEdge(string Id, string Source, string Target, string Kind, bool Directed,
    string Resolution, string Basis, string? Confidence, bool Proxy, ImmutableArray<string> EvidenceRefs,
    JsonElement Metadata);
public sealed record GraphDocument(GraphContext Context, ImmutableArray<GraphRepository> Repositories,
    ImmutableArray<GraphNode> Nodes, ImmutableArray<GraphEdge> Edges,
    ImmutableArray<GraphEvidence> Evidence, JsonElement Coverage, ImmutableArray<string> Limitations,
    ImmutableArray<string> UnknownEvidenceRefs, string SourceJson)
{
    public const string AggregatePathWarning = "A path in the collapsed overview does not prove a continuous path between concrete services. Inspect original edge endpoints and evidence.";
}

public sealed record GraphReadLimits(int MaxBytes = 16 * 1024 * 1024, int MaxNodes = 10_000,
    int MaxEdges = 30_000, int MaxRepositories = 16, int MaxEvidence = 100_000,
    int MaxStringCharacters = 16_384, int MaxDepth = 48);

public sealed class GraphReadException(string message) : IOException(message);
