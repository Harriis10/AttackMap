using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AttackMap.GraphExplorer;

namespace AttackMap.NativeSpike;

public sealed record FleetSnapshotBinding(string RepositoryId, string ManifestHash, string? SnapshotId, string? CapturedAt);

/// <summary>Attach separately verified child identities to a verified core graph without joining labels.</summary>
public static class FleetGraphBinding
{
    public static GraphDocument Bind(byte[] graph, GraphContext context, FleetWorkspace workspace, IReadOnlyList<FleetSnapshotBinding> snapshots)
    {
        if (workspace.Active is not { } generation || workspace.IsRunning || context.RunId != generation.RunId ||
            context.GenerationId != generation.RunId || context.SelectionRevision != generation.Generation)
            throw new InvalidDataException("Graph context is not the selected finished fleet generation.");
        var document = GraphReader.Read(graph, context);
        var selected = workspace.Repositories.ToDictionary(row => Normalize(row.RepositoryPath), StringComparer.OrdinalIgnoreCase);
        var children = workspace.Children.ToDictionary(row => row.RepositoryId, StringComparer.Ordinal);
        var proofs = snapshots.ToDictionary(row => row.RepositoryId, StringComparer.Ordinal);
        if (document.Repositories.Length != selected.Count || document.Repositories.Select(row => Normalize(row.Root)).Distinct(StringComparer.OrdinalIgnoreCase).Count() != selected.Count)
            throw new InvalidDataException("Graph does not contain exactly the selected repository roots.");
        var enriched = JsonNode.Parse(document.SourceJson)!.AsObject();
        foreach (var item in enriched["repositories"]!.AsArray())
        {
            var row = item!.AsObject(); string root = Normalize(row["root"]!.GetValue<string>());
            if (!selected.TryGetValue(root, out var requested) || !children.TryGetValue(requested.RepositoryId, out var child))
                throw new InvalidDataException("Graph repository is outside the captured fleet child set.");
            string state = row["status"]!.GetValue<string>();
            if (child.State == "completed" ? state is not ("completed" or "partial") : state != child.State)
                throw new InvalidDataException("Graph repository status differs from its verified child.");
            row["requested_id"] = requested.RepositoryId;
            if (child.State == "completed")
            {
                if (!proofs.TryGetValue(requested.RepositoryId, out var proof) || proof.ManifestHash != child.ManifestHash)
                    throw new InvalidDataException("Graph child snapshot lacks its captured manifest proof.");
                row["snapshot_id"] = proof.SnapshotId;
                row["snapshot_at"] = proof.CapturedAt;
                row["host_binding"] = JsonSerializer.SerializeToNode(new { child_manifest_sha256 = proof.ManifestHash });
            }
            else
            {
                row["snapshot_id"] = null; row["snapshot_at"] = null;
                row.Remove("host_binding");
            }
        }
        enriched["host_binding"] = JsonSerializer.SerializeToNode(new { source_summary_sha256 = context.ReportHash,
            run_id = context.RunId, generation = context.SelectionRevision, independent_child_snapshots = true });
        return GraphReader.Read(Encoding.UTF8.GetBytes(enriched.ToJsonString()), context);
    }

    private static string Normalize(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.StartsWith("\\\\") || path.StartsWith("//") || path.Any(char.IsControl))
            throw new InvalidDataException("Graph root must be an absolute local path.");
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
    }
}
