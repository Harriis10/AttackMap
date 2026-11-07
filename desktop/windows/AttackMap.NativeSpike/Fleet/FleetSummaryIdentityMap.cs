namespace AttackMap.NativeSpike;

/// <summary>Maps a verified core summary to the selected transport children by exact canonical root.</summary>
public sealed class FleetSummaryIdentityMap
{
    private readonly FleetWorkspace workspace;
    private readonly FleetGeneration generation;
    private readonly Dictionary<string, string> transportIds;

    private FleetSummaryIdentityMap(FleetWorkspace workspace, FleetGeneration generation, Dictionary<string, string> transportIds)
    {
        this.workspace = workspace;
        this.generation = generation;
        this.transportIds = transportIds;
    }

    public static FleetSummaryIdentityMap Bind(FleetWorkspace workspace, FleetSummary summary)
    {
        if (workspace.Active is not { } generation || workspace.IsRunning)
            throw new InvalidDataException("Finish the selected fleet before binding its summary.");
        var selected = workspace.Repositories.ToDictionary(r => Normalize(r.RepositoryPath), r => r, StringComparer.OrdinalIgnoreCase);
        var complete = workspace.Children.Where(c => c.State == "completed").Select(c => c.RepositoryId).ToHashSet(StringComparer.Ordinal);
        var mappedRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ids = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var row in summary.Repositories)
        {
            string root = Normalize(row.Root);
            if (!selected.TryGetValue(root, out var requested) || !complete.Contains(requested.RepositoryId) ||
                !mappedRoots.Add(root) || !ids.TryAdd(row.RepositoryId, requested.RepositoryId))
                throw new InvalidDataException("Fleet summary does not match unique completed children and their exact roots.");
        }
        if (ids.Count != complete.Count)
            throw new InvalidDataException("Fleet summary omitted a completed selected child.");
        return new(workspace, generation, ids);
    }

    public FleetOpenRepository? Resolve(string coreRepositoryId)
    {
        if (workspace.IsRunning || workspace.Active != generation || !transportIds.TryGetValue(coreRepositoryId, out var id)) return null;
        return workspace.Open(id);
    }

    public FleetOpenRepository? ResolveRoot(string root)
    {
        if (workspace.IsRunning || workspace.Active != generation) return null;
        string normalized;
        try { normalized = Normalize(root); }
        catch (Exception e) when (e is ArgumentException or InvalidDataException or NotSupportedException) { return null; }
        var selected = workspace.Repositories.SingleOrDefault(r => string.Equals(Normalize(r.RepositoryPath), normalized, StringComparison.OrdinalIgnoreCase));
        return selected != null && transportIds.Values.Contains(selected.RepositoryId, StringComparer.Ordinal) ? workspace.Open(selected.RepositoryId) : null;
    }

    private static string Normalize(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Any(char.IsControl) || !Path.IsPathFullyQualified(path) || path.StartsWith("\\\\") || path.StartsWith("//"))
            throw new InvalidDataException("Fleet summary root must be an absolute local path.");
        string full = Path.GetFullPath(path);
        return full.Length == Path.GetPathRoot(full)?.Length ? full : full.TrimEnd('\\', '/');
    }
}
