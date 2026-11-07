namespace AttackMap.NativeSpike;

public sealed record FleetRoot(string RepositoryId, string RepositoryPath);
public sealed record FleetGeneration(string RunId, string RepositorySetId, long Generation);
public sealed record FleetChildStatus(string RepositoryId, string RepositoryPath, string State, string? ManifestPath, string? ManifestHash);
public sealed record FleetOpenRepository(FleetGeneration Generation, FleetRoot Repository, string ManifestPath, string ManifestHash);

/// <summary>Owns only an explicitly selected fleet; never replaces single-repository state.</summary>
public sealed class FleetWorkspace
{
    private readonly List<FleetRoot> roots = new();
    private readonly Dictionary<string, FleetChildStatus> children = new(StringComparer.Ordinal);
    public IReadOnlyList<FleetRoot> Repositories => roots.AsReadOnly();
    public FleetGeneration? Active { get; private set; }
    public string Outcome { get; private set; } = "not started";
    public bool IsRunning { get; private set; }
    public bool IsCurrent => Outcome == "succeeded";
    public IReadOnlyList<FleetChildStatus> Children => roots.Where(r => children.ContainsKey(r.RepositoryId)).Select(r => children[r.RepositoryId]).ToArray();

    public void Add(string id, string path)
    {
        if (IsRunning) throw new InvalidOperationException("Finish or cancel the active fleet before changing repositories.");
        if (string.IsNullOrWhiteSpace(id) || id.Length > 256 || path.Any(char.IsControl) || !Path.IsPathFullyQualified(path) || path.StartsWith("\\\\") || path.StartsWith("//"))
            throw new InvalidDataException("Choose an absolute local repository folder and a unique identifier.");
        string full = Normalize(path);
        if (roots.Count >= 16 || roots.Any(r => r.RepositoryId == id || string.Equals(r.RepositoryPath, full, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException("Fleet requires unique repository identifiers and folders, with at most 16 repositories.");
        roots.Add(new(id, full)); Invalidate();
    }
    public void Remove(string id)
    {
        if (IsRunning) throw new InvalidOperationException("Finish or cancel the active fleet first.");
        roots.RemoveAll(r => r.RepositoryId == id); Invalidate();
    }
    private void Invalidate() { Active = null; children.Clear(); Outcome = "not started"; }
    private static string Normalize(string path) { string full = Path.GetFullPath(path); return full.Length == Path.GetPathRoot(full)?.Length ? full : full.TrimEnd('\\', '/'); }
    public void Begin(FleetGeneration generation)
    {
        if (IsRunning || roots.Count < 2 || string.IsNullOrWhiteSpace(generation.RunId) || !generation.RepositorySetId.StartsWith("fleet:") || generation.Generation < 0)
            throw new InvalidOperationException("A new fleet needs at least two explicitly selected repositories and a broker repository-set identity.");
        Active = generation; Outcome = "running"; IsRunning = true; children.Clear();
    }
    public bool ApplyChild(FleetGeneration generation, FleetChildStatus child)
    {
        if (!IsRunning || Active != generation) return false;
        var root = roots.SingleOrDefault(r => r.RepositoryId == child.RepositoryId);
        if (root == null || !Path.IsPathFullyQualified(child.RepositoryPath) || !string.Equals(root.RepositoryPath, Normalize(child.RepositoryPath), StringComparison.OrdinalIgnoreCase)) return false;
        if (child.State is not ("queued" or "running" or "completed" or "failed" or "cancelled" or "skipped")) return false;
        bool proof = child.ManifestPath != null && Path.IsPathFullyQualified(child.ManifestPath) && child.ManifestHash?.Length == 64 && child.ManifestHash.All(Uri.IsHexDigit);
        if ((child.State == "completed") != proof || (child.State != "completed" && (child.ManifestPath != null || child.ManifestHash != null))) return false;
        if (children.TryGetValue(child.RepositoryId, out var previous) && previous.State is "completed" or "failed" or "cancelled" or "skipped") return false;
        if (children.TryGetValue(child.RepositoryId, out previous) && previous.State == "running" && child.State == "queued") return false;
        children[child.RepositoryId] = child; return true;
    }
    public bool Finish(FleetGeneration generation, string outcome)
    {
        if (!IsRunning || Active != generation || outcome is not ("succeeded" or "partial" or "failed" or "cancelled")) return false;
        int complete = children.Values.Count(c => c.State == "completed");
        if (children.Count != roots.Count || children.Values.Any(c => c.State is "queued" or "running")) return false;
        if (outcome == "failed" && complete > 0 && complete < roots.Count) return false;
        if (outcome == "succeeded" && complete != roots.Count || outcome == "partial" && (complete == 0 || complete == roots.Count)) return false;
        Outcome = outcome; IsRunning = false; return true;
    }
    public FleetOpenRepository? Open(string repositoryId)
    {
        if (Active == null || !children.TryGetValue(repositoryId, out var child) || child.State != "completed") return null;
        return new(Active, roots.Single(r => r.RepositoryId == repositoryId), child.ManifestPath!, child.ManifestHash!);
    }
}
