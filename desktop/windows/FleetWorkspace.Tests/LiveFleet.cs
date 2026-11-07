using AttackMap.NativeSpike;
using System.Security.Cryptography;
using System.Text.Json;

internal static class LiveFleet
{
    public static async Task Run(string[] args)
    {
        string Value(string key) { int i = Array.IndexOf(args, key); if (i < 0 || i + 1 == args.Length) throw new ArgumentException(key); return Path.GetFullPath(args[i + 1]); }
        string engine = Value("--real-engine"), output = Value("--output");
        if (Directory.Exists(output)) throw new IOException("Choose a new output directory.");
        Directory.CreateDirectory(output);
        var roots = new[] { new FleetRoot("one", Path.Combine(output, "fixtures", "a space", "same")),
            new FleetRoot("two", Path.Combine(output, "fixtures", "Žluťoučký", "same")) };
        foreach (var root in roots) { Directory.CreateDirectory(root.RepositoryPath); File.WriteAllText(Path.Combine(root.RepositoryPath, "config.json"), "{\"debug\":true,\"host\":\"0.0.0.0\"}\n"); }
        var before = roots.Select(r => Hash(Path.Combine(r.RepositoryPath, "config.json"))).ToArray();
        var events = new List<FleetChildStatus>();
        FleetGeneration? identity = null;
        FleetSessionResult? result = null;
        var session = new FleetSession();
        var workspace = new FleetWorkspace();
        foreach (var root in roots) workspace.Add(root.RepositoryId, root.RepositoryPath);
        await session.Run(engine, roots, Path.Combine(output, "results"), 11,
            started: generation => { identity = generation; workspace.Begin(generation); },
            child: row => { events.Add(row); if (!workspace.ApplyChild(identity!, row) && !workspace.Children.Contains(row)) throw new InvalidDataException("Workspace rejected actual child."); },
            completed: value => { result = value; foreach (var row in value.Children) workspace.ApplyChild(value.Generation, row);
                if (!workspace.Finish(value.Generation, value.Outcome)) throw new InvalidDataException("Workspace rejected terminal."); return Task.CompletedTask; },
            timeoutSeconds: 180, maxWorkers: 2, options: new FleetScanOptions(TimeoutSeconds: 180, TimeBudgetSeconds: 60), modules: "config");
        if (result == null || identity == null || result.Generation != identity || result.Outcome != "succeeded" ||
            result.Children.Count != 2 || result.Children.Any(c => c.State != "completed") || session.CleanupBlocked || !workspace.IsCurrent)
            throw new InvalidDataException("Real fleet did not complete with the selected generation.");
        string runFolder = Path.Combine(output, "results", "native-fleet-" + identity.RunId);
        foreach (var row in result.Children)
        {
            var root = roots.Single(r => r.RepositoryId == row.RepositoryId);
            using var manifest = JsonDocument.Parse(File.ReadAllText(row.ManifestPath!));
            if (manifest.RootElement.GetProperty("generation_id").GetString() != FleetSession.ChildRunId(identity, row.RepositoryId) ||
                !string.Equals(Path.GetFullPath(manifest.RootElement.GetProperty("run_identity").GetProperty("repo_root").GetString()!), root.RepositoryPath, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Manifest does not belong to the selected child.");
            using var report = JsonDocument.Parse(File.ReadAllText(Path.Combine(Path.GetDirectoryName(row.ManifestPath!)!, "attackmap-report.json")));
            if (!string.Equals(Path.GetFullPath(report.RootElement.GetProperty("scan").GetProperty("root").GetString()!), root.RepositoryPath, StringComparison.OrdinalIgnoreCase) || workspace.Open(row.RepositoryId) == null)
                throw new InvalidDataException("Actual report/workspace root mismatch.");
        }
        if (!before.SequenceEqual(roots.Select(r => Hash(Path.Combine(r.RepositoryPath, "config.json"))))) throw new InvalidDataException("Fixtures changed.");
        using var pointer = JsonDocument.Parse(File.ReadAllText(Path.Combine(runFolder, "current-generation.json")));
        if (pointer.RootElement.GetProperty("generation").GetString() != identity.RunId) throw new InvalidDataException("Current pointer did not publish this run.");
        var proof = new { passed = true, scope = "Actual headless CSharp FleetSession and FleetWorkspace; OS ownership verified by external launcher", engine,
            engine_sha256 = Hash(engine), generation = identity, result, child_events = events, cleanup_blocked = session.CleanupBlocked, fixtures_unchanged = true };
        File.WriteAllText(Path.Combine(output, "result.json"), JsonSerializer.Serialize(proof, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine("PASS actual CSharp FleetSession/Workspace: 2 completed children, manifest/report roots and current generation verified.");
    }
    private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
}
