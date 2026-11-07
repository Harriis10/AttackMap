namespace AttackMap.NativeSpike;

// Input admission for the opt-in native fleet QA journey; performs no writes.
public static class FleetTransportQaInputs
{
    public static string? Read(string[] arguments, string applicationDirectory)
    {
        if (!arguments.Contains("--fleet-transport-smoke")) return null;
        if (arguments.Length != 5 || arguments[1] != "--fleet-transport-smoke")
            throw new ArgumentException("Fleet transport QA requires output, engine and shared_datastores fixture directory.");
        foreach (string path in arguments.Skip(2)) FleetTransportLocalPath(path);
        string directory = Path.GetFullPath(arguments[2]);
        string enginePath = Path.GetFullPath(arguments[3]);
        string corpus = Path.GetFullPath(arguments[4]);
        if (!Directory.Exists(directory) || Directory.EnumerateFileSystemEntries(directory).Any() ||
            !File.Exists(enginePath) || !enginePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            !Directory.Exists(corpus) || Path.GetFileName(corpus) != "shared_datastores" ||
            FleetTransportOverlap(directory, corpus) || FleetTransportOverlap(directory, applicationDirectory) ||
            FleetTransportOverlap(directory, Path.GetDirectoryName(enginePath)!))
            throw new InvalidDataException("Fleet QA requires fresh separate local output, explicit engine and existing fixtures.");
        foreach (string fixture in new[] { Path.Combine("reader", "config.yaml"), Path.Combine("writer", "config.json") })
        {
            string path = Path.Combine(corpus, fixture);
            FleetTransportLocalPath(path);
            if (!File.Exists(path)) throw new FileNotFoundException("Missing fleet fixture.", path);
        }
        return directory;
    }

    private static void FleetTransportLocalPath(string path)
    {
        if (!Path.IsPathFullyQualified(path) || path.StartsWith("\\\\", StringComparison.Ordinal) ||
            path.StartsWith("//", StringComparison.Ordinal) || path.Any(char.IsControl))
            throw new InvalidDataException("Fleet QA requires absolute local paths.");
        string full = Path.GetFullPath(path);
        // Same fixed-drive/canonical/no-ADS policy as ProviderFaultLocalPath; kept pure for non-WinUI tests.
        if (full[Path.GetPathRoot(full)!.Length..].Any(c => c is ':' or '*' or '?' or '"' or '<' or '>' or '|') ||
            new DriveInfo(Path.GetPathRoot(full)!).DriveType != DriveType.Fixed ||
            !string.Equals(path.TrimEnd(Path.DirectorySeparatorChar), full.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Canonical fixed-drive QA paths without alternate streams required.");
        for (string? current = full; current != null; current = Path.GetDirectoryName(current))
        {
            try { if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Redirected fleet QA path."); }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
    }

    private static bool FleetTransportOverlap(string left, string right) =>
        Within(left, right) || Within(right, left);

    private static bool Within(string path, string directory)
    {
        string relative = Path.GetRelativePath(directory, path);
        return !Path.IsPathFullyQualified(relative) && relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    }

}
