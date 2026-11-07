namespace AttackMap.NativeSpike;

// Interactive QA uses the normal restore/save handlers with caller-owned state.
// This flag does not schedule smoke actions or create the supplied directory.
public static class ManualOptionsState
{
    public static string? ReadDirectory(IReadOnlyList<string> arguments)
    {
        if (!arguments.Contains("--options-manual", StringComparer.Ordinal)) return null;
        if (arguments.Count != 3 || arguments[1] != "--options-manual" ||
            !Path.IsPathFullyQualified(arguments[2]))
            throw new ArgumentException("Options manual QA requires only --options-manual and an absolute local caller-created state directory.");
        string directory = Path.GetFullPath(arguments[2]);
        if (directory.StartsWith(@"\\", StringComparison.Ordinal))
            throw new ArgumentException("Options manual QA requires a local state directory.");
        if (!Directory.Exists(directory))
            throw new DirectoryNotFoundException("Create the caller-owned options manual QA directory before launch.");
        return directory;
    }
}
