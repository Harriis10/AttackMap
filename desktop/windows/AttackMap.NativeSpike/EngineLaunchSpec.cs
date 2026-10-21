using System.Diagnostics;

namespace AttackMap.NativeSpike;

public enum EngineRuntimeKind { Python, Frozen }
public enum EngineBrokerKind { Worker, Action }

/// <summary>Explicit executable selection; never searches PATH or probes binaries.</summary>
public sealed class EngineLaunchSpec
{
    public string ExecutablePath { get; }
    public EngineRuntimeKind RuntimeKind { get; }
    public bool InferredFrozenName { get; }

    public EngineLaunchSpec(string executablePath, EngineRuntimeKind? runtimeKind = null)
    {
        if (!Path.IsPathFullyQualified(executablePath) || !File.Exists(executablePath))
            throw new InvalidDataException("Choose an existing absolute engine executable path.");
        if (runtimeKind.HasValue && !Enum.IsDefined(runtimeKind.Value))
            throw new InvalidDataException("Choose Python or Frozen engine runtime.");
        ExecutablePath = Path.GetFullPath(executablePath);
        // Compatibility inference is limited to this exact documented product name.
        // Explicit kind always wins, including renamed frozen development binaries.
        InferredFrozenName = runtimeKind == null && Path.GetFileName(ExecutablePath).Equals("attackmap.exe", StringComparison.OrdinalIgnoreCase);
        RuntimeKind = runtimeKind ?? (InferredFrozenName ? EngineRuntimeKind.Frozen : EngineRuntimeKind.Python);
        // Static guards, checked before anything is spawned: a wrong path must
        // produce a clear error, never a launched process. The desktop app's own
        // executable must never be spawned as an engine (it ignores broker
        // arguments and opens a duplicate window), and a Python-kind selection
        // that carries no Python distribution markers is almost certainly a
        // mispicked executable.
        string? ownExecutable = Environment.ProcessPath;
        if (ownExecutable != null && string.Equals(Path.GetFullPath(ownExecutable), ExecutablePath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The desktop app executable is not an engine. Select the bundled engine (engine\\attackmap.exe) or a Python interpreter with AttackMap installed.");
        if (RuntimeKind == EngineRuntimeKind.Python && !LooksLikePythonInstallation(ExecutablePath))
            throw new InvalidDataException($"'{Path.GetFileName(ExecutablePath)}' is not a recognized engine executable. Select the bundled engine (engine\\attackmap.exe), or python.exe from an environment with AttackMap installed.");
    }

    /// <summary>Static, execution-free recognition of a Python installation:
    /// interpreters ship local DLL/library markers; venv launchers can instead
    /// reference a marked base installation through their local pyvenv.cfg.</summary>
    private static bool LooksLikePythonInstallation(string executablePath)
    {
        foreach (string directory in new[] { Path.GetDirectoryName(executablePath)!, Path.GetDirectoryName(Path.GetDirectoryName(executablePath))! })
        {
            if (directory is null) continue;
            try
            {
                if (Directory.EnumerateFiles(directory, "python3*.dll").Any()) return true;
                if (File.Exists(Path.Combine(directory, "Lib", "os.py"))) return true;
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        return LooksLikeLocalVenv(executablePath);
    }

    private static bool LooksLikeLocalVenv(string executablePath)
    {
        string name = Path.GetFileName(executablePath);
        if (!name.Equals("python.exe", StringComparison.OrdinalIgnoreCase) && !name.Equals("pythonw.exe", StringComparison.OrdinalIgnoreCase)) return false;
        try
        {
            string directory = Path.GetDirectoryName(executablePath)!;
            if (!LocalDirectory(directory)) return false;
            var configurations = new[] { directory, Path.GetDirectoryName(directory) }
                .Where(path => path != null).Select(path => Path.Combine(path!, "pyvenv.cfg"))
                .Distinct(StringComparer.OrdinalIgnoreCase).Where(File.Exists).ToArray();
            if (configurations.Length != 1 || (File.GetAttributes(configurations[0]) & FileAttributes.ReparsePoint) != 0) return false;
            using var stream = new FileStream(configurations[0], FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length is < 1 or > 16384) return false;
            byte[] bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes);
            if (stream.ReadByte() != -1) return false;
            string text = new System.Text.UTF8Encoding(false, true).GetString(bytes);
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string raw in text.Split('\n'))
            {
                string line = raw.Trim(); if (line.Length == 0) continue;
                if (line.Any(character => char.IsControl(character) && character != '\t')) return false;
                int separator = line.IndexOf('='); if (separator <= 0) return false;
                string key = line[..separator].Trim(), value = line[(separator + 1)..].Trim();
                if (key.Length == 0 || !key.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_') || !values.TryAdd(key, value)) return false;
            }
            if (!values.TryGetValue("home", out string? home) || !LocalDirectory(home)) return false;
            // A nested venv's optional executable/command values can name its
            // creating venv. Never execute or recursively follow those fields.
            return File.Exists(Path.Combine(home, "python.exe")) &&
                (Directory.EnumerateFiles(home, "python3*.dll").Any() || File.Exists(Path.Combine(home, "Lib", "os.py")));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        { return false; }
    }

    private static bool LocalDirectory(string directory)
    {
        if (!Path.IsPathFullyQualified(directory) || directory.StartsWith("\\\\", StringComparison.Ordinal) || directory.StartsWith("//", StringComparison.Ordinal) || directory.Any(char.IsControl) || directory.IndexOf(':', Math.Min(2, directory.Length)) >= 0) return false;
        if (directory.Replace('\\', '/').Split('/').Any(part => part is "." or ".." || part.EndsWith(' ') || part.EndsWith('.'))) return false;
        if (!Directory.Exists(directory) || new DriveInfo(Path.GetPathRoot(directory)!).DriveType == DriveType.Network) return false;
        for (DirectoryInfo? part = new(directory); part != null; part = part.Parent)
            if ((part.Attributes & FileAttributes.ReparsePoint) != 0) return false;
        return true;
    }

    public IReadOnlyList<string> ArgumentsFor(EngineBrokerKind broker, string requestPath)
    {
        if (!Enum.IsDefined(broker)) throw new InvalidDataException("Unknown engine broker operation.");
        if (!Path.IsPathFullyQualified(requestPath)) throw new InvalidDataException("Engine request path must be absolute.");
        string target = broker == EngineBrokerKind.Worker ? "desktop-worker" : "desktop-action";
        return RuntimeKind == EngineRuntimeKind.Frozen
            ? new[] { target, "--request", requestPath }
            : new[] { "-m", broker == EngineBrokerKind.Worker ? "attackmap.desktop_worker" : "attackmap.desktop_actions", "--request", requestPath };
    }

    public void Configure(ProcessStartInfo start, EngineBrokerKind broker, string requestPath)
    {
        if (start.Arguments.Length != 0 || start.ArgumentList.Count != 0)
            throw new InvalidDataException("Configure an empty engine argument list; shell command concatenation is unsupported.");
        var arguments = ArgumentsFor(broker, requestPath);
        start.FileName = ExecutablePath;
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.RedirectStandardInput = start.RedirectStandardOutput = start.RedirectStandardError = true;
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
    }

    public ProcessStartInfo CreateStartInfo(EngineBrokerKind broker, string requestPath)
    {
        var start = new ProcessStartInfo();
        Configure(start, broker, requestPath);
        return start;
    }
}
