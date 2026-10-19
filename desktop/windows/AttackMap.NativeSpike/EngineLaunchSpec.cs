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
    /// interpreters ship python3*.dll beside them (root or venv layouts put it
    /// in the interpreter's own directory or one level up, with Lib\os.py as
    /// the layout-confirming alternative).</summary>
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
        return false;
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
