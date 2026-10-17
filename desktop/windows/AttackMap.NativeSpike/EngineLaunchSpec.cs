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
