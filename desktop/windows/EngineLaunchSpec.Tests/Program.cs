using System.Diagnostics;
using AttackMap.NativeSpike;

string root = Path.Combine(Path.GetTempPath(), "attackmap-launch-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
int checks = 0;
void Check(bool condition) { checks++; if (!condition) throw new Exception("Launch spec assertion failed"); }
void Refuse(Action action) { try { action(); throw new Exception("Unsafe launch accepted"); } catch (InvalidDataException) { checks++; } }
try
{
    string python = Path.Combine(root, "python with spaces.exe"), frozen = Path.Combine(root, "AttackMap.exe"), renamed = Path.Combine(root, "renamed.exe");
    foreach (string path in new[] { python, frozen, renamed }) File.WriteAllText(path, "Fake filename fixture; never executed.");
    string request = Path.Combine(root, "request space ü.json");
    foreach (var kind in new[] { EngineRuntimeKind.Python, EngineRuntimeKind.Frozen })
    foreach (var broker in new[] { EngineBrokerKind.Worker, EngineBrokerKind.Action })
    {
        var spec = new EngineLaunchSpec(renamed, kind);
        var start = spec.CreateStartInfo(broker, request);
        string[] expected = kind == EngineRuntimeKind.Frozen
            ? new[] { broker == EngineBrokerKind.Worker ? "desktop-worker" : "desktop-action", "--request", request }
            : new[] { "-m", broker == EngineBrokerKind.Worker ? "attackmap.desktop_worker" : "attackmap.desktop_actions", "--request", request };
        Check(start.ArgumentList.SequenceEqual(expected));
        Check(start.FileName == renamed && !start.UseShellExecute && start.CreateNoWindow);
        Check(start.RedirectStandardInput && start.RedirectStandardOutput && start.RedirectStandardError);
    }
    Check(new EngineLaunchSpec(frozen).RuntimeKind == EngineRuntimeKind.Frozen);
    Check(new EngineLaunchSpec(frozen).InferredFrozenName);
    Check(new EngineLaunchSpec(renamed).RuntimeKind == EngineRuntimeKind.Python);
    Check(new EngineLaunchSpec(frozen, EngineRuntimeKind.Python).RuntimeKind == EngineRuntimeKind.Python);
    Refuse(() => new EngineLaunchSpec("python.exe"));
    Refuse(() => new EngineLaunchSpec(Path.Combine(root, "missing.exe")));
    Refuse(() => new EngineLaunchSpec(python, (EngineRuntimeKind)99));
    Refuse(() => new EngineLaunchSpec(python).ArgumentsFor((EngineBrokerKind)99, request));
    Refuse(() => new EngineLaunchSpec(python).ArgumentsFor(EngineBrokerKind.Worker, "relative.json"));
    Refuse(() => new EngineLaunchSpec(python).Configure(new ProcessStartInfo { Arguments = "untrusted" }, EngineBrokerKind.Worker, request));
    Console.WriteLine($"EngineLaunchSpec: {checks} checks passed; no executable probing or child launch.");
}
finally { Directory.Delete(root, recursive: true); }
