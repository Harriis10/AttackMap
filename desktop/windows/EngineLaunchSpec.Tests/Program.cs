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
    File.WriteAllText(Path.Combine(root, "python313.dll"), "Static Python layout marker; never loaded.");
    if (Environment.ProcessPath is string self) Refuse(() => new EngineLaunchSpec(self, EngineRuntimeKind.Frozen));
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
    File.Delete(Path.Combine(root, "python313.dll"));
    Refuse(() => new EngineLaunchSpec(renamed, EngineRuntimeKind.Python));
    string venvRoot = Path.Combine(root, "venv with spaces ü"), baseRoot = Path.Combine(root, "base python ü");
    string scripts = Path.Combine(venvRoot, "Scripts"); Directory.CreateDirectory(scripts); Directory.CreateDirectory(baseRoot);
    string launcher = Path.Combine(scripts, "python.exe"), wrongLauncher = Path.Combine(scripts, "cmd.exe"), cfg = Path.Combine(venvRoot, "pyvenv.cfg");
    File.WriteAllText(launcher, "Static launcher fixture; never executed."); File.WriteAllText(wrongLauncher, "Not Python; never executed.");
    File.WriteAllText(Path.Combine(baseRoot, "python.exe"), "Static base fixture; never executed.");
    string baseDll = Path.Combine(baseRoot, "python313.dll"); File.WriteAllText(baseDll, "Marker; never loaded.");
    void Configuration(string text) => File.WriteAllText(cfg, text, new System.Text.UTF8Encoding(false));
    string valid = $"home = {baseRoot}\ninclude-system-site-packages = false\nversion = 3.13.15\nexecutable = {python}\ncommand = ignored, never executed\n";
    Configuration(valid);
    Check(new EngineLaunchSpec(launcher).RuntimeKind == EngineRuntimeKind.Python);
    Check(new EngineLaunchSpec(launcher).ArgumentsFor(EngineBrokerKind.Worker, request).SequenceEqual(new[] { "-m", "attackmap.desktop_worker", "--request", request }));
    Refuse(() => new EngineLaunchSpec(wrongLauncher));
    Refuse(() => new EngineLaunchSpec(renamed));
    if (Environment.ProcessPath is string own) Refuse(() => new EngineLaunchSpec(own, EngineRuntimeKind.Python));
    Check(new EngineLaunchSpec(frozen).RuntimeKind == EngineRuntimeKind.Frozen);
    Check(new EngineLaunchSpec(renamed, EngineRuntimeKind.Frozen).RuntimeKind == EngineRuntimeKind.Frozen);
    File.Delete(baseDll); Directory.CreateDirectory(Path.Combine(baseRoot, "Lib")); string osMarker = Path.Combine(baseRoot, "Lib", "os.py"); File.WriteAllText(osMarker, "Marker; never imported.");
    Check(new EngineLaunchSpec(launcher).RuntimeKind == EngineRuntimeKind.Python);
    File.Delete(osMarker); Refuse(() => new EngineLaunchSpec(launcher)); File.WriteAllText(baseDll, "Marker; never loaded.");
    foreach (string invalid in new[] { "home = relative/python\n", "home = https://example.invalid/python\n", "home = \\\\server\\python\n", $"home = {baseRoot}\\.\n", valid + $"HOME = {baseRoot}\n", valid + "not a configuration line\n", "= empty key\n", valid + new string('x', 16384) })
    { Configuration(invalid); Refuse(() => new EngineLaunchSpec(launcher)); }
    File.WriteAllBytes(cfg, new byte[] { 0xff }); Refuse(() => new EngineLaunchSpec(launcher));
    Configuration(valid); File.WriteAllText(Path.Combine(scripts, "pyvenv.cfg"), valid); Refuse(() => new EngineLaunchSpec(launcher)); File.Delete(Path.Combine(scripts, "pyvenv.cfg"));
    File.Delete(cfg); Refuse(() => new EngineLaunchSpec(launcher)); Configuration(valid);
    string realVenv = Path.GetFullPath(".tools/wp024-freeze-venv/Scripts/python.exe");
    if (File.Exists(realVenv))
    {
        var real = new EngineLaunchSpec(realVenv);
        Check(real.RuntimeKind == EngineRuntimeKind.Python);
        Check(real.ArgumentsFor(EngineBrokerKind.Action, request).SequenceEqual(new[] { "-m", "attackmap.desktop_actions", "--request", request }));
        Console.WriteLine("PASS actual prepared venv static recognition; no executable launched or probed.");
    }
    else Console.WriteLine("SKIP actual prepared venv recognition: task-owned environment absent on this host.");
    Console.WriteLine($"EngineLaunchSpec: {checks} checks passed; no executable probing or child launch.");
}
finally { Directory.Delete(root, recursive: true); }
