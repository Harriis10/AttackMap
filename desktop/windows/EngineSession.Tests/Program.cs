using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using AttackMap.NativeSpike;

// Process-local only; inherited by controlled children, never changes machine WER settings.
if (OperatingSystem.IsWindows()) NativeErrors.SetErrorMode(0x0001 | 0x0002 | 0x8000);
if (args.Length is < 1 or > 2 || !Path.IsPathFullyQualified(args[0]) || !File.Exists(args[0]))
{
    Console.Error.WriteLine("Usage: dotnet EngineSession.Tests.dll <absolute ControlledFakeBroker.exe> [results.json]");
    return 2;
}
string output = Path.Combine(AppContext.BaseDirectory, "qa-" + Guid.NewGuid().ToString("N"));
int exitCode = 0;
try
{
string inputBroker = Path.GetFullPath(args[0]);
Directory.CreateDirectory(output);
string brokerDirectory = Path.Combine(output, "controlled-engine");
Directory.CreateDirectory(brokerDirectory);
foreach (string file in Directory.EnumerateFiles(Path.GetDirectoryName(inputBroker)!))
    File.Copy(file, Path.Combine(brokerDirectory, Path.GetFileName(file)));
// Preserve apphost's embedded DLL identity and runtime sidecars, while exercising
// the production guard's documented frozen executable name and argument format.
string broker = Path.Combine(brokerDirectory, "attackmap.exe");
File.Copy(inputBroker, broker, true);
if (new EngineLaunchSpec(broker).RuntimeKind != EngineRuntimeKind.Frozen) throw new InvalidOperationException("Test broker must use the guarded Frozen launch path.");
Console.WriteLine("Fixture output: " + output);
var results = new List<object>();
void Check(bool value, string message) { if (!value) throw new Exception(message); }
async Task Reject<T>(Task task) where T : Exception { try { await task; throw new Exception("Unexpected success"); } catch (T) { } }
async Task Case(string name, Func<Task> test) { Console.WriteLine("START " + name); var clock = Stopwatch.StartNew(); await test(); results.Add(new { name, passed = true, elapsed_ms = clock.Elapsed.TotalMilliseconds }); Console.WriteLine($"PASS {name} ({clock.Elapsed.TotalMilliseconds:F1} ms)"); }
string Folder(string name) { string path = Path.Combine(output, name); Directory.CreateDirectory(path); return path; }
Task Run(EngineSession session, string mode, string folder, Action<string>? progress = null, Func<string, Task>? complete = null) => session.Run(broker, output, folder, 1, progress ?? (_ => { }), complete ?? (_ => Task.CompletedTask), modules: mode);
async Task Marker(string folder)
{
    var clock = Stopwatch.StartNew();
    while (clock.Elapsed < TimeSpan.FromSeconds(15))
    {
        try { using var document = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(folder, "fake-process.json"))); return; } catch (IOException) { } catch (JsonException) { }
        await Task.Delay(10);
    }
    throw new TimeoutException("Fake broker marker absent");
}
foreach (string schema in new[] { "schema10", "schema11", "missing_stage" }) await Case(schema + "_completed_policy_failed", async () =>
{
    int completed = 0; var progress = new List<string>(); string folder = Folder(schema);
    await Run(new(), schema, folder, progress.Add, path => { Check(path == Path.Combine(folder, "controlled-report.json"), "Wrong artifact callback"); completed++; return Task.CompletedTask; });
    Check(completed == 1 && progress.Any(text => text.Contains("policy failed")), "Execution success/policy failure confused");
});
await Case("duplicate_out_of_order_and_terminal_ignored", async () =>
{
    int completed = 0; var progress = new List<string>();
    await Run(new(), "ordering", Folder("ordering"), progress.Add, _ => { completed++; return Task.CompletedTask; });
    Check(completed == 1 && progress.Count == 3, "Duplicate/regressive progress or terminal callback accepted");
});
await Case("structured_callbacks_preserve_identity_and_accepted_revisions", async () =>
{
    string folder = Folder("structured-callbacks");
    var snapshots = new List<EngineProgressSnapshot>();
    RunIdentity? identity = null; int completed = 0;
    await new EngineSession().Run(broker, output, folder, 7, _ => { }, _ => { completed++; return Task.CompletedTask; },
        started: value => identity = value, modules: "ordering", structuredProgress: snapshots.Add);
    Check(snapshots.Count == 3 && snapshots.Select(value => value.Revision).SequenceEqual(new long[] { 1, 3, 5 }), "Unaccepted revisions reached structured callback");
    Check(identity != null && snapshots.All(value => value.RunId == identity.RunId && value.Repository == output && value.Generation == 7), "Structured callback identity changed");
    Check(snapshots.Take(2).All(value => !value.Terminal) && snapshots.Last().Terminal && completed == 1, "Terminal progress/artifact callback gates confused");
});
await Case("bad_schema_eof_cleanup_before_readmission", async () =>
{
    var session = new EngineSession(); string folder = Folder("bad-schema");
    await Reject<InvalidDataException>(Run(session, "bad_schema_eof", folder));
    Check(File.Exists(Path.Combine(folder, "eof-observed.json")) && !session.CleanupBlocked, "Cleanup did not complete");
    await Run(session, "schema11", Folder("readmitted"));
});
await Case("exclusive_run", async () =>
{
    var session = new EngineSession(); string folder = Folder("exclusive"); var first = Run(session, "gate", folder); await Marker(folder);
    await Reject<InvalidOperationException>(Run(session, "schema11", Folder("rejected")));
    Check(!File.Exists(Path.Combine(output, "rejected", "native-request.json")), "Rejected run wrote request");
    await File.WriteAllTextAsync(Path.Combine(folder, "release"), "go"); await first;
});
await Case("cancel_disconnect_exit_races", async () =>
{
    foreach (string mode in new[] { "cancel", "disconnect" })
    {
        var session = new EngineSession(); string folder = Folder(mode); var task = Run(session, mode, folder); await Marker(folder);
        if (mode == "cancel") session.Cancel(); else session.Disconnect(); await task;
        for (int cycle = 0; cycle < 100; cycle++) { session.Cancel(); session.Disconnect(); }
        Check(!session.CleanupBlocked, "Exit race poisoned admission");
    }
    // Exercise pipe operations while terminal delivery and process exit overlap.
    for (int cycle = 0; cycle < 10; cycle++)
    {
        var session = new EngineSession();
        await Run(session, "schema11", Folder("exit-race-" + cycle), complete: _ =>
        {
            for (int attempt = 0; attempt < 100; attempt++) { session.Cancel(); session.Disconnect(); }
            return Task.CompletedTask;
        });
        session.Cancel(); session.Disconnect();
    }
});
// Last: an invalid protocol plus a childless fake that ignores EOF deliberately blocks admission.
await Case("ignored_eof_cleanup_blocks_restart", async () =>
{
    var session = new EngineSession(); string folder = Folder("blocked"); var task = Run(session, "bad_schema_ignore_eof", folder); await Marker(folder);
    using var identity = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(folder, "fake-process.json"))); var record = identity.RootElement;
    try
    {
        await Reject<IOException>(task); Check(session.CleanupBlocked, "Cleanup was not blocked");
        await Reject<InvalidOperationException>(Run(session, "schema11", Folder("blocked-restart")));
        Check(!File.Exists(Path.Combine(output, "blocked-restart", "native-request.json")), "Blocked run admitted");
    }
    finally
    {
        using var process = Process.GetProcessById(record.GetProperty("pid").GetInt32());
        Check(process.StartTime.ToUniversalTime().Ticks == record.GetProperty("start_ticks").GetInt64() && string.Equals(process.MainModule!.FileName, broker, StringComparison.OrdinalIgnoreCase) && string.Equals(record.GetProperty("executable").GetString(), broker, StringComparison.OrdinalIgnoreCase), "Fake identity changed; refusing termination");
        process.Kill(); await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
    }
});
string source = Path.GetFullPath("desktop/windows/AttackMap.NativeSpike/EngineSession.cs");
await File.WriteAllTextAsync(args.Length > 1 ? args[1] : Path.Combine(output, "results.json"), JsonSerializer.Serialize(new { scope = "Actual EngineSession with childless controlled fake broker; no UI/platform acceptance", output_base = output, session_sha256 = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(source))), results }, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine("Fixture output: " + output);
}
catch (Exception error)
{
    Console.Error.WriteLine(error);
    exitCode = 1;
}
finally
{
    try
    {
    int checkedMarkers = 0;
    foreach (string marker in Directory.Exists(output) ? Directory.EnumerateFiles(output, "fake-process.json", SearchOption.AllDirectories) : Array.Empty<string>())
    {
        using var document = JsonDocument.Parse(File.ReadAllText(marker));
        var record = document.RootElement;
        checkedMarkers++;
        try
        {
            using var process = Process.GetProcessById(record.GetProperty("pid").GetInt32());
            string expected = Path.Combine(output, "controlled-engine", "attackmap.exe");
            if (process.StartTime.ToUniversalTime().Ticks != record.GetProperty("start_ticks").GetInt64()) continue; // PID reused.
            if (!string.Equals(process.MainModule!.FileName, expected, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(record.GetProperty("executable").GetString(), expected, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Fake identity changed; refusing termination.");
            process.Kill();
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (ArgumentException) { } // Already exited.
    }
    Console.WriteLine($"Cleanup verified: {checkedMarkers} owned fake process markers; zero matching live children.");
    }
    catch (Exception error)
    {
        Console.Error.WriteLine("Cleanup unverified: " + error);
        exitCode = 1;
    }
}
return exitCode;

internal static class NativeErrors
{
    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    internal static extern uint SetErrorMode(uint mode);
}
