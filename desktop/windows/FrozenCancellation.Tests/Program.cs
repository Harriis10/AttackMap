using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AttackMap.NativeSpike;

string executable = Path.GetFullPath(args[0]);
string proofPath = Path.GetFullPath(args[1]);
int cycles = args.Length > 2 ? int.Parse(args[2]) : 50;
int fileCount = args.Length > 3 ? int.Parse(args[3]) : 2000;
if (cycles is < 1 or > 50 || fileCount is < 32 or > 4000) throw new ArgumentOutOfRangeException();
string owned = Path.Combine(Path.GetTempPath(), "attackmap-frozen-cancellation-" + Guid.NewGuid().ToString("N"));
string repository = Path.Combine(owned, "repository");
Directory.CreateDirectory(repository);
// Bounded local synthetic fixture; no child signal handlers or artificial broker gates.
string content = "from flask import Flask, request\napp = Flask(__name__)\n@app.get('/synthetic')\ndef route():\n    return request.args.get('value', '')\n" + string.Concat(Enumerable.Repeat("# synthetic ordinary analysis input\n", 100));
for (int i = 0; i < fileCount; i++) await File.WriteAllTextAsync(Path.Combine(repository, $"source_{i:D4}.py"), content);
var samples = new List<object>();
var ackTimes = new List<double>();
var treeTimes = new List<double>();
object? admission = null;
string? failure = null;
var sourceNames = new[] { "EngineSession", "EngineProtocol", "EngineLaunchSpec", "NativeScanOptions", "ProviderConfiguration", "RunPresentation" };
string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
void Save() => File.WriteAllText(proofPath, JsonSerializer.Serialize(new {
    scope = "Ordinary frozen Windows broker/analyze-child cancellation through production EngineSession; no UI acknowledgement, stubborn-descendant, Narrator, supported-OS or final-package claim",
    excludes = "Later scan_service/CLI preflight diagnostic fixes", executable, executableSha256 = Hash(executable), owned,
    fixture = new { files = fileCount, bytesPerFile = Encoding.UTF8.GetByteCount(content), modules = "python", ai = false, cve = false },
    requestedCycles = cycles, sampledCycles = ackTimes.Count, samples, admission, failure,
    cancelApiReturnP95Milliseconds = Percentile(ackTimes), ownedTreeExitP95Milliseconds = Percentile(treeTimes),
    allSampledTreesExitWithinFiveSeconds = treeTimes.Count == cycles && treeTimes.All(x => x <= 5000),
    sourceHashes = sourceNames.ToDictionary(n => n + ".cs", n => Hash(Path.Combine("desktop/windows/AttackMap.NativeSpike", n + ".cs"))),
    testAssemblySha256 = Hash(typeof(EngineSession).Assembly.Location)
}, new JsonSerializerOptions { WriteIndented = true }));
Directory.CreateDirectory(Path.GetDirectoryName(proofPath)!);
try
{
    for (int cycle = 0; cycle < cycles; cycle++)
    {
        var session = new EngineSession();
        string output = Path.Combine(owned, "cycle-" + cycle);
        RunIdentity? identity = null;
        var progress = new List<string>();
        bool published = false;
        Task run = session.Run(executable, repository, output, cycle + 1, text => { lock (progress) progress.Add(text); }, _ => { published = true; return Task.CompletedTask; }, id => identity = id, modules: "python");
        var held = new List<Process>();
        try
        {
            var observed = await Observe(output, repository, executable, run, held);
            if (observed == null)
            {
                await run;
                samples.Add(new { cycle, outcome = "natural_completion_before_identity_proof_not_sampled", runId = identity?.RunId, published });
                Save();
                throw new InvalidOperationException("Natural completion before owned broker/analyze identity proof; no automatic retry.");
            }
            var clock = Stopwatch.StartNew();
            session.Cancel();
            double ack = clock.Elapsed.TotalMilliseconds;
            await Task.WhenAll(held.Select(p => p.WaitForExitAsync())).WaitAsync(TimeSpan.FromSeconds(15));
            double exit = clock.Elapsed.TotalMilliseconds;
            await run.WaitAsync(TimeSpan.FromSeconds(15));
            if (session.CleanupBlocked || published || !progress.Any(x => x.Contains("cancelled"))) throw new Exception("Cancellation did not finish with cancelled state, no publication and verified admission cleanup.");
            ackTimes.Add(ack); treeTimes.Add(exit);
            samples.Add(new { cycle, outcome = "cancelled", runId = identity!.RunId, requestSha256 = Hash(Path.Combine(output, "native-request.json")), cancelApiReturnMilliseconds = ack, ownedTreeExitMilliseconds = exit, observed, published, cleanupBlocked = session.CleanupBlocked, progress });
            Save(); Console.WriteLine($"PASS cycle {cycle + 1}/{cycles}: API {ack:F3}ms; owned tree {exit:F3}ms");
        }
        finally
        {
            // Production EOF cancellation owns cleanup. Never kill an unverified PID/tree here.
            if (!run.IsCompleted) { session.Disconnect(); try { await run.WaitAsync(TimeSpan.FromSeconds(15)); } catch { } }
            foreach (var process in held) process.Dispose();
        }
    }
    var shared = new EngineSession();
    using var gate = new Barrier(20);
    int started = 0, rejected = 0;
    var paths = Enumerable.Range(0, 20).Select(i => Path.Combine(owned, "admission-" + i)).ToArray();
    var attempts = paths.Select((path, index) => Task.Factory.StartNew(async () => {
        gate.SignalAndWait(TimeSpan.FromSeconds(15));
        try { await shared.Run(executable, repository, path, 100 + index, _ => { }, _ => Task.CompletedTask, _ => Interlocked.Increment(ref started), modules: "python"); }
        catch (InvalidOperationException) { Interlocked.Increment(ref rejected); }
    }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default).Unwrap()).ToArray();
    var wait = Stopwatch.StartNew();
    while (Volatile.Read(ref started) == 0 && wait.Elapsed < TimeSpan.FromSeconds(10)) await Task.Delay(10);
    string admitted = paths.Single(path => File.Exists(Path.Combine(path, "native-request.json")));
    var handles = new List<Process>();
    try
    {
        var observed = await Observe(admitted, repository, executable, Task.WhenAll(attempts), handles) ?? throw new Exception("Admission fixture naturally completed before process proof.");
        shared.Cancel();
        await Task.WhenAll(attempts).WaitAsync(TimeSpan.FromSeconds(20));
        await Task.WhenAll(handles.Select(p => p.WaitForExitAsync())).WaitAsync(TimeSpan.FromSeconds(5));
        int requests = paths.Count(path => File.Exists(Path.Combine(path, "native-request.json")));
        if (started != 1 || rejected != 19 || requests != 1 || shared.CleanupBlocked) throw new Exception("Twenty-way admission invariant failed.");
        admission = new { attempted = 20, started, rejected, requests, observed, cleanupBlocked = shared.CleanupBlocked };
    }
    finally { shared.Disconnect(); foreach (var handle in handles) handle.Dispose(); }
    Save();
    if (treeTimes.Any(x => x > 5000)) throw new Exception("At least one owned tree exceeded five seconds.");
    Console.WriteLine($"PASS exact twenty-way admission; {cycles}-cycle completion scope recorded.");
}
catch (Exception error) { failure = error.GetType().Name + ": " + error.Message; Save(); throw; }

static double? Percentile(List<double> values) => values.Count == 0 ? null : values.Order().ElementAt((int)Math.Ceiling(values.Count * .95) - 1);

static async Task<List<Identity>?> Observe(string output, string repository, string executable, Task run, List<Process> held)
{
    string request = Path.Combine(output, "native-request.json");
    var wait = Stopwatch.StartNew();
    while (wait.Elapsed < TimeSpan.FromSeconds(30))
    {
        var rows = await Snapshot(request);
        var broker = rows.SingleOrDefault(r => r.CommandLine.Contains("desktop-worker") && r.CommandLine.Contains(request, StringComparison.OrdinalIgnoreCase));
        var analyze = rows.FirstOrDefault(r => r.CommandLine.Contains("desktop-worker") && r.CommandLine.Contains("--engine") && r.CommandLine.Contains(output, StringComparison.OrdinalIgnoreCase));
        if (broker != null && analyze != null && broker.ParentPid == Environment.ProcessId
            && analyze.CommandLine.Contains(output, StringComparison.OrdinalIgnoreCase)
            && Ancestor(analyze, broker.Pid, rows))
        {
            try
            {
                using var original = JsonDocument.Parse(File.ReadAllBytes(request));
                string preparedPath = Directory.GetFiles(output, "desktop-request.json", SearchOption.AllDirectories)
                    .Single(path => analyze.CommandLine.Contains(path, StringComparison.OrdinalIgnoreCase));
                using var prepared = JsonDocument.Parse(File.ReadAllBytes(preparedPath));
                if (prepared.RootElement.GetProperty("run_id").GetString() != original.RootElement.GetProperty("run_id").GetString()
                    || prepared.RootElement.GetProperty("repository_path").GetString() != repository
                    || !Path.GetFullPath(prepared.RootElement.GetProperty("output_path").GetString()!).StartsWith(output + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Prepared engine request identity mismatch.");
                foreach (var row in rows)
                {
                    var process = Process.GetProcessById(row.Pid);
                    _ = process.Handle; // Held identity prevents PID reuse from changing the exit observation.
                    if (process.HasExited || Math.Abs((process.StartTime.ToUniversalTime() - row.CreatedUtc).TotalMilliseconds) > 1 || !string.Equals(process.MainModule!.FileName, row.Image, StringComparison.OrdinalIgnoreCase)) { process.Dispose(); throw new IOException("Identity changed during handle acquisition."); }
                    if ((row.Pid == broker.Pid || row.Pid == analyze.Pid) && !string.Equals(row.Image, executable, StringComparison.OrdinalIgnoreCase)) { process.Dispose(); throw new IOException("Unexpected broker/analyze image."); }
                    held.Add(process);
                }
                if (held.All(p => !p.HasExited)) return rows;
            }
            catch (Exception error) when (error is ArgumentException or InvalidOperationException or IOException or System.ComponentModel.Win32Exception) { foreach (var p in held) p.Dispose(); held.Clear(); }
        }
        if (run.IsCompleted) return null;
        await Task.Delay(20); // Identity polling only, never counted as measured cancellation.
    }
    throw new TimeoutException("No live owned broker/analyze descendant identity proof within thirty seconds.");
}
static bool Ancestor(Identity row, int parent, List<Identity> rows)
{
    var seen = new HashSet<int>();
    while (seen.Add(row.Pid)) { if (row.ParentPid == parent) return true; var next = rows.FirstOrDefault(p => p.Pid == row.ParentPid); if (next == null) return false; row = next; }
    return false;
}
static async Task<List<Identity>> Snapshot(string request)
{
    string script = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$request=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + Convert.ToBase64String(Encoding.UTF8.GetBytes(request)) + "'));$all=@(Get-CimInstance Win32_Process);$root=@($all|Where-Object {$_.CommandLine -and $_.CommandLine.Contains($request)});$ids=[Collections.Generic.HashSet[int]]::new();foreach($r in $root){[void]$ids.Add([int]$r.ProcessId)};do{$count=$ids.Count;foreach($r in $all){if($ids.Contains([int]$r.ParentProcessId)){[void]$ids.Add([int]$r.ProcessId)}}}while($ids.Count -ne $count);@($all|Where-Object {$ids.Contains([int]$_.ProcessId)}|ForEach-Object {@{Pid=[int]$_.ProcessId;ParentPid=[int]$_.ParentProcessId;Image=$_.ExecutablePath;CommandLine=$_.CommandLine;CreatedUtc=$_.CreationDate.ToUniversalTime().ToString('o')}})|ConvertTo-Json -Depth 4 -Compress";
    var start = new ProcessStartInfo("powershell.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8 };
    foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) }) start.ArgumentList.Add(arg);
    using var process = Process.Start(start)!;
    var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
    await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
    string json = await stdout; string errors = await stderr;
    if (process.ExitCode != 0) throw new IOException("Owned CIM identity query failed: " + errors);
    if (string.IsNullOrWhiteSpace(json)) return new();
    using var document = JsonDocument.Parse(json);
    var elements = document.RootElement.ValueKind == JsonValueKind.Array ? document.RootElement.EnumerateArray().ToArray() : new[] { document.RootElement };
    return elements.Select(e => new Identity(e.GetProperty("Pid").GetInt32(), e.GetProperty("ParentPid").GetInt32(), e.GetProperty("Image").GetString() ?? "", e.GetProperty("CommandLine").GetString() ?? "", DateTime.Parse(e.GetProperty("CreatedUtc").GetString()!).ToUniversalTime())).ToList();
}
record Identity(int Pid, int ParentPid, string Image, string CommandLine, DateTime CreatedUtc);
