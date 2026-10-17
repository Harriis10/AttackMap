using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using AttackMap.NativeSpike;

string broker = Path.GetFullPath(args[0]);
string output = Path.Combine(Path.GetTempPath(), "attackmap-action-runner-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(output);
var results = new List<object>();
void Check(bool condition, string message) { if (!condition) throw new Exception(message); }
async Task Reject<T>(Task<JsonElement> task) where T : Exception
{ try { await task; throw new Exception("Unexpected result delivered"); } catch (T) { } }
Task<JsonElement> Run(string mode, string? path = null, string operation = "compare", string? credential = null, CancellationToken token = default) => DesktopActionRunner.Run(broker, operation, new { mode }, credential, path ?? output, token);
async Task<string> Marker(string folder)
{
    var clock = Stopwatch.StartNew();
    while (clock.Elapsed < TimeSpan.FromSeconds(15))
    {
        var found = Directory.GetFiles(folder, "fake-process.json", SearchOption.AllDirectories);
        if (found.Length == 1) { try { using var document = JsonDocument.Parse(await File.ReadAllTextAsync(found[0])); return found[0]; } catch (JsonException) { } catch (IOException) { } }
        await Task.Delay(10);
    }
    throw new TimeoutException("Fake broker start marker missing");
}
async Task Case(string name, Func<Task> test) { var clock = Stopwatch.StartNew(); await test(); results.Add(new { name, passed = true, elapsed_ms = clock.Elapsed.TotalMilliseconds }); Console.WriteLine("PASS " + name); }
await Case("valid_identity_and_hash", async () => Check((await Run("valid")).GetProperty("status").GetString() == "ok", "Missing result"));
foreach (string mode in new[] { "bad_identity", "bad_hash", "bad_result_identity" })
    await Case(mode + "_delivers_no_result", () => Reject<InvalidDataException>(Run(mode)));
await Case("concurrent_admission_exactly_one", async () =>
{
    string folder = Path.Combine(output, "concurrent"); Directory.CreateDirectory(folder);
    var first = Run("gate", folder); string marker = await Marker(folder);
    await Reject<InvalidOperationException>(Run("valid", folder));
    Check(Directory.GetDirectories(folder).Length == 1, "Second broker admitted");
    await File.WriteAllTextAsync(Path.Combine(Path.GetDirectoryName(marker)!, "release"), "go"); await first;
    await Run("valid");
});
await Case("credential_environment_only_and_scrubbed", async () =>
{
    string secret = Guid.NewGuid().ToString("N");
    string[] keys = { "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID", "ATTACKMAP_ACTION_CREDENTIAL" };
    var prior = keys.ToDictionary(key => key, Environment.GetEnvironmentVariable);
    try
    {
        foreach (string key in keys) Environment.SetEnvironmentVariable(key, secret);
        var result = await Run("valid", operation: "provider_check", credential: secret);
        Check(result.GetProperty("credential_present").GetBoolean() && !result.GetProperty("inherited_present").GetBoolean(), "Provider environment incorrect");
        result = await Run("valid", credential: secret);
        Check(!result.GetProperty("credential_present").GetBoolean() && !result.GetProperty("inherited_present").GetBoolean(), "Nonprovider received credentials");
        foreach (string request in Directory.GetFiles(output, "request.json", SearchOption.AllDirectories)) Check(!(await File.ReadAllTextAsync(request)).Contains(secret), "Credential persisted in request");
    }
    finally { foreach (string key in keys) Environment.SetEnvironmentVariable(key, prior[key]); }
});
await Case("cancellation_eof_cleanup", async () =>
{
    string folder = Path.Combine(output, "cancel"); Directory.CreateDirectory(folder);
    using var cancellation = new CancellationTokenSource(); var task = Run("wait_eof", folder, token: cancellation.Token);
    string marker = await Marker(folder); cancellation.Cancel(); await Reject<OperationCanceledException>(task);
    Check(File.Exists(Path.Combine(Path.GetDirectoryName(marker)!, "eof-observed.json")), "EOF not observed");
    using var identity = JsonDocument.Parse(await File.ReadAllTextAsync(marker));
    try { using var process = Process.GetProcessById(identity.RootElement.GetProperty("pid").GetInt32()); Check(process.HasExited, "Broker remains alive"); } catch (ArgumentException) { }
    Check(!DesktopActionRunner.CleanupBlocked, "Cleanup incorrectly blocked"); await Run("valid");
});
// Deliberately poisons admission. Always last; no reset of production safety state.
await Case("ignored_eof_blocks_admission_after_cleanup_timeout", async () =>
{
    string folder = Path.Combine(output, "blocked"); Directory.CreateDirectory(folder);
    using var cancellation = new CancellationTokenSource(); var task = Run("ignore_eof", folder, token: cancellation.Token);
    string marker = await Marker(folder);
    using var identity = JsonDocument.Parse(await File.ReadAllTextAsync(marker));
    var record = identity.RootElement; int pid = record.GetProperty("pid").GetInt32();
    try
    {
        var clock = Stopwatch.StartNew(); cancellation.Cancel(); await Reject<IOException>(task);
        Check(clock.Elapsed >= TimeSpan.FromSeconds(9.5), "Cleanup deadline skipped");
        Check(DesktopActionRunner.CleanupBlocked, "Unverified cleanup did not block admission");
        await Reject<InvalidOperationException>(Run("valid", folder));
        Check(Directory.GetDirectories(folder).Length == 1, "Blocked admission launched broker");
    }
    finally
    {
        using var process = Process.GetProcessById(pid);
        Check(process.StartTime.ToUniversalTime().Ticks == record.GetProperty("start_ticks").GetInt64(), "PID identity changed; refusing termination");
        Check(string.Equals(process.MainModule!.FileName, broker, StringComparison.OrdinalIgnoreCase) && string.Equals(record.GetProperty("executable").GetString(), broker, StringComparison.OrdinalIgnoreCase), "Executable identity changed; refusing termination");
        process.Kill(); // Only the verified, childless fake created by this test.
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
    }
});
string source = Path.GetFullPath("desktop/windows/AttackMap.NativeSpike/DesktopActionRunner.cs");
string evidence = JsonSerializer.Serialize(new { scope = "Actual DesktopActionRunner with childless controlled fake broker; no UI or platform acceptance claim", output_base = output, runner_sha256 = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(source))), results }, new JsonSerializerOptions { WriteIndented = true });
await File.WriteAllTextAsync(args.Length > 1 ? args[1] : Path.Combine(output, "results.json"), evidence);
Console.WriteLine("Fixture output: " + output);
