using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

// Test-only broker: never launches children, accesses the network, or stores credentials.
int index = Array.IndexOf(args, "--request");
using var request = JsonDocument.Parse(await File.ReadAllTextAsync(args[index + 1]));
var root = request.RootElement;
if (root.TryGetProperty("run_id", out var runIdentity))
{
    string output = root.GetProperty("output_path").GetString()!;
    string modeName = root.GetProperty("modules").EnumerateArray().Select(value => value.GetString()).FirstOrDefault() ?? "schema11";
    using var process = Process.GetCurrentProcess();
    await File.WriteAllTextAsync(Path.Combine(output, "fake-process.json"), JsonSerializer.Serialize(new { pid = process.Id, start_ticks = process.StartTime.ToUniversalTime().Ticks, executable = Environment.ProcessPath, mode = modeName }));
    string schema = modeName == "schema10" ? "1.0" : modeName.StartsWith("bad_schema") ? "99.0" : "1.1";
    void Send(long revision, string state, bool terminal = false) => Console.WriteLine(JsonSerializer.Serialize(new { schema_version = schema, kind = terminal ? "terminal" : "progress", run_id = runIdentity.GetString(), repository_id = root.GetProperty("repository_id").GetString(), generation = root.GetProperty("generation").GetInt64(), revision, state, stage = "controlled", execution_outcome = "succeeded", policy_outcome = "failed", artifact_readiness = "ready", artifact_path = Path.Combine(output, "controlled-report.json") }));
    if (modeName == "missing_stage") Console.WriteLine(JsonSerializer.Serialize(new { schema_version = schema, kind = "progress", run_id = runIdentity.GetString(), repository_id = root.GetProperty("repository_id").GetString(), generation = root.GetProperty("generation").GetInt64(), revision = 1, state = "queued" }));
    else Send(1, "queued");
    if (modeName == "bad_schema_ignore_eof") await Task.Delay(Timeout.Infinite);
    if (modeName is "bad_schema_eof" or "cancel" or "disconnect")
    {
        if (modeName == "cancel") await Console.In.ReadLineAsync(); else await Console.In.ReadToEndAsync();
        await File.WriteAllTextAsync(Path.Combine(output, "eof-observed.json"), "true");
        if (modeName == "bad_schema_eof") return;
    }
    if (modeName == "gate") while (!File.Exists(Path.Combine(output, "release"))) await Task.Delay(10);
    Send(3, "running");
    if (modeName == "ordering") { Send(3, "running"); Send(2, "queued"); Send(4, "queued"); }
    Send(5, "completed", true);
    if (modeName == "ordering") Send(6, "completed", true);
    return;
}
string id = root.GetProperty("request_id").GetString()!;
string operation = root.GetProperty("operation").GetString()!;
string folder = root.GetProperty("output_path").GetString()!;
string mode = root.GetProperty("payload").GetProperty("mode").GetString()!;
using var self = Process.GetCurrentProcess();
await File.WriteAllTextAsync(Path.Combine(folder, "fake-process.json"), JsonSerializer.Serialize(new { pid = self.Id, start_ticks = self.StartTime.ToUniversalTime().Ticks, executable = Environment.ProcessPath, mode }));
if (mode == "ignore_eof") await Task.Delay(Timeout.Infinite);
if (mode == "wait_eof")
{
    await Console.In.ReadToEndAsync();
    await File.WriteAllTextAsync(Path.Combine(folder, "eof-observed.json"), "true");
    return;
}
if (mode == "gate")
    while (!File.Exists(Path.Combine(folder, "release"))) await Task.Delay(10);
string? credential = Environment.GetEnvironmentVariable("ATTACKMAP_ACTION_CREDENTIAL");
bool inherited = new[] { "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID" }.Any(key => Environment.GetEnvironmentVariable(key) != null);
byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new { request_id = mode == "bad_result_identity" ? "wrong" : id, operation, result = new { status = "ok", credential_present = credential != null, inherited_present = inherited } });
string result = Path.Combine(folder, id + ".result.json");
await File.WriteAllBytesAsync(result, bytes);
Console.WriteLine(JsonSerializer.Serialize(new { schema_version = "1.1", kind = "action_result", request_id = mode == "bad_identity" ? "wrong" : id, operation, state = "completed", result_path = result, sha256 = mode == "bad_hash" ? new string('0', 64) : Convert.ToHexString(SHA256.HashData(bytes)) }));
