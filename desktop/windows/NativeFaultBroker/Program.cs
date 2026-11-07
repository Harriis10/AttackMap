using System.Security.Cryptography;
using System.Text.Json;
// Controlled fault broker: childless, no network, outputs only inside its request folder.
int argument = Array.IndexOf(args, "--request");
using var document = JsonDocument.Parse(await File.ReadAllTextAsync(args[argument + 1]));
var request = document.RootElement;
bool worker = request.TryGetProperty("run_id", out var run);
string folder = request.GetProperty("output_path").GetString()!;
string mode = worker ? request.GetProperty("modules")[0].GetString()! : request.GetProperty("payload").GetProperty("mode").GetString()!;
if (mode == "exit_no_terminal") { Environment.ExitCode = 7; return; }
if (mode is "malformed_message" or "oversized_message")
{
    Console.WriteLine(mode == "malformed_message" ? "{" : new string('x', worker ? 65537 : 32769));
    await Console.Out.FlushAsync(); await Console.In.ReadToEndAsync();
    await File.WriteAllTextAsync(Path.Combine(folder, "eof.json"), "true"); return;
}
string id = worker ? run.GetString()! : request.GetProperty("request_id").GetString()!;
string artifact = Path.Combine(folder, worker ? "attackmap-report.json" : id + ".result.json");
string operation = worker ? "" : request.GetProperty("operation").GetString()!;
byte[] bytes = worker
    ? JsonSerializer.SerializeToUtf8Bytes(new { scan = new { root = request.GetProperty("repository_id").GetString() }, findings = Array.Empty<object>() })
    : JsonSerializer.SerializeToUtf8Bytes(new { request_id = id, operation, result = new { status = "ok" } });
if (mode != "missing_artifact") await File.WriteAllBytesAsync(artifact, mode == "malformed_artifact" ? "{"u8.ToArray() : bytes);
string hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
if (worker && mode != "missing_manifest")
    await File.WriteAllTextAsync(Path.Combine(folder, "artifact-manifest.json"), mode == "malformed_manifest" ? "{" : JsonSerializer.Serialize(new { schema_version = "1.0.0", artifact_type = "attackmap_artifact_manifest", generation_id = id, run_identity = new { repo_root = request.GetProperty("repository_id").GetString() }, compatibility_exports = new[] { new { path = "attackmap-report.json", checksum = hash } } }));
if (worker) Console.WriteLine(JsonSerializer.Serialize(new { schema_version = "1.1", kind = "terminal", run_id = id, repository_id = request.GetProperty("repository_id").GetString(), generation = request.GetProperty("generation").GetInt64(), revision = 1, state = "completed", execution_outcome = "succeeded", policy_outcome = "passed", artifact_readiness = "ready", artifact_path = artifact }));
else Console.WriteLine(JsonSerializer.Serialize(new { schema_version = "1.1", kind = "action_result", request_id = id, operation, state = "completed", result_path = artifact, sha256 = hash }));
if (mode == "completed_exit7") Environment.ExitCode = 7;
