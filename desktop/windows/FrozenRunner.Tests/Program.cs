using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using AttackMap.NativeSpike;

string executable = Path.GetFullPath(args[0]);
string output = Path.Combine(Path.GetTempPath(), "attackmap-frozen-runner-" + Guid.NewGuid().ToString("N"));
string repository = Path.Combine(output, "synthetic-repository");
Directory.CreateDirectory(repository);
await File.WriteAllTextAsync(Path.Combine(repository, "package.json"), """{"name":"synthetic-native-frozen-probe","version":"1.0.0","private":true}""");
await File.WriteAllTextAsync(Path.Combine(repository, "index.js"), "// Synthetic local-only QA input\nconsole.log('hello');\n");
var checks = new List<string>();
void Check(bool value, string name) { if (!value) throw new Exception(name); checks.Add(name); Console.WriteLine("PASS " + name); }
var clock = Stopwatch.StartNew();
var progress = new List<string>();
RunIdentity? identity = null;
string? artifact = null;
var session = new EngineSession();
await session.Run(executable, repository, Path.Combine(output, "scan"), 1, progress.Add, path => { artifact = path; return Task.CompletedTask; }, run => identity = run, new NativeScanOptions());
Check(identity != null && artifact != null && File.Exists(artifact), "Frozen worker returns canonical ready artifact through actual EngineSession");
using var report = JsonDocument.Parse(await File.ReadAllBytesAsync(artifact!));
Check(report.RootElement.GetProperty("scan").GetProperty("root").GetString() == repository && report.RootElement.GetProperty("findings").ValueKind == JsonValueKind.Array, "Canonical report repository identity and findings shape");
var selection = ExportSelection.Capture(artifact!, ExportSelection.Hash(await File.ReadAllBytesAsync(artifact!)), identity);
Check(selection.Verified && selection.RunId == identity!.RunId, "Manifest generation and canonical report hash verified");
await selection.Export(Path.Combine(output, "verified-copy.json"), false);
Check(!session.CleanupBlocked && progress.Any(text => text.Contains("completed")), "Completed worker exits with verified cleanup");
string baseline = Path.Combine(output, "baseline.json"), current = Path.Combine(output, "current.json");
string fixture = JsonSerializer.Serialize(new { scan = new { root = repository, scanned_files = new[] { "index.js" }, analyzer_errors = Array.Empty<string>(), limitations = Array.Empty<string>() }, findings = Array.Empty<object>() });
await File.WriteAllTextAsync(baseline, fixture); await File.WriteAllTextAsync(current, fixture);
var comparison = await DesktopActionRunner.Run(executable, "compare", new { baseline_path = baseline, current_path = current }, outputBase: Path.Combine(output, "actions"));
Check(comparison.GetProperty("comparison_version").GetString() == "1.0", "Frozen compare action returns supported result through actual DesktopActionRunner");
foreach (var item in new[] { ("baseline", baseline), ("current", current) })
{
    var record = comparison.GetProperty(item.Item1);
    Check(record.GetProperty("report_path").GetString() == item.Item2 && record.GetProperty("report_sha256").GetString() == ExportSelection.Hash(await File.ReadAllBytesAsync(item.Item2)), "Compare " + item.Item1 + " path and source hash verified");
}
Check(!DesktopActionRunner.CleanupBlocked, "Frozen action exits with verified cleanup");
object? realRepositoryParity = null;
if (args.Length > 2)
{
    string realRepository = Path.GetFullPath(args[2]);
    string parityOutput = Path.Combine(Path.GetFullPath(".pytest_cache"), "frozen-juice-parity-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(parityOutput);
    string? nativeArtifact = null;
    RunIdentity? realIdentity = null;
    var realProgress = new List<string>();
    await new EngineSession().Run(executable, realRepository, Path.Combine(parityOutput, "native"), 1, realProgress.Add, path => { nativeArtifact = path; return Task.CompletedTask; }, run => realIdentity = run, new NativeScanOptions());
    Check(nativeArtifact != null && realIdentity != null, "Frozen Juice Shop session completes with canonical artifact");
    var realSelection = ExportSelection.Capture(nativeArtifact!, ExportSelection.Hash(await File.ReadAllBytesAsync(nativeArtifact!)), realIdentity);
    Check(realSelection.Verified, "Frozen Juice Shop generation/report manifest verified");
    string directOutput = Path.Combine(parityOutput, "cli");
    var start = new ProcessStartInfo(executable) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
    foreach (string argument in new[] { "analyze", realRepository, "--output", directOutput }) start.ArgumentList.Add(argument);
    start.Environment["PYTHONUTF8"] = "1";
    using var direct = Process.Start(start)!;
    var stdout = direct.StandardOutput.ReadToEndAsync(); var stderr = direct.StandardError.ReadToEndAsync();
    await direct.WaitForExitAsync();
    await File.WriteAllTextAsync(Path.Combine(parityOutput, "cli.stdout.txt"), await stdout);
    await File.WriteAllTextAsync(Path.Combine(parityOutput, "cli.stderr.txt"), await stderr);
    Check(direct.ExitCode == 0, "Same frozen direct CLI completes with default local options");
    string cliArtifact = Path.Combine(directOutput, "attackmap-report.json");
    using var nativeJson = JsonDocument.Parse(await File.ReadAllBytesAsync(nativeArtifact!));
    using var cliJson = JsonDocument.Parse(await File.ReadAllBytesAsync(cliArtifact));
    string[] Ids(JsonElement value) => value.GetProperty("findings").EnumerateArray().Select(finding => finding.GetProperty("id").GetString()!).Order(StringComparer.Ordinal).ToArray();
    var nativeIds = Ids(nativeJson.RootElement); var cliIds = Ids(cliJson.RootElement);
    Check(nativeIds.SequenceEqual(cliIds), "Same frozen native/CLI normalized finding IDs match exactly");
    string[] Labels(JsonElement value) => value.GetProperty("findings").EnumerateArray().Select(finding => string.Join("|", new[] { "id", "severity", "confidence", "score" }.Select(key => finding.TryGetProperty(key, out var supplied) ? supplied.ToString() : "not_supplied"))).Order(StringComparer.Ordinal).ToArray();
    Check(Labels(nativeJson.RootElement).SequenceEqual(Labels(cliJson.RootElement)), "Same frozen native/CLI supplied severity confidence score match");
    realRepositoryParity = new { repository = realRepository, output = parityOutput, nativeArtifact, cliArtifact, nativeReportSha256 = realSelection.ReportHash, nativeManifestSha256 = realSelection.ManifestHash, cliReportSha256 = ExportSelection.Hash(await File.ReadAllBytesAsync(cliArtifact)), findingCount = nativeIds.Length, findingIdsEqual = true, suppliedPriorityLabelsEqual = true, sameAnalyzerSelection = "Same immutable frozen executable, automatic analyzer discovery and no explicit modules for both; no .venv comparison", progress = realProgress };
}
string[] sourceFiles = { "EngineSession.cs", "DesktopActionRunner.cs", "EngineLaunchSpec.cs", "EngineProtocol.cs", "NativeScanOptions.cs", "ProviderConfiguration.cs", "RunPresentation.cs", "ExportSelection.cs" };
var sourceHashes = sourceFiles.ToDictionary(name => name, name => ExportSelection.Hash(File.ReadAllBytes(Path.Combine("desktop/windows/AttackMap.NativeSpike", name))));
await File.WriteAllTextAsync(args[1], JsonSerializer.Serialize(new { scope = "Frozen Windows engine through production C# session/action runners; synthetic fixture and optional targeted real-repository parity, no AI/CVE or manual UI claim", executable, executableSha256 = ExportSelection.Hash(await File.ReadAllBytesAsync(executable)), testAssemblySha256 = ExportSelection.Hash(await File.ReadAllBytesAsync(typeof(EngineSession).Assembly.Location)), sourceHashes, output, runId = identity!.RunId, artifact, reportSha256 = selection.ReportHash, manifestSha256 = selection.ManifestHash, progress, realRepositoryParity, checks, elapsedMilliseconds = clock.Elapsed.TotalMilliseconds }, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine("Fixture output: " + output);
