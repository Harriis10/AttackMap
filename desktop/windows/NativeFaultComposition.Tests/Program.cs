using System.Security.Cryptography;
using System.Text.Json;
using AttackMap.NativeSpike;
string broker = Path.GetFullPath(args[0]);
string output = Path.Combine(Path.GetTempPath(), "attackmap-native-fault-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(output);
var results = new List<object>();
var gaps = new List<string>();
foreach (string mode in new[] { "malformed_message", "oversized_message", "exit_no_terminal", "missing_artifact", "malformed_artifact", "missing_manifest", "malformed_manifest", "completed_exit7" })
{
    var session = new EngineSession(); string displayed = "previous-valid-report"; RunIdentity? identity = null;
    string folder = Path.Combine(output, "worker-" + mode); bool rejected = false;
    try
    {
        await session.Run(broker, output, folder, 1, _ => { }, async path =>
        {
            var imported = await ReportAdapter.Load(path);
            ExportSelection.Capture(path, imported.ReadHash, identity);
            displayed = "new-report";
        }, run => identity = run, modules: mode);
    }
    catch (Exception error) when (error is IOException or JsonException or InvalidDataException) { rejected = true; }
    bool acceptedAsSuccess = !rejected;
    bool passed = rejected && displayed == "previous-valid-report" && !session.CleanupBlocked;
    if (!passed) gaps.Add("EngineSession " + mode + ": rejected=" + rejected + ", displayed=" + displayed);
    bool retried = false;
    await session.Run(broker, output, folder + "-retry", 2, _ => { }, _ => { retried = true; return Task.CompletedTask; }, modules: "valid");
    if (!retried) throw new Exception("Readmission failed");
    bool eofRequired = mode is "malformed_message" or "oversized_message";
    if (eofRequired && !File.Exists(Path.Combine(folder, "eof.json"))) throw new Exception("Missing EOF cleanup proof");
    results.Add(new { runner = "EngineSession+ReportAdapter+ExportSelection", mode, passed, rejected, acceptedAsSuccess, displayed, admissionReleased = retried, eofObserved = eofRequired });
    Console.WriteLine((passed ? "PASS " : "GAP ") + "worker " + mode);
}
foreach (string mode in new[] { "malformed_message", "oversized_message", "exit_no_terminal", "missing_artifact", "malformed_artifact", "completed_exit7" })
{
    bool delivered = false, rejected = false; string folder = Path.Combine(output, "action-" + mode);
    try { await DesktopActionRunner.Run(broker, "compare", new { mode }, outputBase: folder); delivered = true; }
    catch (Exception error) when (error is IOException or JsonException or InvalidDataException) { rejected = true; }
    bool passed = rejected && !delivered && !DesktopActionRunner.CleanupBlocked;
    if (!passed) gaps.Add("DesktopActionRunner " + mode + ": result delivered=" + delivered);
    await DesktopActionRunner.Run(broker, "compare", new { mode = "valid" }, outputBase: folder + "-retry");
    results.Add(new { runner = "DesktopActionRunner", mode, passed, rejected, delivered, admissionReleased = true });
    Console.WriteLine((passed ? "PASS " : "GAP ") + "action " + mode);
}
var sources = new[] { "EngineSession.cs", "DesktopActionRunner.cs", "ReportAdapter.cs", "ExportSelection.cs" }.ToDictionary(name => name, name => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine("desktop/windows/AttackMap.NativeSpike", name)))));
await File.WriteAllTextAsync(args[1], JsonSerializer.Serialize(new { scope = "Actual process fault composition; plain report import callback equivalent validation, no MainWindow/UI automation claim", output, sources, results, gaps, limitations = new[] { "Previous-report retention is test host state; native UI fault task completion remains unproven", "Cleanup timeout/admission latch already tested separately, not repeated here", "No broker descendants or network" } }, new JsonSerializerOptions { WriteIndented = true }));
Environment.ExitCode = gaps.Count == 0 ? 0 : 1;
namespace AttackMap.NativeSpike { public sealed record FixtureFinding(string Id, string Title, string Severity, string Basis, string Confidence, string Source, string Evidence, string Recommendation); }
