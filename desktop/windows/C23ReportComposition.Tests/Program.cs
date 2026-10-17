using System.Text.Json;
using AttackMap.NativeSpike;
string output = Path.Combine(Path.GetTempPath(), "attackmap-c23-composition-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(output);
var checks = new List<string>();
void Check(bool condition, string name) { if (!condition) throw new Exception(name); checks.Add(name); }
string golden = Path.Combine(AppContext.BaseDirectory, "fixtures", "conflicting-partial.json");
var imported = await ReportAdapter.Load(golden);
var conflict = imported.Findings[0];
Check(conflict.Id == "synthetic-conflict" && conflict.Confidence == "low" && conflict.Severity == "medium", "Adapter preserves labels for conflicting partial evidence");
foreach (string supplied in new[] { "synthetic-obs-č", "present", "absent", "synthetic-overlay", "metadata status: unknown", "candidates truncated: true", "ownership: unknown", "point contributions: not_supplied" })
    Check(conflict.Evidence.Contains(supplied), "Supplied finding context retained: " + supplied);
Check(conflict.Evidence.Contains("Candidate evidence is not a verified association") && conflict.Evidence.Contains("trust boundary crossing: unknown"), "Conflict candidates do not become verified links or trust crossings");
Check(imported.Coverage.Contains("Distinct accepted source paths enumerated by analyzers: 1") && imported.Coverage.Contains("legacy aggregate; may overlap): 12"), "Distinct accepted paths remain separate from aggregate count");
Check(imported.Coverage.Contains("coverage truncated") && imported.Coverage.Contains("unsupported_language") && imported.Coverage.Contains("does not establish complete"), "Unsupported language and truncated coverage remain supplied limitations");
Check(imported.Findings[1].Source == "Location unavailable" && SourceLocation.Inspect(output, imported.FindingRecords[1].GetRawText()).Count == 0, "Missing location yields no invented live source target");
string live = Path.Combine(output, "src", "ž.unknown"); Directory.CreateDirectory(Path.GetDirectoryName(live)!);
await File.WriteAllTextAsync(live, "SYNTHETIC unsupported extension\nč Unicode source\n");
var inspected = SourceLocation.Inspect(output, imported.FindingRecords[0].GetRawText()).Single();
Check(inspected.Status == "valid" && inspected.Comparison == "unknown" && inspected.ScanTimeSha256 == null, "Live unsupported-extension location can be inspected without inferred scan-time integrity");
Check(inspected.Warning == SourceLocation.UnknownWarning, "Unsupported-language live inspection retains stale-source warning");
string selectedFolder = Path.Combine(output, "run-A"); Directory.CreateDirectory(selectedFolder);
string selectedReport = Path.Combine(selectedFolder, "attackmap-report.json");
byte[] selectedBytes = await File.ReadAllBytesAsync(golden); await File.WriteAllBytesAsync(selectedReport, selectedBytes);
string manifest = JsonSerializer.Serialize(new { schema_version = "1.0.0", artifact_type = "attackmap_artifact_manifest", generation_id = "run-A", run_identity = new { repo_root = imported.Repository }, compatibility_exports = new[] { new { path = "attackmap-report.json", checksum = imported.ReadHash } } });
await File.WriteAllTextAsync(Path.Combine(selectedFolder, "artifact-manifest.json"), manifest);
var selected = ExportSelection.Capture(selectedReport, imported.ReadHash, new RunIdentity("run-A", imported.Repository, 1, DateTimeOffset.UtcNow));
string laterFolder = Path.Combine(output, "run-B"); Directory.CreateDirectory(laterFolder);
await File.WriteAllTextAsync(Path.Combine(laterFolder, "attackmap-report.json"), "{\"newer\":true}");
await File.WriteAllTextAsync(Path.Combine(output, "current-generation.json"), "{\"generation_id\":\"run-B\"}");
string destination = Path.Combine(output, "selected-export.json"); await selected.Export(destination, false);
Check((await File.ReadAllBytesAsync(destination)).SequenceEqual(selectedBytes) && selected.RunId == "run-A", "Exact selected run export ignores later current pointer and newer report");
var copied = await ReportAdapter.Load(destination);
Check(copied.Findings[0].Evidence == conflict.Evidence && copied.Coverage == imported.Coverage, "Exact selected export retains conflict uncertainty and partial coverage presentation");
Console.WriteLine($"PASS {checks.Count} C23 report/source/export composition checks");
if (args.Length > 0) await File.WriteAllTextAsync(args[0], JsonSerializer.Serialize(new { scope = "Synthetic C23 adapter/source/export composition; no UI acceptance", checks, output, fixtureSha256 = ExportSelection.Hash(selectedBytes), limitations = new[] { "No unsupported-language analyzer execution", "Long-path live-source and export behavior covered by existing independent suites", "No manual source picker/reveal/copy, keyboard or Narrator verification" } }, new JsonSerializerOptions { WriteIndented = true }));
namespace AttackMap.NativeSpike { public sealed record FixtureFinding(string Id, string Title, string Severity, string Basis, string Confidence, string Source, string Evidence, string Recommendation); }
