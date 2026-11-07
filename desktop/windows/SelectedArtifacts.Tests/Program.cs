using System.Text;
using System.Text.Json;
using AttackMap.NativeSpike;

var directory = Path.Combine(Path.GetTempPath(), "attackmap-artifacts-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
var report = Path.Combine(directory, "attackmap-report.json"); var manifest = Path.Combine(directory, "artifact-manifest.json");
var ai = Path.Combine(directory, "žluťoučký.md"); File.WriteAllText(report, "{}"); File.WriteAllText(ai, "Synthetic → 🔒");
int checks = 0;
void Check(bool result) { checks++; if (!result) throw new Exception($"Failed check {checks}"); }
async Task Reject(Func<Task> operation) { bool rejected = false; try { await operation(); } catch (Exception e) when (e is InvalidDataException or IOException or JsonException or DecoderFallbackException) { rejected = true; } Check(rejected); }
object Entry(string path, string format = "md", string? checksum = null) => new { name = path, path, format, role = "compatibility-export", checksum = checksum ?? ExportSelection.Hash(File.ReadAllBytes(Path.Combine(directory, path))) };
ExportSelection Write(object[]? sections = null, string schema = "1.0.0", string generation = "selected-run")
{
    File.WriteAllText(manifest, JsonSerializer.Serialize(new { schema_version = schema, artifact_type = "attackmap_artifact_manifest", generation_id = generation, sections = sections ?? new[] { Entry("žluťoučký.md") }, compatibility_exports = new[] { Entry("attackmap-report.json", "json") } }));
    return new(report, ExportSelection.Hash(File.ReadAllBytes(report)), "selected-run", manifest, ExportSelection.Hash(File.ReadAllBytes(manifest)), null, null);
}
try
{
    var selection = Write(); var records = SelectedArtifacts.List(selection); Check(records.Count == 2);
    var record = records.Single(r => r.Format == "md"); Check(await SelectedArtifacts.ReadText(selection, record) == "Synthetic → 🔒");
    await Reject(() => Task.Run(() => SelectedArtifacts.List(selection with { RunId = null })));
    await Reject(() => SelectedArtifacts.ReadText(selection, record with { FullPath = report }));
    File.AppendAllText(ai, "tampered"); await Reject(() => SelectedArtifacts.ReadText(selection, record)); File.WriteAllText(ai, "Synthetic → 🔒");
    await Reject(() => SelectedArtifacts.ReadText(selection, record, 2));
    File.AppendAllText(report, " "); await Reject(() => SelectedArtifacts.ReadText(selection, record)); File.WriteAllText(report, "{}");
    File.AppendAllText(manifest, " "); await Reject(() => Task.Run(() => SelectedArtifacts.List(selection)));
    await Reject(() => Task.Run(() => SelectedArtifacts.List(Write(schema: "2.0.0"))));
    await Reject(() => Task.Run(() => SelectedArtifacts.List(Write(generation: "other-run"))));
    await Reject(() => Task.Run(() => SelectedArtifacts.List(Write(new[] { Entry("žluťoučký.md"), Entry("žluťoučký.md") }))));
    await Reject(() => Task.Run(() => SelectedArtifacts.List(Write(new[] { Entry("../outside.md", checksum: new string('a', 64)) }))));
    await Reject(() => Task.Run(() => SelectedArtifacts.List(Write(new[] { Entry("žluťoučký.md", checksum: "bad") }))));
    await Reject(() => Task.Run(() => SelectedArtifacts.List(Write(new[] { Entry("missing.md", checksum: new string('a', 64)) }))));
    File.WriteAllBytes(ai, new byte[] { 0xff }); selection = Write(); record = SelectedArtifacts.List(selection).First(); await Reject(() => SelectedArtifacts.ReadText(selection, record));
    File.Delete(ai);
    File.CreateSymbolicLink(ai, report); selection = Write(); await Reject(() => Task.Run(() => SelectedArtifacts.List(selection))); File.Delete(ai);
    File.WriteAllText(ai, "Synthetic → 🔒"); selection = Write();
    var alias = directory + "-alias";
    try
    {
        Directory.CreateSymbolicLink(alias, directory);
        var redirected = selection with { ReportPath = Path.Combine(alias, "attackmap-report.json"), ManifestPath = Path.Combine(alias, "artifact-manifest.json") };
        await Reject(() => Task.Run(() => SelectedArtifacts.List(redirected)));
    }
    finally { if (Directory.Exists(alias)) Directory.Delete(alias); }
    await Reject(() => Task.Run(() => SelectedArtifacts.List(Write(new[] { Entry("žluťoučký.md", format: "html") }))));
    // The same valid bytes in a different generation are not a substitute for selected membership.
    selection = Write(); record = SelectedArtifacts.List(selection).First();
    await Reject(() => SelectedArtifacts.ReadText(selection, record with { FullPath = Path.Combine(directory + "-other", "žluťoučký.md") }));
    var realManifest = Path.GetFullPath(".pytest_cache/m3-native-context-scan/af2d132c84944a97a71698e4646904d7/artifact-manifest.json");
    if (File.Exists(realManifest))
    {
        using var real = JsonDocument.Parse(File.ReadAllBytes(realManifest));
        var realReport = Path.Combine(Path.GetDirectoryName(realManifest)!, "attackmap-report.json");
        var captured = new ExportSelection(realReport, ExportSelection.Hash(File.ReadAllBytes(realReport)), real.RootElement.GetProperty("generation_id").GetString(), realManifest, ExportSelection.Hash(File.ReadAllBytes(realManifest)), null, null);
        Check(SelectedArtifacts.List(captured).Count > 10);
    }
    File.WriteAllText(manifest, JsonSerializer.Serialize(new { schema_version = "1.0.0", artifact_type = "attackmap_artifact_manifest", generation_id = "saved-run", run_identity = new { repo_root = "saved-repository" }, sections = new[] { Entry("žluťoučký.md") }, compatibility_exports = new[] { Entry("attackmap-report.json", "json") } }));
    var reportHash = ExportSelection.Hash(File.ReadAllBytes(report));
    var reopened = ExportSelection.CaptureSavedGeneration(report, reportHash, "saved-repository");
    Check(reopened.Verified && reopened.RunId == "saved-run");
    Check(await SelectedArtifacts.ReadText(reopened, SelectedArtifacts.List(reopened).Single(x => x.Format == "md")) == "Synthetic → 🔒");
    await Reject(() => Task.Run(() => ExportSelection.CaptureSavedGeneration(report, reportHash, "other-repository")));
    File.AppendAllText(report, " ");
    await Reject(() => Task.Run(() => ExportSelection.CaptureSavedGeneration(report, reportHash, "saved-repository")));
    File.WriteAllText(report, "{}");
    File.WriteAllText(manifest, "malformed");
    await Reject(() => Task.Run(() => ExportSelection.CaptureSavedGeneration(report, reportHash, "saved-repository")));
    File.Delete(manifest);
    Check(!ExportSelection.CaptureSavedGeneration(report, reportHash, "saved-repository").Verified);
    Console.WriteLine($"{checks} selected-artifact checks passed; actual symlink rejected; no UI acceptance claim");
}
finally { Directory.Delete(directory, true); }
