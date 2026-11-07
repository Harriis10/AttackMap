using System.Text.Json;
using AttackMap.NativeSpike;

int checks = 0;
void Check(bool value, string name) { checks++; if (!value) throw new Exception(name); }
Dictionary<string, object?> Timing() => new() { ["schema_version"] = "1.0", ["clock"] = "engine_utc", ["scope"] = "analysis_pipeline_before_publication", ["started_at"] = "2026-10-15T12:00:00.123456+00:00", ["finished_at"] = "2026-10-15T12:01:00Z", ["outcome"] = "completed" };
string Manifest(Dictionary<string, object?> timing) => JsonSerializer.Serialize(new { scan_timing = timing });
Check(ScanTiming.Parse(Manifest(Timing()))?.Label.Contains("before publication") == true, "UTC Z and offset accepted with precise scope");
foreach (string outcome in new[] { "completed", "failed", "cancelled" })
{
    var timing = Timing(); timing["outcome"] = outcome;
    Check(ScanTiming.Parse(Manifest(timing))?.Outcome == outcome, "explicit outcome preserved");
}
foreach (var change in new (string Field, object? Value)[] {
    ("schema_version", "2.0"), ("clock", "client_utc"), ("scope", "publication"), ("outcome", "succeeded"),
    ("started_at", null), ("finished_at", null), ("finished_at", "2026-10-15T11:00:00Z"),
    ("started_at", "2026-10-15T12:00:00+01:00"), ("started_at", "2026-10-15T12:00:00-00:00"),
    ("started_at", "2026-10-15T12:00:00"), ("started_at", "2026-02-30T12:00:00Z"), ("started_at", 123) })
{
    var timing = Timing(); timing[change.Field] = change.Value;
    Check(ScanTiming.Parse(Manifest(timing)) == null, "unsupported or malformed timing is unknown: " + change.Field);
}
foreach (string text in new[] { "{}", "[]", "{", "{\"scan_timing\":null}" }) Check(ScanTiming.Parse(text) == null, "missing/malformed timing unknown");
Check(ScanTiming.Parse(Manifest(Timing()).Replace("\"clock\":\"engine_utc\"", "\"clock\":\"client_utc\",\"clock\":\"engine_utc\"")) == null, "duplicate timing fields unknown");

var directory = Path.Combine(Path.GetTempPath(), "attackmap-scan-timing-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(directory);
try
{
    string report = Path.Combine(directory, "attackmap-report.json"), run = Path.Combine(directory, "run-manifest.json"), manifest = Path.Combine(directory, "artifact-manifest.json");
    File.WriteAllText(report, "{}"); File.WriteAllText(run, Manifest(Timing()));
    object Entry(string path) => new { name = path, path, format = "json", role = "compatibility-export", checksum = ExportSelection.Hash(File.ReadAllBytes(Path.Combine(directory, path))) };
    ExportSelection Capture(bool listRun = true)
    {
        File.WriteAllText(manifest, JsonSerializer.Serialize(new { schema_version = "1.0.0", artifact_type = "attackmap_artifact_manifest", generation_id = "selected", sections = Array.Empty<object>(), compatibility_exports = listRun ? new[] { Entry("attackmap-report.json"), Entry("run-manifest.json") } : new[] { Entry("attackmap-report.json") } }));
        return new(report, ExportSelection.Hash(File.ReadAllBytes(report)), "selected", manifest, ExportSelection.Hash(File.ReadAllBytes(manifest)), null, null);
    }
    var selected = Capture();
    Check((await ScanTiming.ReadLabel(selected)).Contains("outcome: completed"), "hash-bound timing read");
    File.WriteAllText(Path.Combine(directory, "current-generation.json"), "{\"generation\":\"other-run\"}");
    Check((await ScanTiming.ReadLabel(selected)).Contains("outcome: completed"), "mutable current pointer cannot redirect captured selection");
    Check(await ScanTiming.ReadLabel(selected with { RunId = null }) == ScanTiming.UnknownLabel, "legacy never reads adjacent run manifest");
    Check(await ScanTiming.ReadLabel(Capture(false)) == ScanTiming.UnknownLabel, "unlisted adjacent run manifest ignored");
    selected = Capture(); File.AppendAllText(run, " ");
    Check(await ScanTiming.ReadLabel(selected) == ScanTiming.UnknownLabel, "tampered timing artifact unknown");
    File.WriteAllText(run, Manifest(Timing())); selected = Capture(); File.AppendAllText(manifest, " ");
    Check(await ScanTiming.ReadLabel(selected) == ScanTiming.UnknownLabel, "changed captured manifest unknown");
    selected = Capture(); File.AppendAllText(report, " ");
    Check(await ScanTiming.ReadLabel(selected) == ScanTiming.UnknownLabel, "changed displayed report unknown");
    File.WriteAllText(report, "{}"); selected = Capture(); File.Delete(run);
    Check(await ScanTiming.ReadLabel(selected) == ScanTiming.UnknownLabel, "missing listed run manifest unknown");
    Console.WriteLine($"PASS {checks} scan timing parsing and captured-generation checks; no UI acceptance claim");
}
finally { Directory.Delete(directory, true); }
