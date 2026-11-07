using System.Text.Json;
using AttackMap.NativeSpike;

int checks = 0;
void Check(bool condition, string label) { if (!condition) throw new Exception(label); ++checks; Console.WriteLine("PASS " + label); }
async Task Reject(Func<Task> action, string label)
{
    bool rejected = false;
    try { await action(); }
    catch (Exception error) when (error is InvalidDataException or JsonException or IOException) { rejected = true; }
    Check(rejected, label);
}
string root = Path.Combine(Path.GetTempPath(), "attackmap-report-snapshot-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
string reportPath = Path.Combine(root, "attackmap-report.json");
string manifestPath = Path.Combine(root, "artifact-manifest.json");
string repository = "C:/synthetic-repository";
byte[] reportA = JsonSerializer.SerializeToUtf8Bytes(new
{
    scan = new { root = repository, files_scanned = 2, secret_hints = new[] { new { id = "s1", name = "hint", kind = "token", file = "secret.txt", line = 4, value = "DO_NOT_RENDER" } } },
    findings = new[] { new { id = "f1", title = "Supplied finding", severity = "high", confidence = "high", mitigation = "Review it" } },
    exploitability = new[] { new { id = "r1", subject = "Supplied risk", finding_id = "f1", score = 10 } },
    attack_paths = new[] { new { id = "p1", name = "Supplied path", impact = "Unknown" } },
    defensive_review = "# Supplied review",
    defensive_review_json = new { recommendations = new[] { new { id = "a1", action = "Inspect", finding_id = "f1", secret_value = "DO_NOT_RENDER" } }, strengths = Array.Empty<object>() }
});
byte[] reportB = JsonSerializer.SerializeToUtf8Bytes(new { scan = new { root = repository }, findings = Array.Empty<object>() });
void WriteManifest(byte[] reported, string manifestReportHashOverride = "")
{
    string hash = manifestReportHashOverride.Length == 0 ? ExportSelection.Hash(reported) : manifestReportHashOverride;
    File.WriteAllText(manifestPath, JsonSerializer.Serialize(new
    {
        schema_version = "1.0.0", artifact_type = "attackmap_artifact_manifest", generation_id = "generation-a",
        run_identity = new { repo_root = repository }, sections = Array.Empty<object>(),
        compatibility_exports = new[] { new { name = "attackmap-report.json", path = "attackmap-report.json", role = "compatibility-export", format = "json", checksum = hash } }
    }));
}
FileStream OpenRead(string path)
{
    return new FileStream(path, new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.Read, Options = FileOptions.Asynchronous | FileOptions.SequentialScan });
}
try
{
    File.WriteAllBytes(reportPath, reportA); WriteManifest(reportA);
    int opens = 0;
    var snapshot = await VerifiedReportSnapshot.Load(reportPath, null, path => { ++opens; return OpenRead(path); });
    Check(opens == 1, "test_single_open_feeds_all_three_projections_and_manifest");
    var legacyReport = await ReportAdapter.Load(reportPath);
    Check(snapshot.Report.ReadHash == legacyReport.ReadHash && snapshot.Report.Review == legacyReport.Review &&
        snapshot.Report.Findings.Select(x => x.Id).SequenceEqual(legacyReport.Findings.Select(x => x.Id)) &&
        snapshot.Sections.Exploitability.Rows.Single().Evidence.Id == "r1" && snapshot.Overview.Actions.Items.Single().Id == "a1",
        "test_legacy_adapter_and_public_export_selection_output_unchanged_on_existing_fixtures");
    Check(snapshot.ReadHash == snapshot.Selection.ReportHash && snapshot.Sections.ReadHash == snapshot.ReadHash &&
        snapshot.Overview.ReadHash == snapshot.ReadHash && snapshot.Selection.RunId == snapshot.Sections.GenerationId,
        "test_hash_and_generation_are_identical_across_snapshot_and_selection");
    Check(!JsonSerializer.Serialize(snapshot.Sections).Contains("DO_NOT_RENDER") && !JsonSerializer.Serialize(snapshot.Overview).Contains("DO_NOT_RENDER"),
        "test_secret_values_do_not_enter_section_or_overview_projection");

    File.WriteAllBytes(reportPath, reportB); WriteManifest(reportA);
    var captured = ExportSelection.CaptureSavedGeneration(reportPath, reportA, repository);
    Check(captured.ReportHash == ExportSelection.Hash(reportA) && captured.Verified,
        "test_manifest_selection_uses_captured_bytes_without_report_reread");
    WriteManifest(reportB);
    await Reject(() => Task.Run(() => ExportSelection.CaptureSavedGeneration(reportPath, reportA, repository)),
        "test_captured_hash_mismatch_fails");

    File.WriteAllBytes(reportPath, reportA); WriteManifest(reportA);
    var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var lockedLoad = VerifiedReportSnapshot.Load(reportPath, null, OpenRead, async () => { entered.SetResult(); await release.Task; });
    await entered.Task;
    bool writeRejected = false;
    try { using var writer = new FileStream(reportPath, FileMode.Open, FileAccess.Write, FileShare.None); }
    catch (IOException) { writeRejected = true; }
    release.SetResult(); var lockedSnapshot = await lockedLoad;
    Check(writeRejected && lockedSnapshot.ReadHash == ExportSelection.Hash(reportA),
        "test_read_lock_survives_until_manifest_and_projection_complete");

    var malformedPath = Path.Combine(root, "malformed.json");
    File.WriteAllText(malformedPath, "{");
    await Reject(() => VerifiedReportSnapshot.Load(malformedPath, null), "test_malformed_json_fails");
    File.WriteAllText(malformedPath, JsonSerializer.Serialize(new { schema_version = "1.0.0", scan = new { root = repository }, findings = Array.Empty<object>() }));
    await Reject(() => VerifiedReportSnapshot.Load(malformedPath, null), "test_versioned_envelope_fails");

    string oversizedPath = Path.Combine(root, "oversized.json");
    using (var oversized = new FileStream(oversizedPath, FileMode.Create, FileAccess.Write, FileShare.None)) oversized.SetLength(64 * 1024 * 1024 + 1L);
    await Reject(() => VerifiedReportSnapshot.Load(oversizedPath, null), "test_oversized_stream_fails_before_projection");

    string growingPath = Path.Combine(root, "growing.json");
    File.WriteAllBytes(growingPath, reportA);
    await Reject(() => VerifiedReportSnapshot.Load(growingPath, null,
        path => new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite),
        () =>
        {
            using var stream = new FileStream(growingPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            stream.WriteByte(32);
            return Task.CompletedTask;
        }), "test_growing_stream_fails_before_projection");

    using (var cancelled = new CancellationTokenSource())
    {
        var pending = VerifiedReportSnapshot.Load(reportPath, null, OpenRead,
            () => { cancelled.Cancel(); return Task.CompletedTask; }, cancelled.Token);
        bool cancelledRead = false;
        try { await pending; } catch (OperationCanceledException) { cancelledRead = true; }
        Check(cancelledRead, "test_cancellation_before_parse_returns_no_snapshot");
    }
    using (var cancelled = new CancellationTokenSource())
    {
        int projections = 0;
        var pending = VerifiedReportSnapshot.Load(reportPath, null, OpenRead, null, cancelled.Token,
            () => { if (++projections == 1) cancelled.Cancel(); });
        bool cancelledProjection = false;
        try { await pending; } catch (OperationCanceledException) { cancelledProjection = true; }
        Check(cancelledProjection && projections == 1, "test_cancellation_between_projections_returns_no_snapshot");
    }

    var previous = SynchronizationContext.Current;
    try
    {
        SynchronizationContext.SetSynchronizationContext(new ThrowingSynchronizationContext());
        var background = await VerifiedReportSnapshot.Load(reportPath, null).ConfigureAwait(false);
        Check(background.Report.Findings.Count == 1, "test_background_projection_does_not_touch_sync_context");
    }
    finally { SynchronizationContext.SetSynchronizationContext(previous); }
    Console.WriteLine($"PASS {checks} report snapshot checks; one locked read, captured identity, background projection; no UI or provider calls");
}
finally { Directory.Delete(root, true); }

sealed class ThrowingSynchronizationContext : SynchronizationContext
{
    public override void Post(SendOrPostCallback d, object? state) => throw new InvalidOperationException("UI synchronization context used.");
    public override void Send(SendOrPostCallback d, object? state) => throw new InvalidOperationException("UI synchronization context used.");
}
namespace AttackMap.NativeSpike
{
    public sealed record FixtureFinding(string Id, string Title, string Severity, string Basis, string Confidence, string Source, string Evidence, string Recommendation);
}
