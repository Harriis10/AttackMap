using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AttackMap.NativeSpike;

public sealed record ScanTiming(DateTimeOffset StartedAt, DateTimeOffset FinishedAt, string Outcome)
{
    public const string UnknownLabel = "Engine scan timing unavailable (missing, unsupported or unverifiable).";
    public string Label => $"Engine analysis started (UTC): {StartedAt.UtcDateTime:O}; analysis finished before publication (UTC): {FinishedAt.UtcDateTime:O}; outcome: {Outcome}. This is not publication completion time.";

    public static ScanTiming? Parse(string runManifest)
    {
        try
        {
            using var document = JsonDocument.Parse(runManifest);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count(item => item.Name == "scan_timing") != 1 || !root.TryGetProperty("scan_timing", out var timing) || timing.ValueKind != JsonValueKind.Object ||
                timing.EnumerateObject().Select(item => item.Name).Distinct(StringComparer.Ordinal).Count() != timing.EnumerateObject().Count()) return null;
            string? Text(string name) => timing.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
            if (Text("schema_version") != "1.0" || Text("clock") != "engine_utc" || Text("scope") != "analysis_pipeline_before_publication" ||
                Text("outcome") is not ("completed" or "failed" or "cancelled") || !Utc(Text("started_at"), out var started) || !Utc(Text("finished_at"), out var finished) || finished < started) return null;
            return new(started, finished, Text("outcome")!);
        }
        catch (JsonException) { return null; }
    }

    private static bool Utc(string? value, out DateTimeOffset parsed)
    {
        parsed = default;
        return value != null && value.Length <= 40 && Regex.IsMatch(value, @"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|\+00:00)\z", RegexOptions.CultureInvariant) &&
            DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out parsed) && parsed.Offset == TimeSpan.Zero;
    }

    public static async Task<string> ReadLabel(ExportSelection selection) => (await ReadLabelMeasured(selection)).Label;

    internal static async Task<ScanTimingRead> ReadLabelMeasured(ExportSelection selection)
    {
        if (!selection.Verified) return new(UnknownLabel, 0);
        int reportIntegrityReads = 0;
        try
        {
            var records = await Task.Run(() => SelectedArtifacts.List(selection));
            ++reportIntegrityReads;
            var record = records.SingleOrDefault(item => Path.GetFileName(item.FullPath) == "run-manifest.json" && item.Format == "json");
            if (record == null) return new(UnknownLabel, reportIntegrityReads);
            string text = await SelectedArtifacts.ReadText(selection, record, 1024 * 1024);
            reportIntegrityReads += 2;
            return new(Parse(text)?.Label ?? UnknownLabel, reportIntegrityReads);
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or JsonException or InvalidOperationException or ArgumentException)
        { return new(UnknownLabel, reportIntegrityReads); }
    }
}

internal sealed record ScanTimingRead(string Label, int ReportIntegrityReadCount);
