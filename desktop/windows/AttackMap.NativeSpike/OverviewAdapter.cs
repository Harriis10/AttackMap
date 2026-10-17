using System.Text;
using System.Text.Json;

namespace AttackMap.NativeSpike;

/// <summary>Bounded plain-text projection of supplied core review facts; no ranking or inferred associations.</summary>
public static class OverviewAdapter
{
    private const int MaxItems = 16;
    private const int MaxText = 2048;

    public static string Read(JsonElement canonicalRoot)
    {
        var output = new StringBuilder("Supplied core overview\nStatic analysis does not establish runtime behavior or verified control enforcement. Core order and labels are preserved.\n");
        var review = Object(canonicalRoot, "defensive_review_json");
        if (review.ValueKind != JsonValueKind.Object)
            output.AppendLine("Structured defensive review unavailable; strengths, actions and analyst notes are unknown. Open Reports for any supplied legacy review.");
        else
        {
            output.AppendLine("\nNext actions (core order; no native rescoring)");
            Items(output, review, "recommendations", item => $"{Field(item, "action")}\n  priority={Field(item, "priority")}; basis={Field(item, "evidence_basis")}; confidence={Field(item, "confidence")}\n  linked finding: {Field(item, "linked_finding")}\n  surface association: {Field(item, "surface_association")}\n  uncertainty: {Field(item, "uncertainty")}");
            output.AppendLine("\nSystem overview (supplied)");
            var system = Object(review, "system_overview");
            string[] fields = ["repository_type", "raw_inferred_entry_point_count", "external_call_count", "database_count", "auth_hint_count", "secret_hint_count", "asset_count", "control_count_present", "control_count_absent", "notable_observation_count", "detection_opportunity_count", "attack_techniques_observed_count"];
            foreach (string field in fields) output.AppendLine($"{field}: {Field(system, field)}");
            output.AppendLine("\nPositive indicators / strengths (supplied; not finding-owned control links)");
            Items(output, review, "strengths", item => $"{Field(item, "statement")}\n  basis={Field(item, "evidence_basis")}; confidence={Field(item, "confidence")}\n  evidence: {ArrayText(item, "evidence")}");
            output.AppendLine("\nAnalyst notes (supplied; conflicting statements are not resolved)");
            Items(output, review, "analyst_notes", Scalar);
            output.AppendLine("\nCore uncertainty / limitations");
            Items(output, Object(review, "limitations_meta"), "notes", Scalar);
        }
        output.AppendLine("\nCoverage (supplied; enumeration does not establish complete analysis)");
        var scan = Object(canonicalRoot, "scan");
        output.AppendLine($"files_scanned (legacy aggregate): {Field(scan, "files_scanned")}");
        var scanned = Object(scan, "scanned_files");
        output.AppendLine(scanned.ValueKind == JsonValueKind.Array ? $"scanned_files enumeration records: {scanned.GetArrayLength()}" : "Unique-file enumeration: unknown");
        output.AppendLine("Analyzer errors:"); Items(output, scan, "analyzer_errors", Scalar);
        output.AppendLine("Coverage limitations:"); Items(output, scan, "limitations", Scalar);
        const int totalLimit = 64 * 1024;
        return output.Length <= totalLimit ? output.ToString() : output.ToString(0, totalLimit) + "\n[Overview truncated at 64 Ki characters; open Reports for full supplied text.]";
    }

    private static JsonElement Object(JsonElement value, string name) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var result) ? result : default;
    private static string Field(JsonElement value, string name) => Scalar(Object(value, name));
    private static string Scalar(JsonElement value)
    {
        string? text = value.ValueKind switch { JsonValueKind.String => value.GetString(), JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => value.ToString(), _ => null };
        if (text == null) return "unknown / not supplied";
        return text.Length <= MaxText ? text : text[..MaxText] + " [field truncated]";
    }
    private static string ArrayText(JsonElement value, string name)
    {
        var array = Object(value, name);
        if (array.ValueKind != JsonValueKind.Array) return "unknown / not supplied";
        return string.Join("; ", array.EnumerateArray().Take(4).Select(Scalar)) + (array.GetArrayLength() > 4 ? " [evidence list truncated]" : "");
    }
    private static void Items(StringBuilder output, JsonElement value, string name, Func<JsonElement, string> project)
    {
        var array = Object(value, name);
        if (array.ValueKind != JsonValueKind.Array) { output.AppendLine("unknown / not supplied"); return; }
        if (array.GetArrayLength() == 0) { output.AppendLine("Supplied list is empty; absence is not proof of safety or control enforcement."); return; }
        int number = 0;
        foreach (var item in array.EnumerateArray().Take(MaxItems)) output.AppendLine($"{++number}. {project(item)}");
        if (array.GetArrayLength() > MaxItems) output.AppendLine($"[List truncated: {MaxItems} of {array.GetArrayLength()} supplied records shown.]");
    }
}
