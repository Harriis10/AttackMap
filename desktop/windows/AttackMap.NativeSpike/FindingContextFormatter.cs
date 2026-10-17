using System.Text;
using System.Text.Json;
namespace AttackMap.NativeSpike;

/// <summary>Plain-text projection of core context. Does not associate evidence or calculate priority.</summary>
public static class FindingContextFormatter
{
    public const int MaximumCharacters = 49152;
    public static string Format(JsonElement context)
    {
        if (context.ValueKind != JsonValueKind.Object)
            return "Finding context unavailable; supplied context is missing or not an object. Evidence associations remain unknown.";
        if (!context.TryGetProperty("context_version", out var version) || version.ValueKind != JsonValueKind.String || version.GetString() != "1.0")
            return "Finding context unavailable: unsupported or missing context version (supported: 1.0). Evidence associations remain unknown.";
        var writer = new Projection();
        writer.Line("Core-supplied finding context (version 1.0)");
        writer.Line("Candidate evidence is not a verified association. Static flow is not verified runtime reachability or an inter-service trust relationship.");
        writer.Section(context, "finding_id", "Finding identity");
        writer.Section(context, "claim", "Claim");
        writer.Section(context, "priority", "Priority factors");
        writer.Section(context, "source", "Source quality");
        writer.Section(context, "evidence", "Candidate evidence");
        writer.Section(context, "observed_controls", "Observed controls");
        writer.Section(context, "trust_chain", "Trust chain");
        writer.Section(context, "recommendation", "Recommendation");
        writer.Section(context, "suppression", "Suppression");
        writer.Section(context, "uncertainty", "Uncertainty");
        return writer.Finish();
    }

    private sealed class Projection
    {
        private readonly StringBuilder text = new();
        private int nodes;
        private bool truncated;
        public void Line(string value)
        {
            // Reserve space for the mandatory truncation disclosure.
            int remaining = MaximumCharacters - 200 - text.Length;
            if (remaining <= 0) { truncated = true; return; }
            if (value.Length > remaining) { value = value[..remaining]; truncated = true; }
            text.AppendLine(value);
        }
        public void Section(JsonElement root, string key, string heading)
        {
            Line(""); Line(heading);
            if (root.TryGetProperty(key, out var value)) Render(value, 0, "");
            else Line("  unknown (not supplied)");
        }
        private void Render(JsonElement value, int depth, string label)
        {
            if (++nodes > 512 || depth > 10 || text.Length >= MaximumCharacters - 200) { truncated = true; return; }
            string prefix = new(' ', (depth + 1) * 2);
            if (label.Length > 256) { label = label[..256]; truncated = true; }
            if (value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
            {
                if (label.Length > 0) Line(prefix + label + ":");
                int count = 0;
                if (value.ValueKind == JsonValueKind.Object)
                {
                    foreach (var property in value.EnumerateObject())
                    {
                        if (++count > 32) { truncated = true; break; }
                        Render(property.Value, depth + 1, property.Name.Replace('_', ' '));
                    }
                }
                else foreach (var item in value.EnumerateArray())
                {
                    if (++count > 32) { truncated = true; break; }
                    Render(item, depth + 1, "[" + count + "]");
                }
                if (count == 0) Line(prefix + "  none supplied (empty collection)");
                return;
            }
            string scalar = value.ValueKind switch
            {
                JsonValueKind.Null or JsonValueKind.Undefined => "unknown (not supplied)",
                JsonValueKind.String => value.GetString() ?? "unknown (not supplied)",
                _ => value.GetRawText()
            };
            if (scalar.Length > 4096) { scalar = scalar[..4096]; truncated = true; }
            Line(prefix + (label.Length == 0 ? "" : label + ": ") + scalar);
        }
        public string Finish()
        {
            if (truncated) text.AppendLine("\nDisplay truncated: depth, record, field or text limit reached. Omitted supplied context remains available in the canonical report; no missing values were inferred.");
            return text.ToString();
        }
    }
}
