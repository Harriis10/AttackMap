using System.Text.Json;
namespace AttackMap.NativeSpike;

public sealed record StructureRecord(string Kind, string Title, string Basis, string Source, string Detail)
{
    public string Summary => $"{Kind} | {Basis} | {Source}";
}
public sealed record StructureData(List<StructureRecord> Architecture, List<StructureRecord> Inventory, string ArchitectureNotes, string InventoryNotes);
public static class StructureAdapter
{
    private static readonly string[] Details = ["hint", "name", "version", "ecosystem", "method", "path", "route", "target", "kind", "role", "source_role", "source_quality", "type", "source", "destination", "file", "line", "confidence", "evidence_class", "evidence_basis", "relationship_basis", "auth", "exposure", "category", "guards", "guard_evidence", "direct", "dev", "resolved", "via", "evidence_text", "properties", "source_analyzer", "analyzer", "analyzer_version", "metadata_status", "location_reason", "observation_id", "origins", "conflicts", "context_signals", "rationale"];
    public static StructureData Read(JsonElement root, JsonElement scan)
    {
        var architecture = new List<StructureRecord>();
        var inventory = new List<StructureRecord>();
        var architectureNotes = new List<string>();
        var inventoryNotes = new List<string>();
        foreach (var (key, kind) in new[] { ("service_hints", "Service hint"), ("edge_hints", "Relationship hint"), ("entrypoint_hints", "Entrypoint hint"), ("protocol_hints", "Protocol hint"), ("databases", "Datastore hint"), ("external_calls", "Outbound call") })
            ReadRows(scan, key, kind, architecture, architectureNotes);
        ReadRows(root, "attack_surfaces", "Attack surface", architecture, architectureNotes);
        foreach (var (key, kind) in new[] { ("routes", "Route"), ("dependencies", "Dependency"), ("databases", "Datastore hint"), ("framework_hints", "Framework hint") })
            ReadRows(scan, key, kind, inventory, inventoryNotes);
        const string uncertainty = "Supplied static records only; no UI-inferred nodes or edges. Missing ownership/relationships remain unknown. Observed static evidence is not runtime verification.";
        return new(architecture, inventory, uncertainty + "\n" + string.Join("\n", architectureNotes), uncertainty + "\n" + string.Join("\n", inventoryNotes));
    }
    private static void ReadRows(JsonElement parent, string key, string kind, List<StructureRecord> target, List<string> notes)
    {
        if (!parent.TryGetProperty(key, out var records) || records.ValueKind != JsonValueKind.Array)
        {
            notes.Add($"{key}: unavailable; completeness unknown.");
            return;
        }
        int supplied = 0, ignored = 0;
        foreach (var record in records.EnumerateArray())
        {
            if (record.ValueKind != JsonValueKind.Object) { ignored++; continue; }
            supplied++;
            string title = kind switch {
                "Dependency" => $"{Text(record,"name")} | version {Text(record,"version")} | ecosystem {Text(record,"ecosystem")}",
                "Route" or "Attack surface" => $"{Text(record,"method")} {Text(record,kind == "Route" ? "path" : "route")}",
                "Outbound call" => Text(record,"target"),
                "Datastore hint" => Text(record,"kind"),
                _ => Text(record,"hint",Text(record,"name")) };
            string classification = Text(record,"evidence_class",Text(record,"evidence_basis","unknown (not supplied)"));
            string basis = $"supplied basis: {classification}; relationship: {Text(record,"relationship_basis","unknown")}";
            if (kind.Contains("hint")) basis = "candidate hint; " + basis;
            string location = Text(record,"file","location unknown (not supplied)");
            if (record.TryGetProperty("line",out var line) && line.ValueKind != JsonValueKind.Null) location += ":" + line;
            string detail = string.Join("\n\n", Details.Where(key => record.TryGetProperty(key,out var value) && value.ValueKind != JsonValueKind.Null).Select(key => $"{key} (supplied)\n{record.GetProperty(key)}"));
            target.Add(new(kind,title,basis,location,$"{kind}: {title}\n{basis}\nSource: {location}\n\n{detail}"));
        }
        notes.Add($"{key}: {supplied} supplied records" + (ignored > 0 ? $"; {ignored} malformed records omitted (partial view)." : "."));
    }
    private static string Text(JsonElement item,string key,string fallback="unknown") => item.TryGetProperty(key,out var value) && value.ValueKind != JsonValueKind.Null ? value.ToString() : fallback;
}
