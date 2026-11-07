using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AttackMap.GraphExplorer;
using AttackMap.NativeSpike;

int checks = 0;
void Check(bool passed, string message) { if (!passed) throw new Exception(message); checks++; }
string input = args.Length > 0 ? args[0] : "docs/verification/windows-parity/WP043/fleet16-20261023/core/fleet16-oracle.json";
var context = new GraphContext("host-run", "verified-generation", new string('a', 64), 17);
var document = GraphReader.Read(File.ReadAllBytes(input), context);
void Reject(string json)
{
    using var value = JsonDocument.Parse(json);
    try { WebGraphExportMetadata.Append(document, value.RootElement); throw new Exception("Invalid metadata was accepted: " + json[..Math.Min(json.Length, 100)]); }
    catch (JsonException) { checks++; }
}
var edge = document.Edges[0];
var ui = JsonSerializer.SerializeToElement(new {
    context = new { run_id = "spoofed", report_hash = "fake" },
    counts = new { canonicalNodes = 999999 }, coverage = new { complete = true }, limitations = Array.Empty<string>(),
    view = new { collapsed_ids = new[] { document.Repositories[0].Id }, query = "billing", kind = edge.Kind,
        resolution = edge.Resolution, inter_repo_only = true, neighborhood = "downstream", layout = "fcose" }
});
using var exported = JsonDocument.Parse(WebGraphExportMetadata.Append(document, ui));
using var original = JsonDocument.Parse(document.SourceJson);
foreach (var property in original.RootElement.EnumerateObject())
    if (property.Name != "export_metadata") Check(JsonNode.DeepEquals(JsonNode.Parse(property.Value.GetRawText()), JsonNode.Parse(exported.RootElement.GetProperty(property.Name).GetRawText())), "Canonical property changed: " + property.Name);
var meta = exported.RootElement.GetProperty("export_metadata");
Check(meta.GetProperty("context").GetProperty("run_id").GetString() == context.RunId, "UI replaced host run identity");
Check(meta.GetProperty("context").GetProperty("report_hash").GetString() == context.ReportHash, "UI replaced host report identity");
Check(meta.GetProperty("canonical_counts").GetProperty("nodes").GetInt32() == document.Nodes.Length, "UI replaced canonical node count");
Check(meta.GetProperty("ui_state").GetProperty("requested_layout").GetString() == "fcose", "Requested layout not labelled separately");
Check(!meta.GetProperty("ui_state").TryGetProperty("coverage", out _), "UI coverage escaped into metadata");
Check(meta.GetProperty("ui_state_trust").GetString()!.Contains("Untrusted"), "UI state trust label missing");
Check(exported.RootElement.GetProperty("nodes").GetArrayLength() == document.Nodes.Length, "JSON omitted hidden nodes");
Check(exported.RootElement.GetProperty("edges").GetArrayLength() == document.Edges.Length, "JSON omitted hidden edges");
using var absent = JsonDocument.Parse(WebGraphExportMetadata.Append(document));
Check(!absent.RootElement.GetProperty("export_metadata").GetProperty("ui_state_available").GetBoolean(), "Absent view metadata claimed available");
Reject("[]");
Reject(JsonSerializer.Serialize(new { view = new { query = new string('q', WebGraphExportMetadata.MaximumMetadataCharacters + 1) } }));
Reject(JsonSerializer.Serialize(new { view = new { query = new string('q', 4097) } }));
Reject("{\"view\":{\"query\":\"bad\\nquery\"}}");
Reject("{\"view\":{\"collapsed_ids\":[\"unknown\"]}}");
Reject(JsonSerializer.Serialize(new { view = new { collapsed_ids = new[] { document.Nodes[0].Id, document.Nodes[0].Id } } }));
Reject("{\"view\":{\"query\":\"one\",\"query\":\"two\"}}");
Reject("{\"view\":{\"path\":\"C:/untrusted\"}}");
Reject("{\"view\":{\"inter_repo_only\":\"true\"}}");
Reject("{\"view\":{\"kind\":\"nonexistent\"}}");
Reject("{\"view\":{\"resolution\":\"nonexistent\"}}");
Reject("{\"view\":{\"neighborhood\":\"arbitrary\"}}");
Reject("{\"view\":{\"layout\":\"arbitrary\"}}");
Reject("{\"view\":null}");
var prior = JsonNode.Parse(document.SourceJson)!;
prior["export_metadata"] = JsonNode.Parse("{\"context\":\"untrusted-old-context\"}");
var priorDocument = GraphReader.Read(Encoding.UTF8.GetBytes(prior.ToJsonString()), context);
using var replaced = JsonDocument.Parse(WebGraphExportMetadata.Append(priorDocument));
Check(replaced.RootElement.EnumerateObject().Count(item => item.Name == "export_metadata") == 1, "Duplicate export metadata introduced");
Check(replaced.RootElement.GetProperty("export_metadata").GetProperty("context").GetProperty("run_id").GetString() == context.RunId, "Prior UI context retained as host identity");
Console.WriteLine($"{checks} export metadata checks PASS; no WinUI control constructed and no GUI launched.");
