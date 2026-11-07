using System.Text.Json;
using AttackMap.NativeSpike;

int checks = 0;
void Check(bool condition) { checks++; if (!condition) throw new Exception($"Failed check {checks}"); }
string Read(object value) { using var document = JsonDocument.Parse(JsonSerializer.Serialize(value)); return OverviewAdapter.Read(document.RootElement); }
var text = Read(new { defensive_review_json = new { system_overview = new { control_count_present = 3 }, strengths = new[] { new { statement = "Synthetic → 🔒", evidence_basis = "observed", confidence = "low", evidence = new[] { "auth hint" } } }, recommendations = new[] { new { action = "SECOND alphabetically", priority = "low", evidence_basis = "heuristic_static" }, new { action = "FIRST alphabetically", priority = "high", evidence_basis = "unknown" } }, analyst_notes = new[] { "Synthetic control present", "Synthetic control absent" }, limitations_meta = new { notes = new[] { "Synthetic contradiction unresolved" } } }, scan = new { files_scanned = 9, scanned_files = new[] { "a.py" }, analyzer_errors = new[] { "Synthetic analyzer failed" }, limitations = new[] { "Synthetic skipped source" } } });
Check(text.Contains("Synthetic → 🔒")); Check(text.Contains("basis=observed; confidence=low"));
Check(text.IndexOf("SECOND alphabetically") < text.IndexOf("FIRST alphabetically"));
Check(text.IndexOf("Next actions") < text.IndexOf("System overview (supplied)"));
Check(text.IndexOf("FIRST alphabetically") < text.IndexOf("Positive indicators / strengths"));
Check(text.Contains("control_count_present: 3"));
Check(text.Contains("surface association: unknown / not supplied"));
Check(text.Contains("Static analysis does not establish runtime behavior or verified control enforcement."));
Check(text.Contains("priority=low; basis=heuristic_static")); Check(text.Contains("Synthetic control present") && text.Contains("Synthetic control absent"));
Check(text.Contains("Synthetic contradiction unresolved")); Check(text.Contains("Synthetic analyzer failed")); Check(text.Contains("Synthetic skipped source")); Check(text.Contains("scanned_files enumeration records: 1"));
Check(Read(new { }).Contains("Structured defensive review unavailable"));
Check(Read(new { defensive_review_json = new { } }).Contains("unknown / not supplied"));
var huge = Read(new { defensive_review_json = new { recommendations = Enumerable.Range(0, 40).Select(i => new { action = new string('x', 10000) }) } });
Check(huge.Contains("field truncated")); Check(huge.Contains("List truncated: 16 of 40")); Check(huge.Length < 66000);
var html = Read(new { defensive_review_json = new { analyst_notes = new[] { "<script>synthetic()</script>" } } }); Check(html.Contains("<script>synthetic()</script>"));
var saved = Path.GetFullPath(".pytest_cache/m3-native-context-scan/af2d132c84944a97a71698e4646904d7/attackmap-report.json");
if (File.Exists(saved))
{
    using var real = JsonDocument.Parse(File.ReadAllBytes(saved)); var projected = OverviewAdapter.Read(real.RootElement);
    var review = real.RootElement.GetProperty("defensive_review_json");
    Check(projected.Contains(review.GetProperty("strengths")[0].GetProperty("statement").GetString()!));
    var actions = review.GetProperty("recommendations");
    Check(projected.IndexOf(actions[0].GetProperty("action").GetString()!) < projected.IndexOf(actions[1].GetProperty("action").GetString()!));
    Check(projected.IndexOf(actions[0].GetProperty("action").GetString()!) < projected.IndexOf("System overview (supplied)"));
    Check(projected.Contains("runtime behavior"));
}
Console.WriteLine($"{checks} overview projection checks passed; supplied labels/order only; no UI acceptance claim");
