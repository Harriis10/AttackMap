using System.Text.Json;
using AttackMap.NativeSpike;
int checks = 0;
void Check(bool condition,string label) { if (!condition) throw new Exception(label); checks++; }
string fixtures = Path.Combine(AppContext.BaseDirectory,"fixtures");
string nonempty = Path.Combine(fixtures,"report-nonempty-legacy.json");
var report = await ReportSectionAdapter.Load(nonempty,generationId:"synthetic-generation-1");
Check(report.GenerationId == "synthetic-generation-1", "caller generation retained");
Check(report.Paths.Rows.Single().Evidence.Name == "Public feedback to datastore" && report.Paths.Rows.Single().Evidence.Id == null,"path source identity without invented ID");
Check(report.Exploitability.Rows.Select(r => r.Score).SequenceEqual(new double?[] {100,98,93,90}),"core score/order retained");
Check(report.Dependencies.Rows.Single().Evidence.Name == "express","dependency projection");
Check(report.Secrets.Rows.Single().Name == "API_KEY","secret metadata");
Check(report.Suppressed.Rows.Single().Evidence.Id == "s1","suppressed identity");
Check(report.Analyzers.Availability == SectionAvailability.Missing && report.Fleet.Availability == SectionAvailability.Missing,"absent inventories unknown");
using(var fleet = JsonDocument.Parse("{\"repo_count\":2,\"repos\":[{\"repo_id\":\"sample\",\"root\":\"C:/a/sample\"},{\"repo_id\":\"sample-2\",\"root\":\"C:/b/sample\"}],\"failed\":[\"sample-2\"],\"cross_repo_links\":[{\"resolution\":\"candidate\",\"client_repo\":\"sample\",\"server_repo\":\"sample-2\"}]}"))
{
    var projected=ReportSectionAdapter.ReadFleet(fleet.RootElement,"synthetic","fleet-generation");
    Check(projected.Repositories.Rows.Select(r=>r.RepositoryId).SequenceEqual(new[]{"sample","sample-2"}),"fleet core IDs and source order");
    Check(projected.Links.Rows.Single().Source.GetProperty("resolution").GetString()=="candidate","fleet candidate not promoted");
    Check(projected.Failed?.GetArrayLength()==1 && projected.GenerationId=="fleet-generation","fleet failures and generation retained");
}
using var expected = JsonDocument.Parse(await File.ReadAllBytesAsync(Path.Combine(fixtures,"report-expectations.json")));
foreach (var item in expected.RootElement.GetProperty("reports").EnumerateObject())
{
    var projected = await ReportSectionAdapter.Load(Path.Combine(fixtures,item.Name));
    var sections = item.Value.GetProperty("sections");
    void Golden<T>(string key,ReportSection<T> section,Func<T,JsonElement> source)
    {
        var exp = sections.GetProperty(key);
        if (exp.GetProperty("state").GetString() == "missing") { Check(section.Availability == SectionAvailability.Missing,key+" missing"); return; }
        Check(section.SuppliedCount == exp.GetProperty("count").GetInt32(),key+" exact count");
        var rows = exp.GetProperty("rows_in_source_order").EnumerateArray().ToArray();
        Check(section.Rows.Count == rows.Length,key+" displayed count");
        for (int i=0;i<rows.Length;i++) Check(System.Text.Json.Nodes.JsonNode.DeepEquals(System.Text.Json.Nodes.JsonNode.Parse(source(section.Rows[i]).GetRawText()),System.Text.Json.Nodes.JsonNode.Parse(rows[i].GetRawText())),key+" ordered full row");
    }
    Golden("attack_paths",projected.Paths,r=>r.Evidence.Source);
    Golden("exploitability",projected.Exploitability,r=>r.Evidence.Source);
    Golden("attack_surfaces",projected.Surface,r=>r.Evidence.Source);
    Golden("scan.routes",projected.Routes,r=>r.Evidence.Source);
    Golden("scan.dependencies",projected.Dependencies,r=>r.Evidence.Source);
    Golden("scan.vulnerabilities",projected.Vulnerabilities,r=>r.Source);
    Golden("scan.workflow_issues",projected.Workflows,r=>r.Source);
    Golden("scan.taint_chains",projected.Taint,r=>r.Source);
    Golden("scan.analyzer_errors",projected.AnalyzerErrors,r=>r.Source);
    Golden("suppressed_findings",projected.Suppressed,r=>r.Evidence.Source);
}
using(var malformed = JsonDocument.Parse("{\"scan\":{\"root\":\"synthetic\",\"dependencies\":{}},\"findings\":[],\"attack_paths\":[null,{\"id\":\"kept\"}]}"))
{
    var partial = ReportSectionAdapter.Read(malformed.RootElement,"synthetic");
    Check(partial.Paths.Availability == SectionAvailability.Partial && partial.Paths.SuppliedCount == 2 && partial.Paths.Rows.Single().Evidence.SourceIndex == 1,"malformed row partial and original index");
    Check(partial.Dependencies.Availability == SectionAvailability.Malformed,"malformed section distinct");
}
using(var secrets = JsonDocument.Parse("{\"scan\":{\"root\":\"synthetic\",\"secret_hints\":[{\"name\":\"hint\",\"value\":\"DO_NOT_RENDER\",\"evidence_text\":\"DO_NOT_RENDER\"}]},\"findings\":[]}"))
    Check(!JsonSerializer.Serialize(ReportSectionAdapter.Read(secrets.RootElement,"synthetic").Secrets).Contains("DO_NOT_RENDER"),"secret payload not projected");
using(var large = JsonDocument.Parse(JsonSerializer.Serialize(new {scan=new {root="synthetic"}, findings=Array.Empty<object>(), attack_paths=Enumerable.Range(0,10001).Select(i=>new {id=i.ToString()})})))
{
    var limited = ReportSectionAdapter.Read(large.RootElement,"synthetic");
    Check(limited.Paths.Availability == SectionAvailability.Partial && limited.Paths.Rows.Count == 10000 && limited.Paths.SuppliedCount == 10001,"oversized row set bounded with count");
}
try { await ReportSectionAdapter.Load(nonempty,new string('0',64)); throw new Exception("hash change accepted"); } catch(InvalidDataException) { checks++; }
string temp = Path.Combine(Path.GetTempPath(),"attackmap-wp007-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(temp);
try
{
    string oversized=Path.Combine(temp,"oversized.json"); using(var stream=File.Create(oversized)) stream.SetLength(ReportSectionAdapter.MaxBytes+1L);
    try { await ReportSectionAdapter.Load(oversized); throw new Exception("oversized accepted"); } catch(InvalidDataException) { checks++; }
    string invalid=Path.Combine(temp,"invalid.json"); await File.WriteAllTextAsync(invalid,"{broken");
    try { await ReportSectionAdapter.Load(invalid); throw new Exception("malformed JSON accepted"); } catch(JsonException) { checks++; }
}
finally { Directory.Delete(temp,true); }
Console.WriteLine($"PASS {checks} WP007 typed section checks; no native UI/provider acceptance");
