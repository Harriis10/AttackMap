using System.Text.Json;
using AttackMap.NativeSpike;
int checks=0;
void Check(bool condition,string label){if(!condition)throw new Exception(label);checks++;}
string fixtures=Path.Combine(AppContext.BaseDirectory,"fixtures");
var model=new InventoryViewModel(await ReportSectionAdapter.Load(Path.Combine(fixtures,"report-nonempty-legacy.json"),generationId:"selected-1"));
Check(model.Groups.Count==9,"all independent inventory groups");
Check(model.Generation=="selected-1","selected generation");
var groupToSection=new Dictionary<string,string>{{"Attack surface","attack_surfaces"},{"Routes","scan.routes"},{"Dependencies","scan.dependencies"},{"CVE / vulnerabilities","scan.vulnerabilities"},{"Secrets","scan.secret_hints"},{"CI workflows","scan.workflow_issues"},{"Data flows","scan.taint_chains"},{"Analyzer errors","scan.analyzer_errors"}};
using(var expected=JsonDocument.Parse(await File.ReadAllBytesAsync(Path.Combine(fixtures,"report-expectations.json"))))
foreach(var item in expected.RootElement.GetProperty("reports").EnumerateObject())
{
    var current=new InventoryViewModel(await ReportSectionAdapter.Load(Path.Combine(fixtures,item.Name)));
    foreach(var mapping in groupToSection)
    {
        var group=current.Groups.Single(g=>g.Name==mapping.Key);var exp=item.Value.GetProperty("sections").GetProperty(mapping.Value);
        if(exp.GetProperty("state").GetString()=="missing")Check(group.Availability==SectionAvailability.Missing&&group.SuppliedCount==null,mapping.Key+" unavailable");
        else
        {
            Check(group.Items.Count==exp.GetProperty("count").GetInt32()&&group.SuppliedCount==group.Items.Count,mapping.Key+" exact count");
            Check(group.Items.Select(r=>r.SourceIndex).SequenceEqual(Enumerable.Range(0,group.Items.Count)),mapping.Key+" source order");
        }
    }
}
model.Choose("CVE / vulnerabilities");Check(model.Notice.Contains("lookup state is not supplied")&&model.Notice.Contains("Empty records do not prove"),"CVE empty not disabled/success");
model.Choose("Analyzers");Check(model.Notice.Contains("unavailable")&&model.Current.Availability==SectionAvailability.Missing,"missing analyzers unknown");
model.Choose("Dependencies");Check(model.Visible.Single().Title=="npm: express @ 4.18.0","exact dependency identity");model.Select(model.Visible.Single());
model.Filter(query:"express");Check(model.Selected!=null,"selection retained when visible");
model.Filter(severity:"high");Check(model.Visible.Count==0&&model.Selected==null&&model.Notice.Contains("No matches"),"filtered distinct and selection cleared");
model.Filter();Check(model.Visible.Count==1,"clear filters restores source");
using(var partial=JsonDocument.Parse("{\"scan\":{\"root\":\"synthetic\",\"limitations\":[\"partial fixture\"],\"resource_limit_reporting\":\"partial\",\"resource_limit_events\":[{}],\"dependencies\":[null,{\"id\":\"kept\",\"name\":\"safe\"}]},\"findings\":[]}"))
{
    var current=new InventoryViewModel(ReportSectionAdapter.Read(partial.RootElement,"synthetic"));current.Choose("Dependencies");
    Check(current.Current.Availability==SectionAvailability.Partial&&current.Current.SuppliedCount==2&&current.Visible.Single().SourceIndex==1,"partial rows keep supplied count/index");
    Check(current.Notice.Contains("partial fixture")&&current.Notice.Contains("Resource-limit reporting: partial")&&current.Notice.Contains("resource-limit events"),"global partial limitations retained");
}
using(var synthetic=JsonDocument.Parse(JsonSerializer.Serialize(new{scan=new{root="synthetic",dependencies=new[]{new{id="d2",name="second",version="2",severity="high",confidence=0.8,evidence_basis="observed",file="src/a.json",line=3},new{id="d1",name="first",version="1",severity="low",confidence=0.2,evidence_basis="inferred",file="src/b.json",line=4}},secret_hints=new[]{new{id="s",name="hint",kind="generic",file="src/config",line=2,value="DO_NOT_RENDER",evidence_text="DO_NOT_RENDER"}},workflow_issues=new object[]{new{title=new string('x',5000),severity="medium"}},analyzers=new[]{new{name="a",status="not_used"},new{name="b",status="not_applicable"}},analyzer_errors=new[]{new{analyzer="failed",reason="synthetic error"}}},findings=Array.Empty<object>()})))
{
    var current=new InventoryViewModel(ReportSectionAdapter.Read(synthetic.RootElement,"synthetic"));
    current.Choose("Dependencies");Check(current.Visible.Select(r=>r.Id).SequenceEqual(new[]{"d2","d1"}),"IDs retain core unsorted order");
    current.Filter(severity:"high",confidence:"0.8",evidence:"observed");Check(current.Visible.Single().Id=="d2"&&current.Visible.Single().File=="src/a.json","severity/confidence/evidence filters and source");
    current.Choose("Secrets");Check(!JsonSerializer.Serialize(current.Groups).Contains("DO_NOT_RENDER"),"no raw secret value or evidence anywhere in inventory model");
    Check(current.Visible.Single().File=="src/config"&&current.Visible.Single().Id=="s","safe secret source identity");
    current.Choose("Analyzers");Check(current.Visible[0].Detail.Contains("not_used")&&current.Visible[1].Detail.Contains("not_applicable"),"explicit analyzer states preserved");
    current.Choose("Analyzer errors");Check(current.Visible.Single().Detail.Contains("synthetic error"),"failed analyzer separate");
    current.Choose("CI workflows");Check(current.Visible.Single().Title.Length==5000,"long supplied text preserved");
}
Console.WriteLine($"PASS {checks} WP009 inventory checks; visual acceptance pending");
