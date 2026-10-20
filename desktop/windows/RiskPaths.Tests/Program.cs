using System.Text.Json;
using AttackMap.NativeSpike;
int checks=0;
void Check(bool condition,string label){if(!condition)throw new Exception(label);checks++;}
string fixtures=Path.Combine(AppContext.BaseDirectory,"fixtures");
var report=await ReportSectionAdapter.Load(Path.Combine(fixtures,"report-nonempty-legacy.json"),generationId:"selected-generation-1");
var model=new RiskPathsViewModel(report);
Check(model.All.Count==5,"all ranked scores and paths projected");
Check(model.All.Take(4).Select(r=>r.Score).SequenceEqual(new double?[]{100,98,93,90}),"supplied score order preserved");
Check(model.All.Last().Detail.Contains("POST /api/Feedbacks")&&model.All.Last().Detail.Contains("Data integrity"),"path chain and impact inspectable");
Check(model.All.All(r=>r.Classification=="unknown"&&r.Confidence=="unknown"),"legacy missing classification unknown");
Check(model.All.All(r=>r.FindingIds.Count==0&&r.Sources.Count==0),"no inferred finding/source links from title/route/location text");
Check(model.Generation=="selected-generation-1","selected generation retained");
model.Filter(route:"/rest/chat");Check(model.Visible.Count==1&&model.Visible.Single().Score==98,"route filter preserves engine score");
model.Select(model.Visible.Single());Check(model.Selected!=null,"selection");
model.Filter(sink:"sql_execute");Check(model.Visible.Single().Score==93&&model.Selected==null,"sink filter and selection clearing");
model.Filter(confidence:"high");Check(model.Visible.Count==0&&model.Notice.Contains("No rows match"),"filtered distinct from empty");
model.Filter();Check(model.Visible.Count==5,"clear filters restores all");
var empty=new RiskPathsViewModel(await ReportSectionAdapter.Load(Path.Combine(fixtures,"report-empty.json")));
Check(empty.Notice.Contains("contain no displayable")&&!empty.Notice.Contains("requested section is unavailable"),"empty explicit");
var missing=new RiskPathsViewModel(await ReportSectionAdapter.Load(Path.Combine(fixtures,"report-missing-sections.json")));
Check(missing.Notice.Contains("unavailable")&&missing.Generation.Contains("unknown"),"missing legacy distinct");
using(var supplied=JsonDocument.Parse("{\"scan\":{\"root\":\"synthetic\"},\"findings\":[],\"exploitability\":[{\"id\":\"x\",\"subject\":\"candidate row\",\"evidence_class\":\"candidate\",\"confidence\":0.6,\"score\":7,\"file\":\"src/a.ts\",\"line\":2,\"finding_ids\":[\"f1\"],\"factors\":[{\"name\":\"core factor\",\"points\":7}]}],\"attack_paths\":[{\"name\":\"observed static\",\"classification\":\"observed\"},{\"name\":\"speculative path\",\"classification\":\"speculative\",\"steps\":[]}]}"))
{
    var suppliedModel=new RiskPathsViewModel(ReportSectionAdapter.Read(supplied.RootElement,"synthetic"));
    suppliedModel.Filter(classification:"candidate");var row=suppliedModel.Visible.Single();
    Check(row.Score==7&&row.Confidence=="0.6"&&row.Detail.Contains("core factor"),"candidate labels/confidence/factors preserved");
    Check(row.Sources.Single()==new RiskSourceLink("src/a.ts",2)&&row.FindingIds.Single()=="f1","only explicit structured links");
    suppliedModel.Filter(classification:"speculative");Check(suppliedModel.Visible.Single().Title=="speculative path","speculative separate filter");
    suppliedModel.Filter(classification:"observed");Check(suppliedModel.Visible.Single().Title=="observed static"&&suppliedModel.Notice.Contains("do not establish runtime"),"observed static not runtime proof");
}
Console.WriteLine($"PASS {checks} WP008 risk/path model checks; native preview/keyboard acceptance separate");
