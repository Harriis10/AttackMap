using System.Text.Json;
using AttackMap.NativeSpike;
int checks=0;void Check(bool condition,string label){if(!condition)throw new Exception(label);checks++;}
string fixtures=Path.Combine(AppContext.BaseDirectory,"fixtures");
var report=await ParityOverviewAdapter.Load(Path.Combine(fixtures,"report-nonempty-legacy.json"),generation:"g1");
Check(report.Counts.Single(c=>c.Name=="Ranked risk records").Value==4&&report.Paths.Items.Count==1,"exact core counts");
Check(report.Risks.Items.Select(r=>r.Detail.Split(';')[0]).SequenceEqual(new[]{"Core score: 100","Core score: 98","Core score: 93","Core score: 90"}),"core risk order and values");
Check(report.Actions.Availability==SectionAvailability.Missing&&report.Strengths.Availability==SectionAvailability.Missing,"no actions/strengths from legacy prose");
Check(report.Risks.Items.All(i=>i.Link==null)&&report.Paths.Items.Single().Link==null,"no invented legacy links");
var empty=await ParityOverviewAdapter.Load(Path.Combine(fixtures,"report-empty.json"));var missing=await ParityOverviewAdapter.Load(Path.Combine(fixtures,"report-missing-sections.json"));
Check(empty.Counts[0].Value==0&&empty.Counts[0].Availability==SectionAvailability.Present,"explicit empty remains zero");
Check(missing.Counts[0].Value==null&&missing.Counts[0].Availability==SectionAvailability.Missing,"unknown never zero");
var partial=await ParityOverviewAdapter.Load(Path.Combine(fixtures,"report-partial-legacy.json"));Check(partial.Coverage.Contains("partial projection")&&partial.Counts.Single(c=>c.Name=="Dependencies").Value==null,"partial scan and missing dependency count");
string temporary=Path.Combine(Path.GetTempPath(),"attackmap-wp011-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(temporary);
try
{
    string file=Path.Combine(temporary,"synthetic.json");
    await File.WriteAllTextAsync(file,JsonSerializer.Serialize(new{scan=new{root="synthetic",secret_hints=new[]{new{name="hint",value="DO_NOT_RENDER"}},resource_limit_events=new[]{new{reason="synthetic"}},resource_limit_reporting="partial"},findings=Array.Empty<object>(),attack_paths=new[]{new{id="p1",name="explicit path",impact="synthetic"}},exploitability=new[]{new{id="risk1",subject="first",score=1,finding_id="f1"},new{id="risk2",subject="second",score=99,finding_id="f2"}},defensive_review_json=new{recommendations=new object[]{new{id="a2",action=new string('x',5000),priority="high",finding_id="f1",secret_value="DO_NOT_RENDER"},new{id="a1",action="second action",priority="low",path_id="p1"}},strengths=new[]{new{statement="supplied strength",evidence_basis="observed",confidence=0.8,evidence_text="DO_NOT_RENDER"}}}}));
    var overview=await ParityOverviewAdapter.Load(file,generation:"g1");
    Check(overview.Risks.Items.Select(r=>r.Id).SequenceEqual(new[]{"risk1","risk2"}),"does not rescore lower score first");
    Check(overview.Actions.Items.Select(r=>r.Id).SequenceEqual(new[]{"a2","a1"})&&overview.Actions.Items[0].Title.Length==5000,"action core order and long text");
    Check(overview.Strengths.Items.Single().Title=="supplied strength"&&overview.Strengths.Items.Single().Detail.Contains("0.8"),"supplied strength");
    Check(!JsonSerializer.Serialize(overview).Contains("DO_NOT_RENDER"),"safe secret constraint");
    var link=overview.Actions.Items[0].Link!;Check(link.Kind=="finding"&&link.Identity=="f1"&&overview.Allows(link,"g1",overview.ReadHash),"explicit generation-bound finding link");
    Check(!overview.Allows(link,"g2",overview.ReadHash)&&!overview.Allows(link,"g1","changed")&&!overview.Allows(link with{Generation="stale"},"g1",overview.ReadHash),"stale generation/hash links rejected");
    Check(!overview.Allows(link with{Identity="invented"},"g1",overview.ReadHash),"unissued identity rejected");
    Check(overview.Coverage.Contains("PARTIAL")&&overview.Coverage.Contains("Resource-limit reporting: partial"),"resource partial coverage");
    try{await ParityOverviewAdapter.Load(file,new string('0',64));throw new Exception("hash change accepted");}catch(InvalidDataException){checks++;}
    await File.WriteAllTextAsync(file,"{\"scan\":{\"root\":\"synthetic\"},\"findings\":[],\"defensive_review_json\":{\"recommendations\":{},\"strengths\":[null,{\"statement\":\"retained\"}]}} ");
    var malformed=await ParityOverviewAdapter.Load(file);Check(malformed.Actions.Availability==SectionAvailability.Malformed&&malformed.Strengths.Availability==SectionAvailability.Partial&&malformed.Strengths.Items.Single().SourceIndex==1,"malformed sections partial original index");
    await File.WriteAllTextAsync(file,"{\"scan\":{\"root\":\"synthetic\"},\"findings\":[],\"defensive_review_json\":null}");
    Check((await ParityOverviewAdapter.Load(file)).Actions.Availability==SectionAvailability.Malformed,"malformed structured review distinct from missing");
}
finally{Directory.Delete(temporary,true);}
Console.WriteLine($"PASS {checks} bounded WP011 overview checks; shell/visual/keyboard acceptance pending");
