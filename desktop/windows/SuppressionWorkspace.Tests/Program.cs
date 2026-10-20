using System.Text.Json;using AttackMap.NativeSpike;
int checks=0;void Check(bool condition,string label){if(!condition)throw new Exception(label);checks++;}
string fixtures=Path.Combine(AppContext.BaseDirectory,"fixtures");var report=await ReportSectionAdapter.Load(Path.Combine(fixtures,"report-nonempty-legacy.json"),generationId:"g1");
var model=new SuppressionWorkspaceModel(report);string hashA=new('a',64),hashB=new('b',64);
Check(model.Rows.Single().Id=="s1"&&model.Rows.Single().Reason=="accepted in tests"&&model.Rows.Single().Origin=="unknown"&&model.Rows.Single().Expiry=="unknown","exact suppressed identity/reason/unknown");
Check(model.SuppliedCount==1&&model.Rows.Single().SourceIndex==0,"source count/order");
Check(!model.CanApply&&!model.CanPreview,"no unverified apply");
model.NoSuppress=true;long ticket=model.BeginBaselineSelection();Check(model.CompleteBaselineSelection(ticket,"C:/synthetic/baseline.yaml",hashA),"explicit local baseline");
Check(model.NoSuppress&&model.Baseline?.Sha256==hashA,"no suppress independent of baseline");
Check(!model.CanPreview,"suppressed title/ID never auto-selects action finding");
model.SetFinding("explicit-finding-id");var preview=model.Request("suppression_preview")!;Check(model.Busy&&model.Request("suppression_preview")==null,"busy prevents duplicate dispatch");
Check(!model.AcceptPreview(preview,preview.Baseline with{Sha256=hashB},"wrong-baseline",true)&&!model.CanApply,"preview result baseline hash mismatch rejected");
Check(!model.AcceptPreview(preview,preview.Baseline with{Path="C:/synthetic/other.yaml"},"wrong-path",true)&&!model.CanApply,"preview result baseline path mismatch rejected");
Check(model.AcceptPreview(preview,preview.Baseline,"opaque-preview",true)&&model.CanApply,"exact preview enables apply");
var apply=model.Request("suppression_apply")!;Check(apply.FindingId=="explicit-finding-id"&&apply.Baseline.Path.EndsWith("baseline.yaml")&&apply.NoSuppress,"intent carries exact baseline/finding/context only");
Check(model.AcceptApplied(apply,"opaque-receipt",hashB)&&model.CanUndo&&!model.CanApply&&model.Rows.Single().Id=="s1","host apply receipt enables undo without recalculation");
var undo=model.Request("suppression_undo")!;Check(model.AcceptUndone(undo)&&!model.CanApply&&!model.CanPreview&&model.Baseline?.Sha256==null,"undo requires refreshed hash, report unchanged");
long oldTicket=model.BeginBaselineSelection();long newTicket=model.BeginBaselineSelection();Check(!model.CompleteBaselineSelection(oldTicket,"C:/synthetic/old.yaml",hashA)&&model.CompleteBaselineSelection(newTicket,"C:/synthetic/current.yaml",hashA),"stale async baseline selection rejected");
model.SetFinding("id");var first=model.Request("suppression_preview")!;model.AcceptPreview(first,first.Baseline,"first",true);var second=model.Request("suppression_preview")!;Check(!model.AcceptPreview(first,first.Baseline,"old-result",true)&&model.AcceptPreview(second,second.Baseline,"second",true),"stale same-context action response rejected");
long changed=model.BeginBaselineSelection();model.CompleteBaselineSelection(changed,"C:/synthetic/current.yaml",hashB);Check(!model.CanApply&&!model.AcceptPreview(second,second.Baseline,"old-hash",true),"baseline hash change requires new preview");
var refreshed=model.Request("suppression_preview")!;model.AcceptPreview(refreshed,refreshed.Baseline,"refreshed",true);
var staleApply=model.Request("suppression_apply")!;model.ClearBaseline();Check(!model.AcceptApplied(staleApply,"stale",hashB)&&model.NoSuppress,"baseline clear blocks old apply result and preserves no-suppress");
foreach(string unsafePath in new[]{"relative.yaml","C:/synthetic/../escape.yaml","https://name:secret@example.test/file","//server/share/base.yaml","C:/synthetic/base.yaml:stream","C:/synthetic/\nbase.yaml","C:/synthetic/CON.yaml","C:/synthetic/base.yaml "})
{long t=model.BeginBaselineSelection();Check(!model.CompleteBaselineSelection(t,unsafePath,hashA),"unsafe path rejected");}
long missing=model.BeginBaselineSelection();Check(model.CompleteBaselineSelection(missing,"C:/synthetic/missing.yaml",null)&&!model.CanPreview,"missing baseline blocks preview");
long current=model.BeginBaselineSelection();model.CompleteBaselineSelection(current,"C:/synthetic/current.yaml",hashA);model.SetFinding("id");var prior=model.Request("suppression_preview")!;model.SetReport(report with{GenerationId="g2"});Check(!model.AcceptPreview(prior,prior.Baseline,"stale-gen",true)&&model.Baseline==null,"generation switch invalidates baseline/async result");
var empty=new SuppressionWorkspaceModel(await ReportSectionAdapter.Load(Path.Combine(fixtures,"report-empty.json")));var absent=new SuppressionWorkspaceModel(await ReportSectionAdapter.Load(Path.Combine(fixtures,"report-missing-sections.json")));Check(empty.SuppliedCount==0&&absent.SuppliedCount==null&&absent.Availability==SectionAvailability.Missing,"empty vs missing");
using(var malformed=JsonDocument.Parse("{\"scan\":{\"root\":\"synthetic\"},\"findings\":[],\"suppressed_findings\":{}}"))
Check(new SuppressionWorkspaceModel(ReportSectionAdapter.Read(malformed.RootElement,hashA,"g1")).Availability==SectionAvailability.Malformed,"malformed section explicit");
using(var document=JsonDocument.Parse(JsonSerializer.Serialize(new{scan=new{root="synthetic"},findings=Array.Empty<object>(),suppressed_findings=new object?[]{null,new{id="z",title=new string('x',5000),reason="source reason",origin="explicit baseline",expires="2030-01-01",secret_value="DO_NOT_RENDER",evidence_text="DO_NOT_RENDER"},new{id="a",title="same",reason="other"}}})))
{
    var supplied=new SuppressionWorkspaceModel(ReportSectionAdapter.Read(document.RootElement,hashA,"g1"));
    Check(supplied.Availability==SectionAvailability.Partial&&supplied.SuppliedCount==3&&supplied.Rows.Select(r=>r.Id).SequenceEqual(new[]{"z","a"})&&supplied.Rows[0].SourceIndex==1,"partial malformed row keeps original order/index/count");
    Check(supplied.Rows[0].Title.Length==5000&&supplied.Rows[0].Origin=="explicit baseline"&&supplied.Rows[0].Expiry=="2030-01-01","long text/origin/expiry supplied");
    Check(!JsonSerializer.Serialize(supplied.Rows).Contains("DO_NOT_RENDER"),"raw secret/evidence excluded");
    Check(!supplied.CanPreview,"titles never become action identity");
}
Console.WriteLine($"PASS {checks} bounded WP012 suppression checks; no baseline writes or real apply/undo/rescan performed");
