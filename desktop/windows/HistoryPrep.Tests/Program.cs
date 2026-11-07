using System.Text.Json;using AttackMap.NativeSpike.HistoryPrep;
int checks=0;void Check(bool condition,string label){if(!condition)throw new Exception(label);checks++;}
string hash1=new('a',64),hash2=new('b',64),hash3=new('c',64),hash4=new('d',64);
var repoA=new RecentRepository("repo-a","C:/synthetic/žluťoučký/sample","sample","g3",hash3);var repoB=new RecentRepository("repo-b","C:/synthetic/team-b/sample","sample","g1",hash1);
var raw=JsonSerializer.Serialize(new{SchemaVersion=1,Repositories=new[]{repoA,repoB},FutureMetadata=new{preserve="yes"}});var loaded=RecentRepositoriesCodec.Decode(raw);
Check(loaded.Supported&&loaded.Document!.Repositories.Count==2&&loaded.Document.Repositories.Select(r=>r.RepositoryId).SequenceEqual(new[]{"repo-a","repo-b"}),"same basename identities/order");
Check(RecentRepositoriesCodec.Encode(loaded,loaded.Document!.Repositories).Contains("FutureMetadata")&&loaded.Document.Repositories[0].Root.Contains("žluťoučký"),"Unicode paths/unknown metadata preserved");
foreach(string corrupt in new[]{"{broken","{\"SchemaVersion\":99,\"Repositories\":[]}","{\"SchemaVersion\":1,\"SchemaVersion\":1,\"Repositories\":[]}","{\"SchemaVersion\":1,\"Repositories\":[null]}"})
{var failed=RecentRepositoriesCodec.Decode(corrupt);Check(!failed.Supported&&failed.OriginalRaw==corrupt,"corrupt/unknown original retained");try{RecentRepositoriesCodec.Encode(failed,Array.Empty<RecentRepository>());throw new Exception("overwrote failed input");}catch(InvalidDataException){checks++;}}
HistoryArtifact Artifact(string id,string hash,string repo="repo-a")=>new(repo,id,hash,$"C:/synthetic/reports/{repo}/{id}/attackmap-report.json");
var g1=new RetainedGeneration(Artifact("g1",hash1),true,false,"completed","passed");var g2=new RetainedGeneration(Artifact("g2",hash2),false,false,"completed","passed");var g3=new RetainedGeneration(Artifact("g3",hash3),false,true,"completed","failed");
var model=new HistoryComparisonModel();model.SelectRepository(repoA,true);Check(model.Status.Contains("no scan started"),"select recent does not scan");model.SetGenerations(new[]{g3,g1,g2});
Check(model.Generations.Select(g=>g.Artifact.GenerationId).SequenceEqual(new[]{"g3","g1","g2"}),"source order not inferred chronology");
model.SelectGeneration(g3.Artifact);Check(model.Status.Contains("Completed analysis; policy failed")&&model.BeginLoad()!=null,"policy failure completed analysis");
Check(model.SetNextRun(NextBaselineMode.Previous,true)&&model.NextRun!.Baseline==g3.Artifact&&model.NextRun.FailOnNewHigh,"previous next-run captures exact supplied current generation");
var g4=new RetainedGeneration(Artifact("g4",hash4),false,true,"completed","passed");model.SetGenerations(new[]{g4,g3 with{IsCurrent=false},g2,g1});
Check(model.NextRun!.Baseline==g3.Artifact,"captured previous baseline survives new current without pointer drift");
Check(model.RetentionCandidates().All(a=>a!=g1.Artifact&&a!=g4.Artifact&&a!=g3.Artifact),"pin/current/baseline excluded from retention proposals");
Check(model.SetNextRun(NextBaselineMode.Custom,false,g2.Artifact)&&model.NextRun!.Baseline==g2.Artifact,"custom exact baseline");
Check(model.SetNextRun(NextBaselineMode.None,true)&&model.NextRun!.Baseline==null&&model.NextRun.FailOnNewHigh,"none baseline and explicit policy intent");
model.SelectGeneration(g2.Artifact);var ticket=model.BeginLoad()!;Check(model.AcceptLoad(ticket,hash2)&&!model.AcceptLoad(ticket,hash3),"delayed load hash validation");
var compare=model.Compare(g1.Artifact)!;
using(var expected=JsonDocument.Parse(await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory,"fixtures/expected.json"))))
{
    var ids=expected.RootElement.GetProperty("finding_ids");
    var categories=expected.RootElement.GetProperty("complete_diff").EnumerateObject().Select(p=>new CoreDiffCategory(p.Name,p.Value.GetArrayLength(),p.Value.EnumerateArray().Select(k=>ids.GetProperty(k.GetString()!).GetString()!).ToArray())).ToArray();
    Check(model.AcceptComparison(compare,categories),"accept exact core fixture categories");
    Check(model.Comparison.Select(c=>c.Name).SequenceEqual(categories.Select(c=>c.Name))&&model.Comparison[1].FindingIds.SequenceEqual(categories[1].FindingIds),"title/line drift diff identities/order retained without recomputation");
}
var earlier=model.Compare(g1.Artifact)!;var later=model.Compare(g3.Artifact)!;
Check(!model.AcceptComparison(earlier,Array.Empty<CoreDiffCategory>())&&model.AcceptComparison(later,new[]{new CoreDiffCategory("unknown_future_category",null,new[]{"explicit-id"})}),"later same-selection compare rejects older baseline result");
Check(model.Comparison.Single().SuppliedCount==null&&model.Comparison.Single().Name=="unknown_future_category","unknown source category/count preserved without zero/defaulting");
Check(!model.AcceptComparison(later,new[]{new CoreDiffCategory("malformed",-1,Array.Empty<string>())}),"malformed negative source count rejected");
var customTicket=model.BeginCustomSelection()!;var pin=model.Pin(true)!;model.SelectRepository(repoB,false);Check(!model.AcceptLoad(ticket,hash2)&&!model.AcceptComparison(compare,Array.Empty<CoreDiffCategory>())&&!model.IsCurrent(pin)&&!model.AcceptCustomSelection(customTicket,g1.Artifact),"repo switch rejects stale load/compare/pin/custom callbacks");
Check(model.Status.Contains("unavailable")&&model.Status.Contains("Recover"),"missing repo recoverable");
model.SetGenerations(new[]{new RetainedGeneration(Artifact("g1",hash1,"repo-b"),false,true,"completed","passed")});model.SelectGeneration(Artifact("g1",hash1,"repo-b"));Check(model.BeginLoad()!=null,"retained report remains selectable when repo missing");
try{model.SetGenerations(new[]{g1,g1});throw new Exception("duplicate generation accepted");}catch(InvalidDataException){checks++;}
string ownedTempBase=Path.GetFullPath(Path.GetTempPath());
string ownedHistory=Path.GetFullPath(Path.Combine(ownedTempBase,"attackmap-recent-tests-"+Guid.NewGuid().ToString("N")));
Directory.CreateDirectory(ownedHistory);
try
{
    string storePath=Path.Combine(ownedHistory,"recent.json");var store=new RecentRepositoriesStore(storePath);
    Check(store.Load().Count==0&&!File.Exists(storePath),"empty history load does not create a file");
    store.Remember(repoA.Root,"g3",hash3);store.Remember(repoB.Root,"g1",hash1);store.Remember(repoA.Root);
    Check(store.Load().Count==2&&store.Load()[0].Root==Path.TrimEndingDirectorySeparator(Path.GetFullPath(repoA.Root))&&store.Load()[0].LastGenerationId=="g3","store deduplicates recent selection and retains last generation");
    using(var doc=JsonDocument.Parse(File.ReadAllText(storePath)))
    {var expanded=System.Text.Json.Nodes.JsonNode.Parse(doc.RootElement.GetRawText())!.AsObject();expanded["FutureMetadata"]="retain";File.WriteAllText(storePath,expanded.ToJsonString());}
    store.Remember(repoB.Root);Check(File.ReadAllText(storePath).Contains("FutureMetadata"),"store preserves unknown future metadata");
    string corrupt="{\"SchemaVersion\":99,\"Repositories\":[]}";File.WriteAllText(storePath,corrupt);
    try{store.Remember(repoA.Root);throw new Exception("unknown saved history replaced");}catch(InvalidDataException){Check(File.ReadAllText(storePath)==corrupt,"unknown history original preserved on save");}
}
finally
{
    if(!ownedHistory.StartsWith(Path.TrimEndingDirectorySeparator(ownedTempBase)+Path.DirectorySeparatorChar,OperatingSystem.IsWindows()?StringComparison.OrdinalIgnoreCase:StringComparison.Ordinal)||!Path.GetFileName(ownedHistory).StartsWith("attackmap-recent-tests-",StringComparison.Ordinal))throw new InvalidDataException("Owned history cleanup escaped its temporary base.");
    Directory.Delete(ownedHistory,recursive:true);
}
Console.WriteLine($"PASS {checks} bounded WP013 history checks; owned temporary history files only; no scans, report/pin writes or retention deletes");
