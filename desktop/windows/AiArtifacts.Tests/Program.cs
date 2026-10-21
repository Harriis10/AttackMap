using System.Text;
using System.Text.Json;
using AttackMap.NativeSpike;

int checks = 0;
void Check(bool test, string reason) { if (!test) throw new Exception(reason); checks++; }
const string complete = "{\"backend\":\"api\",\"model\":\"local\",\"usage_status\":\"unknown\",\"reference_validation\":{\"reference_validity\":\"valid\",\"claim_support\":\"not_assessed\"}}";
foreach (string mode in AiArtifactProjection.Modes)
{
    string run = JsonSerializer.Serialize(new { desktop_ai = new { mode, status = "completed", model_output_available = true } });
    var page = AiArtifactProjection.Project(mode, "<script>inert</script>", complete, run);
    Check(page.State == "completed", mode + " state");
    Check(page.Markdown == "<script>inert</script>", "inert text preserved");
    Check(page.Notice.Contains("Usage status: unknown"), "unknown usage");
    Check(page.Notice.Contains("Claim support: \"not_assessed\""), "support separate");
    Check(AiArtifactProjection.Project(mode, "text", complete).State.Contains("completion unknown"), "absence cannot prove complete");
}
Check(AiArtifactProjection.Project("triage", "fallback", "{\"backend\":\"deterministic\"}").State.Contains("no completed model"), "fallback");
Check(AiArtifactProjection.Project("hunt_verify", "text", "{\"backend\":\"api\",\"model\":\"local\",\"abstained_votes\":2,\"failed_passes\":1}").State == "partial", "abstentions");
Check(AiArtifactProjection.Project("review", "", complete).State == "unavailable", "empty output");
Check(AiArtifactProjection.Project("review", "text", "{}").State == "unavailable", "missing metadata");
foreach (string malformed in new[] { "[]", "{", "{\"failed_passes\":-1}" })
{
    bool failed = false; try { AiArtifactProjection.Project("review", "text", malformed); } catch (Exception e) when (e is JsonException or InvalidDataException) { failed = true; }
    Check(failed, "malformed rejected");
}
var workspace = new AiArtifactWorkspace();
Check((await workspace.Load())!.Pages.All(p => p.Markdown == "" && p.State == "unavailable"), "legacy does not read adjacent files");
string folder = Path.Combine(Path.GetTempPath(), "attackmap-wp016-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(folder);
try
{
    string report = Path.Combine(folder, "attackmap-report.json"), manifest = Path.Combine(folder, "artifact-manifest.json");
    File.WriteAllText(report, "{}", new UTF8Encoding(false));
    var contents = new Dictionary<string,string> { ["attackmap-report.json"] = "{}", ["defensive-review-llm.md"] = "saved review", ["defensive-review-llm.meta.json"] = complete, ["run-manifest.json"] = "{\"desktop_ai\":{\"mode\":\"review\",\"status\":\"completed\",\"model_output_available\":true}}" };
    foreach (var pair in contents) File.WriteAllText(Path.Combine(folder,pair.Key),pair.Value,new UTF8Encoding(false));
    var sections = contents.Select(pair => new { name = pair.Key, path = pair.Key, role = "analysis", format = Path.GetExtension(pair.Key)[1..], checksum = ExportSelection.Hash(File.ReadAllBytes(Path.Combine(folder,pair.Key))) }).ToArray();
    File.WriteAllText(manifest, JsonSerializer.Serialize(new { schema_version="1.0.0", artifact_type="attackmap_artifact_manifest", generation_id="run-a", sections, compatibility_exports=Array.Empty<object>() }),new UTF8Encoding(false));
    var selected = new ExportSelection(report,ExportSelection.Hash(File.ReadAllBytes(report)),"run-a",manifest,ExportSelection.Hash(File.ReadAllBytes(manifest)),null,null);
    workspace.Select(selected); var snapshot = await workspace.Load();
    Check(snapshot!.Generation == "run-a", "generation bound");
    Check(snapshot.Pages[0].Markdown == "saved review", "verified bytes read");
    Check(snapshot.Pages.Skip(1).All(p=>p.State=="unavailable"),"missing modes explicit");
    workspace.Select(selected); Task<AiArtifactSnapshot?> delayed=workspace.Load(); workspace.Cancel();
    Check(await delayed == null,"late response discarded");
    var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var capturedRecords = SelectedArtifacts.List(selected); int listCalls=0;
    var closing = new AiArtifactWorkspace(async value => { Interlocked.Increment(ref listCalls); started.SetResult(); await release.Task; return capturedRecords; });
    closing.Select(selected); Task<AiArtifactSnapshot?> closingRead=closing.Load(); await started.Task; closing.Stop();
    // Break metadata before releasing the delayed listing: a post-stop read would throw.
    string metadataPath=Path.Combine(folder,"defensive-review-llm.meta.json"); File.WriteAllText(metadataPath,"changed after close");
    release.SetResult();
    Check(await closingRead == null,"close invalidates pending read");
    Check(listCalls==1,"stop prevents follow-up artifact reads and final revalidation");
    File.WriteAllText(metadataPath,complete,new UTF8Encoding(false));
    Check(closing.IsStopped,"stop is terminal");
    closing.Select(selected); Check(await closing.Load() == null,"selection cannot restart closed workspace");
    closing.Cancel(); closing.Stop(); Check(await closing.Load() == null,"repeated stop and cancel remain terminal");
    // After stop, even a broken selection must not start I/O or surface an error.
    closing.Select(selected with { ReportPath=Path.Combine(folder,"missing.json") });
    Check(await closing.Load() == null,"closed workspace performs no subsequent artifact reads");
    File.WriteAllText(Path.Combine(folder,"defensive-review-llm.md"),"tampered");
    workspace.Select(selected); bool rejected=false; try { await workspace.Load(); } catch(InvalidDataException) { rejected=true; }
    Check(rejected,"tampered output rejected");
    File.WriteAllText(report,"changed"); rejected=false; try { await workspace.Load(); } catch(InvalidDataException) { rejected=true; }
    Check(rejected,"tampered report rejected");
}
finally { Directory.Delete(folder,true); }
Console.WriteLine($"PASS {checks} AI artifact projection and captured-generation checks; fixture only; no provider or GUI.");

