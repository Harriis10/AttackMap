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
    Check(page.Summary.Contains("Usage: unknown") && page.Summary.Contains("output tokens: unknown") && !page.Summary.Contains("output tokens: 0"), "compact unknown usage never zero");
    Check(page.Summary.Contains("Reference validity: valid; Claim support: not assessed") && page.Summary.Contains("valid references do not confirm claims"), "compact reference validity never claim support");
    Check(AiArtifactProjection.Project(mode, "text", complete).State.Contains("completion unknown"), "absence cannot prove complete");
}
Check(AiArtifactProjection.Project("triage", "fallback", "{\"backend\":\"deterministic\"}").State.Contains("no completed model"), "fallback");
Check(AiArtifactProjection.Project("hunt_verify", "text", "{\"backend\":\"api\",\"model\":\"local\",\"abstained_votes\":2,\"failed_passes\":1}").State == "partial", "abstentions");
var abstentions = AiArtifactProjection.Project("hunt_verify", "text", "{\"backend\":\"api\",\"model\":\"local\",\"abstained_votes\":2,\"failed_passes\":1}");
Check(abstentions.Summary.Contains("hunt_verify · partial") && abstentions.Summary.Contains("Jury abstentions: 2; failed passes: 1"), "compact jury warnings stay visible");
var fallback = AiArtifactProjection.Project("triage", "fallback", "{\"backend\":\"deterministic\"}");
Check(fallback.Summary.Contains("deterministic fallback; no completed model response"), "compact fallback does not imply a completed model");
string largeRun = JsonSerializer.Serialize(new { desktop_ai = new { mode="review", status="completed", model_output_available=true, service_parameters = new { provider = new { provider="openai", model="local", extra="bulky_configuration_marker"+new string('x',10000) } } } });
var compact = AiArtifactProjection.Project("review", "unchanged narrative", complete, largeRun);
Check(compact.Summary.Contains("Provider: openai (api); model: local") && compact.Summary.Length < 700 && !compact.Summary.Contains("bulky_configuration_marker"), "large supplied configuration stays outside compact summary");
Check(compact.Notice.Contains("bulky_configuration_marker") && compact.Metadata == complete && compact.Markdown == "unchanged narrative", "complete technical detail and artifact bytes preserved");
var reported = AiArtifactProjection.Project("review", "text", "{\"backend\":\"api\",\"model\":\"local\",\"usage_status\":\"reported\",\"usage\":{\"input_tokens\":0,\"output_tokens\":12}}");
Check(reported.Summary.Contains("input tokens: 0; output tokens: 12"), "reported zero distinct from unknown usage");
const string scopedAccounting = """
    {"backend":"api","model":"local","usage":{"input_tokens":506556,"output_tokens":5955},
     "allowance":{"token_allowance_kind":"output_tokens","usage_status":"reported","unknown_output_usage_calls":0},
     "citation_context":{"reference_validity":"mechanically_checked","claim_support":"not_assessed"},
     "failed_passes":0,"abstained_votes":1}
    """;
var scoped = AiArtifactProjection.Project("hunt_verify", "saved narrative", scopedAccounting);
Check(scoped.State == "partial" && scoped.Summary.Contains("Jury abstentions: 1; failed passes: 0"), "accounting does not erase abstention partial state");
Check(scoped.Summary.Contains("Usage: unknown (artifact metadata); input tokens: 506556; output tokens: 5955"), "numeric aggregate counts do not manufacture artifact usage status");
Check(scoped.Summary.Contains("Shared output accounting (artifact allowance): reported; unknown output-usage calls: 0"), "shared output settlement has its own scope");
Check(scoped.Summary.Contains("Reference validity: unknown; Claim support: not assessed") && scoped.Summary.Contains("Captured citation context: mechanically checked (context only)"), "checked context never promoted to output validity or claim support");
Check(scoped.Notice.Contains("does not establish input or per-call usage") && scoped.Notice.Contains("does not validate references in this output"), "technical notice explains independent metadata scopes");
Check(scoped.Metadata == scopedAccounting && scoped.Markdown == "saved narrative", "scope presentation leaves artifact bytes unchanged");
string runAccounting = """
    {"desktop_ai":{"mode":"hunt_verify","status":"completed","model_output_available":true,
      "allowance":{"token_allowance_kind":"output_tokens","usage_status":"partial_or_unknown","unknown_output_usage_calls":1}}}
    """;
var selectedAccounting = AiArtifactProjection.Project("hunt_verify", "text", scopedAccounting, runAccounting);
Check(selectedAccounting.State == "partial" && selectedAccounting.Summary.Contains("Shared output accounting (run allowance): partial_or_unknown; unknown output-usage calls: 1"), "matching run allowance projected without promoting completion");
Check(!selectedAccounting.Summary.Contains("artifact allowance"), "shared accounting identifies which supplied snapshot is displayed");
var otherModeAccounting = AiArtifactProjection.Project("hunt", "text", scopedAccounting, runAccounting);
Check(otherModeAccounting.Summary.Contains("artifact allowance") && !otherModeAccounting.Summary.Contains("run allowance"), "different requested mode cannot replace artifact allowance");
var absentRunAllowance = AiArtifactProjection.Project("hunt_verify", "text", scopedAccounting, "{\"desktop_ai\":{\"mode\":\"hunt_verify\",\"status\":\"partial\"}}");
Check(absentRunAllowance.Summary.Contains("artifact allowance"), "missing run allowance preserves explicitly supplied artifact snapshot");
var unknownAllowanceScope = AiArtifactProjection.Project("review", "text", "{\"backend\":\"api\",\"model\":\"local\",\"allowance\":{\"usage_status\":\"reported\"}}");
Check(unknownAllowanceScope.Summary.Contains("Allowance usage (artifact allowance): reported; scope: unknown") && !unknownAllowanceScope.Summary.Contains("Shared output accounting"), "allowance status alone cannot establish output scope");
foreach (string invalidCount in new[] { "null", "-1", "1.5", "\"0\"", "true" })
{
    var unknownCounter = AiArtifactProjection.Project("review", "text", "{\"backend\":\"api\",\"model\":\"local\",\"allowance\":{\"token_allowance_kind\":\"output_tokens\",\"unknown_output_usage_calls\":" + invalidCount + "}}");
    Check(unknownCounter.Summary.Contains("unknown output-usage calls: unknown"), "invalid unknown-usage counter is never fabricated as zero");
}
var invalidOutputReferences = AiArtifactProjection.Project("review", "text", """
    {"backend":"api","model":"local","reference_validation":{"reference_validity":"invalid","scope":"selected_prompt_producer_evidence_ids","claim_support":"not_assessed"},
     "citation_context":{"reference_validity":"mechanically_checked","claim_support":"supported_by_cited_evidence"}}
    """);
Check(invalidOutputReferences.Summary.Contains("Reference validity: invalid; Claim support: not assessed"), "context claims do not replace output reference validation");
Check(invalidOutputReferences.Summary.Contains("Reference check scope: selected prompt producer evidence ids"), "producer evidence ID scope visible separately from source validity");
Check(!invalidOutputReferences.Summary.Contains("supported by cited evidence"), "context-level support cannot manufacture output claim support");
Check(AiArtifactProjection.Unavailable("review", "No supplied output").Summary.Contains("unavailable"), "compact unavailable remains explicit");
Check(AiArtifactProjection.Project("review", "", complete).State == "unavailable", "empty output");
Check(AiArtifactProjection.Project("review", "text", "{}").State == "unavailable", "missing metadata");
foreach (string malformed in new[] { "[]", "{", "{\"failed_passes\":-1}" })
{
    bool failed = false; try { AiArtifactProjection.Project("review", "text", malformed); } catch (Exception e) when (e is JsonException or InvalidDataException) { failed = true; }
    Check(failed, "malformed rejected");
}
var artifactReads = new Dictionary<string, int>(StringComparer.Ordinal);
var workspace = new AiArtifactWorkspace(
    value => Task.Run(() => SelectedArtifacts.List(value)),
    (value, record, limit) =>
    {
        string name = Path.GetFileName(record.FullPath);
        artifactReads[name] = artifactReads.GetValueOrDefault(name) + 1;
        return SelectedArtifacts.ReadText(value, record, limit);
    });
Check((await workspace.Load("review"))!.Pages.Single() is { Markdown: "", State: "unavailable" }, "legacy does not read adjacent files");
string folder = Path.Combine(Path.GetTempPath(), "attackmap-wp016-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(folder);
try
{
    string report = Path.Combine(folder, "attackmap-report.json"), manifest = Path.Combine(folder, "artifact-manifest.json");
    File.WriteAllText(report, "{}", new UTF8Encoding(false));
    var contents = new Dictionary<string,string> {
        ["attackmap-report.json"] = "{}",
        ["defensive-review-llm.md"] = "saved review",
        ["defensive-review-llm.meta.json"] = complete,
        ["vulnerability-hypotheses.md"] = "saved hunt",
        ["vulnerability-hypotheses.meta.json"] = "{",
        ["run-manifest.json"] = "{\"desktop_ai\":{\"mode\":\"review\",\"status\":\"completed\",\"model_output_available\":true}}"
    };
    foreach (var pair in contents) File.WriteAllText(Path.Combine(folder,pair.Key),pair.Value,new UTF8Encoding(false));
    var sections = contents.Select(pair => new { name = pair.Key, path = pair.Key, role = "analysis", format = Path.GetExtension(pair.Key)[1..], checksum = ExportSelection.Hash(File.ReadAllBytes(Path.Combine(folder,pair.Key))) }).ToArray();
    File.WriteAllText(manifest, JsonSerializer.Serialize(new { schema_version="1.0.0", artifact_type="attackmap_artifact_manifest", generation_id="run-a", sections, compatibility_exports=Array.Empty<object>() }),new UTF8Encoding(false));
    var selected = new ExportSelection(report,ExportSelection.Hash(File.ReadAllBytes(report)),"run-a",manifest,ExportSelection.Hash(File.ReadAllBytes(manifest)),null,null);
    workspace.Select(selected); var snapshot = await workspace.Load("review");
    Check(snapshot!.Generation == "run-a", "generation bound");
    Check(snapshot.Pages.Single().Markdown == "saved review", "verified bytes read; malformed nonselected metadata not parsed");
    Check(snapshot.ProseReadCount == 1 && snapshot.MetadataReadCount == 1 &&
        snapshot.RunManifestReadCount == 1 && snapshot.ReportIntegrityReadCount == 8,
        "snapshot reports selected review and report integrity reads separately");
    Check(artifactReads["defensive-review-llm.md"] == 1 && artifactReads["defensive-review-llm.meta.json"] == 1 &&
        artifactReads.GetValueOrDefault("vulnerability-hypotheses.md") == 0 && artifactReads.GetValueOrDefault("vulnerability-hypotheses.meta.json") == 0,
        "selected review performs exactly one prose and metadata read with zero other-mode reads");
    workspace.Select(selected); var missing = await workspace.Load("triage");
    Check(missing!.Pages.Single().State == "unavailable" && missing.Pages.Single().Mode == "triage" &&
        artifactReads.GetValueOrDefault("triage.md") == 0 && artifactReads.GetValueOrDefault("defensive-review-llm.md") == 1,
        "missing selected mode is unavailable without substituting another mode");
    Check(missing.ProseReadCount == 0 && missing.MetadataReadCount == 0 &&
        missing.RunManifestReadCount == 1 && missing.ReportIntegrityReadCount == 4,
        "missing selected mode reports only run manifest and integrity reads");
    workspace.Select(selected); bool invalidHunt = false;
    try { await workspace.Load("hunt"); } catch (JsonException) { invalidHunt = true; }
    Check(invalidHunt && artifactReads["vulnerability-hypotheses.md"] == 1 && artifactReads["vulnerability-hypotheses.meta.json"] == 1,
        "requesting hunt surfaces its own malformed metadata after exactly one pair read");
    workspace.Select(selected); Task<AiArtifactSnapshot?> delayed=workspace.Load("review"); workspace.Cancel();
    Check(await delayed == null,"late response discarded");
    var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var capturedRecords = SelectedArtifacts.List(selected); int listCalls=0;
    var closing = new AiArtifactWorkspace(async value => { Interlocked.Increment(ref listCalls); started.SetResult(); await release.Task; return capturedRecords; });
    closing.Select(selected); Task<AiArtifactSnapshot?> closingRead=closing.Load("review"); await started.Task; closing.Stop();
    // Break metadata before releasing the delayed listing: a post-stop read would throw.
    string metadataPath=Path.Combine(folder,"defensive-review-llm.meta.json"); File.WriteAllText(metadataPath,"changed after close");
    release.SetResult();
    Check(await closingRead == null,"close invalidates pending read");
    Check(listCalls==1,"stop prevents follow-up artifact reads and final revalidation");
    File.WriteAllText(metadataPath,complete,new UTF8Encoding(false));
    Check(closing.IsStopped,"stop is terminal");
    closing.Select(selected); Check(await closing.Load("review") == null,"selection cannot restart closed workspace");
    closing.Cancel(); closing.Stop(); Check(await closing.Load("review") == null,"repeated stop and cancel remain terminal");
    // After stop, even a broken selection must not start I/O or surface an error.
    closing.Select(selected with { ReportPath=Path.Combine(folder,"missing.json") });
    Check(await closing.Load("review") == null,"closed workspace performs no subsequent artifact reads");
    File.WriteAllText(Path.Combine(folder,"defensive-review-llm.md"),"tampered");
    workspace.Select(selected); bool rejected=false; try { await workspace.Load("review"); } catch(InvalidDataException) { rejected=true; }
    Check(rejected,"tampered output rejected");
    File.WriteAllText(report,"changed"); rejected=false; try { await workspace.Load("review"); } catch(InvalidDataException) { rejected=true; }
    Check(rejected,"tampered report rejected");
}
finally { Directory.Delete(folder,true); }
if (args.Length > 0)
{
    if (args.Length != 3 || args[0] != "--saved-hunt-verify") throw new ArgumentException("Expected --saved-hunt-verify <generation-directory> <projection-json>.");
    string generation = Path.GetFullPath(args[1]);
    string[] names = ["vulnerability-hypotheses.meta.json", "vulnerability-hypotheses.md", "run-manifest.json"];
    var before = names.ToDictionary(name => name, name => ExportSelection.Hash(File.ReadAllBytes(Path.Combine(generation, name))));
    string savedMetadata = File.ReadAllText(Path.Combine(generation, names[0])), savedMarkdown = File.ReadAllText(Path.Combine(generation, names[1]));
    var saved = AiArtifactProjection.Project("hunt_verify", savedMarkdown, savedMetadata, File.ReadAllText(Path.Combine(generation, names[2])));
    Check(saved.State == "partial" && saved.Summary.Contains("Jury abstentions: 1; failed passes: 0"), "retained generation keeps abstention partial state");
    Check(saved.Summary.Contains("Usage: unknown (artifact metadata); input tokens: 506556; output tokens: 5955"), "actual aggregate count provenance stays explicit");
    Check(saved.Summary.Contains("Shared output accounting (run allowance): reported; unknown output-usage calls: 0"), "actual shared output accounting shown independently");
    Check(saved.Summary.Contains("Reference validity: unknown; Claim support: not assessed") && saved.Summary.Contains("Captured citation context: mechanically checked (context only)"), "actual captured context does not establish output references or claims");
    Check(saved.Metadata == savedMetadata && saved.Markdown == savedMarkdown, "actual model text and metadata projected without rewriting");
    Check(names.All(name => before[name] == ExportSelection.Hash(File.ReadAllBytes(Path.Combine(generation, name)))), "actual retained generation bytes unchanged");
    File.WriteAllText(args[2], JsonSerializer.Serialize(new { generation = Path.GetFileName(generation), saved.State, saved.Summary, saved.Notice, source_sha256 = before,
        scope = "Read-only projection of retained artifacts; no new HTTP, model, GUI, semantic or release acceptance." }, new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
}
Console.WriteLine($"PASS {checks} AI artifact projection and captured-generation checks; offline only; no provider or GUI.");

