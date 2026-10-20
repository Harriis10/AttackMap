using System.Text.Json;using AttackMap.NativeSpike;using AttackMap.NativeSpike.ExportPrep;
int checks=0;void Check(bool condition,string label){if(!condition)throw new Exception(label);checks++;}
void Reject(Action action){try{action();throw new Exception("Expected safe rejection");}catch(Exception error)when(error is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException or JsonException){checks++;}}
string root=Path.Combine(Path.GetTempPath(),"attackmap-wp022-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
try
{
    string generation=Path.Combine(root,"žluťoučký-generation-1");Directory.CreateDirectory(generation);
    string report=Path.Combine(generation,"attackmap-report.json"),markdown=Path.Combine(generation,"defensive-review.md"),manifest=Path.Combine(generation,"artifact-manifest.json");
    string source=JsonSerializer.Serialize(new{scan=new{root="C:/synthetic/repo",limitations=new[]{"synthetic partial"},resource_limit_reporting="partial",analyzer_errors=Array.Empty<object>()},findings=new object?[]{new{id="one",rule_id="explicit-rule",title="same title",severity="high",confidence="low",evidence_basis="observed",evidence=new[]{"DO_NOT_RENDER"},secret_value="DO_NOT_RENDER",locations=new object[]{new{file="src/žluťoučký.ts",line=7},new{file="../escape.ts",line=1}}},new{id="two",title="same title",severity="unknown",evidence=new[]{"src/inferred.ts:99 DO_NOT_RENDER"}},null}});
    File.WriteAllText(report,source);File.WriteAllText(markdown,"# Synthetic selected review\n");
    ExportSelection Capture()
    {
        string hash=ExportSelection.Hash(File.ReadAllBytes(report));
        File.WriteAllText(manifest,JsonSerializer.Serialize(new{schema_version="1.0.0",artifact_type="attackmap_artifact_manifest",generation_id="g1",run_identity=new{repo_root="C:/synthetic/repo"},sections=Array.Empty<object>(),compatibility_exports=new[]{new{name="canonical-report",path="attackmap-report.json",role="report",format="json",checksum=hash},new{name="defensive-review",path="defensive-review.md",role="review",format="md",checksum=ExportSelection.Hash(File.ReadAllBytes(markdown))}}}));
        return ExportSelection.Capture(report,hash,new RunIdentity("g1","C:/synthetic/repo",1,DateTimeOffset.UnixEpoch));
    }
    var selected=Capture();var workspace=new SelectedExportWorkspace();workspace.Select(selected);string sarif=await workspace.ReadSarif();Check(sarif==await workspace.ReadSarif(),"deterministic SARIF bytes");
    using(var json=JsonDocument.Parse(sarif))
    {
        Check(json.RootElement.GetProperty("version").GetString()=="2.1.0","SARIF version");var run=json.RootElement.GetProperty("runs")[0];var results=run.GetProperty("results");
        Check(results.GetArrayLength()==2&&results[0].GetProperty("properties").GetProperty("sourceFindingId").GetString()=="one"&&results[1].GetProperty("properties").GetProperty("sourceFindingId").GetString()=="two","duplicate titles preserve distinct source IDs/order");
        Check(results[0].GetProperty("level").GetString()=="error"&&results[1].GetProperty("level").GetString()=="none"&&results[0].GetProperty("properties").GetProperty("confidence").GetString()=="low","severity translated without confidence scoring");
        Check(results[0].GetProperty("locations").GetArrayLength()==1&&results[0].GetProperty("locations")[0].GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString()!.Contains("%"),"Unicode relative source URI only");
        Check(!results[1].TryGetProperty("locations",out _)&&!sarif.Contains("inferred.ts")&&!sarif.Contains("DO_NOT_RENDER")&&!sarif.Contains("security-severity"),"no prose locations/raw secrets/derived score");
        Check(run.GetProperty("properties").GetProperty("partialProjection").GetBoolean()&&run.GetProperty("properties").GetProperty("resourceLimitReporting").GetString()=="partial"&&run.GetProperty("properties").GetProperty("coverageCompleteness").GetString()=="unknown","explicit partial/unknown notifications/properties");
    }
    string destination=Path.Combine(root,"export.sarif");var intent=workspace.Request(SelectedExportFormat.Sarif,SelectedExportOperation.Save,destination)!;Check(workspace.Validate(intent)&&!File.Exists(destination),"callback intent writes nothing");
    File.WriteAllText(destination,"collision");Check(!workspace.Validate(intent),"destination appearing after picker rejected");Reject(()=>workspace.Request(SelectedExportFormat.Sarif,SelectedExportOperation.Save,destination));
    var overwrite=workspace.Request(SelectedExportFormat.Sarif,SelectedExportOperation.Save,destination,true)!;Check(workspace.Validate(overwrite),"approved overwrite bound to destination hash");File.WriteAllText(destination,"changed");Check(!workspace.Validate(overwrite),"overwrite destination hash change rejected");
    string originalReport=File.ReadAllText(report),originalManifest=File.ReadAllText(manifest);workspace.Cancel();Check(!workspace.Validate(intent),"cancel invalidates delayed save");workspace.SaveFailed();Check(File.ReadAllText(report)==originalReport&&File.ReadAllText(manifest)==originalManifest,"cancel/save error leaves original artifacts unchanged");
    string renderer=Path.Combine(root,"inert-test-renderer.exe");File.WriteAllText(renderer,"inert fixture, never executed");var presentPdf=SelectedExportWorkspace.ProbePdf(new[]{renderer});
    foreach(var format in Enum.GetValues<SelectedExportFormat>())
    {
        var request=workspace.Request(format,SelectedExportOperation.Copy,pdf:presentPdf);
        Check(request!=null&&request.Generation=="g1"&&request.ReportHash==selected.ReportHash,"format intents stay selected generation");
    }
    Check(SelectedExportWorkspace.ProbePdf(Array.Empty<string>()).State==PdfDependencyState.Unavailable&&workspace.Request(SelectedExportFormat.Pdf,SelectedExportOperation.Save,Path.Combine(root,"review.pdf"))==null,"typed PDF unavailable without network/download");
    Check(SelectedExportWorkspace.ProbePdf(new[]{"https://example.test/renderer.exe"}).State==PdfDependencyState.Unavailable,"PDF URL is unavailable without network access");
    Reject(()=>workspace.Request((SelectedExportFormat)99,SelectedExportOperation.Copy));
    foreach(string unsafeDestination in new[]{report,manifest,Path.Combine(generation,"other.sarif"),Path.Combine(root,"x","..","escape.sarif"),"https://example.test/export","C:/synthetic/file:stream"})Reject(()=>workspace.Request(SelectedExportFormat.Sarif,SelectedExportOperation.Save,unsafeDestination));
    Reject(()=>workspace.Request(SelectedExportFormat.Sarif,SelectedExportOperation.Save,root));
    string aliasContent=Path.Combine(root,"same-content.json");File.WriteAllText(aliasContent,source);Reject(()=>workspace.Request(SelectedExportFormat.Json,SelectedExportOperation.Save,aliasContent,true));
    var old=workspace.Request(SelectedExportFormat.Json,SelectedExportOperation.Reveal)!;workspace.Select(selected with{RunId="g2"});Check(!workspace.Validate(old),"stale generation intent rejected");workspace.Select(selected);
    File.WriteAllText(report,source+" ");Reject(()=>workspace.Request(SelectedExportFormat.Json,SelectedExportOperation.Open));File.WriteAllText(report,source);
    var current=workspace.Request(SelectedExportFormat.Json,SelectedExportOperation.Reveal)!;File.WriteAllText(manifest,originalManifest+" ");Check(!workspace.Validate(current),"tampered manifest rejected");File.WriteAllText(manifest,originalManifest);
    string unsafeManifest=originalManifest.Replace("\"sections\":[]","\"sections\":[{\"name\":\"unsafe\",\"path\":\"../escape.json\",\"role\":\"artifact\",\"format\":\"json\",\"checksum\":\""+new string('a',64)+"\"}]");
    File.WriteAllText(manifest,unsafeManifest);workspace.Select(selected with{ManifestHash=ExportSelection.Hash(File.ReadAllBytes(manifest))});Reject(()=>workspace.Request(SelectedExportFormat.Json,SelectedExportOperation.Copy));File.WriteAllText(manifest,originalManifest);workspace.Select(selected);
    string alias=Path.Combine(root,"redirected");Directory.CreateSymbolicLink(alias,generation);Reject(()=>workspace.Request(SelectedExportFormat.Sarif,SelectedExportOperation.Save,Path.Combine(alias,"new.sarif")));Directory.Delete(alias);
    string linked=Path.Combine(root,"linked-report.json");File.CreateSymbolicLink(linked,report);Reject(()=>workspace.Request(SelectedExportFormat.Sarif,SelectedExportOperation.Save,linked,true));File.Delete(linked);
    string longPath=root;for(int i=0;i<7;i++)longPath=Path.Combine(longPath,"long-unicode-žluťoučký-segment-"+i);Directory.CreateDirectory(longPath);
    var longIntent=workspace.Request(SelectedExportFormat.Sarif,SelectedExportOperation.Save,Path.Combine(longPath,"selected.sarif"))!;Check(longIntent.Destination!.Length>260&&workspace.Validate(longIntent),"long Unicode destination intent");
    string longReport=Path.Combine(longPath,"attackmap-report.json");File.Copy(report,longReport);File.Copy(markdown,Path.Combine(longPath,"defensive-review.md"));File.Copy(manifest,Path.Combine(longPath,"artifact-manifest.json"));workspace.Select(ExportSelection.CaptureSavedGeneration(longReport,selected.ReportHash,"C:/synthetic/repo"));Check(await workspace.ReadSarif()==sarif,"long Unicode selected source uses same captured generation content");
    Reject(()=>SelectedSarifProjection.Project("{broken","g1",selected.ReportHash));Reject(()=>SelectedSarifProjection.Project(new string(' ',64*1024*1024+1),"g1",selected.ReportHash));
    using(var fileOnly=JsonDocument.Parse(SelectedSarifProjection.Project("{\"scan\":{\"root\":\"synthetic\"},\"findings\":[{\"id\":\"file-only\",\"locations\":[{\"file\":\"src/file.ts\"}]}]}","g1",selected.ReportHash)))
    Check(!fileOnly.RootElement.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("locations")[0].GetProperty("physicalLocation").TryGetProperty("region",out _),"no fabricated line 1 for file-level location");
    string many=JsonSerializer.Serialize(new{scan=new{root="synthetic"},findings=Enumerable.Range(0,10001).Select(i=>new{id=i.ToString(),title="bounded"})});using(var bounded=JsonDocument.Parse(SelectedSarifProjection.Project(many,"g1",selected.ReportHash)))Check(bounded.RootElement.GetProperty("runs")[0].GetProperty("results").GetArrayLength()==10000&&bounded.RootElement.GetProperty("runs")[0].GetProperty("properties").GetProperty("partialProjection").GetBoolean(),"large finding projection explicitly bounded");
    Check(File.ReadAllText(report)==originalReport&&File.ReadAllText(markdown)=="# Synthetic selected review\n","all checks preserve selected source originals");
}
finally{Directory.Delete(root,true);}
Console.WriteLine($"PASS {checks} bounded WP022 selected-export/SARIF checks; no actual export/PDF/shell acceptance");
