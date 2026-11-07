using AttackMap.NativeSpike;
string path = Path.Combine(Path.GetTempPath(), $"attackmap-report-adapter-{Guid.NewGuid():N}.json");
int checks = 0;
try
{
    await File.WriteAllTextAsync(path, """{"scan":{"root":"C:/non-ASCII-č"},"findings":[{"id":"original-id","title":"Claim","severity":"high","score":17,"confidence":"low","locations":[{"file":"long/source.ts","line":9}],"evidence":["Static evidence"],"mitigation":"Concrete improvement"}]}""");
    var report = await ReportAdapter.Load(path);
    var row = report.Findings.Single();
    Check(report.Review == "No defensive review supplied in this report." && report.ArchitectureSummary == "No architecture summary supplied in this report.", "missing supplied review and architecture use explicit fallbacks");
    string suppliedReview = "# Obrana č\n\n**Unknown** candidate <script>never execute</script>\n- supplied evidence";
    string suppliedArchitecture = "## Architektura ž\n\n`service → datastore`\nRelationship: unknown";
    await File.WriteAllTextAsync(path, System.Text.Json.JsonSerializer.Serialize(new { scan = new { root = "C:/synthetic" }, findings = Array.Empty<object>(), defensive_review = suppliedReview, architecture_summary = suppliedArchitecture }));
    var proseReport = await ReportAdapter.Load(path);
    Check(proseReport.Review == suppliedReview, "supplied Unicode Markdown review retained exactly as text");
    Check(proseReport.ArchitectureSummary == suppliedArchitecture, "supplied Unicode Markdown architecture retained exactly as text");
    Check(row.Id == "original-id" && row.Severity == "high" && row.Confidence == "low", "preserve engine labels");
    Check(row.Evidence.Contains("Priority supplied by engine: 17") && row.Recommendation == "Concrete improvement", "preserve score and recommendation");
    Check(row.Basis.Contains("unknown") && row.Evidence.Contains("unverified") && row.Source == "long/source.ts:9", "legacy uncertainty and source");
    Check(row.Evidence.Contains("Finding context unavailable") && row.Evidence.Contains("remain unknown"), "legacy context absence explicitly unknown");
    await File.WriteAllTextAsync(path, """{"scan":{"root":"C:/synthetic"},"findings":[{"id":"context-id","title":"Synthetic context","severity":"high","context":{"context_version":"1.0","finding_id":"context-id","claim":{"runtime_verification":"unknown"},"evidence":{"candidates":[{"file":"src/č.ts","ownership":"unknown"}]},"trust_chain":{"status":"candidate","trust_boundary_crossing":"unknown"},"priority":{"point_contributions":"not_supplied"}}}]}""");
    var contextReport = await ReportAdapter.Load(path);
    var contextRow = contextReport.Findings.Single();
    var suppliedContext = contextReport.FindingRecords.Single().GetProperty("context");
    Check(suppliedContext.GetProperty("evidence").GetProperty("candidates")[0].GetProperty("file").GetString() == "src/č.ts", "supplied context records retain Unicode candidate evidence");
    Check(contextRow.Evidence.Contains("Core-supplied finding context") && contextRow.Evidence.Contains("Candidate evidence is not a verified association") && contextRow.Evidence.Contains("not_supplied") && contextRow.Evidence.Contains("trust boundary crossing: unknown"), "detail retains supplied context and uncertainty without alternate scoring");
    await File.WriteAllTextAsync(path, """{"scan":{"root":"C:/synthetic"},"findings":[{"id":"future-context","context":{"context_version":"99","claim":{"text":"future claim must not be interpreted"}}}]}""");
    var futureContext = await ReportAdapter.Load(path);
    Check(futureContext.Findings.Single().Evidence.Contains("unsupported or missing context version") && !futureContext.Findings.Single().Evidence.Contains("future claim must not be interpreted"), "unknown context version explicitly unavailable without interpretation");
    Check(futureContext.FindingRecords.Single().GetProperty("context").GetProperty("context_version").GetString() == "99", "unknown version original record remains available");
    foreach (string invalid in new[] { "[]", "{\"scan\":[]}", "{\"scan\":{\"root\":\"x\"},\"findings\":[1]}", "{\"schema_version\":\"99\",\"scan\":{\"root\":\"x\"},\"findings\":[]}" })
    {
        await File.WriteAllTextAsync(path, invalid);
        bool rejected = false;
        try { await ReportAdapter.Load(path); } catch (InvalidDataException) { rejected = true; }
        Check(rejected, "reject malformed or explicit versioned input");
    }
    var store = new LocalSettingsStore(path);
    File.Delete(path);
    Check(store.Load() == new LocalSettings(), "missing settings default local paths empty");
    string absolutePython = Path.GetFullPath("engine folder/python.exe");
    string absoluteRepo = Path.GetFullPath("repository with spaces and č");
    var saved = new LocalSettings(PythonPath: absolutePython, RepositoryPath: absoluteRepo);
    store.Save(saved);
    Check(new LocalSettingsStore(path).Load() == saved, "settings roundtrip across store instances");
    string original = await File.ReadAllTextAsync(path);
    bool badSave = false;
    try { store.Save(new LocalSettings(PythonPath: "relative/python.exe")); } catch (InvalidDataException) { badSave = true; }
    Check(badSave && await File.ReadAllTextAsync(path) == original, "invalid save preserves prior settings");
    foreach (string invalid in new[] { "{", "{}", "{\"SchemaVersion\":99}", "{\"SchemaVersion\":1,\"PythonPath\":\"relative\"}", new string(' ',16385) })
    {
        await File.WriteAllTextAsync(path, invalid);
        bool rejected = false;
        try { store.Load(); } catch (Exception error) when (error is InvalidDataException or System.Text.Json.JsonException) { rejected = true; }
        Check(rejected && await File.ReadAllTextAsync(path) == invalid, "invalid settings rejected and original preserved");
    }
    store.Clear();
    store.Clear();
    Check(store.Load() == new LocalSettings(), "clear saved paths idempotently");
    var view = new RunPresentation();
    var oldReport = new DisplayedReport(absoluteRepo, "old-run", "Scan timestamp unavailable", "Unknown coverage");
    var nextRun = new RunIdentity("new-run", absoluteRepo, 2, DateTimeOffset.Parse("2026-10-15T10:00:00Z"));
    view.SelectRepository(absoluteRepo);
    view.Publish(oldReport);
    Check(!view.PreviousResult && view.Summary.Contains("old-run"), "initial displayed saved report");
    view.Begin(nextRun);
    Check(view.PreviousResult && view.Summary.Contains("PREVIOUS VALID REPORT") && view.Summary.Contains("Active run: new-run"), "rescan preserves previous report distinct from active run");
    view.Update("Cancelling; artifacts pending");
    Check(view.Summary.Contains("Cancelling") && view.Coverage == "Unknown coverage", "cancel retains displayed coverage");
    view.End("Engine cancelled; artifacts unavailable");
    Check(view.ActiveRun == null && view.PreviousResult && view.Displayed == oldReport, "cancel confirmation preserves previous result");
    view.Begin(nextRun);
    view.End("Engine failed; artifacts unavailable");
    Check(view.PreviousResult && view.Displayed == oldReport && view.Summary.Contains("failed"), "failure cannot promote previous report");
    view.Begin(nextRun);
    view.Publish(new DisplayedReport(absoluteRepo,"new-run","Client-request timestamp","Limitation supplied by engine"));
    view.End("Engine completed; artifacts ready");
    Check(!view.PreviousResult && view.Summary.Contains("new-run") && !view.Summary.Contains("old-run"), "ready new report replaces previous report");
    view.SelectRepository(absolutePython);
    Check(view.PreviousResult && view.Summary.Contains(absolutePython) && view.Summary.Contains(absoluteRepo), "repository switch keeps report ownership explicit");
    Check(report.Coverage.Contains("legacy aggregate") && report.Coverage.Contains("completeness is unverified"), "absent coverage never claims complete");
    var defaults = new NativeScanOptions();
    using (var requestJson = System.Text.Json.JsonDocument.Parse(NativeScanRequest.Serialize("run", absoluteRepo, absolutePython, 1, defaults, "")))
    {
        var root = requestJson.RootElement;
        var options = root.GetProperty("options");
        Check(root.GetProperty("modules").GetArrayLength() == 0 && !options.GetProperty("cve").GetBoolean() && !options.GetProperty("recall").GetBoolean() && !options.GetProperty("strict_analyzers").GetBoolean() && !options.GetProperty("no_suppress").GetBoolean(), "default request leaves network/advanced options off");
        Check(options.GetProperty("secrets_history").GetInt32() == 0 && options.GetProperty("timeout_seconds").GetInt32() == 600 && options.EnumerateObject().Count() == 6, "bounded defaults use exact engine option names");
    }
    var advanced = new NativeScanOptions(true, true, true, true, 10000, 86400);
    using (var requestJson = System.Text.Json.JsonDocument.Parse(NativeScanRequest.Serialize("run", absoluteRepo, absolutePython, 1, advanced, "javascript-web, config javascript-web")))
    {
        var options = requestJson.RootElement.GetProperty("options");
        Check(options.GetProperty("cve").GetBoolean() && options.GetProperty("strict_analyzers").GetBoolean() && options.GetProperty("no_suppress").GetBoolean() && options.GetProperty("recall").GetBoolean() && options.GetProperty("secrets_history").GetInt32() == 10000 && options.GetProperty("timeout_seconds").GetInt32() == 86400, "selected options forwarded without UI policy");
        Check(requestJson.RootElement.GetProperty("modules").GetArrayLength() == 2, "module selection validates and deduplicates");
    }
    foreach (var invalid in new[] { new NativeScanOptions(SecretsHistory: -1), new NativeScanOptions(SecretsHistory: 10001), new NativeScanOptions(TimeoutSeconds: 0), new NativeScanOptions(TimeoutSeconds: 86401) })
    {
        bool rejected = false;
        try { invalid.Validate(); } catch (InvalidDataException) { rejected = true; }
        Check(rejected, "invalid numeric option rejected before launch");
    }
    foreach (string invalid in new[] { "--install-missing", "foo;command", "../analyzer", "a/b", new string('x',129), string.Join(",",Enumerable.Range(0,33).Select(i => $"analyzer{i}")) })
    {
        bool rejected = false;
        try { NativeScanOptions.ParseModules(invalid); } catch (InvalidDataException) { rejected = true; }
        Check(rejected, "invalid module names/limits rejected before launch");
    }
    string oldSettings = System.Text.Json.JsonSerializer.Serialize(new { SchemaVersion = 1, PythonPath = absolutePython, RepositoryPath = absoluteRepo });
    await File.WriteAllTextAsync(path, oldSettings);
    Check(store.Load().EffectiveOptions == defaults && store.Load().Modules == "" && await File.ReadAllTextAsync(path) == oldSettings, "old path-only settings load defaults without rewriting original");
    store.Save(saved with { Options = advanced, Modules = "javascript-web, config" });
    var restoredAdvanced = new LocalSettingsStore(path).Load();
    Check(restoredAdvanced.EffectiveOptions == advanced && restoredAdvanced.Modules == "javascript-web, config", "explicit advanced selections restore including prior CVE opt-in");
    string beforeInvalid = await File.ReadAllTextAsync(path);
    bool invalidSettings = false;
    try { store.Save(saved with { Options = new NativeScanOptions(TimeoutSeconds: 0) }); } catch (InvalidDataException) { invalidSettings = true; }
    Check(invalidSettings && await File.ReadAllTextAsync(path) == beforeInvalid, "invalid options preserve existing settings");
    var profileOptions = new NativeScanOptions(AnalyzerProfile: "php-laminas-omeka@1.0");
    store.Save(saved with { Options = profileOptions, Modules = "php-web,config,php-laminas,default,omeka-s" });
    var profileSaved = store.Load();
    Check(profileSaved.EffectiveOptions.AnalyzerProfile == profileOptions.AnalyzerProfile && profileSaved.Modules.Contains("php-web"), "named profile and base expansion survive settings roundtrip");
    using (var profileWire = System.Text.Json.JsonDocument.Parse(NativeScanRequest.Serialize("run", absoluteRepo, absolutePython, 1, profileOptions, "")))
        Check(profileWire.RootElement.GetProperty("schema_version").GetString() == "1.5" && profileWire.RootElement.GetProperty("modules").GetArrayLength() == 0 && profileWire.RootElement.GetProperty("options").GetProperty("analyzer_profile").GetString() == profileOptions.AnalyzerProfile, "named profile uses schema 1.5 without overriding modules");
    bool mixedProfile = false;
    try { NativeScanRequest.Serialize("run", absoluteRepo, absolutePython, 1, profileOptions, "config"); } catch (InvalidDataException) { mixedProfile = true; }
    Check(mixedProfile, "profile plus explicit modules rejected before launch");
    bool invalidProfile = false;
    try { (profileOptions with { AnalyzerProfile = "python@1.0\n" }).Validate(); } catch (InvalidDataException) { invalidProfile = true; }
    Check(invalidProfile, "profile identity cannot contain trailing control characters");
    store.Save(saved with { Options = new NativeScanOptions(), Modules = "config" });
    Check(store.Load().EffectiveOptions.AnalyzerProfile == null && store.Load().Modules == "config", "clearing named profile cannot revive through settings merge");
    var golden = await ReportAdapter.Load(Path.Combine(AppContext.BaseDirectory,"fixtures","structure-golden.json"));
    Check(golden.Structure.Architecture.Count == 7 && golden.Structure.Inventory.Count == 4, "only supplied architecture/inventory records emitted");
    var service = golden.Structure.Architecture.Single(row => row.Kind == "Service hint");
    Check(service.Source.Contains("žluťoučký.ts") && service.Source.Length > 200 && service.Detail.Contains("conflicts (supplied)") && service.Detail.Contains("origins (supplied)") && service.Detail.Contains("role (supplied)") && service.Detail.Contains("source_role (supplied)"), "Unicode long sources and supplied roles/conflicts/origins preserved");
    var edge = golden.Structure.Architecture.Single(row => row.Kind == "Relationship hint");
    Check(edge.Basis.Contains("candidate hint") && edge.Basis.Contains("relationship: unknown") && !edge.Basis.Contains("static_observed"), "unknown edge not promoted to observed");
    var surface = golden.Structure.Architecture.Single(row => row.Kind == "Attack surface");
    Check(surface.Basis.Contains("static_observed") && surface.Basis.Contains("relationship: unknown") && surface.Detail.Contains("deployment reachability unknown"), "supplied static basis and uncertain deployment remain distinct");
    Check(golden.Structure.Inventory.Single(row => row.Kind == "Route").Source.Contains("location unknown"), "missing source explicitly unknown");
    Check(golden.Structure.Inventory.Any(row => row.Title.Contains("pkg-č | version ^2.0 | ecosystem npm")) && golden.Structure.Inventory.Any(row => row.Title.Contains("version-missing | version unknown | ecosystem unknown")), "dependency metadata preserved with unknown missing fields");
    Check(!golden.Structure.Inventory.Any(row => row.Detail.Contains("SECRET_SENTINEL")) && !golden.Structure.Architecture.Any(row => row.Detail.Contains("SECRET_SENTINEL")), "secret evidence excluded from this inventory slice");
    var missing = await ReportAdapter.Load(Path.Combine(AppContext.BaseDirectory,"fixtures","structure-missing.json"));
    Check(missing.Structure.Architecture.Count == 0 && missing.Structure.Inventory.Count == 0 && missing.Structure.ArchitectureNotes.Contains("completeness unknown"), "missing arrays create no inferred structure");
    await File.WriteAllTextAsync(path,"""{"scan":{"root":"x","routes":[1,{"method":"GET","path":"/x"}]},"findings":[]}""");
    var malformed = await ReportAdapter.Load(path);
    Check(malformed.Structure.Inventory.Count == 1 && malformed.Structure.InventoryNotes.Contains("1 malformed records omitted (partial view)"), "malformed records report partial view");
    string exportRoot = Path.Combine(Path.GetTempPath(),"attackmap-export-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(exportRoot);
    try
    {
        string generation = Path.Combine(exportRoot,"generation"); Directory.CreateDirectory(generation);
        string jsonPath = Path.Combine(generation,"attackmap-report.json");
        string reviewPath = Path.Combine(generation,"defensive-review.md");
        byte[] originalJson = System.Text.Encoding.UTF8.GetBytes("{\"claim\":\"č unchanged labels\"}");
        byte[] originalReview = System.Text.Encoding.UTF8.GetBytes("# Supplied review\nUnknown is unknown. č\n");
        await File.WriteAllBytesAsync(jsonPath,originalJson); await File.WriteAllBytesAsync(reviewPath,originalReview);
        string manifestPath = Path.Combine(generation,"artifact-manifest.json");
        string manifest = System.Text.Json.JsonSerializer.Serialize(new { schema_version="1.0.0",artifact_type="attackmap_artifact_manifest",generation_id="selected-run",run_identity=new { repo_root=absoluteRepo },compatibility_exports=new[] { new { path="attackmap-report.json",checksum=ExportSelection.Hash(originalJson) },new { path="defensive-review.md",checksum=ExportSelection.Hash(originalReview) } } });
        await File.WriteAllTextAsync(manifestPath,manifest);
        var selected = ExportSelection.Capture(jsonPath,ExportSelection.Hash(originalJson),new RunIdentity("selected-run",absoluteRepo,1,DateTimeOffset.UtcNow));
        string destination = Path.Combine(exportRoot,"export-č.json");
        await selected.Export(destination,false);
        Check((await File.ReadAllBytesAsync(destination)).SequenceEqual(originalJson),"JSON export preserves exact displayed bytes/Unicode labels");
        string longFolder = Path.Combine(exportRoot,new string('a',100),new string('b',100));Directory.CreateDirectory(longFolder);
        string mdDestination = Path.Combine(longFolder,"review.md");
        await selected.Export(mdDestination,true);
        Check((await File.ReadAllBytesAsync(mdDestination)).SequenceEqual(originalReview),"long path Markdown export copies same verified generation");
        Check(ExportSelection.SafeName("../../bad:*run") == "______bad__run" && selected.SuggestedName(false).Contains("selected-run"),"suggested names contain sanitized selected identity");
        bool collision = false; try { await selected.Export(jsonPath,false); } catch (InvalidDataException) { collision = true; }
        Check(collision && (await File.ReadAllBytesAsync(jsonPath)).SequenceEqual(originalJson),"source collision rejected without mutation");
        await File.WriteAllTextAsync(jsonPath,"changed");
        bool changed = false; try { await selected.Export(destination,false); } catch (InvalidDataException) { changed = true; }
        Check(changed && (await File.ReadAllBytesAsync(destination)).SequenceEqual(originalJson),"changed source preserves existing destination");
        await File.WriteAllBytesAsync(jsonPath,originalJson);
        await File.WriteAllTextAsync(manifestPath,manifest + " ");
        bool changedManifest = false; try { await selected.Export(destination,false); } catch (InvalidDataException) { changedManifest = true; }
        Check(changedManifest && (await File.ReadAllBytesAsync(destination)).SequenceEqual(originalJson),"changed manifest preserves existing destination");
        await File.WriteAllTextAsync(manifestPath,manifest);
        await File.WriteAllTextAsync(reviewPath,"changed review");
        bool changedReview = false; try { await selected.Export(mdDestination,true); } catch (InvalidDataException) { changedReview = true; }
        Check(changedReview && (await File.ReadAllBytesAsync(mdDestination)).SequenceEqual(originalReview),"changed review rejected by captured manifest hash");
        var legacy = ExportSelection.Capture(jsonPath,ExportSelection.Hash(originalJson),null);
        Check(!legacy.Verified && legacy.Disclosure.Contains("unverified") && legacy.MarkdownPath == null,"legacy import never inherits adjacent manifest identity");
        bool legacyMd = false; try { await legacy.Export(mdDestination,true); } catch (InvalidDataException) { legacyMd = true; }
        Check(legacyMd,"legacy Markdown export unavailable with actionable error");
        await legacy.Export(destination,false);
        Check((await File.ReadAllBytesAsync(destination)).SequenceEqual(originalJson),"legacy JSON copy exact bytes with unverified disclosure");
    }
    finally { Directory.Delete(exportRoot,true); }
    foreach (string version in new[] { "1.0", "9.9" })
    {
        await File.WriteAllTextAsync(path, System.Text.Json.JsonSerializer.Serialize(new { scan = new { root = "synthetic" }, findings = new[] { new { id = "controls-proof", title = "Supplied claim", context = new { context_version = version, observed_controls = new[] { new { observation_id = "control-č", description = "Observed input validation; effectiveness unknown" } } } } } }));
        var controlsReport = await ReportAdapter.Load(path);
        string rendered = controlsReport.Findings.Single().Evidence;
        Check(version == "1.0" ? rendered.Contains("see core-supplied finding context below") && rendered.Contains("control-č") && rendered.Contains("not proof that the claim is mitigated") && !rendered.Contains("Observed controls: not separately supplied") : rendered.Contains("Observed controls: not separately supplied") && rendered.Contains("unsupported or missing context version"), "Observed controls label follows supported supplied context " + version);
    }
    await File.WriteAllTextAsync(path, """{"scan":{"root":"synthetic"},"findings":[{"id":"legacy-controls"}]}""");
    Check((await ReportAdapter.Load(path)).Findings.Single().Evidence.Contains("Observed controls: not separately supplied"), "Legacy finding does not invent observed controls");
    Console.WriteLine($"PASS {checks} native adapter/settings/presentation/options/structure/export checks");
}
finally { File.Delete(path); }
void Check(bool passed, string label) { if (!passed) throw new Exception(label); checks++; }
namespace AttackMap.NativeSpike
{
    public sealed record FixtureFinding(string Id, string Title, string Severity, string Basis, string Confidence, string Source, string Evidence, string Recommendation);
}
