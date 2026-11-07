using AttackMap.NativeSpike;
using System.Text.Json;
using System.Text.Json.Nodes;
int checks = 0;
void Check(bool value, string name) { checks++; if (!value) throw new Exception(name); }
void Reject(Action action, string name) { bool rejected = false; try { action(); } catch (InvalidDataException) { rejected = true; } Check(rejected, name); }
string Event(string schema, long rev, string stage = "analyzer:done", long? done = null, long? total = null, string state = "running", string run = "r", string repo = "C:/one/app", long gen = 1, bool terminal = false) => JsonSerializer.Serialize(new { schema_version = schema, run_id = run, repository_id = repo, generation = gen, revision = rev, kind = terminal ? "terminal" : "progress", state, stage, completed_units = done, total_units = total, execution_outcome = state == "completed" ? "succeeded" : state });
foreach (string schema in new[] { "1.0", "1.1", "1.2", "1.3" })
{
    var protocol = new EngineProtocol("r", "C:/one/app", 1);
    Check(protocol.ParseAndAccept(Event(schema, 0)), schema + " accepted");
    Check(!protocol.Terminal && protocol.Progress!.Stage == "analyzer:done", "analyzer done not terminal");
    Check(protocol.ParseAndAccept(Event(schema, 1, done: 0, total: 0)) && protocol.Percent == null, "zero total indeterminate");
    Check(!protocol.ParseAndAccept(Event(schema, 0)), "out of order ignored");
    Reject(() => protocol.ParseAndAccept(Event(schema, 2, run: "other")), "cross run rejected");
    Reject(() => protocol.ParseAndAccept(Event(schema, 2, repo: "C:/two/app")), "same basename distinct repo");
    Reject(() => protocol.ParseAndAccept(Event(schema, 2, gen: 2)), "cross generation rejected");
    Check(protocol.Revision == 1, "invalid identity cannot poison revision");
}
var p = new EngineProtocol("r", "C:/one/app", 1);
Reject(() => p.ParseAndAccept(Event("2.0", 0)), "unknown schema");
Reject(() => p.ParseAndAccept(Event("1.3", 0, done: 2, total: 1)), "over total");
Reject(() => p.ParseAndAccept(Event("1.3", 0, done: -1)), "negative units");
var model = new ScanProgressModel(); model.Select("r", "C:/one/app", 1);
EngineProgressSnapshot S(long rev, long? done = null, long? total = null, string stage = "analyze", string state = "running", bool terminal = false) => new("r", "C:/one/app", 1, rev, state, stage, done, total, terminal);
bool Take(EngineProgressSnapshot s, int seconds) => model.Accept(s, TimeSpan.FromSeconds(seconds));
Check(Take(S(0), 0) && model.Indeterminate, "unknown total");
Check(Take(S(1, 0, 0), 1) && model.Indeterminate, "zero total");
Check(Take(S(2, 1, 10), 2) && model.EstimatedRemaining == null, "one observation no ETA");
Check(Take(S(3, 2, 10), 3) && model.EstimatedRemaining == null, "two observations no ETA");
Check(Take(S(4, 3, 10), 4) && model.EstimatedRemaining == TimeSpan.FromSeconds(7), "three monotonic observations estimate");
Check(model.EtaText.Contains("Estimated") && model.EtaText.Contains("current stage"), "estimate label scope");
Check(!Take(S(3, 1, 10), 5) && model.Completed == 3, "stale does not regress");
Check(!Take(S(5, 2, 10), 5) && model.Completed == 3, "new revision regressing units rejected");
Check(!Take(S(5) with { Repository = "C:/two/app" }, 5), "cross repo model rejected");
Check(!Take(S(5) with { RunId = "old" }, 5), "cross run model rejected");
Check(!Take(S(5) with { Generation = 2 }, 5), "cross generation model rejected");
string longStage = "unknown-" + new string('界', 4096);
Check(Take(S(5, stage: longStage), 5) && model.Stage == longStage && model.Indeterminate && model.EstimatedRemaining == null, "unknown long stage preserved");
Check(Take(S(6, 1, 2, "done"), 6) && !model.Terminal, "stage done never terminal");
model.RequestCancel(); Check(model.State == "cancelling", "local cancel");
Check(!Take(S(7, 2, 2), 7) && model.State == "cancelling", "queued callback cannot undo local cancel");
Check(Take(S(7, state: "cancelling"), 7), "cancelling event accepted");
Check(Take(S(8, state: "cancelled", terminal: true), 8) && model.Terminal, "cancel terminal");
Check(!Take(S(9), 9), "terminal cannot regress");
model.Select("r2", "C:/two/app", 2); Check(model.State == "queued" && model.Percent == null && !Take(S(10), 10), "repo switch clears and rejects previous callback");
model.ClearSelection(); Check(model.State == "idle" && !Take(S(11), 11), "clear selection rejects late callbacks");
model.Select("r", "C:/one/app", 1);
Check(Take(S(0, 1, 10), 10) && Take(S(1, 2, 10), 9) && model.EstimatedRemaining == null, "backward monotonic clock resets estimate");
Check(Take(S(2, 3, 20), 11) && model.EstimatedRemaining == null, "total change resets estimate");
Check(model.Activity.Count == 1, "file-count progress does not duplicate stage activity");
for (int i = 3; i < 208; i++) Take(S(i, stage: "Analyzer step " + i), i);
Check(model.Activity.Count == 200 && model.EarlierActivityCount == 6 && model.Activity[^1].Stage == "Analyzer step 207", "live activity retains bounded recent stages and omission count");
Check(!Take(S(209) with { RunId = "stale" }, 209) && model.Activity[^1].Stage == "Analyzer step 207", "foreign activity cannot enter selected run");
model.Select("new", "C:/one/app", 2);
Check(model.Activity.Count == 0 && model.EarlierActivityCount == 0, "new run clears old live activity");
model.ClearSelection(); Check(model.Activity.Count == 0, "clear selection clears activity");
var picker = new AnalyzerSelectionModel();
Reject(picker.ValidateForScan, "discovery required");
picker.Restore("removed,python");
picker.LoadDiscovery("""{"schema":1,"modules":[{"name":"python","display_name":"Python","enabled_by_default":true,"experimental":false},{"name":"beta","display_name":"Beta","enabled_by_default":false,"experimental":true},{"name":"opt","enabled_by_default":false},{"name":"legacy"}]}""");
Check(picker.Rows().Count == 5 && picker.Rows("zz").Single().Name == "removed", "filtered missing selected retained");
Check(picker.Rows().Single(x => x.Name == "beta").Experimental, "experimental metadata");
Check(picker.Rows().Single(x => x.Name == "opt").Status == "Opt-in", "opt-in metadata");
Check(picker.Rows().Single(x => x.Name == "legacy").EnabledByDefault == null, "missing default unknown");
Reject(picker.ValidateForScan, "missing explicit analyzer blocks");
picker.Select("removed", false); picker.ValidateForScan(); Check(picker.RequestModules == "python", "explicit names preserved");
picker.SetAnalyzerErrors(new Dictionary<string,string>{{"python","Synthetic analyzer failed"}});
Check(picker.Rows().Single(x => x.Name == "python").Error != null, "analyzer error shown");
picker.SetAutomatic(true); Check(picker.RequestModules == "" && picker.Rows().Any(x => x.Selected), "Automatic preserves choices but emits no modules");
picker.EngineChanged(); Check(picker.DiscoveryError != null && picker.Rows("absent").Any(x => x.Name == "python" && x.Missing), "engine change retains selection");
Reject(picker.ValidateForScan, "stale discovery blocks Automatic");
picker.LoadDiscovery("{broken"); Check(picker.DiscoveryError != null && picker.Rows().Any(x => x.Name == "python"), "malformed discovery retained selected");
picker.LoadDiscovery("""{"schema":99,"modules":[]}"""); Check(picker.DiscoveryError != null, "unknown discovery major");
picker.LoadDiscovery("""{"schema":1,"modules":[{"name":"x"},{"name":"x"}]}"""); Check(picker.DiscoveryError != null, "duplicate inventory refused");
Reject(() => picker.Select("a,b",true), "single selector name required");
picker.LoadDiscovery("""{"schema":1,"modules":[]}"""); picker.Restore(""); picker.ValidateForScan(); Check(picker.Automatic && picker.Rows().Count == 0, "empty discovery distinct from error");
const string profileDiscovery = """
{"schema":1,"modules":[
 {"name":"config","display_name":"Config","enabled_by_default":true,"experimental":false},
 {"name":"javascript-web","display_name":"JavaScript","enabled_by_default":true,"experimental":false},
 {"name":"node-service","display_name":"Node","enabled_by_default":false,"experimental":true},
 {"name":"atproto","display_name":"ATProto","enabled_by_default":false,"experimental":true},
 {"name":"default","display_name":"Fallback","enabled_by_default":true,"experimental":false},
 {"name":"node-atproto","display_name":"Node overlay","enabled_by_default":true,"experimental":true}],
 "analyzer_profiles":{"schema_version":"1.0","profiles":[
 {"name":"automatic","display_name":"Automatic","version":"1.0","qualified_name":"automatic@1.0","selection_mode":"automatic","module_names":[],"experimental_module_names":[],"available":true,"missing_module_names":[],"expanded_module_names":["config","javascript-web","default","node-atproto"],"installed_experimental_module_names":["node-atproto"],"opt_in_module_names":[]},
 {"name":"node-atproto","display_name":"Node / ATProto","version":"1.0","qualified_name":"node-atproto@1.0","selection_mode":"explicit","module_names":["javascript-web","node-service","config","atproto","default","node-atproto"],"experimental_module_names":["node-service","atproto","node-atproto"],"available":true,"missing_module_names":[],"expanded_module_names":["javascript-web","node-service","config","atproto","default","node-atproto"],"installed_experimental_module_names":["node-service","atproto","node-atproto"],"opt_in_module_names":["node-service","atproto"]}]},
 "analyzer_catalog":{"schema":1,"scope":"installed_discovery","candidates":[
 {"candidate_id":"builtin:config","name":"config","origin":"builtin","status":"effective","package":{"name":"attackmap","version":"0.4.0"},"metadata":{"version":"0.1.0"},"implementation":{"module":"attackmap.analyzers","qualname":"BuiltinConfigAnalyzer","source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
 {"candidate_id":"plugin:config","name":"config","origin":"plugin","status":"shadowed","package":{"name":"config-plugin","version":"0.2.0"},"metadata":{"version":"0.2.0"},"shadowed_by":"builtin:config"}]}}
""";
string ProfileFixture(Action<JsonObject> change)
{
    var fixture = JsonNode.Parse(profileDiscovery)!.AsObject(); change(fixture); return fixture.ToJsonString();
}
var profilePicker = new AnalyzerSelectionModel(); profilePicker.LoadDiscovery(profileDiscovery); profilePicker.ValidateForScan();
Check(profilePicker.Profiles.Count == 2 && profilePicker.ProfileCatalogError == null && profilePicker.CatalogError == null, "versioned profiles and provenance loaded");
Check(profilePicker.Rows().Single(item => item.Name == "config").OriginSummary!.Contains("Built-in · attackmap 0.4.0 · analyzer 0.1.0"), "effective origin and both versions visible");
Check(profilePicker.Rows().Single(item => item.Name == "config").ShadowedSummary!.Contains("config-plugin 0.2.0"), "shadowed implementation retained distinctly");
Check(profilePicker.Rows().Single(item => item.Name == "config").ImplementationSummary!.Contains("BuiltinConfigAnalyzer"), "implementation identity visible");
string discoveryFailureFixture = ProfileFixture(fixture =>
{
    var candidates = fixture["analyzer_catalog"]!["candidates"]!.AsArray();
    foreach (string stage in new[] { "load", "initialization", "metadata", "contract" })
        candidates.Add(new JsonObject { ["candidate_id"] = "failure:" + stage, ["name"] = "config", ["origin"] = "plugin", ["status"] = stage + "_error",
            ["package"] = new JsonObject { ["name"] = "broken-plugin" },
            ["error"] = new JsonObject { ["stage"] = stage, ["error_type"] = stage == "contract" ? null : "ValueError", ["message"] = "PRIVATE raw source token C:/private/secret.py" } });
    candidates.Add(new JsonObject { ["candidate_id"] = "policy", ["name"] = "third-party", ["origin"] = "plugin", ["status"] = "skipped_policy", ["package"] = new JsonObject { ["name"] = "third-party-plugin" }, ["error"] = null });
    fixture["analyzer_catalog"]!["discovery_errors"] = new JsonArray(new JsonObject { ["stage"] = "entry_points", ["error_type"] = "RuntimeError", ["message"] = "PRIVATE enumeration text" });
});
var discoveryFailurePicker = new AnalyzerSelectionModel(); discoveryFailurePicker.LoadDiscovery(discoveryFailureFixture);
discoveryFailurePicker.ValidateForScan();
Check(discoveryFailurePicker.DiscoveryIssues.Count == 6 && discoveryFailurePicker.CatalogError == null, "candidate and enumeration failures remain distinct from empty discovery");
Check(discoveryFailurePicker.DiscoveryIssues.Select(item => item.Status).SequenceEqual(new[] { "load_error", "initialization_error", "metadata_error", "contract_error", "skipped_policy", "entry_points_error" }), "load initialization metadata contract policy and enumeration reasons retained");
Check(discoveryFailurePicker.DiscoveryIssues.Single(item => item.Status == "load_error").Summary.Contains("load/ValueError") && discoveryFailurePicker.DiscoveryIssues.Single(item => item.Status == "skipped_policy").Reason.Contains("trusted analyzer policy"), "safe error type and explicit policy reason shown");
Check(discoveryFailurePicker.DiscoveryIssues.All(item => !item.Summary.Contains("PRIVATE") && !item.Summary.Contains("C:/")), "raw discovery exception text never rendered");
Check(discoveryFailurePicker.Rows().Count == 6 && discoveryFailurePicker.Rows().Single(item => item.Name == "config").OriginSummary!.StartsWith("Built-in"), "failed same-name plugin is separate from usable built-in inventory");
discoveryFailurePicker.Restore("third-party"); Reject(discoveryFailurePicker.ValidateForScan, "policy skipped candidate cannot become selectable usable inventory");
Check(discoveryFailurePicker.Rows().Single(item => item.Name == "third-party").Missing && discoveryFailurePicker.DiscoveryIssues.Count == 6, "saved unavailable selection and exact discovery reason both retained");
discoveryFailurePicker.EngineChanged(); Check(discoveryFailurePicker.DiscoveryIssues.Count == 0, "engine change clears stale discovery failure records");
discoveryFailurePicker.LoadDiscovery(discoveryFailureFixture); discoveryFailurePicker.LoadDiscovery(profileDiscovery);
Check(discoveryFailurePicker.DiscoveryIssues.Count == 0, "discovery refresh clears previous failure records");
discoveryFailurePicker.LoadDiscovery(ProfileFixture(fixture =>
{
    fixture["analyzer_catalog"]!["candidates"]!.AsArray().Add(new JsonObject { ["name"] = "C:/PRIVATE/source.py", ["status"] = "load_error", ["package"] = new JsonObject { ["name"] = "file:///PRIVATE/pkg.whl" }, ["error"] = new JsonObject { ["stage"] = "load", ["error_type"] = "ValueError" } });
}));
Check(discoveryFailurePicker.DiscoveryIssues.Single().Name == "Analyzer name unavailable" && discoveryFailurePicker.DiscoveryIssues.Single().Package == "package unknown", "path-shaped candidate metadata is not rendered");
foreach (Action<JsonObject> corrupt in new Action<JsonObject>[] {
    fixture => fixture["analyzer_catalog"]!["candidates"]![2]!["error"]!["stage"] = "metadata",
    fixture => fixture["analyzer_catalog"]!["candidates"]![2]!["error"]!["error_type"] = "PRIVATE secret value",
    fixture => fixture["analyzer_catalog"]!["discovery_errors"] = JsonNode.Parse("[" + string.Join(",", Enumerable.Repeat("{\"stage\":\"entry_points\",\"error_type\":\"ValueError\"}", 65)) + "]")
})
{
    var malformed = JsonNode.Parse(discoveryFailureFixture)!.AsObject(); corrupt(malformed);
    discoveryFailurePicker.LoadDiscovery(malformed.ToJsonString());
    Check(discoveryFailurePicker.CatalogError != null && discoveryFailurePicker.DiscoveryIssues.Count == 0, "malformed or oversized discovery failure details cannot publish partial or stale records");
}
profilePicker.SelectProfile("node-atproto@1.0"); profilePicker.ValidateForScan();
string expandedProfile = profilePicker.ExpandedProfileModules;
Check(profilePicker.RequestProfile == "node-atproto@1.0" && profilePicker.RequestModules == "" && !profilePicker.Automatic && expandedProfile.Split(',').Length == 6, "named profile emits identity separately and retains expanded bases");
Check(profilePicker.Profiles.Single(item => item.Name == "node-atproto").ExperimentalModuleNames.Count == 3 && profilePicker.Profiles.Single(item => item.Name == "node-atproto").OptInModuleNames.Count == 2, "experimental and opt-in selection flags retained");
profilePicker.Select("config", false); profilePicker.ValidateForScan();
Check(profilePicker.SelectedProfile == null && profilePicker.RequestProfile == null && !profilePicker.Automatic && profilePicker.RequestModules.Split(',').Length == 5 && !profilePicker.RequestModules.Split(',').Contains("config"), "manual override becomes exact Custom without adding bases");
profilePicker.SetAutomatic(true); profilePicker.ValidateForScan(); Check(profilePicker.RequestProfile == null && profilePicker.RequestModules == "", "Automatic sends neither explicit modules nor named profile");
var restoredProfilePicker = new AnalyzerSelectionModel(); restoredProfilePicker.RestoreProfile("node-atproto@1.0", expandedProfile);
Reject(restoredProfilePicker.ValidateForScan, "restored named profile requires fresh inventory");
restoredProfilePicker.LoadDiscovery(profileDiscovery); restoredProfilePicker.ValidateForScan();
Check(restoredProfilePicker.RequestProfile == "node-atproto@1.0" && restoredProfilePicker.ExpandedProfileModules == expandedProfile, "qualified identity and saved expansion restored");
restoredProfilePicker.RestoreProfile("node-atproto@1.0", "config"); Reject(restoredProfilePicker.ValidateForScan, "changed same-version saved membership is stale");
Check(restoredProfilePicker.RequestProfile == "node-atproto@1.0" && restoredProfilePicker.ProfileSelectionError!.Contains("stale"), "stale profile never downgrades to Custom or Automatic");
restoredProfilePicker.LoadDiscovery(profileDiscovery); Reject(restoredProfilePicker.ValidateForScan, "discovery refresh cannot silently accept changed saved expansion");
restoredProfilePicker.SelectProfile("node-atproto@1.0"); restoredProfilePicker.ValidateForScan();
restoredProfilePicker.EngineChanged(); Reject(restoredProfilePicker.ValidateForScan, "engine change invalidates profile inventory");
Check(restoredProfilePicker.RequestProfile == "node-atproto@1.0" && restoredProfilePicker.Rows("invisible").Count == 6 && restoredProfilePicker.Rows().All(item => item.Missing), "engine change retains identity and all selected missing modules under filters");
restoredProfilePicker.LoadDiscovery(profileDiscovery); restoredProfilePicker.ValidateForScan();
foreach (string missingProfile in new[] { "removed@1.0", "node-atproto@2.0", "automatic@2.0" })
{
    restoredProfilePicker.RestoreProfile(missingProfile, expandedProfile); Reject(restoredProfilePicker.ValidateForScan, "missing saved profile or version blocked " + missingProfile);
    Check(restoredProfilePicker.RequestProfile == missingProfile && !restoredProfilePicker.Automatic, "missing profile is retained without fallback " + missingProfile);
}
string missingLayerFixture = ProfileFixture(fixture =>
{
    fixture["modules"]!.AsArray().RemoveAt(3);
    var named = fixture["analyzer_profiles"]!["profiles"]![1]!;
    named["available"] = false; named["missing_module_names"] = new JsonArray("atproto");
    named["installed_experimental_module_names"] = new JsonArray("node-service", "node-atproto");
    named["opt_in_module_names"] = new JsonArray("node-service");
});
profilePicker.LoadDiscovery(missingLayerFixture); profilePicker.SelectProfile("node-atproto@1.0");
Reject(profilePicker.ValidateForScan, "available named definition missing a required plugin blocked");
Check(profilePicker.ProfileSelectionError!.Contains("atproto") && profilePicker.Rows("no match").Single().Name == "atproto", "missing profile layer visible through filter");
string oldCapabilities = ProfileFixture(fixture => { fixture.Remove("analyzer_profiles"); fixture.Remove("analyzer_catalog"); });
profilePicker.LoadDiscovery(oldCapabilities); Reject(profilePicker.ValidateForScan, "older engine cannot silently restore named profile");
profilePicker.SetAutomatic(true); profilePicker.ValidateForScan();
profilePicker.Restore("config"); profilePicker.ValidateForScan(); Check(profilePicker.RequestModules == "config", "older capabilities retain Automatic and exact Custom compatibility");
foreach (Action<JsonObject> corrupt in new Action<JsonObject>[] {
    fixture => fixture["analyzer_profiles"]!["schema_version"] = "2.0",
    fixture => fixture["analyzer_profiles"]!["profiles"]!.AsArray().Add(fixture["analyzer_profiles"]!["profiles"]![1]!.DeepClone()),
    fixture => fixture["analyzer_profiles"]!["profiles"]![1]!["available"] = false,
    fixture => fixture["analyzer_profiles"]!["profiles"]![1]!["expanded_module_names"] = new JsonArray("config"),
    fixture => fixture["analyzer_profiles"]!["profiles"]![1]!["module_names"] = new JsonArray("config", "config"),
    fixture => fixture["analyzer_profiles"]!["profiles"]![1]!["installed_experimental_module_names"] = new JsonArray("config"),
    fixture => fixture["analyzer_profiles"]!["profiles"]![1]!["qualified_name"] = "node-atproto@9.0",
    fixture => fixture["analyzer_profiles"]!["profiles"]![1]!["display_name"] = "bad\nlabel",
})
{
    var invalidProfiles = new AnalyzerSelectionModel(); invalidProfiles.LoadDiscovery(ProfileFixture(corrupt));
    Check(invalidProfiles.DiscoveryError == null && invalidProfiles.ProfileCatalogError != null && invalidProfiles.Profiles.Count == 0, "malformed optional profile catalog isolated from installed inventory");
    invalidProfiles.ValidateForScan(); invalidProfiles.Restore("config"); invalidProfiles.ValidateForScan();
    invalidProfiles.RestoreProfile("node-atproto@1.0", expandedProfile); Reject(invalidProfiles.ValidateForScan, "malformed profile catalog blocks named restore");
}
var invalidProvenance = new AnalyzerSelectionModel();
invalidProvenance.LoadDiscovery(ProfileFixture(fixture => fixture["analyzer_catalog"]!["candidates"]![1]!["shadowed_by"] = "other:config"));
Check(invalidProvenance.CatalogError != null && invalidProvenance.Rows().All(item => item.OriginSummary == null), "malformed shadowing cannot publish partial provenance");
invalidProvenance.SelectProfile("node-atproto@1.0"); invalidProvenance.ValidateForScan();
Reject(() => profilePicker.RestoreProfile("node-atproto", expandedProfile), "profile restore requires version");
Reject(() => profilePicker.SelectProfile("<script>@1.0"), "hostile profile identity rejected");
var oversizedProfiles = new AnalyzerSelectionModel(); oversizedProfiles.LoadDiscovery(new string(' ', 4 * 1024 * 1024 + 1));
Check(oversizedProfiles.DiscoveryError != null, "oversized profile capability payload bounded");
const string reportLedger = """
{"schema_version":"1.0","scope":"analyzer_selection_and_execution","inventory_scope":"supplied_candidates","selection_mode":"explicit","profile_id":"node-atproto@1.0","resolution_complete":true,"execution_complete":true,"entries":[
 {"name":"config","version":"9.0","priority":30,"origin":"plugin","implementation_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","selection":"selected","applicability":"applicable","execution":"succeeded","analysis_started":true,"execution_mode":"in_process","skip_reason":null,"error":null},
 {"name":"atproto","version":"0.1","origin":"plugin","implementation_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","selection":"skipped","applicability":"unmatched","execution":"skipped","analysis_started":false,"execution_mode":null,"skip_reason":"unmatched","error":null},
 {"name":"node-service","version":"0.1","origin":"plugin","implementation_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","selection":"selected","applicability":"applicable","execution":"failed","analysis_started":null,"execution_mode":"isolated","skip_reason":null,"error":{"stage":"isolated_host","error_type":"HostFailure"}},
 {"name":"broken-detect","version":null,"origin":"supplied","implementation_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","selection":"skipped","applicability":"detect_error","execution":"skipped","analysis_started":false,"execution_mode":null,"skip_reason":"detect_error","error":{"stage":"detect","error_type":"ValueError"}},
 {"name":"opt-in","version":"0.1","origin":"plugin","implementation_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","selection":"skipped","applicability":"applicable","execution":"skipped","analysis_started":false,"execution_mode":null,"skip_reason":"opt_in","error":null},
 {"name":"deadline","version":"0.1","origin":"builtin","implementation_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","selection":"selected","applicability":"applicable","execution":"skipped","analysis_started":false,"execution_mode":null,"skip_reason":"pipeline_deadline","error":null}]}
""";
void ApplyLedger(AnalyzerSelectionModel target, string fixture, string label = "Report C:/other/repository · generation 7")
{
    using var document = JsonDocument.Parse(fixture); target.SetRunLedger(document.RootElement, label);
}
string LedgerFixture(Action<JsonObject> change)
{
    var fixture = JsonNode.Parse(reportLedger)!.AsObject(); change(fixture); return fixture.ToJsonString();
}
var ledgerPicker = new AnalyzerSelectionModel(); ledgerPicker.LoadDiscovery(profileDiscovery); ApplyLedger(ledgerPicker, reportLedger);
Check(ledgerPicker.RunLedgerRows.Count == 6 && ledgerPicker.RunLedgerLabel.Contains("other/repository"), "ledger bound to selected report label");
Check(ledgerPicker.RunLedgerRows.Single(item => item.Name == "config").Origin.StartsWith("plugin") && ledgerPicker.Rows().Single(item => item.Name == "config").OriginSummary!.StartsWith("Built-in"), "same name in different report never joined to current implementation");
Check(ledgerPicker.RunLedgerRows.Single(item => item.Name == "node-service").AnalysisStarted == "unknown" && ledgerPicker.RunLedgerRows.Single(item => item.Name == "node-service").Error == "isolated_host/HostFailure", "isolated host failure does not claim analysis started");
Check(ledgerPicker.RunLedgerNotice.Contains("1 succeeded, 1 failed, 4 skipped") && ledgerPicker.RunLedgerNotice.Contains("does not prove full coverage"), "terminal outcomes never reported as all-success coverage");
Check(ledgerPicker.RunLedgerRows.Single(item => item.Name == "broken-detect").Applicability == "detect_error" && ledgerPicker.RunLedgerRows.Single(item => item.Name == "atproto").Applicability == "unmatched", "detect failure remains distinct from unmatched");
Check(ledgerPicker.RunLedgerRows.Single(item => item.Name == "opt-in").SkipReason == "opt_in" && ledgerPicker.RunLedgerRows.Single(item => item.Name == "deadline").SkipReason == "pipeline_deadline", "opt-in and deadline skip remain distinct");
ledgerPicker.EngineChanged(); Check(ledgerPicker.RunLedgerRows.Count == 6 && ledgerPicker.Rows().Count == 0, "engine inventory invalidation does not rewrite separate report observations");
ApplyLedger(ledgerPicker, LedgerFixture(fixture => { fixture["inventory_scope"] = "registered_candidates"; fixture["selection_mode"] = "automatic"; fixture["profile_id"] = null; fixture["execution_complete"] = false; }));
Check(ledgerPicker.RunLedgerNotice.Contains("registered_candidates") && ledgerPicker.RunLedgerNotice.Contains("terminal outcomes incomplete"), "registered scope and incomplete report decisions accepted without success inference");
foreach (Action<JsonObject> corruptLedger in new Action<JsonObject>[] {
    fixture => fixture["schema_version"] = "9.0",
    fixture => fixture["inventory_scope"] = "all-installed-and-executed",
    fixture => fixture["execution_complete"] = "true",
    fixture => fixture["entries"]![0]!["execution"] = "done",
    fixture => fixture["entries"]![0]!["analysis_started"] = false,
    fixture => fixture["entries"]![0]!["implementation_sha256"] = "invalid",
    fixture => fixture["entries"]![2]!["error"]!["error_type"] = "<raw secret error text>",
})
{
    ApplyLedger(ledgerPicker, LedgerFixture(corruptLedger));
    Check(ledgerPicker.RunLedgerRows.Count == 0 && ledgerPicker.RunLedgerNotice.Contains("unavailable or incompatible"), "malformed ledger clears previous rows and remains unknown");
}
ApplyLedger(ledgerPicker, LedgerFixture(fixture =>
{
    var repeated = fixture["entries"]![0]!.DeepClone();
    repeated["execution"] = "failed"; repeated["error"] = new JsonObject { ["stage"] = "analysis", ["error_type"] = "ValueError" };
    fixture["entries"]!.AsArray().Add(repeated);
}));
Check(ledgerPicker.RunLedgerRows.Count == 7 && ledgerPicker.RunLedgerRows[0].Name == "config" && ledgerPicker.RunLedgerRows[6].Name == "config", "repeated direct API analyzer invocations retained in ledger order");
Check(ledgerPicker.RunLedgerRows[0].Execution == "succeeded" && ledgerPicker.RunLedgerRows[6].Execution == "failed" && ledgerPicker.RunLedgerNotice.Contains("1 succeeded, 2 failed, 4 skipped"), "same analyzer name never merges separate recorded invocation outcomes");
ApplyLedger(ledgerPicker, reportLedger); ledgerPicker.SetRunLedger(null, "Older selected report");
Check(ledgerPicker.RunLedgerRows.Count == 0 && ledgerPicker.RunLedgerLabel == "Older selected report" && ledgerPicker.RunLedgerNotice.Contains("unknown"), "older report without ledger cannot retain prior execution claims");
string DetailedLedger(Action<JsonObject>? change = null) => LedgerFixture(fixture =>
{
    fixture["schema_version"] = "1.1";
    foreach (var entry in fixture["entries"]!.AsArray())
    {
        entry!["detect_duration_ms"] = null; entry["analysis_duration_ms"] = null;
        entry["signal_counts"] = null; entry["lifecycle_events"] = new JsonArray();
    }
    var first = fixture["entries"]![0]!;
    first["detect_duration_ms"] = 0.25; first["analysis_duration_ms"] = 12.5;
    first["signal_counts"] = JsonNode.Parse("""{"routes":3,"external_calls":2,"databases":1,"auth_hints":4,"secret_hints":0}""");
    first["lifecycle_events"] = JsonNode.Parse("""[{"stage":"detect","state":"started","elapsed_ms":0},{"stage":"selection","state":"selected","elapsed_ms":0.25},{"stage":"analysis","state":"requested","elapsed_ms":1},{"stage":"analysis","state":"succeeded","elapsed_ms":13.5}]""");
    change?.Invoke(fixture);
});
ApplyLedger(ledgerPicker, DetailedLedger());
Check(ledgerPicker.RunLedgerRows.Count == 6 && ledgerPicker.RunLedgerRows[0].DetectDurationMs == 0.25 && ledgerPicker.RunLedgerRows[0].AnalysisDurationMs == 12.5, "detailed ledger preserves observed durations");
Check(ledgerPicker.RunLedgerRows[0].SignalSummary.Contains("routes: 3") && ledgerPicker.RunLedgerRows[0].Lifecycle.Count == 4 && ledgerPicker.RunLedgerRows[0].Lifecycle[2].Contains("requested"), "detailed ledger presents premerge counts and isolated request distinctly");
Check(ledgerPicker.RunLedgerRows[1].AnalysisDurationMs == null && ledgerPicker.RunLedgerRows[1].SignalSummary.Contains("not recorded"), "missing observations never become zero or success");
foreach (Action<JsonObject> corrupt in new Action<JsonObject>[] {
    fixture => fixture["entries"]![0]!["detect_duration_ms"] = -1,
    fixture => fixture["entries"]![0]!["analysis_duration_ms"] = "NaN",
    fixture => fixture["entries"]![0]!["signal_counts"]!["routes"] = -1,
    fixture => fixture["entries"]![0]!["lifecycle_events"]![3]!["elapsed_ms"] = 0.1,
    fixture => fixture["entries"]![0]!["lifecycle_events"]![3]!["error_type"] = "raw secret\ntext",
    fixture => fixture["entries"]![0]!.AsObject().Remove("lifecycle_events"),
})
{
    ApplyLedger(ledgerPicker, DetailedLedger(corrupt));
    Check(ledgerPicker.RunLedgerRows.Count == 0 && ledgerPicker.RunLedgerNotice.Contains("incompatible"), "invalid detailed ledger clears previous observations");
}
ApplyLedger(ledgerPicker, reportLedger);
Check(ledgerPicker.RunLedgerRows.Count == 6 && ledgerPicker.RunLedgerRows[0].DetectDurationMs == null && ledgerPicker.RunLedgerRows[0].Lifecycle.Count == 0, "schema1.0 remains readable without invented timing");
if (args.Length > 0)
{
    string folder = Path.Combine(Path.GetTempPath(), "attackmap-wp006-callback-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(folder);
    var snapshots = new List<EngineProgressSnapshot>(); int completedCalls = 0; RunIdentity? identity = null;
    await new EngineSession().Run(Path.GetFullPath(args[0]), folder, folder, 7, _ => { }, _ => { completedCalls++; return Task.CompletedTask; }, started: value => identity = value, modules: "ordering", structuredProgress: snapshots.Add);
    Check(snapshots.Count == 3 && snapshots.Select(x => x.Revision).SequenceEqual(new long[] { 1, 3, 5 }), "structured callbacks only accepted revisions");
    Check(identity != null && snapshots.All(x => x.RunId == identity.RunId && x.Repository == folder && x.Generation == 7), "structured callbacks bound to started identity");
    Check(snapshots.Take(2).All(x => !x.Terminal) && snapshots.Last().Terminal && completedCalls == 1, "structured terminal distinct from stage progress/artifact callback");
    Console.WriteLine("Actual EngineSession callback checked with childless ControlledFakeBroker; fixture directory: " + folder);
}
Console.WriteLine($"ScanProgress: {checks} checks passed; synthetic protocol/model/discovery only, no engine/provider process.");


