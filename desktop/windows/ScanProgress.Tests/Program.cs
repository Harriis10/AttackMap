using AttackMap.NativeSpike;
using System.Text.Json;
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


