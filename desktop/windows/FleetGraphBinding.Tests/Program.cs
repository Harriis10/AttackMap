using AttackMap.NativeSpike;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text;
using AttackMap.GraphExplorer;

int checks = 0;
void Check(bool value, string reason) { checks++; if (!value) throw new Exception(reason); }
void Reject(Action action, string reason)
{
    try { action(); } catch (Exception e) when (e is InvalidDataException or IOException or ArgumentException) { checks++; return; }
    throw new Exception(reason);
}
var workspace = new FleetWorkspace();
string Root(int i) => i is 0 or 1 ? $@"C:\fleet16\owner{i}\same" : $@"C:\fleet16\service{i}";
string Id(int i) => $"transport-guid-{i:00}";
for (int i = 0; i < 16; i++) workspace.Add(Id(i), Root(i));
var generation = new FleetGeneration("fleet16-identity", "fleet:selected-set", 11);
workspace.Begin(generation);
FleetSummary Summary(bool partial = false) => new(
    Enumerable.Range(0, partial ? 15 : 16).Select(i => new FleetRepositorySummary($"core-slug-{i}", Root(i), i, default)).ToArray(),
    Array.Empty<FleetContractLink>(), Array.Empty<JsonElement>(), Array.Empty<JsonElement>(), Array.Empty<JsonElement>(), Array.Empty<JsonElement>());
Reject(() => FleetSummaryIdentityMap.Bind(workspace, Summary()), "Cannot bind before terminal.");
for (int i = 0; i < 16; i++)
    Check(workspace.ApplyChild(generation, new(Id(i), Root(i), "completed", $@"C:\owned\{i}\artifact-manifest.json", new string('a', 64))), "Child accepted.");
Check(workspace.Finish(generation, "succeeded"), "Fleet terminal accepted.");
var summary = Summary(); var map = FleetSummaryIdentityMap.Bind(workspace, summary);
for (int i = 0; i < 16; i++)
{
    Check(map.Resolve($"core-slug-{i}")?.Repository.RepositoryId == Id(i), "Slug resolves to correct transport ID.");
    Check(map.ResolveRoot(Root(i).ToUpperInvariant() + "\\")?.Repository.RepositoryId == Id(i), "Canonical exact root resolves.");
}
Check(map.Resolve("same") == null, "Basename never resolves as identity.");
Check(map.Resolve("transport-guid-00") == null, "GUID is not a core slug fallback.");
Check(map.ResolveRoot(@"C:\fleet16\unrelated\same") == null, "Equal basename in unrelated root rejected.");
Check(map.ResolveRoot(@"\\server\share") == null, "UNC source root rejected.");
Check(map.ResolveRoot("relative") == null, "Relative source root rejected.");
Reject(() => FleetSummaryIdentityMap.Bind(workspace, summary with { Repositories = summary.Repositories.Skip(1).ToArray() }), "Missing completed child rejected.");
Reject(() => FleetSummaryIdentityMap.Bind(workspace, summary with { Repositories = summary.Repositories.Append(summary.Repositories[0] with { RepositoryId = "different-slug" }).ToArray() }), "Duplicate root under another slug rejected.");
Reject(() => FleetSummaryIdentityMap.Bind(workspace, summary with { Repositories = summary.Repositories.Select((r,i) => i == 0 ? r with { Root = @"C:\other\same" } : r).ToArray() }), "Unrelated root rejected.");
Reject(() => FleetSummaryIdentityMap.Bind(workspace, summary with { Repositories = summary.Repositories.Select((r,i) => i == 1 ? r with { RepositoryId = "core-slug-0" } : r).ToArray() }), "Duplicate core slug rejected.");
workspace.Begin(generation with { Generation = 12 });
Check(map.Resolve("core-slug-0") == null && map.ResolveRoot(Root(0)) == null, "Previous generation map invalidated.");
var partial = new FleetWorkspace(); for (int i = 0; i < 16; i++) partial.Add(Id(i), Root(i));
partial.Begin(generation);
for (int i = 0; i < 16; i++) Check(partial.ApplyChild(generation, i == 15 ? new(Id(i), Root(i), "failed", null, null) : new(Id(i), Root(i), "completed", $@"C:\owned\{i}\artifact-manifest.json", new string('b',64))), "Partial child accepted.");
Check(partial.Finish(generation, "partial"), "Partial retained.");
var partialMap = FleetSummaryIdentityMap.Bind(partial, Summary(true));
Check(partialMap.Resolve("core-slug-14")?.Repository.RepositoryId == Id(14), "Successful sibling opens.");
Check(partialMap.ResolveRoot(Root(15)) == null, "Failed child never gains success proof.");
Reject(() => FleetSummaryIdentityMap.Bind(partial, Summary()), "Summary cannot claim failed child succeeded.");
foreach (int workers in new[] { 1, 2, 4 }) { new FleetExecutionOptions(7200, workers).Validate(); checks++; }
Reject(() => new FleetExecutionOptions(0, 1).Validate(), "Zero budget rejected.");
Reject(() => new FleetExecutionOptions(86401, 1).Validate(), "Unbounded budget rejected.");
Reject(() => new FleetExecutionOptions(600, 0).Validate(), "Zero worker rejected.");
Reject(() => new FleetExecutionOptions(600, 16).Validate(), "16 roots not 16 workers.");
Check(new FleetExecutionOptions().TimeoutSeconds == 600 && new FleetExecutionOptions().MaxWorkers == 1, "Existing defaults preserved.");
var oraclePath = Path.Combine(Environment.CurrentDirectory, "docs/verification/windows-parity/WP043/fleet16-20261023/core/fleet16-oracle.json");
byte[] oracleBytes = File.ReadAllBytes(oraclePath);
var oracle = JsonNode.Parse(oracleBytes)!.AsObject();
var graphWorkspace = new FleetWorkspace();
var snapshots = new List<FleetSnapshotBinding>();
int repoIndex = 0;
foreach (var node in oracle["repositories"]!.AsArray())
{
    string id = $"selected-{repoIndex++}", rootPath = node!["root"]!.GetValue<string>();
    graphWorkspace.Add(id, rootPath);
    snapshots.Add(new(id, new string('c',64), "snapshot-" + id, "2026-10-23T10:00:00Z"));
}
var graphGeneration = new FleetGeneration("actual-fleet-context", "fleet:selected-set", 19);
graphWorkspace.Begin(graphGeneration);
foreach (var requested in graphWorkspace.Repositories)
    graphWorkspace.ApplyChild(graphGeneration, new(requested.RepositoryId, requested.RepositoryPath, "completed", @"C:\owned\artifact-manifest.json", new string('c',64)));
graphWorkspace.Finish(graphGeneration, "succeeded");
var graphContext = new GraphContext(graphGeneration.RunId, graphGeneration.RunId, new string('d',64), graphGeneration.Generation);
var bound = FleetGraphBinding.Bind(oracleBytes, graphContext, graphWorkspace, snapshots);
Check(bound.Repositories.Length == 16 && bound.Nodes.Length == 40 && bound.Edges.Length == 34, "Binding preserves all canonical facts.");
Check(bound.Repositories.All(repo => repo.RequestedId!.StartsWith("selected-") && repo.SnapshotId == "snapshot-" + repo.RequestedId), "Snapshot binding by exact root.");
Reject(() => FleetGraphBinding.Bind(oracleBytes, graphContext with { SelectionRevision = 18 }, graphWorkspace, snapshots), "Stale generation rejected.");
Reject(() => FleetGraphBinding.Bind(oracleBytes, graphContext with { RunId = "other" }, graphWorkspace, snapshots), "Other run rejected.");
Reject(() => FleetGraphBinding.Bind(oracleBytes, graphContext, graphWorkspace, snapshots.Skip(1).ToArray()), "Missing snapshot proof rejected.");
Reject(() => FleetGraphBinding.Bind(oracleBytes, graphContext, graphWorkspace, snapshots.Select((row,i) => i == 0 ? row with { ManifestHash = new string('e',64) } : row).ToArray()), "Wrong child manifest rejected.");
byte[] Changed(Action<JsonObject> edit) { var copy = oracle.DeepClone().AsObject(); edit(copy); return Encoding.UTF8.GetBytes(copy.ToJsonString()); }
Reject(() => FleetGraphBinding.Bind(Changed(copy => copy["repositories"]![0]!["root"] = @"C:\unrelated\service"), graphContext, graphWorkspace, snapshots), "Equal basename root substitution rejected.");
Reject(() => FleetGraphBinding.Bind(Changed(copy => copy["repositories"]![0]!["status"] = "failed"), graphContext, graphWorkspace, snapshots), "Graph status cannot contradict child proof.");
Reject(() => FleetGraphBinding.Bind(Changed(copy => copy["repositories"]!.AsArray().RemoveAt(0)), graphContext, graphWorkspace, snapshots), "Missing requested group rejected.");
graphWorkspace.Begin(graphGeneration with { Generation = 20 });
Reject(() => FleetGraphBinding.Bind(oracleBytes, graphContext, graphWorkspace, snapshots), "In-flight replacement cannot acquire old graph.");
Console.WriteLine($"PASS {checks} fleet identity/budget/graph-binding checks; no native UI or fleet scan acceptance.");
