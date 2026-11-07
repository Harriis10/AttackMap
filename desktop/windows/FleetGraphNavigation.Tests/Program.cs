using System.Collections.Immutable;
using System.Text.Json;
using AttackMap.GraphExplorer;
using AttackMap.NativeSpike;

int checks = 0;
void Check(bool value, string name) { checks++; if (!value) throw new InvalidOperationException(name); }
JsonElement Json(object value) => JsonSerializer.SerializeToElement(value);
var context = new GraphContext("run-1", "generation-1", "summary-hash-1", 4);
var repos = ImmutableArray.Create(
    new GraphRepository("qualified-a", "same", "transport-a", @"C:\fixture-a\same", "same", "completed", "snapshot-a", "2026-10-23T09:00:00Z"),
    new GraphRepository("qualified-b", "same-2", "transport-b", @"C:\fixture-b\same", "same", "partial", "snapshot-b", "2026-10-23T09:01:00Z"));
var nodes = ImmutableArray.Create(
    new GraphNode("node-a", "service", "same", "qualified-a", null, ["endpoint-a"], Json(new { })),
    new GraphNode("node-b", "service", "same", "qualified-b", null, [], Json(new { })));
var edges = ImmutableArray.Create(
    new GraphEdge("edge-observed", "node-a", "node-b", "http", true, "observed", "core_contract_link", null, false, ["call-a", "route-b", "missing"], Json(new { })),
    new GraphEdge("edge-candidate", "node-a", "node-b", "http", true, "candidate", "core_contract_link", "low", false, ["call-a", "route-b"], Json(new { })));
GraphEvidence Evidence(string id, string? repo, string? file, object? line) => new(id, repo, Json(new { file, line, source_analyzer = "fixture", observation_id = id, basis = "supplied_static_source_location" }));
var records = ImmutableArray.Create(
    Evidence("call-a", "qualified-a", "src/client.cs", 12),
    Evidence("route-b", "qualified-b", "src/server.cs", null),
    Evidence("endpoint-a", "qualified-a", "src/host.cs", 3),
    Evidence("unrelated", "qualified-a", "src/unrelated.cs", 2));
var graph = new GraphDocument(context, repos, nodes, edges, records, Json(new { }), [], ["missing"], "{}");
var selection = new FleetGraphSelection(context, "aggregate-presentation", true, [], ["edge-observed", "edge-candidate"]);
Check(FleetGraphEvidenceNavigation.TryDescribe(graph, context, selection, out var detail, out _), "describe selected underlying edges");
Check(detail!.Edges.Select(edge => edge.Id).SequenceEqual(selection.EdgeIds), "underlying IDs preserved");
Check(detail.Edges.Select(edge => edge.Resolution).SequenceEqual(["observed", "candidate"]), "resolution preserved separately");
Check(detail.Items.Length == 4, "edge and endpoint references deduplicated without borrowing unrelated evidence");
Check(detail.Items.Single(item => item.Id == "call-a").Side == "Source repository", "source-side evidence label");
Check(detail.Items.Single(item => item.Id == "route-b").Side == "Target repository", "target-side evidence label");
Check(detail.Items.Single(item => item.Id == "call-a").RepositoryLabel.Contains(@"C:\fixture-a\same"), "same basename retains exact source root");
Check(detail.Items.Single(item => item.Id == "route-b").RepositoryLabel.Contains("qualified-b"), "qualified repository identity visible");
Check(detail.Items.Single(item => item.Id == "endpoint-a").EndpointOnly, "endpoint evidence does not become relationship evidence");
Check(detail.Items.Single(item => item.Id == "missing").Record == null, "unknown evidence remains explicit");
Check(detail.Items.Single(item => item.Id == "call-a").EdgeIds.Length == 2, "aggregate retains per-record edge association");
var source = FleetGraphEvidenceNavigation.BuildSourceRequest(graph, context, selection, "call-a", out string reason);
Check(source != null && reason == "", "source request");
Check(source!.GraphRepositoryId == "qualified-a" && source.RequestedRepositoryId == "transport-a" && source.RepositoryRoot == @"C:\fixture-a\same", "qualified root and transport never joined by basename");
Check(source.RelativePath == "src/client.cs" && source.Line == 12 && source.SnapshotId == "snapshot-a", "supplied file line and snapshot retained");
Check(FleetGraphEvidenceNavigation.TryValidate(graph, context, source, out _), "revalidation against current graph");
var server = FleetGraphEvidenceNavigation.BuildSourceRequest(graph, context, selection, "route-b", out _);
Check(server is { Line: null, RequestedRepositoryId: "transport-b", SnapshotId: "snapshot-b" }, "target file-only location keeps unknown line");
var sameFileGraph = graph with { Evidence = records.SetItem(1, Evidence("route-b", "qualified-b", "src/client.cs", 12)) };
var sameFileSource = FleetGraphEvidenceNavigation.BuildSourceRequest(sameFileGraph, context, selection, "call-a", out _);
var sameFileTarget = FleetGraphEvidenceNavigation.BuildSourceRequest(sameFileGraph, context, selection, "route-b", out _);
Check(sameFileSource is { GraphRepositoryId: "qualified-a", RequestedRepositoryId: "transport-a", RepositoryRoot: @"C:\fixture-a\same", RelativePath: "src/client.cs", Line: 12 }, "equal file and line retain source root identity");
Check(sameFileTarget is { GraphRepositoryId: "qualified-b", RequestedRepositoryId: "transport-b", RepositoryRoot: @"C:\fixture-b\same", RelativePath: "src/client.cs", Line: 12 }, "equal file and line retain target root identity");
Check(FleetGraphEvidenceNavigation.TryValidate(sameFileGraph, context, sameFileSource!, out _), "same-file source revalidates");
Check(FleetGraphEvidenceNavigation.TryValidate(sameFileGraph, context, sameFileTarget!, out _), "same-file target revalidates");
Check(!FleetGraphEvidenceNavigation.TryValidate(sameFileGraph, context, sameFileSource! with { GraphRepositoryId = sameFileTarget!.GraphRepositoryId, RequestedRepositoryId = sameFileTarget.RequestedRepositoryId, RepositoryRoot = sameFileTarget.RepositoryRoot, SnapshotId = sameFileTarget.SnapshotId, SnapshotAt = sameFileTarget.SnapshotAt }, out _), "equal file and line cannot substitute another repository identity");
Check(!FleetGraphEvidenceNavigation.TryValidate(sameFileGraph, context, sameFileTarget! with { EvidenceId = sameFileSource!.EvidenceId }, out _), "equal file and line cannot substitute another evidence ID");
Check(FleetGraphEvidenceNavigation.BuildSourceRequest(graph, context, selection, "unrelated", out _) == null, "unrelated registry record refused");
Check(FleetGraphEvidenceNavigation.BuildSourceRequest(graph, context, selection, "missing", out reason) == null && reason.Contains("unavailable"), "missing record cannot navigate");
foreach (var stale in new[] { context with { RunId = "other" }, context with { GenerationId = "other" }, context with { ReportHash = "other" }, context with { SelectionRevision = 5 } })
{
    Check(FleetGraphEvidenceNavigation.BuildSourceRequest(graph, stale, selection, "call-a", out _) == null, "stale host context refused");
    Check(!FleetGraphEvidenceNavigation.TryValidate(graph, stale, source, out _), "stale request refused");
    Check(!FleetGraphEvidenceNavigation.TryDescribe(graph, context, selection with { Context = stale }, out _, out _), "stale selection refused");
}
foreach (var altered in new[] {
    source with { Context = context with { RunId = "foreign" } }, source with { GraphRepositoryId = "qualified-b" },
    source with { RequestedRepositoryId = "transport-b" }, source with { RepositoryRoot = @"C:\fixture-b\same" },
    source with { RelativePath = "src/server.cs" }, source with { Line = 1 }, source with { SnapshotId = "foreign" },
    source with { SnapshotAt = null }, source with { EvidenceId = "unrelated" } })
    Check(!FleetGraphEvidenceNavigation.TryValidate(graph, context, altered, out _), "tampered source request refused");
Check(!FleetGraphEvidenceNavigation.TryDescribe(graph, context, selection with { EdgeIds = ["foreign"] }, out _, out _), "unknown canonical edge refused");
Check(!FleetGraphEvidenceNavigation.TryDescribe(graph, context, selection with { NodeIds = [], EdgeIds = [] }, out _, out _), "empty selection refused");
Check(FleetGraphEvidenceNavigation.SameSelection(selection, selection with { EdgeIds = selection.EdgeIds.ToArray().ToImmutableArray() }), "back selection semantic equality");
Check(!FleetGraphEvidenceNavigation.SameSelection(selection, selection with { EdgeIds = ["edge-observed"] }), "changed back selection refused");
foreach (string hostile in new[] { "../outside.cs", "src/../../outside.cs", @"..\outside.cs", @"C:\outside.cs", @"C:outside.cs", "/outside.cs", @"\\server\share\source.cs", @"\\?\C:\outside.cs", "https://example.com/a.cs", "file:///C:/outside.cs", "src/a.cs:stream", "src//a.cs", "src/./a.cs", "src/../a.cs", "src/a.cs\n", "src/a.cs\0", "src/<a>.cs", "src/a?.cs", "src/a*.cs", "src/CON", "src/con.txt", "src/LPT1.cs", "src/COM9", "src/COM¹.cs", "src/LPT².cs", "src/CONIN$", "src/CONOUT$", "src/CLOCK$", "src/a.cs.", "src/a.cs ", "src/ a.cs", new string('a', 2049) })
{
    var changed = graph with { Evidence = records.SetItem(0, Evidence("call-a", "qualified-a", hostile, 12)) };
    Check(FleetGraphEvidenceNavigation.BuildSourceRequest(changed, context, selection, "call-a", out _) == null, "hostile or outside-root source refused: " + hostile.Replace('\0', '?'));
}
foreach (string valid in new[] { "src/client.cs", @"src\client.cs", "src/český soubor.cs", "src/a&b.cs" })
{
    var changed = graph with { Evidence = records.SetItem(0, Evidence("call-a", "qualified-a", valid, 12)) };
    Check(FleetGraphEvidenceNavigation.BuildSourceRequest(changed, context, selection, "call-a", out _) != null, "bounded relative source accepted");
}
foreach (object? invalidOrUnknownLine in new object?[] { null, 0, -1, "12", long.MaxValue })
{
    var changed = graph with { Evidence = records.SetItem(0, Evidence("call-a", "qualified-a", "src/client.cs", invalidOrUnknownLine)) };
    Check(FleetGraphEvidenceNavigation.BuildSourceRequest(changed, context, selection, "call-a", out _) is { Line: null }, "unknown line never replaced with an invented value");
}
var noFile = graph with { Evidence = records.SetItem(0, Evidence("call-a", "qualified-a", null, null)) };
Check(FleetGraphEvidenceNavigation.BuildSourceRequest(noFile, context, selection, "call-a", out reason) == null && reason.Contains("No source file"), "record without source cannot navigate");
var noRepo = graph with { Evidence = records.SetItem(0, Evidence("call-a", null, "src/client.cs", 12)) };
Check(FleetGraphEvidenceNavigation.BuildSourceRequest(noRepo, context, selection, "call-a", out _) == null, "unknown repository cannot navigate");
foreach (var changedRepo in new[] { repos[0] with { RequestedId = null }, repos[0] with { Status = "failed" }, repos[0] with { Root = @"\\server\share" }, repos[0] with { Root = "relative/root" } })
    Check(FleetGraphEvidenceNavigation.BuildSourceRequest(graph with { Repositories = repos.SetItem(0, changedRepo) }, context, selection, "call-a", out _) == null, "unbound failed or unsafe child refused");
Check(FleetGraphEvidenceNavigation.BuildSourceRequest(graph with { Repositories = repos.SetItem(1, repos[1] with { Root = repos[0].Root }) }, context, selection, "call-a", out _) == null, "duplicate canonical root refused");
Check(FleetGraphEvidenceNavigation.BuildSourceRequest(graph with { Repositories = repos.SetItem(1, repos[1] with { RequestedId = repos[0].RequestedId }) }, context, selection, "call-a", out _) == null, "duplicate transport child refused");
foreach (string unsafeRoot in new[] { repos[0].Root + ".", repos[0].Root + " ", repos[0].Root + @".\", repos[0].Root + @" \", @"C:\fixture-a.\same", @"C:\fixture-a \same", @"C:\CON\same", @"C:\LPT1\same", @"C:\COM¹\same", @"C:\fixture-a\..\same" })
{
    var aliased = graph with { Repositories = repos.SetItem(0, repos[0] with { Root = unsafeRoot }) };
    Check(FleetGraphEvidenceNavigation.BuildSourceRequest(aliased, context, selection, "call-a", out _) == null, "ambiguous or device root component refused before canonicalization");
    Check(!FleetGraphEvidenceNavigation.TryValidate(graph, context, source with { RepositoryRoot = unsafeRoot }, out _), "forged aliased request root refused");
}
foreach (string duplicateAlias in new[] { repos[0].Root + ".", repos[0].Root + " ", repos[0].Root + @".\", repos[0].Root + @" \" })
{
    var aliased = graph with { Repositories = repos.SetItem(1, repos[1] with { Root = duplicateAlias }) };
    Check(FleetGraphEvidenceNavigation.BuildSourceRequest(aliased, context, selection, "call-a", out _) == null, "duplicate aliased root invalidates source repository join");
    Check(FleetGraphEvidenceNavigation.BuildSourceRequest(aliased, context, selection, "route-b", out _) == null, "duplicate aliased root cannot select target repository");
}
var noReferences = graph with { Nodes = nodes.SetItem(0, nodes[0] with { EvidenceRefs = [] }), Edges = edges.SetItem(0, edges[0] with { EvidenceRefs = [] }) };
Check(FleetGraphEvidenceNavigation.TryDescribe(noReferences, context, selection with { EdgeIds = ["edge-observed"] }, out var empty, out _) && empty!.Items.IsEmpty, "no supplied evidence is explicit empty");
var sameRepositoryEdge = graph with { Edges = edges.SetItem(0, edges[0] with { Target = "node-a" }) };
Check(FleetGraphEvidenceNavigation.TryDescribe(sameRepositoryEdge, context, selection with { EdgeIds = ["edge-observed"] }, out var sameRepository, out _) && sameRepository!.Items.Single(item => item.Id == "call-a").Side == "Source and target repository", "same-repository endpoint role explicit");
Console.WriteLine($"PASS {checks} focused graph evidence/navigation checks. Synthetic semantics only; no filesystem open, GUI or provider calls.");
