using System.Collections.Immutable;
using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using AttackMap.GraphExplorer;

int checks = 0;
var groups = new List<string>();
var context = new GraphContext("fixture-run", "generation-1", new string('a', 64), 7);
void Check(bool value, string message) { if (!value) throw new Exception(message); checks++; }
void Group(string name) { groups.Add(name); Console.WriteLine($"CHECK {name}"); }
GraphDocument Read(JsonObject json, GraphReadLimits? limits = null) => GraphReader.Read(Encoding.UTF8.GetBytes(json.ToJsonString()), context, limits);
void Reject(JsonObject json, string message, GraphReadLimits? limits = null)
{
    try { Read(json, limits); throw new Exception("ACCEPTED: " + message); }
    catch (GraphReadException) { checks++; }
}
JsonObject Node(string id, string kind, string? repo, string? parent, string? label = null) => new()
{
    ["id"] = id, ["kind"] = kind, ["repo_id"] = repo, ["parent_id"] = parent,
    ["label"] = label ?? id, ["evidence_refs"] = new JsonArray("ev:1")
};
JsonObject Edge(string id, string source, string target, string resolution = "resolved", string kind = "http_call", bool directed = true) => new()
{
    ["id"] = id, ["source"] = source, ["target"] = target, ["kind"] = kind,
    ["directed"] = directed, ["resolution"] = resolution, ["basis"] = "observed",
    ["confidence"] = 0.8, ["evidence_refs"] = new JsonArray("ev:1")
};
JsonObject Fixture(int servicesPerRepository = 2)
{
    var repositories = new JsonArray(); var nodes = new JsonArray(); var edges = new JsonArray();
    for (int i = 0; i < 16; i++)
    {
        string repo = $"repo:{i}";
        repositories.Add(new JsonObject { ["id"] = repo, ["repo_id"] = $"slug-{i}", ["requested_id"] = $"guid-{i}",
            ["root"] = $"C:/fleet/root-{i}/same-name", ["label"] = "same-name", ["status"] = "completed", ["snapshot_id"] = $"snapshot-{i}" });
        nodes.Add(Node(repo, "repository", repo, null));
        for (int j = 0; j < (i == 15 ? 0 : servicesPerRepository); j++) nodes.Add(Node($"s:{i}:{j}", i == 14 ? "component" : "service", repo, repo));
    }
    nodes.Add(Node("proxy:gateway", "external", null, null));
    edges.Add(Edge("edge:a-b1", "s:0:0", "s:1:0"));
    edges.Add(Edge("edge:b2-c", "s:1:1", "s:2:0"));
    edges.Add(Edge("edge:c-a", "s:2:0", "s:0:0"));
    edges.Add(Edge("edge:parallel", "s:0:1", "s:1:1"));
    edges.Add(Edge("edge:candidate", "s:0:0", "s:1:0", "candidate"));
    edges.Add(Edge("edge:reverse", "s:1:0", "s:0:0"));
    edges.Add(Edge("edge:local", "s:0:0", "s:0:1", "resolved", "calls"));
    edges.Add(Edge("edge:self", "s:2:0", "s:2:0"));
    edges.Add(Edge("edge:undirected", "s:0:0", "s:1:0", "resolved", "http_call", false));
    var proxy1 = Edge("edge:proxy-in", "s:0:0", "proxy:gateway", "via_proxy"); proxy1["proxy_leg"] = "client_to_proxy"; proxy1["relation_id"] = "relation:proxy";
    var proxy2 = Edge("edge:proxy-out", "proxy:gateway", "s:3:0", "via_proxy"); proxy2["proxy_leg"] = "proxy_to_service"; proxy2["relation_id"] = "relation:proxy";
    edges.Add(proxy1); edges.Add(proxy2);
    return new JsonObject { ["schema_version"] = "1.0", ["kind"] = "fleet_architecture", ["repositories"] = repositories,
        ["nodes"] = nodes, ["edges"] = edges,
        ["evidence"] = new JsonArray(new JsonObject { ["id"] = "ev:1", ["repo_id"] = "repo:0", ["kind"] = "source", ["file"] = "src/server.cs", ["line"] = 42, ["source_analyzer"] = "fixture" }),
        ["coverage"] = new JsonObject { ["http"] = "partial", ["rpc"] = "unanalysed", ["requested"] = 16 },
        ["limitations"] = new JsonArray("Synthetic contract fixture, not a scan. Independent child snapshots; no global atomic snapshot.") };
}
LayoutRequest Request(GraphProjection projection) => new(projection,
    projection.Nodes.Select(n => new NodeMeasure(n.Id, n.Original.Kind == "repository" ? 170 : 140, 46)).ToImmutableArray(),
    projection.Edges.Select(e => new EdgeMeasure(e.Id, 60, 18)).ToImmutableArray());

if (args.Contains("--compare-files"))
{
    var compareAdapter = new MsaglLayoutAdapter();
    foreach (string path in args.Where(x => !x.StartsWith("--", StringComparison.Ordinal)))
    {
        byte[] bytes = await File.ReadAllBytesAsync(path);
        string sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
        var timer = Stopwatch.StartNew();
        var model = GraphReader.Read(bytes, context with { ReportHash = sha256 });
        long readMs = timer.ElapsedMilliseconds;
        foreach (bool collapse in new[] { true, false })
        {
            timer.Restart();
            var projected = GraphProjection.Create(model, collapse ? model.Repositories.Select(x => x.Id) : null);
            long projectionMs = timer.ElapsedMilliseconds;
            var canonicalIds = projected.Edges.SelectMany(x => x.UnderlyingEdgeIds).Concat(projected.Nodes.SelectMany(x => x.InternalEdgeIds)).Order();
            if (!canonicalIds.SequenceEqual(model.Edges.Select(x => x.Id).Order())) throw new Exception("Comparison projection lost an original edge.");
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            timer.Restart();
            string outcome, message = ""; double? width = null, height = null;
            try
            {
                var result = await compareAdapter.LayoutAsync(Request(projected), timeout.Token);
                outcome = "completed"; width = result.Bounds.Width; height = result.Bounds.Height;
            }
            catch (OperationCanceledException) { outcome = "cancelled_and_worker_awaited"; }
            catch (GraphReadException error) { outcome = "declined_explicit_bounds"; message = error.Message; }
            Console.WriteLine(JsonSerializer.Serialize(new { kind = "native-layout-same-input-comparison", file = Path.GetFileName(path), sha256,
                synthetic = true, bytes = bytes.Length, repositories = model.Repositories.Length, nodes = model.Nodes.Length, edges = model.Edges.Length,
                mode = collapse ? "all_repositories_collapsed" : "all_expanded", read_ms = readMs, projection_ms = projectionMs,
                visible_nodes = projected.Nodes.Length, visible_edges = projected.Edges.Length, original_edges_preserved = true,
                default_max_nodes = 1000, default_max_edges = 3000, deadline_ms = 15000, outcome, layout_or_decline_ms = timer.ElapsedMilliseconds,
                width, height, message, cumulative_process_working_set_bytes = Process.GetCurrentProcess().WorkingSet64,
                scope = "Layout worker only; no native render/interaction/GUI or release proof." }));
        }
    }
    return;
}

Group("16 repository identity, multi-service, library and disconnected groups");
var fixture = Fixture(); var document = Read(fixture);
Check(document.Repositories.Length == 16 && document.Repositories.Select(x => x.Id).Distinct().Count() == 16, "All 16 stable repository identities");
Check(document.Repositories.Select(x => x.Label).Distinct().Count() == 1 && document.Repositories.Select(x => x.Root).Distinct().Count() == 16, "Duplicate basenames do not merge roots");
Check(document.Nodes.Count(n => n.RepoId == "repo:1" && n.Kind == "service") == 2, "Multiple services remain distinct");
Check(document.Nodes.All(n => n.RepoId != "repo:14" || n.Kind != "service") && document.Nodes.Count(n => n.RepoId == "repo:15") == 1, "Library and orphan groups do not invent services");
Check(document.Repositories[3].RequestedId == "guid-3" && document.Repositories[3].RepoId == "slug-3", "Transport ID and slug retained separately");

Group("schema version, malformed JSON, duplicate JSON keys and bounded data");
var bad = Fixture(); bad["schema_version"] = "2.0"; Reject(bad, "schema");
Reject(Fixture(), "bytes", new(MaxBytes: 30)); Reject(Fixture(), "nodes", new(MaxNodes: 12)); Reject(Fixture(), "edges", new(MaxEdges: 2));
Reject(Fixture(), "repos", new(MaxRepositories: 15)); Reject(Fixture(), "strings", new(MaxStringCharacters: 4));
foreach (string input in new[] { "{", "{\"kind\":\"a\",\"kind\":\"b\"}" })
{ try { GraphReader.Read(Encoding.UTF8.GetBytes(input), context); throw new Exception("Malformed input accepted"); } catch (GraphReadException) { checks++; } }

Group("duplicate IDs, dangling endpoints and repository group completeness");
bad = Fixture(); bad["nodes"]!.AsArray().Add(bad["nodes"]![0]!.DeepClone()); Reject(bad, "duplicate node");
bad = Fixture(); bad["edges"]!.AsArray().Add(bad["edges"]![0]!.DeepClone()); Reject(bad, "duplicate edge");
bad = Fixture(); bad["repositories"]![1]!["id"] = "repo:0"; Reject(bad, "duplicate repo");
bad = Fixture(); bad["evidence"]!.AsArray().Add(bad["evidence"]![0]!.DeepClone()); Reject(bad, "duplicate evidence");
bad = Fixture(); bad["edges"]![0]!["target"] = "missing"; Reject(bad, "dangling endpoint");
bad = Fixture(); bad["nodes"]!.AsArray().RemoveAt(0); Reject(bad, "missing repository group");

Group("containment parent validation and semantic cycles");
bad = Fixture(); bad["nodes"]![1]!["parent_id"] = "missing"; Reject(bad, "dangling parent");
bad = Fixture(); bad["nodes"]![1]!["parent_id"] = "s:0:1"; bad["nodes"]![2]!["parent_id"] = "s:0:0"; Reject(bad, "parent cycle");
bad = Fixture(); bad["nodes"]![1]!["parent_id"] = "repo:1"; Reject(bad, "cross repo parent");
bad = Fixture(); bad["nodes"]![1]!["parent_id"] = "proxy:gateway"; Reject(bad, "owned node under external unknown owner");
Check(document.Edges.Any(x => x.Source == x.Target) && document.Edges.Any(x => x.Id == "edge:c-a"), "Cycles and self-loops accepted as semantic facts");

Group("unknown evidence and additive hostile label data are inert");
var unknown = Fixture(); unknown["nodes"]![1]!["evidence_refs"]!.AsArray().Add("ev:unknown");
unknown["new_additive_field"] = new JsonObject { ["data"] = "retained" }; unknown["nodes"]![1]!["label"] = "<script>fetch('https://hostile.invalid')</script>";
var unknownDoc = Read(unknown);
Check(unknownDoc.UnknownEvidenceRefs.SequenceEqual(new[] { "ev:unknown" }) && unknownDoc.Limitations.Any(x => x.Contains("unknown")), "Unknown evidence is explicit");
Check(unknownDoc.Nodes[1].Label.StartsWith("<script>") && unknownDoc.SourceJson.Contains("new_additive_field"), "Literal labels and additive metadata preserved");
Check(unknownDoc.Evidence[0].Data.GetProperty("line").GetInt32() == 42, "Evidence registry source remains exact");
bad = Fixture(); bad["evidence"]![0]!["file"] = new JsonObject(); Reject(bad, "invalid evidence file type");
bad = Fixture(); bad["evidence"]![0]!["line"] = "not-a-number"; Reject(bad, "invalid evidence line type");
bad = Fixture(); bad["evidence"]![0]!["line"] = -1; Reject(bad, "negative evidence line");
bad = Fixture(); bad["evidence"]![0]!["line"] = null; Check(Read(bad).Evidence[0].Line is null, "Unknown evidence line remains null");

Group("failed child state preserves successful siblings");
var partial = Fixture(); partial["repositories"]![15]!["status"] = "failed";
var partialDoc = Read(partial);
Check(partialDoc.Repositories.Count(x => x.Status == "completed") == 15 && partialDoc.Nodes.Any(x => x.Id == "repo:15"), "Failed child is visible alongside 15 completed siblings");
Check(!partialDoc.Edges.Any(x => x.Source == "repo:15" || x.Target == "repo:15"), "No fabricated connectivity for failure");

Group("reversible collapse and underlying identity conservation");
var overview = GraphProjection.Create(document, document.Repositories.Select(x => x.Id));
Check(overview.Nodes.Length == 17 && overview.HiddenNodeCount == 30, "16 collapsed groups plus explicit proxy");
Check(overview.Edges.SelectMany(x => x.UnderlyingEdgeIds).Concat(overview.Nodes.SelectMany(x => x.InternalEdgeIds)).Order().SequenceEqual(document.Edges.Select(x => x.Id).Order()), "Every canonical edge retained exactly once");
var expanded = GraphProjection.Create(document);
Check(expanded.Nodes.Length == document.Nodes.Length && expanded.Edges.SelectMany(x => x.UnderlyingEdgeIds).Order().SequenceEqual(document.Edges.Select(x => x.Id).Order()), "Expand restores canonical identities");
Check(document.SourceJson == Read(fixture).SourceJson, "Presentation never changes canonical JSON");

Group("aggregation separates kind, direction, resolution, proxy and relation legs");
var observed = overview.Edges.Single(x => x.Source == "repo:0" && x.Target == "repo:1" && x.Directed && x.Resolution == "resolved");
Check(observed.Count == 2 && observed.UnderlyingEdgeIds.Contains("edge:a-b1") && observed.UnderlyingEdgeIds.Contains("edge:parallel"), "Only compatible observed edges aggregate");
Check(overview.Edges.Any(x => x.Resolution == "candidate") && overview.Edges.Any(x => !x.Directed) && overview.Edges.Any(x => x.Source == "repo:1" && x.Target == "repo:0"), "Candidate, undirected and reverse edges remain separate");
Check(overview.Edges.Count(x => x.Proxy) == 2 && overview.Edges.Any(x => x.Target == "proxy:gateway") && overview.Edges.Any(x => x.Source == "proxy:gateway"), "Proxy intermediate never becomes direct edge");
Check(overview.Nodes.Single(x => x.Id == "repo:0").InternalEdgeIds.SequenceEqual(new[] { "edge:local" }), "Hidden internal counts remain accessible");
var ownedProxy = Fixture(); var ownedProxyNode = ownedProxy["nodes"]!.AsArray().Last()!;
ownedProxyNode["repo_id"] = "repo:0"; ownedProxyNode["parent_id"] = "repo:0"; ownedProxyNode["component_role"] = "proxy";
var ownedProxyOverview = GraphProjection.Create(Read(ownedProxy), document.Repositories.Select(x => x.Id));
Check(ownedProxyOverview.Nodes.Any(x => x.Id == "proxy:gateway") && ownedProxyOverview.Edges.Any(x => x.Source == "proxy:gateway") && ownedProxyOverview.Edges.Any(x => x.Target == "proxy:gateway"), "Parented explicit proxy survives repository collapse");

Group("aggregate path warning and exact canonical path verification");
Check(overview.PathNotice.Contains("does not prove") && !overview.IsContinuousCanonicalPath(new[] { "edge:a-b1", "edge:b2-c" }), "A->B->C overview does not invent internal flow across B");
Check(overview.IsContinuousCanonicalPath(new[] { "edge:b2-c", "edge:c-a", "edge:a-b1" }), "Exact endpoint continuity can be inspected");
Check(!overview.IsContinuousCanonicalPath(new[] { observed.Id }), "Aggregate ID cannot substitute for canonical edge ID");
Check(!overview.IsContinuousCanonicalPath(new[] { "edge:candidate" }), "Candidate relation cannot qualify a canonical path");

Group("nested collapse and deterministic projection");
var nested = Fixture(); nested["nodes"]!.AsArray().Add(Node("nested:component", "component", "repo:0", "s:0:0"));
var nestedDoc = Read(nested);
Check(GraphProjection.Create(nestedDoc, new[] { "repo:0", "s:0:0" }).VisibleNodeForOriginal["nested:component"] == "repo:0", "Outermost collapsed ancestor wins");
Check(GraphProjection.Create(document, new[] { "repo:1", "repo:0" }).Edges.Select(x => x.Id).SequenceEqual(GraphProjection.Create(document, new[] { "repo:0", "repo:1" }).Edges.Select(x => x.Id)), "Collapse order is deterministic");

Group("presentation resolution, inter-repository and one-hop neighborhood filters");
var filterFixture = Fixture();
filterFixture["edges"]![0]!["resolution"] = "observed";
filterFixture["edges"]![9]!["resolution"] = "observed_via_proxy"; filterFixture["edges"]![9]!["scope"] = "cross_repository";
filterFixture["edges"]![10]!["resolution"] = "observed_via_proxy"; filterFixture["edges"]![10]!["scope"] = "cross_repository";
var filterDoc = Read(filterFixture);
var observedFilter = GraphProjection.Create(filterDoc, filterDoc.Repositories.Select(x => x.Id), new(GraphResolutionFilter.Observed, true));
Check(observedFilter.Edges.Sum(x => x.Count) == 3 && observedFilter.Edges.Count(x => x.Proxy) == 2, "Observed filter preserves both qualified proxy legs");
Check(observedFilter.Edges.SelectMany(x => x.UnderlyingEdgeIds).Concat(observedFilter.Nodes.SelectMany(x => x.InternalEdgeIds)).Concat(observedFilter.FilteredEdgeIds).Order().SequenceEqual(filterDoc.Edges.Select(x => x.Id).Order()), "Filtering retains every excluded canonical edge ID");
var candidates = GraphProjection.Create(filterDoc, null, new(GraphResolutionFilter.Candidate));
Check(candidates.Edges.Length == 1 && candidates.Edges[0].UnderlyingEdgeIds[0] == "edge:candidate", "Exact candidate bucket");
var upstream = GraphProjection.Create(filterDoc, filterDoc.Repositories.Select(x => x.Id), new(Neighborhood: GraphNeighborhood.Upstream, FocusNodeId: "repo:1"));
Check(upstream.Edges.All(e => e.Target == "repo:1"), "Upstream is an explicit one-hop modeled neighborhood");
var downstream = GraphProjection.Create(filterDoc, filterDoc.Repositories.Select(x => x.Id), new(Neighborhood: GraphNeighborhood.Downstream, FocusNodeId: "repo:1"));
Check(downstream.Edges.All(e => e.Source == "repo:1"), "Downstream uses original endpoint membership");
Check(observedFilter.Document.Edges.Length == document.Edges.Length && observedFilter.Nodes.Length == overview.Nodes.Length, "All repository identity and canonical facts survive filtering");
var exportedFilter = JsonNode.Parse(GraphExporter.JsonWithMetadata(filterDoc, observedFilter))!;
Check(exportedFilter["edges"]!.AsArray().Count == filterDoc.Edges.Length && exportedFilter["export_metadata"]!["resolution_filter"]!.GetValue<string>() == "Observed", "Full JSON includes excluded facts and explicit filter metadata");

Group("actual MSAGL runtime binding and overview layout");
var adapter = new MsaglLayoutAdapter();
var overviewLayout = await adapter.LayoutAsync(Request(overview));
Check(overviewLayout.Nodes.Length == overview.Nodes.Length && overviewLayout.Edges.Length == overview.Edges.Length, "Actual solver preserves projected IDs/counts");
Check(overviewLayout.Edges.All(e => e.Segments.Length > 0), "Actual edge curves converted");
Check(overviewLayout.Nodes.All(n => overviewLayout.Bounds.Contains(n.Bounds)), "Bounds include every overview node");
Check(overviewLayout.Edges.Where(e => overview.Edges.Single(p => p.Id == e.Id).Directed).All(e => e.TargetArrow is not null), "Solver arrowheads preserved");

Group("actual cluster containment and Y-down layout geometry");
var detail = GraphProjection.Create(document, document.Repositories.Skip(2).Select(x => x.Id));
var detailLayout = await adapter.LayoutAsync(Request(detail));
foreach (var node in detailLayout.Nodes.Where(x => x.ParentId is not null))
    Check(detailLayout.Nodes.Single(x => x.Id == node.ParentId).Bounds.Contains(node.Bounds), "Expanded group contains its child");
Check(detailLayout.Nodes.All(n => n.Bounds.X >= 0 && n.Bounds.Y >= 0), "Y-down normalized coordinates");
foreach (var edge in detailLayout.Edges)
{
    foreach (var s in edge.Segments)
        foreach (var p in new LayoutPoint?[] { s.Start, s.End, s.Control1, s.Control2 }.OfType<LayoutPoint>())
            Check(detailLayout.Bounds.Contains(new(p.X, p.Y, 0, 0)), "Curve hull inside exported bounds");
    if (edge.LabelBounds is { } label) Check(detailLayout.Bounds.Contains(label), "Labels inside full graph bounds");
    foreach (var a in new[] { edge.TargetArrow, edge.SourceArrow }.OfType<LayoutArrow>())
        foreach (var p in new[] { a.Tip, a.Left, a.Right }) Check(detailLayout.Bounds.Contains(new(p.X, p.Y, 0, 0)), "Arrowhead bounds");
}

Group("orientation and stale publication identity");
var chainJson = Fixture(); chainJson["edges"] = new JsonArray(Edge("chain", "s:0:0", "s:1:0"));
var chain = GraphProjection.Create(Read(chainJson), document.Repositories.Select(x => x.Id));
var down = await adapter.LayoutAsync(Request(chain));
var right = await adapter.LayoutAsync(Request(chain) with { Direction = LayoutDirection.LeftToRight });
Check(down.Nodes.Single(x => x.Id == "repo:0").Bounds.Y < down.Nodes.Single(x => x.Id == "repo:1").Bounds.Y, "TD orientation is actual downward flow");
Check(right.Nodes.Single(x => x.Id == "repo:0").Bounds.X < right.Nodes.Single(x => x.Id == "repo:1").Bounds.X, "LR orientation is actual rightward flow");
Check(down.IsCurrent(context) && !down.IsCurrent(context with { GenerationId = "generation-2" }) && !down.IsCurrent(context with { SelectionRevision = 8 }) && !down.IsCurrent(context with { ReportHash = "changed" }), "Stale generation/revision/hash cannot publish");

Group("layout budgets and invalid measurements do not truncate facts");
try { await adapter.LayoutAsync(Request(detail) with { MaxNodes = 1 }); throw new Exception("Layout cap bypassed"); } catch (GraphReadException) { checks++; }
try { await adapter.LayoutAsync(Request(detail) with { NodeMeasures = [] }); throw new Exception("Missing measure accepted"); } catch (ArgumentException) { checks++; }
try { await adapter.LayoutAsync(Request(detail) with { NodeMeasures = Request(detail).NodeMeasures.SetItem(0, new(detail.Nodes[0].Id, double.NaN, 40)) }); throw new Exception("NaN accepted"); } catch (ArgumentException) { checks++; }
Check(document.Nodes.Length == 47 && document.Edges.Length == 11, "Full canonical graph remains intact after layout rejection");

Group("cancellation is awaited and subsequent layout remains usable");
using (var canceled = new CancellationTokenSource())
{
    canceled.Cancel();
    try { await adapter.LayoutAsync(Request(overview), canceled.Token); throw new Exception("Pre-cancel ignored"); } catch (OperationCanceledException) { checks++; }
}
var stressJson = Fixture(70); var stress = GraphProjection.Create(Read(stressJson));
using (var midflight = new CancellationTokenSource(TimeSpan.FromMilliseconds(25)))
{
    var timer = Stopwatch.StartNew();
    try { await adapter.LayoutAsync(Request(stress) with { MaxNodes = 1100 }, midflight.Token); throw new Exception("Expected stress cancellation"); }
    catch (OperationCanceledException) { checks++; Console.WriteLine($"CANCEL awaited worker completion in {timer.ElapsedMilliseconds} ms"); }
}
Check((await adapter.LayoutAsync(Request(overview))).Nodes.Length == 17, "Worker usable after cancellation completed");

Group("optional supplied canonical fixture parity");
foreach (string path in args.Where(x => !x.StartsWith("--", StringComparison.Ordinal)))
{
    var supplied = GraphReader.Read(await File.ReadAllBytesAsync(path), context);
    var collapsed = GraphProjection.Create(supplied, supplied.Repositories.Select(x => x.Id));
    Check(collapsed.Edges.SelectMany(x => x.UnderlyingEdgeIds).Concat(collapsed.Nodes.SelectMany(x => x.InternalEdgeIds)).Order().SequenceEqual(supplied.Edges.Select(x => x.Id).Order()), "Core fixture edge parity");
    var suppliedLayout = await adapter.LayoutAsync(Request(collapsed));
    Check(suppliedLayout.Nodes.Length == collapsed.Nodes.Length, "Core oracle actual collapsed layout");
    Check(collapsed.Edges.Any(e => e.Count == 2 && e.Resolution == "observed"), "Core oracle direct observed callsites aggregate");
    Check(collapsed.Edges.Where(e => e.Resolution == "via_proxy").All(e => e.Proxy), "Both core proxy legs retain proxy semantics");
    var someExpanded = GraphProjection.Create(supplied, supplied.Repositories.Skip(2).Select(x => x.Id));
    var expandedLayout = await adapter.LayoutAsync(Request(someExpanded));
    Check(expandedLayout.Nodes.Length == someExpanded.Nodes.Length && expandedLayout.Edges.Length == someExpanded.Edges.Length, "Core oracle expanded layout with containment edges");
    Check(GraphExporter.CanonicalJson(supplied) == Encoding.UTF8.GetString(await File.ReadAllBytesAsync(path)), "Complete source JSON exact export");
    XDocument.Parse(GraphExporter.Svg(collapsed, suppliedLayout)); checks++;
    Console.WriteLine($"CORE_FIXTURE repos={supplied.Repositories.Length} nodes={supplied.Nodes.Length} edges={supplied.Edges.Length} evidence={supplied.Evidence.Length}");
}
Group("inert complete SVG export and stale export rejection");
var hostileLayout = await adapter.LayoutAsync(Request(GraphProjection.Create(unknownDoc, unknownDoc.Repositories.Select(x => x.Id))));
string svg = GraphExporter.Svg(GraphProjection.Create(unknownDoc, unknownDoc.Repositories.Select(x => x.Id)), hostileLayout);
var xml = XDocument.Parse(svg);
Check(!xml.Descendants().Any(x => x.Name.LocalName is "script" or "foreignObject" or "image"), "SVG has no active or external content");
Check(xml.Descendants().Any(x => x.Name.LocalName == "metadata" && x.Value.Contains("generation-1")), "Full export includes identity/coverage metadata");
try { GraphExporter.Svg(overview, overviewLayout with { Context = context with { SelectionRevision = 100 } }); throw new Exception("Stale export accepted"); } catch (InvalidOperationException) { checks++; }

Group("latest layout request wins and dispose waits for worker termination");
await using (var session = new LayoutSession())
{
    var older = session.ReplaceAsync(Request(stress) with { MaxNodes = 1100 });
    var latest = session.ReplaceAsync(Request(overview));
    Check(await older is null, "Superseded request never publishes");
    Check((await latest)?.Nodes.Length == 17, "Latest request can publish after old worker ends");
}
var msagl = Assembly.Load("Microsoft.Msagl");
Console.WriteLine($"MSAGL_RUNTIME {msagl.FullName}; references={string.Join(';', msagl.GetReferencedAssemblies().Select(x => x.FullName))}");
Console.WriteLine($"PASS {checks} checks in {groups.Count} groups. Synthetic contract/actual local MSAGL layout only; no scans, provider calls, native UI or release acceptance.");

if (args.Contains("--benchmark") || args.Contains("--write-benchmarks-only"))
{
    foreach (var size in new[] { (Nodes: 100, Edges: 300), (Nodes: 1000, Edges: 3000), (Nodes: 10000, Edges: 30000) })
    {
        var corpus = Fixture(); var corpusNodes = new JsonArray(); var corpusEdges = new JsonArray();
        for (int i = 0; i < 16; i++) corpusNodes.Add(Node($"repo:{i}", "repository", $"repo:{i}", null));
        for (int i = 0; i < size.Nodes - 16; i++) corpusNodes.Add(Node($"bench:{i}", "service", $"repo:{i % 16}", $"repo:{i % 16}"));
        for (int i = 0; i < size.Edges; i++)
            corpusEdges.Add(Edge($"bench-edge:{i}", $"bench:{i % (size.Nodes - 16)}", $"bench:{(i * 13 + 1) % (size.Nodes - 16)}", i % 10 == 0 ? "candidate" : "observed", "dependency"));
        corpus["nodes"] = corpusNodes; corpus["edges"] = corpusEdges;
        var input = Encoding.UTF8.GetBytes(corpus.ToJsonString());
        string? outputOption = args.FirstOrDefault(x => x.StartsWith("--benchmark-dir=", StringComparison.Ordinal));
        if (outputOption is not null)
        {
            string outputDirectory = Path.GetFullPath(outputOption["--benchmark-dir=".Length..]);
            Directory.CreateDirectory(outputDirectory);
            await File.WriteAllBytesAsync(Path.Combine(outputDirectory, $"fleet16-{size.Nodes}-{size.Edges}.json"), input);
        }
        if (args.Contains("--write-benchmarks-only")) continue;
        var loadTimer = Stopwatch.StartNew();
        var model = GraphReader.Read(input, context);
        var overviewModel = GraphProjection.Create(model, model.Repositories.Select(x => x.Id));
        loadTimer.Stop();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var layoutTimer = Stopwatch.StartNew(); string result;
        try
        {
            var layout = await adapter.LayoutAsync(Request(overviewModel), timeout.Token);
            result = $"overview_ms={layoutTimer.ElapsedMilliseconds} extent={layout.Bounds.Width:0}x{layout.Bounds.Height:0}";
        }
        catch (OperationCanceledException) { result = $"overview_cancel_awaited_ms={layoutTimer.ElapsedMilliseconds}"; }
        Console.WriteLine($"BENCH synthetic_16_groups nodes={size.Nodes} edges={size.Edges} bytes={input.Length} read_projection_ms={loadTimer.ElapsedMilliseconds} visible_nodes={overviewModel.Nodes.Length} visible_edges={overviewModel.Edges.Length} {result} working_set_bytes={Process.GetCurrentProcess().WorkingSet64}");
        if (size.Nodes <= 1000)
        {
            using var detailTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            layoutTimer.Restart();
            try
            {
                var detailResult = await adapter.LayoutAsync(Request(GraphProjection.Create(model)), detailTimeout.Token);
                Console.WriteLine($"BENCH detail nodes={size.Nodes} edges={size.Edges} ms={layoutTimer.ElapsedMilliseconds} extent={detailResult.Bounds.Width:0}x{detailResult.Bounds.Height:0} working_set_bytes={Process.GetCurrentProcess().WorkingSet64}");
            }
            catch (OperationCanceledException) { Console.WriteLine($"BENCH detail nodes={size.Nodes} edges={size.Edges} cancel_awaited_ms={layoutTimer.ElapsedMilliseconds}"); }
        }
        else
        {
            try { await adapter.LayoutAsync(Request(GraphProjection.Create(model)), CancellationToken.None); throw new Exception("10k detail should exceed the explicit default layout bound"); }
            catch (GraphReadException) { Console.WriteLine("BENCH detail nodes=10000 edges=30000 declined_by_explicit_1000_3000_display_cap canonical_facts_retained=true"); }
        }
    }
}
