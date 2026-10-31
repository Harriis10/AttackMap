using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AttackMap.GraphExplorer;
using AttackMap.NativeSpike;

int checks = 0;
void Check(bool value, string reason) { checks++; if (!value) throw new InvalidOperationException(reason); }
bool Same(JsonElement left, JsonElement right) => JsonNode.DeepEquals(JsonNode.Parse(left.GetRawText()), JsonNode.Parse(right.GetRawText()));
var input = args.Length > 0 ? Path.GetFullPath(args[0]) : Path.Combine(Environment.CurrentDirectory, "artifacts/roadmap-batch-20261030/wp044");
var output = args.Length > 1 ? Path.GetFullPath(args[1]) : Path.Combine(Environment.CurrentDirectory, "artifacts/roadmap-closeout-20261030/native");
Directory.CreateDirectory(output);
var runs = new List<object>();
foreach (string mode in new[] { "serial", "parallel" })
{
    byte[] bytes = File.ReadAllBytes(Path.Combine(input, mode + "-architecture.json"));
    string hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    var generation = new FleetGeneration("mapping-" + mode, "fleet:synthetic-corpus", 1);
    var context = new GraphContext(generation.RunId, generation.RunId, hash, generation.Generation);
    var raw = GraphReader.Read(bytes, context);
    Check(raw.Repositories.Length == 16 && raw.UnknownEvidenceRefs.IsEmpty, "complete captured identities and evidence registry");
    Check(raw.Repositories.Count(repo => repo.Status == "partial") == 1, "partial relationship coverage retained");
    var edge = raw.Edges.Single(item => item.Kind == "shared_datastore");
    Check(!edge.Directed && edge.Resolution == "declared" && edge.Basis == "matching_explicit_qualified_resource_declarations", "owner assertion remains undirected and declared");
    Check(edge.Metadata.GetProperty("endpoints").GetArrayLength() == 2 && edge.Metadata.GetProperty("resource_id").GetString()!.StartsWith("datastore-resource-"), "qualified endpoint operations and resource retained");
    Check(edge.EvidenceRefs.Length == 2, "exactly two relationship evidence references");
    var rawSelection = new FleetGraphSelection(context, edge.Id, true, [], [edge.Id]);
    Check(FleetGraphEvidenceNavigation.BuildSourceRequest(raw, context, rawSelection, edge.EvidenceRefs[0], out _) == null, "unbound core identity cannot navigate as verified child");

    // Explicit harness child proofs exercise binding; they are not independent manifest verification.
    var workspace = new FleetWorkspace();
    var snapshots = new List<FleetSnapshotBinding>();
    int index = 0;
    foreach (var repo in raw.Repositories)
    {
        string requested = "mapping-child-" + index++;
        workspace.Add(requested, repo.Root);
        snapshots.Add(new(requested, new string('a', 64), repo.SnapshotId, "2026-10-30T00:00:00Z"));
    }
    workspace.Begin(generation);
    foreach (var repo in workspace.Repositories)
        Check(workspace.ApplyChild(generation, new(repo.RepositoryId, repo.RepositoryPath, "completed", Path.Combine(output, repo.RepositoryId + ".json"), new string('a', 64))), "explicit harness child accepted");
    Check(workspace.Finish(generation, "succeeded"), "harness generation terminal");
    var bound = FleetGraphBinding.Bind(bytes, context, workspace, snapshots);
    Check(Same(bound.Edges.Single(item => item.Id == edge.Id).Metadata, edge.Metadata), "binding leaves canonical relationship untouched");
    Check(bound.Nodes.Select(item => item.Id).SequenceEqual(raw.Nodes.Select(item => item.Id)) && bound.Nodes.Zip(raw.Nodes).All(pair => Same(pair.First.Metadata, pair.Second.Metadata)) && Same(bound.Coverage, raw.Coverage), "binding preserves nodes and coverage");
    var collapsed = GraphProjection.Create(bound, bound.Repositories.Select(repo => repo.Id));
    var declared = GraphProjection.Create(bound, bound.Repositories.Select(repo => repo.Id), new(GraphResolutionFilter.Declared, true));
    Check(declared.Edges.Length == 1 && declared.Edges[0].UnderlyingEdgeIds.SequenceEqual([edge.Id]), "declared inter-repository projection retains exact edge identity");
    Check(declared.Edges[0].Resolution == "declared" && !declared.Edges[0].Directed, "presentation does not promote declaration");
    Check(declared.FilteredEdgeCount == bound.Edges.Length - 1, "filtered count includes every excluded original edge");
    Check(declared.HiddenNodeCount == bound.Nodes.Length - declared.Nodes.Length, "hidden node count exact");
    Check(collapsed.HiddenInternalEdgeCount + collapsed.FilteredEdgeCount + collapsed.Edges.Sum(item => item.Count) == bound.Edges.Length, "collapse accounts for every canonical edge");
    Check(!declared.IsContinuousCanonicalPath([edge.Id]), "declaration is not a continuous directed path");
    foreach (var filter in new[] { GraphResolutionFilter.Observed, GraphResolutionFilter.Candidate, GraphResolutionFilter.Inferred })
        Check(!GraphProjection.Create(bound, filter: new(filter)).Edges.Any(item => item.UnderlyingEdgeIds.Contains(edge.Id)), "declared relation never enters other resolution filters");
    foreach (string endpoint in new[] { edge.Source, edge.Target })
        foreach (var direction in new[] { GraphNeighborhood.Upstream, GraphNeighborhood.Downstream })
            Check(GraphProjection.Create(bound, filter: new(GraphResolutionFilter.Declared, false, direction, endpoint)).Edges.Single().UnderlyingEdgeIds.SequenceEqual([edge.Id]), "undirected neighbour does not depend on arbitrary endpoint ordering");
    var selection = rawSelection with { PresentationId = declared.Edges[0].Id };
    Check(FleetGraphEvidenceNavigation.TryDescribe(bound, context, selection, out var detail, out _), "canonical edge inspector opens");
    var direct = detail!.Items.Where(item => !item.EndpointOnly).ToArray();
    Check(direct.Length == 2 && direct.Select(item => item.Id).Order().SequenceEqual(edge.EvidenceRefs.Order()), "two exact relationship records, no endpoint borrowing");
    Check(direct.Select(item => item.Side).Order().SequenceEqual(new[] { "Source repository", "Target repository" }.Order()), "both endpoint repository identities retained");
    var requests = direct.Select(item => FleetGraphEvidenceNavigation.BuildSourceRequest(bound, context, selection, item.Id, out _)).ToArray();
    Check(requests.All(request => request is { RelativePath: "config.json", Line: 5 }), "same file and exact object line on both sides");
    Check(requests.Select(request => request!.RepositoryRoot).Distinct(StringComparer.OrdinalIgnoreCase).Count() == 2, "equal filename and line do not merge roots");
    Check(requests.Select(request => request!.RequestedRepositoryId).Distinct().Count() == 2, "exact child identities remain distinct");
    foreach (var request in requests)
    {
        Check(FleetGraphEvidenceNavigation.TryValidate(bound, context, request!, out _), "source request validates before return");
        Check(FleetGraphEvidenceNavigation.SameSelection(selection, request!.Selection), "back retains canonical selection");
        Check(!FleetGraphEvidenceNavigation.TryValidate(bound, context with { SelectionRevision = 2 }, request, out _), "replaced generation rejects source and back");
        Check(!FleetGraphEvidenceNavigation.TryValidate(bound, context, request with { RepositoryRoot = requests.Single(other => other!.RepositoryRoot != request.RepositoryRoot)!.RepositoryRoot }, out _), "other same-basename root cannot replace source");
        Check(!FleetGraphEvidenceNavigation.TryValidate(bound, context, request with { Line = 6 }, out _), "changed exact source line rejected");
    }
    string exported = GraphExporter.JsonWithMetadata(bound, declared);
    var reread = GraphReader.Read(Encoding.UTF8.GetBytes(exported), context);
    Check(reread.Edges.Length == bound.Edges.Length && reread.Evidence.Length == bound.Evidence.Length, "filtered export retains entire canonical graph");
    Check(Same(reread.Edges.Single(item => item.Id == edge.Id).Metadata, edge.Metadata), "export preserves all declaration fields and exact evidence");
    using (var metadata = JsonDocument.Parse(exported))
        Check(metadata.RootElement.GetProperty("export_metadata").GetProperty("resolution_filter").GetString() == "Declared", "export records declared filter honestly");
    Check(GraphExporter.CanonicalJson(raw) == Encoding.UTF8.GetString(bytes), "canonical JSON byte text preserved");
    File.WriteAllText(Path.Combine(output, mode + "-mapped-export.json"), exported);
    runs.Add(new { mode, input_sha256 = hash, edge_id = edge.Id, resolution = edge.Resolution, directed = edge.Directed,
        source_requests = requests, repositories = bound.Repositories.Length, captured_edges = bound.Edges.Length,
        hidden_nodes = declared.HiddenNodeCount, hidden_internal_edges = declared.HiddenInternalEdgeCount, filtered_edges = declared.FilteredEdgeCount });
}
var result = new { result = "PASS", checks, corpus_kind = "retained production-pipeline output from synthetic physical 16-repository corpus",
    harness_child_proofs = "explicit synthetic binding inputs; not independent artifact verification", native_gui_acceptance = false,
    representative_production_fleet_acceptance = false, provider_calls = 0, runs };
File.WriteAllText(Path.Combine(output, "mapping-result.json"), JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine($"PASS {checks} production-JSON native mapping checks; no GUI, representative production fleet or release acceptance.");
