const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const vm = require("node:vm");
const P = require("../projection.js");
const fixture = require("../synthetic-fixture.js");
const clone = value => JSON.parse(JSON.stringify(value));

test("16 repository groups retain exact qualified identities including failed and identical basenames", () => {
  const graph = fixture.create(), model = P.validateGraph(graph);
  const view = P.projectGraph(model, { collapsedIds: graph.repositories.map(repo => repo.id) });
  assert.equal(view.elements.filter(item => item.group === "nodes" && item.data.kind === "repository").length, 16);
  assert.notEqual(graph.repositories[0].id, graph.repositories[1].id);
  assert.equal(graph.repositories[0].label, graph.repositories[1].label);
  const failed = view.elements.find(item => item.data.canonicalId === graph.repositories[15].id);
  assert.equal(failed.data.status, "failed");
  assert.equal(view.groups.some(edge => edge.source === failed.data.canonicalId || edge.target === failed.data.canonicalId), false);
});

test("collapse is reversible and accounts for every underlying canonical edge without mutation", () => {
  const graph = fixture.create({ nodeCount: 1000, edgeCount: 3000 }), before = JSON.stringify(graph);
  const collapsedIds = graph.repositories.map(repo => repo.id), overview = P.projectGraph(graph, { collapsedIds });
  const represented = [...overview.groups.flatMap(group => group.underlyingIds), ...Object.values(overview.internalEdges).flat()];
  assert.deepEqual(represented.sort(), graph.edges.map(edge => edge.id).sort());
  assert.equal(new Set(represented).size, graph.edges.length);
  const expanded = P.projectGraph(graph), again = P.projectGraph(graph, { collapsedIds });
  assert.equal(expanded.counts.canonicalEdges, 3000); assert.equal(expanded.counts.canonicalNodes, 1000);
  assert.deepEqual(again, overview); assert.equal(JSON.stringify(graph), before);
});

test("aggregation separates opposite directions, boolean directed, observed/candidate, kind, basis and proxy legs", () => {
  const graph = fixture.create({ edgeCount: 4 });
  const source = graph.edges[2].source, target = graph.edges[2].target;
  const baseline = { id: "same", source, target, kind: "http", directed: true, resolution: "observed", leg: "direct", proxy: false, evidence_refs: [] };
  graph.edges = [{ ...baseline, relation_id: "direct-callsite-one" }, { ...baseline, id: "duplicate", relation_id: "direct-callsite-two" }, { ...baseline, id: "opposite", source: target, target: source }, { ...baseline, id: "candidate", resolution: "candidate" }, { ...baseline, id: "undirected", directed: false }, { ...baseline, id: "different-kind", kind: "queue" }, { ...baseline, id: "inferred", basis: "inferred" }, { ...baseline, id: "proxy-leg", proxy_leg: "first", relation_id: "relation" }, { ...baseline, id: "proxy-leg-two", proxy_leg: "second", relation_id: "relation" }];
  const view = P.projectGraph(graph, { collapsedIds: graph.repositories.map(repo => repo.id) });
  assert.equal(view.groups.length, 8);
  assert.deepEqual(view.groups.find(group => group.underlyingIds.includes("same")).underlyingIds, ["duplicate", "same"]);
  assert.equal(view.groups.find(group => group.underlyingIds.includes("candidate")).resolution, "candidate");
});

test("explicit proxy node and both original legs survive repository collapse", () => {
  const graph = fixture.create(), proxy = graph.nodes.find(node => node.kind === "proxy");
  proxy.repo_id = graph.repositories[0].id; proxy.parent_id = graph.repositories[0].id;
  const view = P.projectGraph(graph, { collapsedIds: graph.repositories.map(repo => repo.id) });
  const visibleProxy = view.elements.find(item => item.data.canonicalId === proxy.id);
  assert.ok(visibleProxy); assert.equal(visibleProxy.data.parent, undefined);
  const first = view.groups.find(group => group.underlyingIds.includes(graph.edges[0].id));
  const second = view.groups.find(group => group.underlyingIds.includes(graph.edges[1].id));
  assert.equal(first.target, proxy.id); assert.equal(second.source, proxy.id);
});

test("node and edge identity namespaces cannot collide or interpret selector characters", () => {
  const graph = fixture.create({ edgeCount: 4 }), node = graph.nodes[19];
  const oldId = node.id; node.id = 'odd:[id]#"/\\';
  for (const edge of graph.edges) { if (edge.source === oldId) edge.source = node.id; if (edge.target === oldId) edge.target = node.id; }
  graph.edges[0].id = node.id;
  const model = P.validateGraph(graph), view = P.projectGraph(model);
  const selectedNode = P.selectionFor(model, view, P.nodeViewId(node.id));
  assert.deepEqual(selectedNode.node_ids, [node.id]);
  const group = view.elements.find(item => item.group === "edges" && item.data.underlyingIds.includes(node.id));
  const selectedEdge = P.selectionFor(model, view, group.data.id);
  assert.deepEqual(selectedEdge.edge_ids, [node.id]);
  assert.notEqual(group.data.id, P.nodeViewId(node.id)); assert.equal(P.selectionFor(model, view, "unknown"), null);
});

test("internal edges are counted without fabricating repository self relationships", () => {
  const graph = fixture.create({ edgeCount: 4 });
  const owned = graph.nodes.filter(node => node.parent_id === graph.repositories[0].id);
  graph.edges = [{ id: "internal", source: owned[0].id, target: owned[1].id, directed: true, kind: "http", resolution: "observed", evidence_refs: [] }];
  const view = P.projectGraph(graph, { collapsedIds: [graph.repositories[0].id] });
  assert.equal(view.groups.length, 0); assert.deepEqual(view.internalEdges[graph.repositories[0].id], ["internal"]);
  assert.equal(view.counts.internalEdges, 1);
});

test("filters and display bounds retain canonical totals and all failed repository status groups", () => {
  const graph = fixture.create({ nodeCount: 10000, edgeCount: 30000 });
  const view = P.projectGraph(graph, { maxNodes: 30, maxEdges: 20, resolution: "candidate" });
  assert.equal(view.counts.canonicalNodes, 10000); assert.equal(view.counts.canonicalEdges, 30000);
  assert.ok(view.counts.displayedNodes <= 30); assert.ok(view.counts.displayedEdges <= 20); assert.ok(view.limited);
  assert.equal(view.elements.filter(item => item.data.kind === "repository").length, 16);
  assert.equal(view.counts.representedEdges + view.counts.internalEdges + view.counts.filteredEdges + view.counts.boundedEdges, 30000);
});

test("grouped preset positions are deterministic, finite, and preserve compound ancestry", () => {
  const graph = fixture.create(), view = P.projectGraph(graph);
  const before = JSON.stringify(view), first = P.groupedPositions(view), second = P.groupedPositions(view);
  assert.deepEqual(first, second); assert.equal(JSON.stringify(view), before);
  for (const position of Object.values(first)) { assert.ok(Number.isFinite(position.x)); assert.ok(Number.isFinite(position.y)); }
  const child = graph.nodes.find(node => node.parent_id !== null);
  assert.equal(view.elements.find(item => item.data.canonicalId === child.id).data.parent, P.nodeViewId(child.parent_id));
});

test("validation rejects dangling refs, missing status group, cycles, ownership mismatch and nonboolean directed", () => {
  for (const mutate of [
    graph => { graph.edges[0].target = "absent"; },
    graph => { graph.edges[0].directed = "true"; },
    graph => { graph.edges[0].evidence_refs = ["absent"]; },
    graph => { graph.nodes[0].kind = "service"; },
    graph => { delete graph.repositories[0].root; },
    graph => { graph.evidence[0].file = {}; },
    graph => { graph.evidence[0].line = "not-a-number"; },
    graph => { graph.nodes[19].parent_id = graph.repositories[1].id; },
    graph => { graph.nodes[19].parent_id = graph.nodes[33].id; graph.nodes[33].parent_id = graph.nodes[19].id; }
  ]) { const graph = clone(fixture.create()); mutate(graph); assert.throws(() => P.validateGraph(graph)); }
});

test("pinned deployed assets and notices match SHA256 manifest and declared runtime closure", () => {
  const folder = path.join(__dirname, "..", "vendor"), manifest = JSON.parse(fs.readFileSync(path.join(folder, "manifest.json"), "utf8").replace(/^\uFEFF/, ""));
  const assets = JSON.parse(fs.readFileSync(path.join(folder, "../asset-manifest.json"), "utf8"));
  for (const asset of assets.files) assert.equal(crypto.createHash("sha256").update(fs.readFileSync(path.join(folder, "..", asset.path))).digest("hex"), asset.sha256);
  assert.equal(manifest.lifecycle_scripts_executed, false); assert.equal(manifest.packages.length, 4);
  for (const item of manifest.packages) {
    assert.equal(crypto.createHash("sha256").update(fs.readFileSync(path.join(folder, item.file))).digest("hex"), item.sha256);
    assert.equal(crypto.createHash("sha256").update(fs.readFileSync(path.join(folder, item.license_file))).digest("hex"), item.license_sha256);
    assert.match(fs.readFileSync(path.join(folder, item.license_file), "utf8"), /MIT|Permission is hereby granted/);
  }
  const context = { console, setTimeout, clearTimeout, performance }; vm.createContext(context);
  for (const name of ["cytoscape-3.34.4.min.js", "layout-base-2.0.1.js", "cose-base-2.2.0.js", "cytoscape-fcose-2.2.0.js"]) vm.runInContext(fs.readFileSync(path.join(folder, name), "utf8"), context, { filename: name });
  assert.equal(context.cytoscape.version, "3.34.4");
  const view = P.projectGraph(fixture.create());
  vm.runInContext(`var cy = cytoscape({ headless: true, styleEnabled: true, elements: ${JSON.stringify(view.elements)}, layout: { name: "preset", positions: ${JSON.stringify(P.groupedPositions(view))} } }); cy.layout({ name: "fcose", quality: "proof", randomize: false, animate: false, fit: false, packComponents: false, numIter: 20 }).run(); var result = { nodes: cy.nodes().length, edges: cy.edges().length, finite: cy.nodes().every(node => Number.isFinite(node.position("x")) && Number.isFinite(node.position("y"))) }; cy.destroy();`, context);
  assert.equal(context.result.nodes, view.counts.displayedNodes); assert.equal(context.result.edges, view.counts.displayedEdges); assert.ok(context.result.finite);
});

test("current core fleet16 oracle and failed variant preserve IDs, proxy topology, and evidence registry", () => {
  const repo = path.resolve(__dirname, "../../../..");
  const durable = path.join(repo, "docs/verification/windows-parity/WP043/fleet16-20261023/core");
  const priorStaging = path.join(repo, ".tmp/wp043-fleet16-20261023/core");
  const durableReady = ["fleet16-oracle.json", "fleet16-oracle-failed.json"].every(name => fs.existsSync(path.join(durable, name)));
  const core = process.env.ATTACKMAP_GRAPH_CORE_ORACLE_DIR || (durableReady ? durable : priorStaging);
  for (const filename of ["fleet16-oracle.json", "fleet16-oracle-failed.json"]) {
    const graph = JSON.parse(fs.readFileSync(path.join(core, filename), "utf8"));
    const model = P.validateGraph(graph), collapsed = P.projectGraph(model, { collapsedIds: graph.repositories.map(repo => repo.id) });
    assert.equal(graph.repositories.length, 16);
    const all = [...collapsed.groups.flatMap(group => group.underlyingIds), ...Object.values(collapsed.internalEdges).flat()];
    assert.deepEqual(all.sort(), graph.edges.map(edge => edge.id).sort());
    assert.equal(new Set(all).size, graph.edges.length);
    if (filename === "fleet16-oracle.json") assert.ok(collapsed.groups.some(group => group.resolution === "observed" && group.underlyingIds.length === 2));
    const proxy = graph.nodes.find(node => node.component_role === "proxy");
    assert.ok(proxy); assert.ok(collapsed.elements.find(item => item.data.canonicalId === proxy.id));
    const involved = graph.edges.filter(edge => edge.source === proxy.id || edge.target === proxy.id);
    for (const edge of involved) { const group = collapsed.groups.find(item => item.underlyingIds.includes(edge.id)); assert.ok(group); assert.ok(group.source === proxy.id || group.target === proxy.id); }
    for (const element of collapsed.elements) { const selection = P.selectionFor(model, collapsed, element.data.id); assert.ok(selection); for (const id of selection.evidence_ids) assert.ok(model.evidence.has(id)); }
    if (filename.includes("failed")) assert.ok(graph.repositories.some(repo => repo.status === "failed"));
  }
});
