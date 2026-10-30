const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const P = require("../projection.js");
const fixture = require("../synthetic-fixture.js");

// Minimal DOM exercises the actual page protocol with unavailable graphics.
// It is neither browser visual acceptance nor a claim of native WebView integration.
function page({ hosted = true, graphics = false } = {}) {
  const elements = new Map(), messages = [];
  let resizeCallback, definitions = [], pan = { x: 0, y: 0 }, zoom = 1;
  const canvas = {
    fits: 0, resizes: 0, styleUpdates: 0,
    on() {}, style() { return { update() { canvas.styleUpdates++; } }; },
    pan(value) { if (value) pan = { ...value }; return { ...pan }; },
    zoom(value) { if (typeof value === "number") zoom = value; return zoom; },
    batch(callback) { callback(); },
    elements() { return { remove() { definitions = []; }, unselect() {} }; },
    add(items) { definitions = items; }, layout() { return { run() {} }; },
    fit() { this.fits++; zoom = .5; pan = { x: 0, y: 0 }; }, resize() { this.resizes++; },
    getElementById() { return { select() {} }; },
    nodes() { return definitions.filter(item => item.group === "nodes").map(item => ({ data(key) { return item.data[key]; }, position() { return { x: 10, y: 20 }; } })); },
    destroy() {}, width() { return 800; }, height() { return 300; }
  };
  function element(id = "") {
    const value = { id, value: "", hidden: false, checked: false, disabled: false, textContent: "", className: "", dataset: {}, children: [], options: id === "kind" || id === "resolution" ? [{}] : [], previousElementSibling: {}, classList: { add() {} }, listeners: {}, append(...items) { this.children.push(...items); if (id === "kind" || id === "resolution") this.options.push(...items); }, replaceChildren(...items) { this.children = items; }, remove(index) { this.options.splice(index, 1); }, setAttribute() {}, addEventListener(name, callback) { this.listeners[name] = callback; }, focus() { document.activeElement = this; } };
    return value;
  }
  const document = { activeElement: null, documentElement: { dataset: { theme: "light" } }, getElementById(id) { if (!elements.has(id)) elements.set(id, element(id)); return elements.get(id); }, createElement() { return element(); }, createTextNode(text) { return { textContent: text }; } };
  document.getElementById("neighborhood").value = "all"; document.getElementById("layout").value = "preset";
  const window = { AttackMapProjection: P, AttackMapSyntheticFixture: fixture, ...(hosted ? { chrome: { webview: { postMessage(value) { messages.push(value); }, addEventListener() {} } } } : {}), addEventListener() {}, dispatchEvent() {} };
  if (graphics) {
    window.cytoscape = () => canvas;
    window.ResizeObserver = class { constructor(callback) { resizeCallback = callback; } observe() {} disconnect() {} };
  }
  const context = { window, document, console, performance, devicePixelRatio: 1, crypto: { randomUUID: () => "page-test-session" }, CustomEvent: class { constructor(type, value) { this.type = type; this.detail = value; } }, setTimeout, Blob, URL };
  vm.createContext(context); vm.runInContext(fs.readFileSync(path.join(__dirname, "../app.js"), "utf8"), context);
  return { api: window.AttackMapGraph, messages, elements, document, canvas, resize(width, height) { resizeCallback([{ contentRect: { width, height } }]); } };
}

test("ready advertises bounded layouts; graphics failure retains complete canonical text and export", () => {
  const { api, messages, elements } = page();
  assert.equal(messages[0].type, "ready"); assert.equal(messages[0].protocol, 1); assert.equal(messages[0].page_session, "page-test-session");
  assert.equal(elements.get("png").disabled, true); assert.match(elements.get("png").textContent, /Native PNG unavailable/);
  const graph = fixture.create(); api.replaceGraph(graph, { token: "host-capture-one", run_id: "host-run" });
  assert.equal(api.snapshot().loaded, true); assert.equal(api.snapshot().counts.canonicalEdges, graph.edges.length);
  assert.ok(elements.get("text-list").children.length > 0);
  assert.match(elements.get("status").textContent, /complete keyboard list remains available/);
  assert.equal(messages.at(-1).state, "text-fallback");
  const exported = JSON.parse(api.canonicalJson());
  assert.equal(exported.kind, "fleet_architecture"); assert.deepEqual(exported.edges, graph.edges); assert.deepEqual(exported.evidence, graph.evidence);
  assert.equal(exported.export_metadata.context.token, "host-capture-one");
});

test("bridge selection rejects unknown IDs, stale context and unattached evidence; emits only current validated IDs", () => {
  const { api, messages } = page(), graph = fixture.create(), context = { token: "current-capture" };
  api.replaceGraph(graph, context);
  const edge = graph.edges[0], selection = { node_ids: [], edge_ids: [edge.id], evidence_ids: edge.evidence_refs };
  assert.equal(api.select(selection, { token: "stale-capture" }), false);
  assert.throws(() => api.select({ node_ids: ["unknown"], edge_ids: [], evidence_ids: [] }, context), /unknown/);
  assert.throws(() => api.select({ node_ids: [], edge_ids: [edge.id], evidence_ids: graph.edges[3].evidence_refs }, context), /not attached/);
  assert.equal(api.select(selection, context), true); api.openEvidence();
  const sent = messages.at(-1);
  assert.equal(sent.type, "openEvidence"); assert.equal(sent.context.token, "current-capture");
  assert.deepEqual(Array.from(sent.edge_ids), [edge.id]); assert.deepEqual(Array.from(sent.evidence_ids), edge.evidence_refs);
  assert.equal("file" in sent, false); assert.equal("root" in sent, false); assert.equal("command" in sent, false);
  assert.equal(api.receive({ protocol: 1, type: "select", page_session: "stale-page", context, selection }), false);
  api.clear(); assert.equal(api.snapshot().loaded, false); assert.equal(api.select(selection, context), false);
});

test("invalid replacement cannot corrupt the current graph; unsupported messages are ignored", () => {
  const { api } = page(), graph = fixture.create(); api.replaceGraph(graph, { token: "before" });
  assert.throws(() => api.replaceGraph({ ...graph, schema_version: "2.0" }, { token: "after" }), /schema 1.0/);
  assert.equal(api.snapshot().context.token, "before");
  assert.throws(() => api.replaceGraph(graph, {}), /context.token/); assert.equal(api.snapshot().context.token, "before");
  assert.equal(api.receive({ protocol: 1, type: "execute", command: "anything" }), false);
  assert.equal(api.receive({ protocol: 2, type: "clear" }), false);
});

test("hosted controls and messages require the current page session; JSON export keeps captured identity", () => {
  const { api, messages, elements, document } = page(), graph = fixture.create();
  assert.equal(document.documentElement.dataset.hosted, "true");
  assert.equal(elements.get("demo").hidden, true);
  assert.equal(elements.get("file").disabled, true);
  assert.match(elements.get("empty-help").textContent, /selected Fleet run/);
  assert.equal(messages[0].capabilities.includes("png-overview"), false);
  const context = { token: "host-current", run_id: "fleet-captured", selection_revision: 3 };
  assert.equal(api.receive({ protocol: 1, type: "replaceGraph", context, graph }), false);
  assert.equal(api.snapshot().loaded, false);
  assert.equal(api.receive({ protocol: 1, type: "replaceGraph", page_session: "page-test-session", context, graph }), true);
  assert.equal(api.receive({ protocol: 1, type: "clear" }), false);
  assert.equal(api.snapshot().loaded, true);
  elements.get("json").listeners.click();
  const exported = messages.at(-1);
  assert.equal(exported.type, "export"); assert.equal(exported.format, "json");
  assert.equal(exported.context.token, "host-current");
  assert.equal(exported.metadata.context.run_id, "fleet-captured");
  assert.equal(api.receive({ protocol: 1, type: "clear", page_session: "page-test-session" }), true);
  assert.equal(api.snapshot().loaded, false);
});

test("standalone opening remains empty and exposes its file and labelled synthetic controls", () => {
  const { api, elements, document } = page({ hosted: false });
  assert.equal(api.snapshot().loaded, false);
  assert.equal(document.documentElement.dataset.hosted, "false");
  assert.equal(elements.get("file").disabled, false);
  assert.equal(elements.get("demo").hidden, false);
  elements.get("demo").listeners.click();
  assert.equal(api.snapshot().loaded, true); assert.equal(api.snapshot().synthetic, true);
  assert.equal(elements.get("mode").textContent, "SYNTHETIC FIXTURE");
});

test("a graph replacement clears filters and paging from the previous captured graph", () => {
  const { api, elements } = page(), graph = fixture.create();
  api.replaceGraph(graph, { token: "first" });
  api.setOptions({ kind: "http", resolution: "candidate", query: "missing", interRepoOnly: true });
  elements.get("more").listeners.click();
  api.replaceGraph(graph, { token: "second" });
  const view = api.snapshot().view;
  assert.equal(view.kind, ""); assert.equal(view.resolution, ""); assert.equal(view.query, "");
  assert.equal(view.inter_repo_only, false);
  assert.equal(elements.get("text-list").children.length, 120);
  assert.equal(api.snapshot().counts.representedEdges + api.snapshot().counts.internalEdges, graph.edges.length);
});

test("changing selection recomputes its neighborhood and Back restores the prior focus", () => {
  const { api, elements } = page(), graph = fixture.create(), context = { token: "current" };
  api.replaceGraph(graph, context); api.setOptions({ collapsedIds: [], neighborhood: "downstream" });
  const first = graph.edges[0].source, second = graph.edges[1].target;
  function choose(id) { return { node_ids: [id], edge_ids: [], evidence_ids: graph.nodes.find(node => node.id === id).evidence_refs }; }
  function expected(id) { return P.projectGraph(P.validateGraph(graph), { collapsedIds: [], neighborhood: "downstream", focusIds: [id] }).counts; }
  api.select(choose(first), context);
  assert.deepEqual(JSON.parse(JSON.stringify(api.snapshot().counts)), expected(first));
  api.select(choose(second), context);
  assert.deepEqual(JSON.parse(JSON.stringify(api.snapshot().counts)), expected(second));
  elements.get("back").listeners.click();
  assert.deepEqual(Array.from(api.snapshot().selected.node_ids), [first]);
  assert.deepEqual(JSON.parse(JSON.stringify(api.snapshot().counts)), expected(first));
});

test("single-report architecture opens with its components and relationship visible; a fleet opens collapsed", () => {
  const { api } = page(), fleet = fixture.create(), repo = fleet.repositories[0];
  const services = fleet.nodes.filter(node => node.repo_id === repo.id && node.kind !== "repository").slice(0, 2).map(node => ({ ...node, evidence_refs: [] }));
  assert.equal(services.length, 2);
  const graph = { ...fleet, repositories: [repo], nodes: [fleet.nodes.find(node => node.id === repo.id), ...services],
    edges: [{ id: "single-report-edge", source: services[0].id, target: services[1].id, kind: "dependency", directed: true, resolution: "observed", evidence_refs: [] }], evidence: [] };
  api.replaceGraph(graph, { token: "single-report" });
  assert.equal(api.snapshot().view.collapsed_ids.length, 0);
  assert.equal(api.snapshot().counts.displayedNodes, 3);
  assert.equal(api.snapshot().counts.representedEdges, 1);
  assert.equal(api.snapshot().counts.internalEdges, 0);
  api.replaceGraph(fleet, { token: "fleet" });
  assert.equal(api.snapshot().view.collapsed_ids.length, 16);
});

test("hosted hide and same-size return preserve viewport and selection; an actual resize refits", () => {
  const { api, canvas, resize } = page({ graphics: true }), graph = fixture.create(), context = { token: "resize-capture" };
  resize(800, 300); // Initial observation may precede the graph.
  api.replaceGraph(graph, context);
  api.select({ node_ids: [graph.repositories[0].id], edge_ids: [], evidence_ids: [] }, context);
  canvas.zoom(2); canvas.pan({ x: 80, y: 40 });
  const fits = canvas.fits;
  resize(0, 0); resize(800, 300);
  assert.equal(canvas.fits, fits); assert.equal(canvas.zoom(), 2);
  assert.deepEqual(canvas.pan(), { x: 80, y: 40 });
  assert.deepEqual(Array.from(api.snapshot().selected.node_ids), [graph.repositories[0].id]);
  resize(720, 260);
  assert.equal(canvas.fits, fits + 1); assert.equal(canvas.resizes, 2);
});

test("host-owned theme messages still update hosted canvas styles with a hidden page header", () => {
  const { api, canvas, document } = page({ graphics: true });
  api.replaceGraph(fixture.create(), { token: "theme-capture" });
  assert.equal(api.receive({ protocol: 1, type: "theme", page_session: "page-test-session", theme: "dark" }), true);
  assert.equal(document.documentElement.dataset.theme, "dark"); assert.equal(canvas.styleUpdates, 1);
  assert.equal(api.receive({ protocol: 1, type: "theme", page_session: "page-test-session", theme: "light" }), true);
  assert.equal(document.documentElement.dataset.theme, "light"); assert.equal(canvas.styleUpdates, 2);
});
