(function () {
  "use strict";
  const P = window.AttackMapProjection;
  const $ = id => document.getElementById(id);
  const hosted = Boolean(window.chrome?.webview?.postMessage);
  document.documentElement.dataset.hosted = String(hosted);
  const pageSession = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  let model = null, graph = null, context = null, projection = null, cy = null, selected = null;
  let collapsed = new Set(), history = [], rowLimit = 120, layoutEpoch = 0, lastTiming = null, synthetic = false;
  let canvasSize = null;
  const canvasResize = hosted && typeof window.ResizeObserver === "function" ? new window.ResizeObserver(entries => {
    const bounds = entries[0]?.contentRect;
    if (!bounds || bounds.width <= 0 || bounds.height <= 0) return;
    const changed = !canvasSize || Math.abs(bounds.width - canvasSize.width) > .5 || Math.abs(bounds.height - canvasSize.height) > .5;
    canvasSize = { width: bounds.width, height: bounds.height };
    if (cy && model) { cy.resize(); if (changed) cy.fit(undefined, 25); }
  }) : null;
  canvasResize?.observe($("graph"));
  const incomingTypes = new Set(["replaceGraph", "clear", "select", "theme"]);
  function send(type, fields = {}) {
    const message = { protocol: 1, type, page_session: pageSession, context, ...fields };
    if (hosted && JSON.stringify(message).length > 8 * 1024 * 1024) { status("Selection exceeds the native bridge message limit. Narrow the view or export the complete JSON."); return null; }
    if (hosted) window.chrome.webview.postMessage(message);
    window.dispatchEvent(new CustomEvent("attackmap-graph-message", { detail: message }));
    return message;
  }
  function status(value) { $("status").textContent = value; }
  function contextValue(value) {
    if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.token !== "string" || !value.token.length || value.token.length > 512) throw new Error("A host-owned context.token is required.");
    const json = JSON.stringify(value);
    if (json.length > 8192) throw new Error("Graph context exceeds 8192 characters.");
    return JSON.parse(json);
  }
  function sameContext(value) { return Boolean(context && value && P.stable(value) === P.stable(context)); }
  function theme(value) {
    const name = value === "dark" ? "dark" : "light";
    document.documentElement.dataset.theme = name;
    $("theme").textContent = name === "dark" ? "Light theme" : "Dark theme";
    if (cy) cy.style(graphStyle()).update();
    return name;
  }
  function graphStyle() {
    const dark = document.documentElement.dataset.theme === "dark";
    return [
      { selector: "node", style: { "background-color": dark ? "#285b78" : "#badced", "border-color": dark ? "#73aecf" : "#4d819f", "border-width": 1.3, "shape": "round-rectangle", "width": 125, "height": 46, "label": "data(label)", "font-family": "Segoe UI", "font-size": 11, "color": dark ? "#e3edf7" : "#1c3449", "text-valign": "center", "text-wrap": "ellipsis", "text-max-width": 112, "overlay-opacity": 0 } },
      { selector: ":parent", style: { "background-color": dark ? "#21374a" : "#e8f0f8", "background-opacity": .7, "border-color": dark ? "#5c7992" : "#8aa6bf", "border-width": 1.3, "padding": 25, "font-size": 13, "font-weight": 650, "text-valign": "top", "text-halign": "center", "text-margin-y": 17, "text-max-width": 240 } },
      { selector: 'node[kind = "repository"]', style: { "background-color": dark ? "#24445d" : "#dcebf8", "border-color": dark ? "#6a9dbf" : "#6f98b7", "font-weight": 650 } },
      { selector: 'node[kind = "proxy"], node[componentRole = "proxy"]', style: { "shape": "diamond", "background-color": dark ? "#805c32" : "#edcb96", "border-color": "#bd8a43", "width": 115, "height": 65 } },
      { selector: 'node[kind = "datastore"]', style: { "shape": "barrel", "background-color": dark ? "#4f4d7d" : "#d7d2ed" } },
      { selector: 'node[kind = "external"]', style: { "shape": "ellipse", "background-color": dark ? "#47566b" : "#dbe3ed" } },
      { selector: 'node[status = "failed"], node[status = "unavailable"], node[status = "cancelled"]', style: { "border-color": "#c36e5a", "border-style": "dashed", "background-color": dark ? "#593a37" : "#f6e3df" } },
      { selector: "edge", style: { "width": 1.3, "line-color": dark ? "#7799b5" : "#7393ad", "target-arrow-color": dark ? "#7799b5" : "#7393ad", "target-arrow-shape": "triangle", "curve-style": "bezier", "control-point-step-size": 35, "label": "data(label)", "font-size": 9, "color": dark ? "#b8cede" : "#415c72", "text-background-color": dark ? "#111d29" : "#f8fafc", "text-background-opacity": .92, "text-background-padding": 3, "text-rotation": "autorotate", "overlay-opacity": 0 } },
      { selector: "edge[!directed]", style: { "target-arrow-shape": "none" } },
      { selector: 'edge[resolution = "candidate"], edge[resolution = "unknown"], edge[resolution = "unresolved"], edge[resolution = "inferred"]', style: { "line-style": "dashed", "line-color": "#bf8b40", "target-arrow-color": "#bf8b40" } },
      { selector: ":selected", style: { "border-width": 3, "border-color": dark ? "#ffca81" : "#b85a0a", "line-color": dark ? "#ffca81" : "#b85a0a", "target-arrow-color": dark ? "#ffca81" : "#b85a0a" } },
      { selector: "edge:selected", style: { "width": 3 } }
    ];
  }
  function ensureCanvas() {
    if (cy) return;
    if (typeof window.cytoscape !== "function") throw new Error("Local Cytoscape asset unavailable. The complete keyboard list remains available.");
    cy = window.cytoscape({ container: $("graph"), elements: [], layout: { name: "preset" }, style: graphStyle(), minZoom: .05, maxZoom: 4, wheelSensitivity: .18, pixelRatio: Math.min(devicePixelRatio || 1, 2), hideEdgesOnViewport: false, boxSelectionEnabled: false, selectionType: "single" });
    cy.on("tap", "node, edge", event => chooseView(event.target.id(), true));
    cy.on("dbltap", "node", event => { if (event.target.data("kind") === "repository" || event.target.isParent()) toggleGroup(event.target.data("canonicalId")); });
  }
  function viewOptions(extra = {}) {
    const focus = selected?.node_ids || [];
    return { collapsedIds: $("search").value.trim() ? [] : [...collapsed], query: $("search").value, kind: $("kind").value, resolution: $("resolution").value, interRepoOnly: $("cross").checked, focusIds: focus, neighborhood: $("neighborhood").value, ...extra };
  }
  function viewState() { return { collapsed_ids: [...collapsed].sort(), query: $("search").value, kind: $("kind").value, resolution: $("resolution").value, inter_repo_only: $("cross").checked, neighborhood: $("neighborhood").value, layout: $("layout").value }; }
  function describeCounts() {
    const c = projection.counts;
    return `${model.repositories.size} repositories · ${c.displayedNodes}/${c.canonicalNodes} nodes · ${c.displayedEdges} displayed relationships (${c.representedEdges}/${c.canonicalEdges} original edges) · ${c.internalEdges} internal edges collapsed · ${c.filteredEdges} filtered · ${c.boundedEdges} edges outside bounded view`;
  }
  function render(options = {}) {
    if (!model) return;
    const started = performance.now();
    projection = P.projectGraph(model, viewOptions());
    renderList(); renderSelection();
    $("coverage").textContent = JSON.stringify({ coverage: graph.coverage, limitations: graph.limitations, view: projection.counts, input_limits: P.LIMITS, layout_note: "fCoSE is synchronous and bounded to 350 visible nodes / 1000 displayed edges. No preemptive cancellation claim. Grouped preset is deterministic presentation geometry." }, null, 2);
    let renderFailure = null;
    try {
      ensureCanvas();
      const oldPan = cy.pan(), oldZoom = cy.zoom();
      cy.batch(() => { cy.elements().remove(); cy.add(projection.elements); });
      runLayout(options.layout || "preset", { fit: options.fit !== false });
      if (options.preserveViewport) { cy.zoom(oldZoom); cy.pan(oldPan); }
      syncCanvasSelection();
    } catch (error) { renderFailure = error.message; status(`${error.message} Canonical data is retained for text / JSON export.`); }
    $("empty").hidden = true;
    if (!renderFailure && !lastTiming?.error) status(`${describeCounts()}${projection.limited ? " · Limited view; full graph retained." : ""}`);
    send("layoutState", { state: renderFailure ? "text-fallback" : "rendered", message: renderFailure, counts: projection.counts, view: viewState(), projection_ms: performance.now() - started, timing: lastTiming });
  }
  function runLayout(name = "preset", options = {}) {
    if (!model || !cy || !projection) return null;
    const ticket = ++layoutEpoch;
    if (name === "fcose" && (projection.counts.displayedNodes > P.LIMITS.fcoseNodes || projection.counts.displayedEdges > P.LIMITS.fcoseEdges)) {
      status("fCoSE view exceeds 350 nodes / 1000 edges. Collapse groups or filter; grouped preset remains available.");
      send("layoutState", { state: "bounded-fallback", layout: "fcose", counts: projection.counts }); name = "preset";
    }
    const start = performance.now();
    const positions = P.groupedPositions(projection);
    cy.layout({ name: "preset", positions, fit: false, animate: false }).run();
    let error = null;
    if (name === "fcose") {
      try {
        // Synchronous refinement from known grouped positions. There is no fake timeout/cancel.
        cy.layout({ name: "fcose", quality: "proof", randomize: false, animate: false, fit: false, packComponents: false, nodeDimensionsIncludeLabels: true, numIter: 900, idealEdgeLength: 110, nodeSeparation: 45, gravity: .2, padding: 35 }).run();
      } catch (failure) { error = failure.message; cy.layout({ name: "preset", positions, fit: false }).run(); status(`fCoSE failed; grouped preset shown. ${failure.message}`); }
    }
    if (options.fit !== false) cy.fit(undefined, 45);
    lastTiming = { ticket, layout: name, elapsed_ms: performance.now() - start, synchronous: true, preemptive_cancel: false, error };
    send("layoutState", { state: error ? "fallback" : "complete", ...lastTiming, counts: projection.counts });
    return lastTiming;
  }
  function populateFilters() {
    for (const [id, field] of [["kind", "kind"], ["resolution", "resolution"]]) {
      const element = $(id); while (element.options.length > 1) element.remove(1);
      for (const value of [...new Set(graph.edges.map(edge => edge[field]))].sort()) { const option = document.createElement("option"); option.value = value; option.textContent = value; element.append(option); }
    }
  }
  function replaceGraph(value, hostContext, options = {}) {
    // Validation and deep copy complete before replacing the current canonical snapshot.
    const json = JSON.stringify(value);
    if (json.length > 64 * 1024 * 1024) throw new Error("Graph exceeds the explicit 64 MiB input limit.");
    const candidate = JSON.parse(json), checked = P.validateGraph(candidate), nextContext = contextValue(hostContext);
    clear(false);
    graph = candidate; model = checked; context = nextContext; synthetic = Boolean(options.synthetic);
    collapsed = new Set(graph.repositories.length === 1 ? [] : graph.repositories.map(repo => repo.id));
    populateFilters();
    $("mode").textContent = synthetic ? "SYNTHETIC FIXTURE" : hosted ? "Captured fleet graph" : "Local graph file";
    render();
    return snapshot();
  }
  function clear(notify = true) {
    ++layoutEpoch;
    if (cy) { cy.destroy(); cy = null; }
    model = null; graph = null; context = null; projection = null; selected = null; history = []; collapsed.clear(); lastTiming = null;
    $("text-list").replaceChildren(); $("selection-detail").replaceChildren(); $("selection-summary").textContent = "Select a group, component, or relationship.";
    $("empty").hidden = false; $("mode").textContent = "No graph loaded"; $("coverage").textContent = "No graph loaded."; $("list-count").textContent = "";
    $("toggle").disabled = true; $("evidence").disabled = true; $("back").disabled = true; $("more").hidden = true;
    $("search").value = ""; $("cross").checked = false; $("neighborhood").value = "all";
    $("kind").value = ""; $("resolution").value = ""; rowLimit = 120;
    status("Waiting for graph data."); if (notify) send("layoutState", { state: "cleared" });
  }
  function validatedSelection(value) {
    if (!model || !value || typeof value !== "object") return null;
    const result = {};
    for (const [key, registry] of [["node_ids", model.nodes], ["edge_ids", model.edges], ["evidence_ids", model.evidence]]) {
      const ids = value[key] || [];
      if (!Array.isArray(ids) || ids.length > registry.size || ids.some(id => typeof id !== "string" || !registry.has(id))) throw new Error(`Selection contains unknown ${key}.`);
      result[key] = [...new Set(ids)];
    }
    if (!result.node_ids.length && !result.edge_ids.length && !result.evidence_ids.length) return null;
    // Evidence IDs always come from the chosen canonical objects, never a supplied path.
    const permitted = new Set([...result.node_ids.flatMap(id => model.nodes.get(id).evidence_refs), ...result.edge_ids.flatMap(id => model.edges.get(id).evidence_refs)]);
    if (result.evidence_ids.some(id => !permitted.has(id))) throw new Error("Evidence is not attached to this selection.");
    return result;
  }
  function select(value, hostContext = context, options = {}) {
    if (!sameContext(hostContext)) return false;
    const next = validatedSelection(value);
    if (!next) return false;
    if (options.remember !== false && selected) history.push({ selected, pan: cy?.pan(), zoom: cy?.zoom(), collapsed: [...collapsed] });
    if (history.length > 30) history.shift();
    selected = next;
    if ($("neighborhood").value !== "all") render({ preserveViewport: true });
    else { renderSelection(); renderList(); syncCanvasSelection(); }
    if (options.notify) send("select", { ...selected });
    return true;
  }
  function chooseView(id, notify) { const value = model && projection ? P.selectionFor(model, projection, id) : null; if (value) select(value, context, { notify }); }
  function syncCanvasSelection() {
    if (!cy) return; cy.elements().unselect(); if (!selected) return;
    for (const id of selected.node_ids) cy.getElementById(P.nodeViewId(id)).select();
    for (const element of projection.elements) if (element.group === "edges" && element.data.underlyingIds.some(id => selected.edge_ids.includes(id))) cy.getElementById(element.data.id).select();
  }
  function line(container, label, value, mono = false) { const p = document.createElement("p"), strong = document.createElement("strong"), span = document.createElement("span"); strong.textContent = `${label} `; span.textContent = value; if (mono) span.className = "mono"; p.append(strong, span); container.append(p); }
  function renderSelection() {
    const detail = $("selection-detail"); detail.replaceChildren();
    $("back").disabled = !history.length;
    $("toggle").disabled = !selected?.node_ids.some(id => graph.nodes.some(node => node.parent_id === id));
    $("evidence").disabled = !selected?.evidence_ids.length;
    if (!selected || !model) return;
    $("selection-summary").textContent = `${selected.node_ids.length} nodes · ${selected.edge_ids.length} underlying relationships · ${selected.evidence_ids.length} evidence references`;
    for (const id of selected.node_ids.slice(0, 5)) {
      const node = model.nodes.get(id); line(detail, node.kind, node.label); line(detail, "ID", id, true);
      const repo = model.repositories.get(id); if (repo) line(detail, "Snapshot", `${repo.status} · ${repo.snapshot_id || "identity unavailable"}`);
      const internal = projection.internalEdges[id]; if (internal?.length) line(detail, "Hidden internal edges", `${internal.length} (retained in full JSON)`);
    }
    for (const id of selected.edge_ids.slice(0, 8)) {
      const edge = model.edges.get(id); line(detail, edge.kind, `${edge.source} ${edge.directed ? "→" : "↔"} ${edge.target}`, true); line(detail, "ID / resolution", `${id} · ${edge.resolution}`, true);
      if (edge.basis) line(detail, "Basis", typeof edge.basis === "string" ? edge.basis : JSON.stringify(edge.basis));
    }
    if (selected.edge_ids.length > 8) line(detail, "More", `${selected.edge_ids.length - 8} relationships; inspect native evidence or full JSON.`);
    if (selected.evidence_ids.length) line(detail, "Evidence IDs", selected.evidence_ids.slice(0, 12).join(", "), true);
  }
  function renderList() {
    const list = $("text-list"), focusedKey = document.activeElement?.dataset?.rowKey;
    list.replaceChildren(); if (!projection) return;
    const query = $("search").value.trim().toLocaleLowerCase();
    const rows = [];
    // Full canonical list is intentionally independent of display caps/collapse; it is the fallback.
    for (const node of graph.nodes) if (!query || [node.id, node.label, node.kind].some(value => value.toLocaleLowerCase().includes(query))) rows.push({ label: node.label, secondary: `${node.kind} · ${node.id}`, selection: { node_ids: [node.id], edge_ids: [], evidence_ids: node.evidence_refs } });
    for (const edge of graph.edges) {
      if (($("kind").value && edge.kind !== $("kind").value) || ($("resolution").value && edge.resolution !== $("resolution").value)) continue;
      if ($("cross").checked && model.nodes.get(edge.source).repo_id === model.nodes.get(edge.target).repo_id) continue;
      if (query && ![edge.id, edge.kind, edge.source, edge.target].some(value => value.toLocaleLowerCase().includes(query))) continue;
      rows.push({ label: `${edge.kind}: ${model.nodes.get(edge.source).label} ${edge.directed ? "→" : "↔"} ${model.nodes.get(edge.target).label}`, secondary: `${edge.resolution} · ${edge.id}`, selection: { node_ids: [], edge_ids: [edge.id], evidence_ids: edge.evidence_refs } });
    }
    $("list-count").textContent = `(${Math.min(rowLimit, rows.length)} / ${rows.length})`;
    for (const row of rows.slice(0, rowLimit)) {
      const button = document.createElement("button"), sub = document.createElement("span"); button.type = "button"; button.className = "text-row"; button.setAttribute("role", "listitem"); button.dataset.rowKey = row.selection.node_ids.length ? `n:${row.selection.node_ids[0]}` : `e:${row.selection.edge_ids[0]}`; button.append(document.createTextNode(row.label)); sub.textContent = row.secondary; button.append(sub);
      if (selected && (row.selection.node_ids.some(id => selected.node_ids.includes(id)) || row.selection.edge_ids.some(id => selected.edge_ids.includes(id)))) button.classList.add("selected");
      button.addEventListener("click", () => { select(row.selection, context, { notify: true }); }); list.append(button);
      if (focusedKey === button.dataset.rowKey) button.focus({ preventScroll: true });
    }
    $("more").hidden = rows.length <= rowLimit;
  }
  function toggleGroup(id) { if (!model?.nodes.has(id)) return; collapsed.has(id) ? collapsed.delete(id) : collapsed.add(id); render({ preserveViewport: true }); }
  function openEvidence() { if (selected?.evidence_ids.length) send("openEvidence", { ...selected }); }
  function exportMetadata() { return { context, view: viewState(), counts: projection?.counts, coverage: graph?.coverage, limitations: graph?.limitations, synthetic, scope: "Complete captured canonical graph; discovery coverage may be partial." }; }
  function canonicalJson() {
    if (!graph) throw new Error("No graph loaded.");
    // Export the exact canonical graph, with view/context metadata in a separate envelope.
    return JSON.stringify({ ...graph, export_metadata: exportMetadata() }, null, 2);
  }
  async function exportPng() {
    if (!cy || !projection) throw new Error("No graph canvas available.");
    const captured = context, epoch = layoutEpoch;
    const blob = await cy.png({ output: "blob-promise", full: true, bg: getComputedStyle(document.documentElement).getPropertyValue("--canvas").trim(), maxWidth: 8192, maxHeight: 8192, scale: 1 });
    if (!sameContext(captured) || epoch !== layoutEpoch) throw new Error("Graph changed during PNG export.");
    if (blob.size > 32 * 1024 * 1024) throw new Error("PNG exceeds the explicit 32 MiB export limit.");
    return { blob, metadata: { ...exportMetadata(), scope: "Entire current overview projection, including offscreen elements. Full canonical graph is in JSON.", limited: projection.limited } };
  }
  function download(blob, name) { const url = URL.createObjectURL(blob), anchor = document.createElement("a"); anchor.href = url; anchor.download = name; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
  async function requestExport(format) {
    if (!graph) return;
    if (hosted) { send("export", { format, request_id: crypto.randomUUID(), metadata: exportMetadata() }); return; }
    try { if (format === "json") download(new Blob([canonicalJson()], { type: "application/json" }), "attackmap-fleet-graph.json"); else { const result = await exportPng(); download(result.blob, "attackmap-fleet-overview.png"); download(new Blob([JSON.stringify(result.metadata, null, 2)], { type: "application/json" }), "attackmap-fleet-overview.metadata.json"); } } catch (error) { status(error.message); }
  }
  function snapshot() { return { page_session: pageSession, context, loaded: Boolean(model), synthetic, counts: projection?.counts || null, view: model ? viewState() : null, selected, timing: lastTiming, positions: cy ? cy.nodes().map(node => ({ id: node.data("canonicalId"), ...node.position() })) : [], versions: { cytoscape: window.cytoscape?.version, fcose: "2.2.0" } }; }
  function receive(message) {
    if (!message || message.protocol !== 1 || !incomingTypes.has(message.type) || (hosted ? message.page_session !== pageSession : message.page_session && message.page_session !== pageSession)) return false;
    try {
      if (message.type === "replaceGraph") replaceGraph(message.graph, message.context);
      else if (message.type === "clear") { if (message.context && !sameContext(message.context)) return false; clear(); }
      else if (message.type === "theme") theme(message.theme);
      else if (message.type === "select") return select(message.selection || message, message.context);
      return true;
    } catch (error) { status(error.message); send("layoutState", { state: "error", message: error.message }); return false; }
  }
  window.AttackMapGraph = Object.freeze({ replaceGraph, clear, select, theme, receive, snapshot, runLayout, canonicalJson, exportPng, openEvidence, setOptions(options = {}) { if (!model) return; if (options.collapsedIds) collapsed = new Set(options.collapsedIds.filter(id => model.nodes.has(id))); for (const [key, id] of [["query", "search"], ["kind", "kind"], ["resolution", "resolution"], ["neighborhood", "neighborhood"]]) if (typeof options[key] === "string") $(id).value = options[key]; if (typeof options.interRepoOnly === "boolean") $("cross").checked = options.interRepoOnly; render({ layout: options.layout || "preset" }); return snapshot(); } });
  if (hosted) window.chrome.webview.addEventListener("message", event => receive(event.data));
  for (const id of ["search", "kind", "resolution", "cross", "neighborhood"]) $(id).addEventListener(id === "search" ? "input" : "change", () => { rowLimit = 120; render(); });
  $("theme").addEventListener("click", () => theme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
  $("collapse").addEventListener("click", () => { if (graph) { collapsed = new Set(graph.repositories.map(repo => repo.id)); render(); } });
  $("expand").addEventListener("click", () => { collapsed.clear(); render(); });
  $("toggle").addEventListener("click", () => { if (selected?.node_ids.length) toggleGroup(selected.node_ids[0]); });
  $("evidence").addEventListener("click", openEvidence);
  $("back").addEventListener("click", () => { const last = history.pop(); if (!last) return; selected = last.selected; collapsed = new Set(last.collapsed); render({ preserveViewport: true }); if (cy && last.pan) { cy.zoom(last.zoom); cy.pan(last.pan); } send("select", { ...selected }); });
  $("fit").addEventListener("click", () => cy?.fit(undefined, 45));
  $("zoom-in").addEventListener("click", () => { if (cy) cy.zoom({ level: cy.zoom() * 1.25, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }); });
  $("zoom-out").addEventListener("click", () => { if (cy) cy.zoom({ level: cy.zoom() / 1.25, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }); });
  $("arrange").addEventListener("click", () => { const result = runLayout($("layout").value); if (result) status(`${result.layout}: ${result.elapsed_ms.toFixed(1)} ms · ${describeCounts()}`); });
  $("png").addEventListener("click", () => requestExport("png")); $("json").addEventListener("click", () => requestExport("json"));
  $("more").addEventListener("click", () => { rowLimit += 120; renderList(); });
  $("demo").addEventListener("click", () => replaceGraph(window.AttackMapSyntheticFixture.create(), { token: `synthetic-${pageSession}` }, { synthetic: true }));
  $("file").addEventListener("change", async event => { const file = event.target.files[0]; if (!file) return; try { if (file.size > 64 * 1024 * 1024) throw new Error("Graph file exceeds 64 MiB."); replaceGraph(JSON.parse(await file.text()), { token: `local-file-${pageSession}-${Date.now()}` }); } catch (error) { status(error.message); } event.target.value = ""; });
  window.addEventListener("pagehide", () => { ++layoutEpoch; canvasResize?.disconnect(); cy?.destroy(); cy = null; });
  // The native host decides whether to expose the standalone picker/example actions.
  if (hosted) {
    $("demo").hidden = true; $("file").previousElementSibling.hidden = true; $("file").hidden = true; $("file").disabled = true;
    $("png").disabled = true; $("png").textContent = "Native PNG unavailable"; $("png").title = "Native PNG export is not implemented. Export the full JSON or use the native SVG alternative.";
    $("empty-help").textContent = "The selected Fleet run supplies its captured graph here. Choose or run a Fleet analysis in the desktop workspace.";
    $("inspector").append($("coverage-details"));
  }
  send("ready", { capabilities: ["compound-repositories", "reversible-projection", "preset", "fcose-bounded", "canonical-text", ...(hosted ? [] : ["png-overview"]), "canonical-json"], limits: P.LIMITS });
})();
