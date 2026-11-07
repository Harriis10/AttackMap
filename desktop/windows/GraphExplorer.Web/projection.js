/* AttackMap fleet graph presentation only. No renderer-created relationships. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.AttackMapProjection = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  const LIMITS = Object.freeze({ repositories: 16, nodes: 20000, edges: 60000, evidence: 120000, displayNodes: 1000, displayEdges: 3000, fcoseNodes: 350, fcoseEdges: 1000 });
  const statuses = new Set(["completed", "partial", "failed", "skipped", "cancelled", "unavailable", "queued", "running"]);
  function text(value, name, max = 1024) {
    if (typeof value !== "string" || !value.length || value.length > max || /[\u0000-\u001f]/.test(value)) throw new Error(`Invalid ${name}.`);
    return value;
  }
  function stable(value) {
    if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
    if (value && typeof value === "object") return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
    return JSON.stringify(value);
  }
  function unique(items, name, limit) {
    if (!Array.isArray(items) || items.length > limit) throw new Error(`${name} exceeds the explicit input limit (${limit}).`);
    const map = new Map();
    for (const item of items) {
      if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error(`Invalid ${name} entry.`);
      const id = text(item.id, `${name} ID`);
      if (map.has(id)) throw new Error(`Duplicate ${name} ID: ${id}`);
      map.set(id, item);
    }
    return map;
  }
  function validateGraph(graph) {
    if (!graph || graph.schema_version !== "1.0" || graph.kind !== "fleet_architecture") throw new Error("Expected fleet_architecture schema 1.0.");
    const repositories = unique(graph.repositories, "repository", LIMITS.repositories);
    const nodes = unique(graph.nodes, "node", LIMITS.nodes);
    const edges = unique(graph.edges, "edge", LIMITS.edges);
    const evidence = unique(graph.evidence, "evidence", LIMITS.evidence);
    if (!graph.coverage || typeof graph.coverage !== "object" || Array.isArray(graph.coverage) || !Array.isArray(graph.limitations) || graph.limitations.some(item => typeof item !== "string")) throw new Error("Coverage and limitations are required.");
    for (const repo of repositories.values()) {
      text(repo.label, "repository label");
      text(repo.root, "repository root", 4096);
      for (const key of ["repo_id", "requested_id"]) if (repo[key] !== null && typeof repo[key] !== "string") throw new Error(`Invalid repository ${key}: ${repo.id}`);
      if (!statuses.has(repo.status)) throw new Error(`Invalid repository status: ${repo.id}`);
      const node = nodes.get(repo.id);
      if (!node || node.kind !== "repository" || node.repo_id !== repo.id || node.parent_id !== null) throw new Error(`Repository group missing or invalid: ${repo.id}`);
    }
    function refs(item) {
      if (!Array.isArray(item.evidence_refs) || item.evidence_refs.length > LIMITS.evidence || item.evidence_refs.some(id => typeof id !== "string" || !evidence.has(id))) throw new Error(`Unknown evidence reference: ${item.id}`);
    }
    for (const node of nodes.values()) {
      text(node.kind, "node kind", 128); text(node.label, "node label", 4096); refs(node);
      if (node.repo_id !== null && !repositories.has(node.repo_id)) throw new Error(`Unknown repository: ${node.id}`);
      if (node.parent_id !== null && (!nodes.has(node.parent_id) || node.parent_id === node.id)) throw new Error(`Invalid parent: ${node.id}`);
      if (node.parent_id !== null && nodes.get(node.parent_id).repo_id !== node.repo_id) throw new Error(`Parent ownership mismatch: ${node.id}`);
    }
    // Three-color traversal rejects cycles without recursive stack growth on hostile depth.
    const done = new Set(), depths = new Map();
    for (const node of nodes.values()) {
      const path = new Set(); let current = node;
      while (current && !done.has(current.id)) {
        if (path.has(current.id)) throw new Error(`Containment cycle: ${current.id}`);
        path.add(current.id);
        current = current.parent_id === null ? null : nodes.get(current.parent_id);
      }
      let depth = current ? depths.get(current.id) : 0;
      for (const id of [...path].reverse()) {
        depth++;
        if (depth > 64) throw new Error("Containment exceeds the explicit 64-level limit.");
        done.add(id); depths.set(id, depth);
      }
    }
    for (const edge of edges.values()) {
      text(edge.kind, "edge kind", 128); text(edge.resolution, "edge resolution", 128); refs(edge);
      if (!nodes.has(edge.source) || !nodes.has(edge.target) || typeof edge.directed !== "boolean") throw new Error(`Invalid edge endpoints/directed: ${edge.id}`);
    }
    for (const item of evidence.values()) {
      if (item.repo_id !== null && !repositories.has(item.repo_id)) throw new Error(`Unknown evidence repository: ${item.id}`);
      if (item.file !== null && typeof item.file !== "string") throw new Error(`Invalid evidence file: ${item.id}`);
      if (item.line !== null && (!Number.isSafeInteger(item.line) || item.line < 1)) throw new Error(`Invalid evidence line: ${item.id}`);
    }
    return { graph, repositories, nodes, edges, evidence };
  }
  const nodeViewId = id => `n:${id}`;
  const isProxy = node => node.kind === "proxy" || node.component_role === "proxy" || node.is_proxy === true;
  function edgeSemantics(edge) {
    const extra = {};
    // Preserve every proxy/leg discriminator, rather than joining a direct and proxied relation.
    const proxy = Object.keys(edge).some(key => /proxy/.test(key) && edge[key] !== false && edge[key] !== null && edge[key] !== "")
      || (typeof edge.leg === "string" && !["direct", "none", ""].includes(edge.leg));
    for (const key of Object.keys(edge).sort()) if (/proxy|^leg$|^basis$|^endpoint_resolution$|^confidence$/.test(key) || (key === "relation_id" && proxy)) extra[key] = edge[key];
    return [edge.kind, edge.directed, edge.resolution, extra];
  }
  function projectGraph(document, options = {}) {
    const model = document.nodes instanceof Map ? document : validateGraph(document);
    const collapsed = new Set((options.collapsedIds || []).filter(id => model.nodes.has(id)));
    const query = String(options.query || "").trim().toLocaleLowerCase();
    const matches = node => !query || [node.id, node.label, node.kind, model.repositories.get(node.repo_id)?.label || ""].some(value => value.toLocaleLowerCase().includes(query));
    const focus = new Set((options.focusIds || []).filter(id => model.nodes.has(id)));
    const focused = new Set(focus);
    if (focus.size && options.neighborhood && options.neighborhood !== "all") {
      for (const edge of model.edges.values()) {
        if (focus.has(edge.source) && (options.neighborhood === "downstream" || !edge.directed)) focused.add(edge.target);
        if (focus.has(edge.target) && (options.neighborhood === "upstream" || !edge.directed)) focused.add(edge.source);
      }
    }
    const keep = new Set();
    for (const node of model.nodes.values()) if (matches(node) && (!focus.size || options.neighborhood === "all" || focused.has(node.id))) keep.add(node.id);
    // Retain all requested repository status groups, including failed/unconnected children.
    for (const repo of model.repositories.values()) keep.add(repo.id);
    for (const id of [...keep]) {
      let parent = model.nodes.get(id).parent_id;
      while (parent !== null) { keep.add(parent); parent = model.nodes.get(parent).parent_id; }
    }
    function representative(id) {
      const node = model.nodes.get(id);
      if (isProxy(node)) return id;
      let result = id, parent = node.parent_id;
      while (parent !== null) {
        if (collapsed.has(parent)) result = parent;
        parent = model.nodes.get(parent).parent_id;
      }
      return result;
    }
    const visible = [...model.nodes.values()].filter(node => keep.has(node.id) && representative(node.id) === node.id).sort((a, b) => (a.kind !== "repository") - (b.kind !== "repository") || a.id.localeCompare(b.id));
    const maxNodes = Math.max(model.repositories.size, Math.min(options.maxNodes ?? LIMITS.displayNodes, LIMITS.displayNodes));
    const displayed = visible.slice(0, maxNodes), displayedIds = new Set(displayed.map(node => node.id));
    const hiddenNodeCounts = new Map();
    for (const node of model.nodes.values()) { const id = representative(node.id); if (id !== node.id) hiddenNodeCounts.set(id, (hiddenNodeCounts.get(id) || 0) + 1); }
    const buckets = new Map(), internal = new Map(); let filteredEdges = 0, boundedEdges = 0;
    for (const edge of [...model.edges.values()].sort((a, b) => a.id.localeCompare(b.id))) {
      const sourceNode = model.nodes.get(edge.source), targetNode = model.nodes.get(edge.target);
      if ((options.kind && edge.kind !== options.kind) || (options.resolution && edge.resolution !== options.resolution) || (options.interRepoOnly && sourceNode.repo_id === targetNode.repo_id) || !keep.has(edge.source) || !keep.has(edge.target)) { filteredEdges++; continue; }
      const source = representative(edge.source), target = representative(edge.target);
      if (source === target && (source !== edge.source || target !== edge.target)) {
        if (!internal.has(source)) internal.set(source, []);
        internal.get(source).push(edge.id); continue;
      }
      if (!displayedIds.has(source) || !displayedIds.has(target)) { boundedEdges++; continue; }
      const key = stable([source, target, ...edgeSemantics(edge)]);
      if (!buckets.has(key)) buckets.set(key, { key, source, target, kind: edge.kind, directed: edge.directed, resolution: edge.resolution, semantics: edgeSemantics(edge), underlyingIds: [], evidenceRefs: new Set() });
      const group = buckets.get(key); group.underlyingIds.push(edge.id); edge.evidence_refs.forEach(id => group.evidenceRefs.add(id));
    }
    const maxEdges = Math.max(0, Math.min(options.maxEdges ?? LIMITS.displayEdges, LIMITS.displayEdges));
    const allGroups = [...buckets.values()].sort((a, b) => a.key.localeCompare(b.key));
    const groups = allGroups.slice(0, maxEdges);
    for (const group of allGroups.slice(maxEdges)) boundedEdges += group.underlyingIds.length;
    const elements = displayed.map(node => {
      const parent = node.parent_id !== null && displayedIds.has(node.parent_id) && !collapsed.has(node.parent_id) ? nodeViewId(node.parent_id) : undefined;
      const repo = model.repositories.get(node.id);
      return { group: "nodes", data: { id: nodeViewId(node.id), canonicalId: node.id, parent, label: node.label, kind: node.kind, componentRole: node.component_role || "", repoId: node.repo_id, status: repo?.status || "", collapsed: collapsed.has(node.id), hiddenNodes: hiddenNodeCounts.get(node.id) || 0, hiddenInternalEdges: (internal.get(node.id) || []).length, evidenceRefs: [...node.evidence_refs] } };
    });
    for (const group of groups) elements.push({ group: "edges", data: { id: `a:${stable(group.underlyingIds)}`, source: nodeViewId(group.source), target: nodeViewId(group.target), label: `${group.kind}${group.underlyingIds.length > 1 ? ` ×${group.underlyingIds.length}` : ""}`, kind: group.kind, directed: group.directed, resolution: group.resolution, count: group.underlyingIds.length, underlyingIds: [...group.underlyingIds], evidenceRefs: [...group.evidenceRefs].sort(), semantics: group.semantics } });
    return { elements, groups, internalEdges: Object.fromEntries(internal), collapsedIds: [...collapsed].sort(), counts: { canonicalNodes: model.nodes.size, canonicalEdges: model.edges.size, displayedNodes: displayed.length, displayedEdges: groups.length, representedEdges: groups.reduce((n, g) => n + g.underlyingIds.length, 0), collapsedNodes: [...hiddenNodeCounts.values()].reduce((a, b) => a + b, 0), internalEdges: [...internal.values()].reduce((n, ids) => n + ids.length, 0), filteredEdges, boundedNodes: visible.length - displayed.length, boundedEdges }, limited: visible.length > displayed.length || boundedEdges > 0 };
  }
  function groupedPositions(projection) {
    const nodes = projection.elements.filter(element => element.group === "nodes");
    const roots = nodes.filter(element => !element.data.parent).map(element => element.data).sort((a, b) => (a.kind !== "repository") - (b.kind !== "repository") || a.id.localeCompare(b.id));
    const children = new Map();
    for (const { data } of nodes) if (data.parent) { if (!children.has(data.parent)) children.set(data.parent, []); children.get(data.parent).push(data); }
    const positions = {}, widths = new Map(), heights = new Map(), cellWidths = new Map(), cellHeights = new Map();
    function size(id) {
      const list = (children.get(id) || []).sort((a, b) => a.id.localeCompare(b.id));
      if (!list.length) { widths.set(id, 150); heights.set(id, 85); return; }
      list.forEach(child => size(child.id));
      const columns = Math.ceil(Math.sqrt(list.length));
      const cellWidth = Math.max(...list.map(child => widths.get(child.id))) + 45;
      const cellHeight = Math.max(...list.map(child => heights.get(child.id))) + 50;
      widths.set(id, columns * cellWidth + 30); heights.set(id, Math.ceil(list.length / columns) * cellHeight + 50);
      cellWidths.set(id, cellWidth); cellHeights.set(id, cellHeight);
    }
    roots.forEach(root => size(root.id));
    const columns = Math.ceil(Math.sqrt(roots.length || 1));
    const cellWidth = Math.max(220, ...roots.map(root => widths.get(root.id))) + 90;
    const cellHeight = Math.max(140, ...roots.map(root => heights.get(root.id))) + 90;
    function place(id, x, y) {
      positions[id] = { x, y };
      const list = children.get(id) || [], cols = Math.ceil(Math.sqrt(list.length));
      list.forEach((child, index) => place(child.id, x - widths.get(id) / 2 + 30 + (index % cols + .5) * cellWidths.get(id), y - heights.get(id) / 2 + 40 + (Math.floor(index / cols) + .5) * cellHeights.get(id)));
    }
    roots.forEach((root, index) => place(root.id, (index % columns) * cellWidth, Math.floor(index / columns) * cellHeight));
    // Position calculations never become canonical data.
    return positions;
  }
  function selectionFor(model, projection, viewId) {
    const element = projection.elements.find(item => item.data.id === viewId);
    if (!element) return null;
    const data = element.data;
    if (element.group === "nodes") return { node_ids: [data.canonicalId], edge_ids: [], evidence_ids: data.evidenceRefs.filter(id => model.evidence.has(id)) };
    return { node_ids: [], edge_ids: data.underlyingIds.filter(id => model.edges.has(id)), evidence_ids: data.evidenceRefs.filter(id => model.evidence.has(id)) };
  }
  return Object.freeze({ LIMITS, validateGraph, projectGraph, groupedPositions, selectionFor, nodeViewId, stable });
});
