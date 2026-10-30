/* Deterministic renderer fixture. Every fact below is synthetic, never scan evidence. */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.AttackMapSyntheticFixture = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  function create(options = {}) {
    const nodeCount = options.nodeCount ?? 64, edgeCount = options.edgeCount ?? 96;
    if (!Number.isInteger(nodeCount) || nodeCount < 36 || nodeCount > 20000 || !Number.isInteger(edgeCount) || edgeCount < 4 || edgeCount > 60000) throw new Error("Synthetic corpus bounds are 36–20000 nodes / 4–60000 edges.");
    const repositories = [], nodes = [], edges = [], evidence = [];
    for (let index = 0; index < 16; index++) {
      const id = `synthetic:repository:${String(index + 1).padStart(2, "0")}`;
      const label = index < 2 ? "app (same basename)" : ["identity", "billing", "catalog", "gateway", "notification", "orders", "search", "profiles", "telemetry", "media", "worker", "isolated", "shared-library", "failed-child"][index - 2];
      repositories.push({ id, repo_id: `synthetic-slug-${index + 1}`, requested_id: `synthetic-transport-${index + 1}`, root: `C:/SYNTHETIC/root-${index + 1}/app`, label, status: index === 15 ? "failed" : index === 11 ? "partial" : "completed", snapshot_id: index === 15 ? null : `synthetic-snapshot-${index + 1}` });
      nodes.push({ id, repo_id: id, kind: "repository", label, parent_id: null, evidence_refs: [] });
    }
    nodes.push({ id: "synthetic:proxy", repo_id: null, kind: "proxy", label: "Explicit proxy step", parent_id: null, evidence_refs: [] });
    nodes.push({ id: "synthetic:external", repo_id: null, kind: "external", label: "Qualified external component", parent_id: null, evidence_refs: [] });
    nodes.push({ id: "synthetic:library", repo_id: repositories[14].id, kind: "component", label: "Library only · no hosted service", parent_id: repositories[14].id, evidence_refs: [] });
    const services = [];
    for (let index = 0; nodes.length < nodeCount; index++) {
      const repo = repositories[index % 14], id = `synthetic:service:${String(index + 1).padStart(5, "0")}`;
      const node = { id, repo_id: repo.id, kind: index % 9 === 0 ? "datastore" : "service", label: `${index % 9 === 0 ? "Store" : "Service"} ${index + 1}`, parent_id: repo.id, evidence_refs: [] };
      nodes.push(node); if (index % 14 !== 13) services.push(node);
    }
    function edge(source, target, index, extra = {}) {
      const id = `synthetic:edge:${String(index + 1).padStart(6, "0")}`, evidenceId = `synthetic:evidence:${index + 1}`;
      evidence.push({ id: evidenceId, repo_id: source.repo_id, kind: "synthetic-observation", file: null, line: null, observation_id: `synthetic-observation-${index + 1}`, source_analyzer: "SYNTHETIC-RENDERER-FIXTURE", basis: "synthetic" });
      edges.push({ id, source: source.id, target: target.id, kind: "http", directed: true, resolution: "observed", basis: "synthetic", evidence_refs: [evidenceId], ...extra });
      source.evidence_refs.push(evidenceId);
    }
    edge(services[0], nodes[16], 0, { relation_id: "synthetic:proxied", proxy_leg: "source-to-proxy" });
    edge(nodes[16], services[1], 1, { relation_id: "synthetic:proxied", proxy_leg: "proxy-to-target" });
    edge(services[1], services[0], 2, { resolution: "candidate" });
    edge(services[2], nodes[17], 3, { kind: "external-dependency", directed: false, resolution: "unknown" });
    for (let index = 4; index < edgeCount; index++) {
      const source = services[(index * 7) % services.length], target = services[(index * 11 + 1) % services.length];
      edge(source, target, index, { kind: index % 5 === 0 ? "datastore-access" : "http", directed: index % 11 !== 0, resolution: index % 7 === 0 ? "candidate" : index % 13 === 0 ? "unresolved" : "observed" });
    }
    return { schema_version: "1.0", kind: "fleet_architecture", graph_id: `synthetic-fleet16-${nodeCount}-${edgeCount}`, repositories, nodes, edges, evidence, coverage: { requested: 16, completed: 14, partial: 1, failed: 1, relation_families: { http: "synthetic", queue: "unknown", rpc: "unknown" } }, limitations: ["SYNTHETIC RENDERER FIXTURE. No repository was scanned.", "Repository 16 failed; its absence of edges is unknown coverage.", "Repository 14 is intentionally disconnected; repository 15 is library-only.", "The repository overview does not prove a continuous service path."] };
  }
  return Object.freeze({ create });
});
