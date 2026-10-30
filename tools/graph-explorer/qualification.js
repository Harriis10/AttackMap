(function () {
  "use strict";
  const $ = id => document.getElementById(id), frame = $("candidate");
  const fixtures = Object.freeze({ oracle: "/docs/verification/windows-parity/WP043/fleet16-20261023/core/fleet16-oracle.json", failed: "/docs/verification/windows-parity/WP043/fleet16-20261023/core/fleet16-oracle-failed.json", normal: "/.tmp/graph-explorer-fixtures/SYNTHETIC-fleet16-1000-3000.json", stress: "/.tmp/graph-explorer-fixtures/SYNTHETIC-fleet16-10000-30000.json" });
  const results = [], startedAt = new Date().toISOString();
  let graph = null, currentFixture = null, sequence = 0, busy = false;
  function api() { const value = frame.contentWindow?.AttackMapGraph; if (!value) throw new Error("Candidate page is not ready. Wait for iframe load."); return value; }
  const settle = () => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  function status(message) { $("status").textContent = message; }
  function heap() { const memory = frame.contentWindow.performance.memory; return memory ? { used_js_heap_bytes: memory.usedJSHeapSize, total_js_heap_bytes: memory.totalJSHeapSize, limit_bytes: memory.jsHeapSizeLimit, scope: "Browser-reported JavaScript heap; not renderer/native process working set." } : { scope: "JavaScript heap unavailable; no process memory measurement." }; }
  function record(action, measurements = {}) {
    const state = api().snapshot(), result = { sequence: ++sequence, at: new Date().toISOString(), fixture: currentFixture, synthetic: true, action, measurements, heap: heap(), snapshot: state, qualification_scope: "Actual browser page observation; native host, OS accessibility, real scan, process memory and release acceptance remain separate." };
    results.push(result); $("result").value = JSON.stringify(result, null, 2);
    const count = state.counts;
    $("timings").textContent = count ? `${count.displayedNodes}/${count.canonicalNodes} nodes · ${count.displayedEdges} displayed edge groups · ${count.representedEdges}/${count.canonicalEdges} represented originals · ${count.internalEdges} collapsed internal · ${count.boundedNodes} bounded nodes / ${count.boundedEdges} bounded edges${state.timing ? ` · ${state.timing.layout}: ${state.timing.elapsed_ms.toFixed(2)} ms (synchronous layout only)` : ""}` : "No graph loaded.";
    return result;
  }
  async function operation(name, callback) {
    if (busy) throw new Error("A qualification action is already running.");
    busy = true; document.body.classList.add("busy");
    try { const value = await callback(); status(`${name} complete · ${results.length} recorded result(s).`); return value; }
    catch (error) { status(`${name} failed: ${error.message}`); $("result").value = JSON.stringify({ action: name, error: error.message, at: new Date().toISOString() }, null, 2); throw error; }
    finally { busy = false; document.body.classList.remove("busy"); }
  }
  async function load(name) {
    return operation(`Load ${name}`, async () => {
      if (!Object.prototype.hasOwnProperty.call(fixtures, name)) throw new Error("Unknown allowlisted fixture.");
      api(); const begin = performance.now();
      const response = await fetch(fixtures[name], { cache: "no-store", credentials: "same-origin" });
      if (!response.ok) throw new Error(`Fixture HTTP ${response.status}: ${fixtures[name]}`);
      const bytes = await response.arrayBuffer(), fetched = performance.now();
      const parsed = JSON.parse(new TextDecoder().decode(bytes)), parsedAt = performance.now();
      const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map(value => value.toString(16).padStart(2, "0")).join("");
      graph = parsed; currentFixture = { name, path: fixtures[name], bytes: bytes.byteLength, sha256: hash, repositories: graph.repositories.length, nodes: graph.nodes.length, edges: graph.edges.length };
      const replaceStart = performance.now();
      api().replaceGraph(graph, { token: `qualification-${name}-${sequence + 1}`, run_id: `SYNTHETIC-qualification-${name}` }, { synthetic: true });
      const replaced = performance.now(); await settle();
      return record("load", { fetch_ms: fetched - begin, parse_ms: parsedAt - fetched, replace_validation_projection_layout_ms: replaced - replaceStart, replace_to_two_animation_frames_ms: performance.now() - replaceStart, note: "Animation frames are a settling observation, not proof of all pixels painted." });
    });
  }
  async function action(name) {
    return operation(name, async () => {
      const candidate = api(); if (!graph) throw new Error("Load a fixture first.");
      const begin = performance.now();
      if (name === "collapsed") candidate.setOptions({ collapsedIds: graph.repositories.map(repo => repo.id) });
      else if (name === "expanded") candidate.setOptions({ collapsedIds: [] });
      else if (name === "preset" || name === "fcose") candidate.runLayout(name);
      else if (name === "light" || name === "dark") candidate.theme(name);
      else throw new Error("Unknown qualification action.");
      const returned = performance.now(); await settle();
      return record(name, { call_ms: returned - begin, call_to_two_animation_frames_ms: performance.now() - begin });
    });
  }
  async function compare() {
    return operation("Layout comparison", async () => {
      if (!graph) throw new Error("Load a fixture first.");
      const trials = Math.max(1, Math.min(10, Number.parseInt($("trials").value, 10) || 3)), recorded = [];
      for (const layout of ["preset", "fcose"]) {
        for (let trial = 0; trial < trials; trial++) {
          const begin = performance.now(), timing = api().runLayout(layout), returned = performance.now(); await settle();
          recorded.push(record("layout-comparison", { requested_layout: layout, trial: trial + 1, trials, actual_layout: timing?.layout, call_ms: returned - begin, call_to_two_animation_frames_ms: performance.now() - begin, guarded_fallback: timing?.layout !== layout, synchronous: true, preemptive_cancel_claim: false }));
        }
      }
      return recorded;
    });
  }
  function download() {
    const payload = { kind: "attackmap-web-renderer-qualification", started_at: startedAt, generated_at: new Date().toISOString(), user_agent: navigator.userAgent, origin: location.origin, synthetic: true, results };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }), url = URL.createObjectURL(blob), anchor = document.createElement("a");
    anchor.href = url; anchor.download = `attackmap-web-qualification-${Date.now()}.json`; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  for (const button of document.querySelectorAll("[data-fixture]")) button.addEventListener("click", () => load(button.dataset.fixture).catch(() => {}));
  for (const button of document.querySelectorAll("[data-action]")) button.addEventListener("click", () => action(button.dataset.action).catch(() => {}));
  $("snapshot").addEventListener("click", () => { try { record("snapshot"); status("Snapshot recorded."); } catch (error) { status(error.message); } });
  $("compare").addEventListener("click", () => compare().catch(() => {})); $("download").addEventListener("click", download);
  $("compact").addEventListener("click", () => { document.body.classList.toggle("compact"); $("compact").textContent = document.body.classList.contains("compact") ? "Show results" : "Focus graph"; });
  frame.addEventListener("load", () => { try { api(); status("Candidate ready. Select an allowlisted synthetic fixture."); } catch (error) { status(error.message); } });
  window.AttackMapQualification = Object.freeze({ load, action, compare, record: () => record("snapshot"), results: () => JSON.parse(JSON.stringify(results)), download });
})();
