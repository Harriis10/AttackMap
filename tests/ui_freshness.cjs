/* Exercises the shipped API and view/cache adapter, without a browser dependency. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

const scripts = path.join(__dirname, "../src/attackmap/ui/web/src");
const copy = (value) => JSON.parse(JSON.stringify(value));
const tick = () => new Promise((resolve) => setImmediate(resolve));
function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}

function snapshot(repo, generation, status = "done") {
  return {
    repositoryKey: repo, reportRepositoryKey: repo, reportGeneration: generation,
    runId: generation, status, hasReport: !!generation, repos: [repo],
    findingCount: 1, availableModules: [],
  };
}

function report(repo, generation) {
  return {
    repositoryKey: repo, generationId: generation, repoName: repo,
    reviewMd: `${repo}/${generation}`, findings: [], exploitability: [],
    severityCounts: {}, diagrams: {}, findingCount: 1,
  };
}

async function harness() {
  const elements = new Map();
  const requests = [];
  const renders = [];
  const timers = [];
  const gates = new Map();
  let state = snapshot("a", null, "idle");
  let currentReport = null;
  let activeStates = 0;
  let maxStates = 0;
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      id, innerHTML: "", value: "", style: {}, options: [], listeners: {},
      classList: { toggle() {} }, add() {}, remove() {},
      addEventListener(name, callback) { this.listeners[name] = callback; },
    });
    return elements.get(id);
  }
  const context = vm.createContext({
    URL, URLSearchParams, console, renders,
    location: { search: "", pathname: "/", origin: "http://127.0.0.1" },
    history: {}, sessionStorage: { getItem() { return "token"; } },
    document: { getElementById: element, activeElement: null, querySelectorAll: () => [] },
    window: {}, Option: function() {},
    renderMarkdown: (text) => text, renderMermaidDocument: (text) => text,
    setTimeout: (callback) => timers.push(callback),
    fetch: async (url, options) => {
      requests.push(url.pathname);
      const isState = url.pathname === "/api/state";
      if (isState) maxStates = Math.max(maxStates, ++activeStates);
      const data = copy(isState ? state : url.pathname === "/api/report" ? currentReport : {});
      const gate = gates.get(url.pathname);
      gates.delete(url.pathname);
      if (gate) await gate.promise;
      if (isState) activeStates -= 1;
      return { ok: true, headers: { get: () => "application/json" }, json: async () => data };
    },
  });
  for (const name of ["api.js", "app.js"]) {
    vm.runInContext(fs.readFileSync(path.join(scripts, name), "utf8"), context, { filename: name });
  }
  await vm.runInContext("refreshPromise", context);
  vm.runInContext(`
    const originalRenderMain = renderMain;
    renderMain = (s, r) => {
      renders.push({state: s, report: r, view: currentView});
      return originalRenderMain(s, r);
    };
    currentView = "review";
  `, context);
  return {
    context, requests, renders, timers, elements,
    run: (code) => vm.runInContext(code, context),
    refresh: () => vm.runInContext("refresh()", context),
    set(repo, generation, status = "done") {
      state = snapshot(repo, generation, status);
      currentReport = generation ? report(repo, generation) : null;
    },
    hold(url) { const gate = deferred(); gates.set(url, gate); return gate; },
    maxStates: () => maxStates,
  };
}

test("100 scan sequences retain only the selected repository and generation", async () => {
  const h = await harness();
  for (let i = 0; i < 100; i++) {
    const repo = `repo-${i % 3}`;
    h.set(repo, `first-${i}`);
    await h.refresh();
    assert.equal(h.elements.get("view").innerHTML, `${repo}/first-${i}`);
    if (i % 2) {
      h.set(repo, `first-${i}`, "running");
      for (const view of ["findings", "settings", "recents", "review"]) {
        h.run(`currentView = ${JSON.stringify(view)}`);
        await h.refresh();
        assert.equal(h.run("reportCache"), null);
      }
    }
    // Even sequences finish entirely between polls.
    h.set(repo, `second-${i}`);
    await h.refresh();
    assert.equal(h.elements.get("view").innerHTML, `${repo}/second-${i}`);
    h.set(repo, `second-${i}`, "failed");
    await h.refresh();
    assert.equal(h.run("reportCache"), null);
    assert.ok(!h.elements.get("view").innerHTML.includes(`second-${i}`));
    assert.equal(h.elements.get("export-md").disabled, true);
    h.set(`other-${i}`, null, "idle");
    await h.refresh();
    assert.equal(h.run("reportCache"), null);
    h.set(`other-${i}`, `third-${i}`);
    await h.refresh();
    assert.equal(h.elements.get("view").innerHTML, `other-${i}/third-${i}`);
  }
  for (const { state, report } of h.renders) {
    if (report) {
      assert.equal(report.generationId, state.reportGeneration);
      assert.equal(report.repositoryKey, state.repositoryKey);
      assert.ok(["idle", "done"].includes(state.status));
    }
  }
  assert.equal(h.maxStates(), 1);
});

test("delayed report cannot overwrite a newer workspace or navigation request", async () => {
  const h = await harness();
  h.set("old", "g1");
  const gate = h.hold("/api/report");
  const old = h.refresh();
  await tick();
  h.set("new", "g2");
  h.run('currentView = "findings"');
  const latest = h.refresh();
  gate.resolve();
  await Promise.all([old, latest]);
  assert.ok(!h.renders.some((r) => r.report && r.report.generationId === "g1"));
  assert.equal(h.renders.at(-1).view, "findings");
  assert.equal(h.run("reportCache.generationId"), "g2");
  assert.equal(h.run("reportCache.repositoryKey"), "new");
});

for (const transition of [
  { repo: "a", generation: "g2", status: "done" },
  { repo: "a", generation: "g1", status: "running" },
  { repo: "a", generation: "g1", status: "failed" },
  { repo: "b", generation: "g2", status: "done" },
  { repo: "b", generation: null, status: "idle" },
]) {
  test(`server transition during report load is revalidated: ${JSON.stringify(transition)}`, async () => {
    const h = await harness();
    h.set("a", "g1");
    const gate = h.hold("/api/report");
    const pending = h.refresh();
    await tick();
    // Watch/native changes do not issue another frontend refresh or POST.
    h.set(transition.repo, transition.generation, transition.status);
    gate.resolve();
    await pending;
    assert.ok(!h.renders.some((r) => r.report && r.report.generationId === "g1"));
    if (transition.status === "done") {
      assert.equal(h.run("reportCache.generationId"), transition.generation);
      assert.equal(h.run("reportCache.repositoryKey"), transition.repo);
    } else {
      assert.equal(h.run("reportCache"), null);
      assert.equal(h.elements.get("export-md").disabled, true);
    }
    assert.equal(h.maxStates(), 1);
  });
}

test("report validation does not reuse a state read that predates the report response", async () => {
  const h = await harness();
  h.set("a", "g1");
  const reportGate = h.hold("/api/report");
  const pending = h.refresh();
  await tick();
  const stateGate = h.hold("/api/state");
  const commandState = h.run("getState()");
  await tick();
  h.set("a", "g2");
  reportGate.resolve();
  await tick();
  assert.ok(!h.renders.some((r) => r.report));
  stateGate.resolve();
  await Promise.all([pending, commandState]);
  assert.equal(h.run("reportCache.generationId"), "g2");
  assert.ok(!h.renders.some((r) => r.report && r.report.generationId === "g1"));
  assert.equal(h.maxStates(), 1);
});

test("state polling is serialized across refresh and command handlers", async () => {
  const h = await harness();
  const gate = h.hold("/api/state");
  const requests = [h.refresh(), h.run("getState()"), h.run("getState()"), h.refresh()];
  await tick();
  assert.equal(h.maxStates(), 1);
  gate.resolve();
  await Promise.all(requests);
  assert.equal(h.maxStates(), 1);
  // A new timer is armed only after the prior poll resolves.
  assert.equal(h.timers.length, 1);
  const nextGate = h.hold("/api/state");
  const poll = h.timers[0]();
  await tick();
  assert.equal(h.timers.length, 1);
  nextGate.resolve();
  await poll;
  assert.equal(h.timers.length, 2);
});

test("responses started before a mutation are discarded even without another refresh", async () => {
  const h = await harness();
  h.set("before", "g1");
  const gate = h.hold("/api/state");
  const pending = h.refresh();
  await tick();
  h.set("after", "g2");
  await h.run('post("/api/config", {repo: "after"})');
  gate.resolve();
  await pending;
  assert.equal(h.run("reportCache.generationId"), "g2");
  assert.ok(!h.renders.some((r) => r.state.repositoryKey === "before"));
  assert.equal(h.maxStates(), 1);
});

test("mismatched report identity never enters the cache", async () => {
  const h = await harness();
  h.set("a", "g1");
  const gate = h.hold("/api/state");
  const pending = h.refresh();
  await tick();
  h.set("b", "g2");
  gate.resolve();
  await pending;
  // The post-load validation observes the changed workspace and retries
  // immediately; only the matching current generation may be painted.
  assert.ok(!h.renders.some((r) => r.report && r.report.generationId === "g1"));
  assert.ok(h.renders.every((r) => !r.report || r.report.repositoryKey === r.state.repositoryKey));
  assert.equal(h.run("reportCache.generationId"), "g2");
});

test("typing cannot preserve an old view while the next generation loads", async () => {
  const h = await harness();
  h.set("a", "g1");
  await h.refresh();
  assert.equal(h.elements.get("view").innerHTML, "a/g1");
  h.run('document.activeElement = {id: "suppress-reason"}');
  h.set("a", "g2");
  const gate = h.hold("/api/report");
  const pending = h.refresh();
  await tick();
  assert.ok(!h.elements.get("view").innerHTML.includes("a/g1"));
  assert.equal(h.elements.get("export-md").disabled, true);
  gate.resolve();
  await pending;
  assert.equal(h.elements.get("view").innerHTML, "a/g2");
  h.set("a", "g2", "running");
  h.run('document.activeElement = {id: "repo-label"}');
  await h.refresh();
  assert.ok(h.elements.get("view").innerHTML.includes("Scanning"));
  assert.equal(h.run("reportCache"), null);
});
