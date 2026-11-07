let currentView = "overview";
let openRow = -1;
let selectedFinding = 0;
let reportCache = null;
let renderedReport = null;
let renderedView = null;
let refreshPromise = null;
let refreshRequested = false;
let refreshRevision = 0;
let progressStarted = 0;

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function renderExploitability(rows, report) {
  if (!rows || !rows.length) {
    const chains = (report && report.dataFlows) || [];
    return `<div class="empty-state">
      <h3>No static route→sink paths to rank</h3>
      <p>Heuristic static analysis; runtime reachability and exploitability are not verified.</p>
      <p>The exploitability ranking is built from taint chains (source → variable → sink)
      traced inside request handlers. This scan traced <strong>${chains.length}</strong> such chains,
      so there is nothing to rank.</p>
      <p class="muted">Typical reasons: the repo's framework isn't covered by an installed analyzer
      (e.g. plain-PHP superglobal flows), routes weren't detected, or sinks are reached
      through helper calls the intra-procedural pass doesn't follow. Findings and the
      defensive review still apply — this tab only ranks route→sink flows.</p>
    </div>`;
  }
  return `<p class="muted">Heuristic static analysis; runtime reachability and exploitability are not verified.</p><div class="exploit-list">${rows.map((row, i) => `
    <div class="exploit-row${openRow === i ? " open" : ""}" data-i="${i}">
      <div class="score">${escapeHtml(row.score)}</div>
      <div class="path">${escapeHtml(row.method)} ${escapeHtml(row.route)} → ${escapeHtml(row.sinkKind)}</div>
      <div class="meta">
        <span class="chip">${escapeHtml(row.sinkKind)}</span>
        <span class="chip ${escapeHtml(row.tier)}">${escapeHtml(row.tier)}</span>
        <span class="loc">${escapeHtml(row.location)}</span>
      </div>
      ${openRow === i ? `<ul class="factors">${(row.factors || []).map((f) =>
        `<li>${escapeHtml(f.points)} ${escapeHtml(f.name)}${f.detail ? " — " + escapeHtml(f.detail) : ""}</li>`
      ).join("")}</ul>` : ""}
    </div>`).join("")}</div>`;
}

function renderOverview(r) {
  const sev = r.severityCounts || {};
  const top = r.topPath;
  return `<div class="cards">
    <div class="card"><div class="muted">Findings</div><div class="n">${r.findingCount}</div></div>
    <div class="card"><div class="muted">High</div><div class="n">${sev.high || 0}</div></div>
    <div class="card"><div class="muted">Medium</div><div class="n">${sev.medium || 0}</div></div>
    <div class="card"><div class="muted">Low</div><div class="n">${sev.low || 0}</div></div>
  </div>
  ${top ? `<div class="card" style="margin:0 16px 16px"><div class="muted">Highest static route-to-sink risk score</div>
    <div>${escapeHtml(top.method || "")} ${escapeHtml(top.route || top.subject)} · score ${escapeHtml(top.score)}</div><div class="muted">Heuristic static analysis; runtime reachability and exploitability are not verified.</div></div>` : ""}
  ${renderMarkdown((r.diagrams && r.diagrams.architecture) || "")}`;
}

function renderFindings(r) {
  const findings = r.findings || [];
  const suppressed = r.suppressed || [];
  const f = findings[selectedFinding] || findings[0];
  const list = findings.map((item, i) => {
    const loc = (item.locations && item.locations[0]) || {};
    return `<div class="split-row${i === selectedFinding ? " open" : ""}" data-fi="${i}">
      <div>${escapeHtml(item.title || "")}<div class="muted">${escapeHtml((loc.file || "") + (loc.line ? ":" + loc.line : ""))}</div></div>
      <span class="sev ${escapeHtml(item.severity || "")}">${escapeHtml(item.severity || "")}</span>
    </div>`;
  }).join("");
  const techniques = ((f && f.attack_techniques) || []).map((t) => (typeof t === "string" ? t : (t.technique_id || t.id || ""))).filter(Boolean).join(", ");
  const detail = f ? `<div class="detail">
      <h2>${escapeHtml(f.title || "")}</h2>
      <span class="sev ${escapeHtml(f.severity || "")}">${escapeHtml(f.severity || "")}</span>
      <p>${(f.evidence || []).map((e) => `<div class="muted">${escapeHtml(e)}</div>`).join("")}</p>
      <p><strong>Remediation</strong><br/>${escapeHtml(f.mitigation || "")}</p>
      ${techniques ? `<p>ATT&CK: ${escapeHtml(techniques)}</p>` : ""}
      <p><input id="suppress-reason" placeholder="Suppression reason" />
      <button type="button" class="ghost" id="suppress-btn">Suppress…</button></p>
    </div>` : `<div class="empty">No findings.</div>`;
  const hidden = suppressed.length ? `<details style="padding:12px"><summary>Suppressed (${suppressed.length})</summary>
    ${suppressed.map((s) => `<div class="list-row"><div>${escapeHtml(s.title || s.id || "")}<div class="muted">${escapeHtml(s.reason || "")}</div></div></div>`).join("")}
  </details>` : "";
  return `<div class="master"><div>${list}${hidden}</div>${detail}</div>`;
}

function renderPaths(paths) {
  if (!paths.length) {
    return `<div class="empty-state"><h3>No attack paths</h3>
      <p>No entry→asset trust chains were inferred in this scan.</p></div>`;
  }
  return paths.map((p) => {
    const steps = (p.steps || []).map((s) => (typeof s === "string" ? s : ((s.stage || "") + (s.detail || s.action || s.label ? ": " + (s.detail || s.action || s.label) : "")))).filter(Boolean);
    return `<div class="path-card">
      <div class="path-name">${escapeHtml(p.name || "")}</div>
      <div class="m-row">${steps.map((s, i) =>
        `<span class="m-node">${escapeHtml(s)}</span>${i < steps.length - 1 ? '<span class="m-arrow">→</span>' : ""}`
      ).join("")}</div>
      ${p.impact ? `<div class="path-impact">Impact: ${escapeHtml(p.impact)}</div>` : ""}
    </div>`;
  }).join("");
}

function renderSurface(surfaces) {
  if (!surfaces.length) return `<div class="empty">No attack surface.</div>`;
  return `<table class="grid"><thead><tr><th>Method</th><th>Path</th><th>Category</th><th>Exposure</th><th>File</th></tr></thead><tbody>
    ${surfaces.map((s) => `<tr><td>${escapeHtml(s.method || "")}</td><td>${escapeHtml(s.route || s.path || "")}</td>
      <td>${escapeHtml(s.category || "")}</td><td>${escapeHtml(s.exposure || "")}</td>
      <td>${escapeHtml(s.file || "")}</td></tr>`).join("")}
  </tbody></table>`;
}

function renderInventory(rows, empty) {
  if (!rows || !rows.length) return `<div class="empty">${empty}</div>`;
  return rows.map((item) => {
    const title = item.name || item.id || item.kind || item.rule || item.label || item.package
      || ((item.route_method || item.route_path || item.sink_kind)
        ? `${item.route_method || ""} ${item.route_path || ""} → ${item.sink_kind || ""}`.trim()
        : "item");
    const loc = item.file ? `${item.file}${item.line ? ":" + item.line : ""}`
      : (item.sink_file ? `${item.sink_file}${item.sink_line ? ":" + item.sink_line : ""}` : (item.location || ""));
    return `<div class="list-row"><div>${escapeHtml(title)}<div class="muted">${escapeHtml(item.summary || item.message || item.ecosystem || "")}</div></div>
      <code>${escapeHtml(loc)}</code></div>`;
  }).join("");
}

function renderDependencies(report) {
  const deps = report.dependencies || [];
  const vulns = report.vulnerabilities || [];
  const depRows = deps.length
    ? `<table class="grid"><thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Scope</th><th>Resolved via</th></tr></thead><tbody>
      ${deps.map((d) => `<tr>
        <td>${escapeHtml(d.name || "")}</td>
        <td>${escapeHtml(d.version || "")}</td>
        <td>${escapeHtml(d.ecosystem || "")}</td>
        <td>${d.direct ? "direct" : "transitive"}${d.dev ? " · dev" : ""}</td>
        <td>${escapeHtml(d.via || d.file || "")}</td>
      </tr>`).join("")}
    </tbody></table>`
    : `<div class="empty-state"><h3>No dependencies detected</h3>
       <p>No package manifests or lockfiles were resolved in this scan.</p>
       <p class="muted">Run with <strong>CVE</strong> enabled to cross-reference resolved
       dependencies against OSV.dev advisories.</p></div>`;
  const vulnRows = vulns.length
    ? `<h3 style="padding:12px 12px 0">Known advisories</h3>
       <table class="grid"><thead><tr><th>ID</th><th>Aliases</th><th>Summary</th><th>Affected</th></tr></thead><tbody>
       ${vulns.map((v) => `<tr>
         <td>${escapeHtml(v.id || v.osv_id || "")}</td>
         <td>${escapeHtml((v.aliases || []).join(", "))}</td>
         <td>${escapeHtml(v.summary || "")}</td>
         <td>${escapeHtml(v.affected || v.package || "")}</td>
       </tr>`).join("")}</tbody></table>`
    : "";
  return depRows + vulnRows;
}

function renderFleet(fleet) {
  if (!fleet) return `<div class="empty">Select two or more folders with + Fleet, then run a scan.</div>`;
  const repos = (fleet.repos || []).map((r) => `<div class="list-row"><div>${escapeHtml(r.repo_id || r.root)}</div><span>${escapeHtml(r.findings)}</span></div>`).join("");
  const links = (fleet.cross_repo_links || []).map((l) => `<div class="list-row"><div>${escapeHtml(l.client_repo)} → ${escapeHtml(l.server_repo)}</div><code>${escapeHtml(l.method + " " + (l.path_template || ""))}</code></div>`).join("");
  const failed = (fleet.failed || []).map((f) => `<div class="list-row"><div>${escapeHtml(f.repo_id || "")}<div class="muted">${escapeHtml(f.error || "")}</div></div></div>`).join("");
  const gaps = (fleet.trust_gaps || []).concat(fleet.cross_boundary_flows || []).map((g) => `<div class="list-row"><div>${escapeHtml(g.client_repo || "")} → ${escapeHtml(g.server_repo || "")}<div class="muted">${escapeHtml(g.basis || g.kind || "")}</div></div></div>`).join("");
  return `<div class="cards"><div class="card"><div class="muted">Repos</div><div class="n">${Number(fleet.repo_count) || 0}</div></div>
    <div class="card"><div class="muted">Findings</div><div class="n">${Number(fleet.total_findings) || 0}</div></div></div>
    <h3 style="padding:0 16px">Per-repo rollup</h3>${repos || '<div class="empty">None</div>'}
    <h3 style="padding:0 16px">Contract links</h3>${links || '<div class="empty">None</div>'}
    <h3 style="padding:0 16px">Failed</h3>${failed || '<div class="empty">None</div>'}
    <h3 style="padding:0 16px">Trust gaps / cross-boundary</h3>${gaps || '<div class="empty">None</div>'}`;
}

function renderSettings(state) {
  return `<div class="settings">
    <p>AI and CVE checks are off on first launch. AI sends repository metadata, findings and evidence to the selected provider; verification and remediation may include source excerpts. Secret masking is best effort. Providers control retention.</p><p>CVE checks send dependency ecosystems, package names and versions to OSV (api.osv.dev), including private package names. Custom AI endpoints can be remote.</p><p>API keys are stored with Windows DPAPI and injected only into the selected scan child process.</p>
    <label>Anthropic API key ${state.hasAnthropicKey ? "(saved)" : ""}</label>
    <input type="password" id="anth-key" placeholder="sk-ant-…" />
    <label>OpenAI API key ${state.hasOpenAIKey ? "(saved)" : ""}</label>
    <input type="password" id="oai-key" placeholder="sk-…" />
    <p>LM Studio (OpenAI-compatible local endpoint): keep the provider set to
    <strong>LM Studio (local)</strong> in the toolbar and use Base URL
    <code>http://127.0.0.1:1234/v1</code>. LM Studio accepts any non-empty API key;
    stored production keys are not forwarded to loopback endpoints.</p>
    <p><button type="button" class="run" id="save-keys" style="margin-left:0">Save keys</button></p>
  </div>`;
}

function renderMain(state, report) {
  if (currentView === "settings") return renderSettings(state);
  if (state.status === "running") {
    const p = state.progress || {};
    return `<div class="running">Scanning… ${escapeHtml(p.label || p.event || "")} ${escapeHtml(p.current || "")}</div>`;
  }
  if (state.status === "failed") {
    return `<div class="failed">${escapeHtml(state.error || "Scan failed.")}${state.stderrTail && state.stderrTail !== state.error ? "\n\n" + escapeHtml(state.stderrTail) : ""}</div>`;
  }
  if (currentView === "recents") {
    const items = (state.recents || []).map((r) => `<div class="list-row recent" data-path="${escapeHtml(r.path)}"><div>${escapeHtml(r.name)}<div class="muted">${escapeHtml(r.path)}</div></div></div>`).join("");
    return items || `<div class="empty">No recent scans.</div>`;
  }
  if (!report) return `<div class="empty">${state.hasReport ? "Loading current report…" : "Pick a repository and run a scan."}</div>`;
  if (currentView === "overview") return renderOverview(report);
  if (currentView === "findings") return renderFindings(report);
  if (currentView === "exploitability") return renderExploitability(report.exploitability, report);
  if (currentView === "paths") return renderPaths(report.attackPaths || []);
  if (currentView === "surface") return renderSurface(report.attackSurfaces || []);
  if (currentView === "diagrams") {
    return renderMermaidDocument((report.diagrams && (report.diagrams.paths || report.diagrams.topology)) || "")
      + (report.diagrams && report.diagrams.topology && report.diagrams.paths ? renderMermaidDocument(report.diagrams.topology) : "");
  }
  if (currentView === "review") return renderMarkdown(report.reviewMd || "");
  if (currentView === "ai-review") {
    if (report.aiReviewMd) {
      return renderMarkdown(report.aiReviewMd);
    }
    if (report.aiReviewRequested) {
      return `<div class="empty">AI Review was requested but produced no output. Check the *.meta.json files in the report folder for backend details.</div>`;
    }
    return `<div class="empty">Enable an AI mode to generate a review. Optional AI and CVE features have separate network and data disclosures in Settings.</div>`;
  }
  if (currentView === "diff") return renderMarkdown(report.diffMd || "No baseline diff. Re-run the same repo to compare.");
  if (currentView === "fleet") return renderFleet(report.fleet);
  if (currentView === "deps") return renderDependencies(report);
  if (currentView === "secrets") return renderInventory(report.secrets || [], "No secrets.");
  if (currentView === "ci") return renderInventory(report.workflows || [], "No CI workflow issues.");
  if (currentView === "flows") return renderInventory(report.dataFlows || [], "No data-flow chains.");
  if (currentView === "analyzers") {
    const errors = report.analyzerErrors || [];
    const limits = report.limitations || [];
    return `${errors.map((e) => `<div class="list-row"><div>${escapeHtml(e.analyzer || "")}<div class="muted">${escapeHtml(e.message || "")}</div></div></div>`).join("")}
      ${limits.map((l) => `<div class="list-row"><div>${escapeHtml(l)}</div></div>`).join("")}
      ${!errors.length && !limits.length ? `<div class="empty">Analyzers completed without recorded errors.</div>` : ""}`;
  }
  return "";
}

function paintStatus(state) {
  const status = document.getElementById("status-text");
  const delta = document.getElementById("delta");
  const watching = document.getElementById("watching");
  const run = document.getElementById("run");
  const dot = document.getElementById("dot");
  const barWrap = document.getElementById("bar-wrap");
  const bar = document.getElementById("bar");
  const eta = document.getElementById("eta");
  const reveal = document.getElementById("reveal");
  const p = state.progress || {};
  dot.className = "dot " + (state.status || "");
  if (state.status === "running") {
    status.textContent = `Scanning… ${p.current || p.label || ""}`;
    run.textContent = "Cancel";
    const total = Number(p.total) || 0;
    const done = Number(p.done) || 0;
    if (p.event === "begin") progressStarted = Date.now();
    barWrap.hidden = !total;
    const pct = total ? Math.min(100, Math.round((done / total) * 100)) : 0;
    bar.style.width = pct + "%";
    if (total && done > 0 && progressStarted) {
      const elapsed = (Date.now() - progressStarted) / 1000;
      const remain = Math.max(0, Math.round((elapsed / done) * (total - done)));
      eta.textContent = remain ? `ETA ${remain}s` : "";
    } else eta.textContent = "";
  } else if (state.status === "failed") {
    status.textContent = "Failed";
    run.textContent = "Run scan";
    barWrap.hidden = true;
    eta.textContent = "";
  } else if (state.status === "idle") {
    status.textContent = "Pick a repository and run a scan.";
    run.textContent = "Run scan";
    barWrap.hidden = true;
  } else {
    status.textContent = `Done — ${state.findingCount || 0} findings`;
    run.textContent = "Run scan";
    barWrap.hidden = true;
    eta.textContent = "";
  }
  if (state.newCount || state.resolvedCount) {
    delta.innerHTML = `<span class="new">+${state.newCount} new</span> · <span class="resolved">${state.resolvedCount} resolved</span>`;
  } else delta.textContent = "";
  watching.hidden = !state.watch;
  watching.textContent = state.watchNotice ? `Watching — ${state.watchNotice}` : "Watching";
  reveal.hidden = !state.output;
  const label = document.getElementById("repo-label");
  if (document.activeElement !== label) {
    if (state.repos && state.repos.length) label.value = state.repos.join(" · ");
    else if (state.repo) label.value = state.repo;
  }
  const analyzers = document.getElementById("analyzers");
  if (state.availableModules && analyzers.options.length <= 1) {
    state.availableModules.forEach((m) => analyzers.add(new Option(m.display_name || m.name, m.name)));
  }
}

function showMissing(state) {
  if (!state.missingAnalyzers || !state.missingAnalyzers.length) return "";
  const names = state.missingAnalyzers.map((m) => m.plugin).join(", ");
  return `<div class="banner">Recommended analyzers are not installed: ${escapeHtml(names)}. Install them, then re-run — a heuristic-only pass may miss language-specific sinks.</div>`;
}

async function loadReportIfNeeded(state, isCurrent = () => true) {
  if (!["idle", "done"].includes(state.status) || !state.hasReport
      || !state.reportGeneration || state.reportRepositoryKey !== state.repositoryKey) {
    reportCache = null;
    return null;
  }
  if (reportCache && reportCache.generationId === state.reportGeneration
      && reportCache.repositoryKey === state.repositoryKey) return reportCache;
  reportCache = null;
  selectedFinding = 0;
  openRow = -1;
  try {
    const report = await getReport(state);
    if (!isCurrent()) return null;
    // Watch scans and native folder selection can change the server without
    // a local refresh/post. Revalidate after the report body has arrived so
    // an old response cannot become the current view.
    const latest = await getFreshState();
    if (!isCurrent()) return null;
    if (!["idle", "done"].includes(latest.status) || !latest.hasReport
        || latest.reportGeneration !== state.reportGeneration
        || latest.repositoryKey !== state.repositoryKey
        || latest.reportRepositoryKey !== state.repositoryKey) {
      refreshRequested = true;
      return null;
    }
    if (report.generationId === state.reportGeneration && report.repositoryKey === state.repositoryKey) {
      reportCache = report;
    }
  } catch {
    // The generation may have changed between the state and report requests.
    if (isCurrent()) reportCache = null;
  }
  return reportCache;
}

const VIEW_TITLES = {
  overview: "Overview",
  findings: "Findings",
  exploitability: "Exploitability",
  paths: "Attack paths",
  surface: "Attack surface",
  diagrams: "Diagrams",
  review: "Review",
  "ai-review": "AI Review",
  diff: "Diff",
  fleet: "Fleet",
  deps: "Dependencies",
  secrets: "Secrets",
  ci: "CI workflows",
  flows: "Data flows",
  analyzers: "Analyzers",
  recents: "Recent scans",
};

function canExport(state) {
  return ["idle", "done"].includes(state.status) && currentView !== "settings" && !!reportCache;
}

function paintViewbar(state) {
  const bar = document.getElementById("viewbar");
  const title = document.getElementById("view-title");
  const mdBtn = document.getElementById("export-md");
  const pdfBtn = document.getElementById("export-pdf");
  title.textContent = VIEW_TITLES[currentView] || "";
  const ok = canExport(state);
  mdBtn.disabled = !ok;
  pdfBtn.disabled = !ok;
  bar.hidden = false;
}

function refresh() {
  refreshRequested = true;
  refreshRevision += 1;
  if (!refreshPromise) {
    refreshPromise = refreshPending().finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
}

function paintMain(state, report) {
  paintViewbar(state);
  const focused = document.activeElement && document.activeElement.id;
  if (currentView === "settings" && ["anth-key", "oai-key"].includes(focused)) return;
  if (focused === "suppress-reason" && report && renderedReport === report && renderedView === currentView) return;
  document.getElementById("view").innerHTML = showMissing(state) + renderMain(state, report);
  renderedReport = report;
  renderedView = currentView;
}

async function refreshPending() {
  let state = null;
  while (refreshRequested) {
    refreshRequested = false;
    const revision = refreshRevision;
    const epoch = stateEpoch;
    const isCurrent = () => revision === refreshRevision && epoch === stateEpoch;
    try {
      state = await getState();
      if (!isCurrent()) { refreshRequested = true; continue; }
      paintStatus(state);
      const pendingReport = loadReportIfNeeded(state, isCurrent);
      // Clear the old view while the new generation is still in flight.
      if (!reportCache) paintMain(state, null);
      const report = await pendingReport;
      if (!isCurrent()) { refreshRequested = true; continue; }
      paintMain(state, report);
    } catch (err) {
      if (!isCurrent()) { refreshRequested = true; continue; }
      reportCache = null;
      document.getElementById("view").innerHTML = `<div class="failed">${escapeHtml(err.message || String(err))}</div>`;
      document.getElementById("export-md").disabled = true;
      document.getElementById("export-pdf").disabled = true;
      state = null;
    }
  }
  return state;
}

function suggestedExportName(suffix) {
  const repo = (reportCache && reportCache.repoName) || "report";
  const safe = String(repo).replace(/[^a-zA-Z0-9-_]+/g, "-").replace(/^-+|-+$/g, "").toLowerCase() || "report";
  return `attackmap-${safe}-${currentView}${suffix}`;
}

async function pickSavePath(suggestedName, extension) {
  try {
    if (window.pywebview && window.pywebview.api && window.pywebview.api.pick_save) {
      const chosen = await window.pywebview.api.pick_save(suggestedName, extension);
      if (chosen) return chosen;
    }
  } catch {}
  const res = await post("/api/pick-save", { suggestedName });
  return res.path || "";
}

async function doExport(suffix) {
  const path = await pickSavePath(suggestedExportName(suffix), suffix);
  if (!path) return;
  const result = await post("/api/export", { view: currentView, path });
  if (!result.ok) {
    alert(result.error || "Export failed.");
    return;
  }
  if (suffix.toLowerCase() === ".pdf") {
    // Optionally open a preview/print dialog after the PDF has been written.
    try {
      const state = await getState();
      const md = await (await fetch(`/api/export-source?view=${encodeURIComponent(currentView)}`, {
        headers: { "X-AttackMap-Token": state.token },
      })).text();
      window.openPdfFromMarkdown(md);
    } catch {
      // Preview is optional; the PDF file is already saved.
    }
  } else {
    alert(`Saved to ${result.path}`);
  }
}

async function pickFolder(multi) {
  let paths = [];
  try {
    if (window.pywebview && window.pywebview.api && window.pywebview.api.pick_folder) {
      paths = await window.pywebview.api.pick_folder(multi);
    }
  } catch {
    paths = [];
  }
  if (!paths || !paths.length) {
    const res = await post("/api/pick", { multi: !!multi });
    paths = res.picked || [];
  }
  if (multi && paths.length) {
    const state = await getState();
    const merged = [...new Set([...(state.repos || []), ...paths])];
    await post("/api/config", { repos: merged });
  } else if (paths.length) {
    await post("/api/config", { repos: paths });
  }
  refresh();
}

document.getElementById("sidebar").addEventListener("click", (ev) => {
  const btn = ev.target.closest("button");
  if (!btn) return;
  currentView = btn.dataset.view;
  document.querySelectorAll(".sidebar button").forEach((b) => b.classList.toggle("active", b === btn));
  refresh();
});

document.getElementById("main").addEventListener("click", async (ev) => {
  const row = ev.target.closest(".exploit-row");
  if (row) {
    const i = Number(row.dataset.i);
    openRow = openRow === i ? -1 : i;
    refresh();
    return;
  }
  const find = ev.target.closest(".split-row");
  if (find) {
    selectedFinding = Number(find.dataset.fi);
    refresh();
    return;
  }
  if (ev.target.id === "save-keys") {
    await post("/api/settings", {
      anthropicKey: document.getElementById("anth-key").value,
      openaiKey: document.getElementById("oai-key").value,
    });
    refresh();
    return;
  }
  if (ev.target.id === "suppress-btn" && reportCache) {
    const box = document.getElementById("suppress-reason");
    const reason = box ? box.value.trim() : "";
    const f = reportCache.findings[selectedFinding];
    if (!reason || !f) return;
    await post("/api/suppress", { id: f.id, reason });
    reportCache = null;
    await refresh();
    return;
  }
  const recent = ev.target.closest(".recent");
  if (recent) {
    await post("/api/config", { repo: recent.dataset.path });
    refresh();
  }
});

document.getElementById("run").addEventListener("click", async () => {
  const state = await getState();
  if (state.running) await post("/api/cancel", {});
  else {
    const typed = document.getElementById("repo-label").value.trim();
    if (typed && !state.repo) {
      await post("/api/config", { repo: typed.split(" · ")[0] });
    }
    if (!state.repo && !state.repos?.length && !typed) {
      await pickFolder(false);
    }
    const next = await getState();
    const repos = next.repos && next.repos.length ? next.repos : (typed ? typed.split(" · ") : []);
    if (!repos.length) return;
    const providerSel = document.getElementById("provider").value;
    const isLmStudio = providerSel === "openai-lmstudio";
    await post("/api/run", {
      repos,
      cve: document.getElementById("cve").checked,
      recall: document.getElementById("recall").checked,
      llmMode: document.getElementById("llm-menu").value,
      provider: isLmStudio ? "openai" : providerSel,
      model: document.getElementById("model").value.trim() || null,
      baseUrl: isLmStudio
        ? (document.getElementById("base-url").value.trim() || "http://127.0.0.1:1234/v1")
        : "",
      modules: document.getElementById("analyzers").value,
    });
  }
  refresh();
});

document.getElementById("pick").addEventListener("click", () => pickFolder(false));
document.getElementById("add-folder").addEventListener("click", () => pickFolder(true));
document.getElementById("settings-btn").addEventListener("click", () => {
  currentView = "settings";
  document.querySelectorAll(".sidebar button").forEach((b) => b.classList.toggle("active", b.dataset.view === "settings"));
  refresh();
});
document.getElementById("reveal").addEventListener("click", () => post("/api/reveal", {}));
document.getElementById("export-md").addEventListener("click", () => doExport(".md"));
document.getElementById("export-pdf").addEventListener("click", () => doExport(".pdf"));
window.openPdfFromMarkdown = function(md) {
  const w = window.open("about:blank", "_blank");
  if (!w) return;
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AttackMap – Export</title>
<link rel="stylesheet" href="/src/app.css">
<link rel="stylesheet" href="/src/exploitability.css">
<style>
@media print {
  body { background: #fff; color: #111; }
  .md code { background: #eee; color: #111; }
}
</style>
</head>
<body>
${renderMarkdown(md)}
<script>window.print();<\/script>
</body>
</html>`;
  w.document.open();
  w.document.write(html);
  w.document.close();
};
document.getElementById("watch").addEventListener("change", (ev) => {
  post("/api/watch", { enabled: ev.target.checked }).then(() => refresh());
});
document.getElementById("provider").addEventListener("change", (ev) => {
  document.getElementById("base-url-label").hidden = ev.target.value !== "openai-lmstudio";
});
document.getElementById("llm-menu").addEventListener("change", (ev) => {
  if (ev.target.value !== "none") {
    window.alert("Enabling an LLM provider can send an evidence pack off this machine.");
  }
  post("/api/config", { llmMode: ev.target.value, provider: document.getElementById("provider").value });
});

async function pollState() {
  await refresh();
  const boot = document.getElementById("boot");
  if (boot) boot.remove();
  setTimeout(pollState, 800);
}
pollState();
