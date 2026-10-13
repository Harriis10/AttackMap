let currentView = "overview";
let openRow = -1;
let selectedFinding = 0;
let reportCache = null;
let lastHasReport = false;
let progressStarted = 0;

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function renderExploitability(rows, report) {
  if (!rows || !rows.length) {
    const chains = (report && report.dataFlows) || [];
    return `<div class="empty-state">
      <h3>No route→sink exploitability paths</h3>
      <p>The exploitability ranking is built from taint chains (source → variable → sink)
      traced inside request handlers. This scan traced <strong>${chains.length}</strong> such chains,
      so there is nothing to rank.</p>
      <p class="muted">Typical reasons: the repo's framework isn't covered by an installed analyzer
      (e.g. plain-PHP superglobal flows), routes weren't detected, or sinks are reached
      through helper calls the intra-procedural pass doesn't follow. Findings and the
      defensive review still apply — this tab only ranks route→sink flows.</p>
    </div>`;
  }
  return `<div class="exploit-list">${rows.map((row, i) => `
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
  ${top ? `<div class="card" style="margin:0 16px 16px"><div class="muted">Most exploitable now</div>
    <div>${escapeHtml(top.method || "")} ${escapeHtml(top.route || top.subject)} · score ${escapeHtml(top.score)}</div></div>` : ""}
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
    <p>API keys are stored with Windows DPAPI and injected only into the scan child process.</p>
    <label>Anthropic API key ${state.hasAnthropicKey ? "(saved)" : ""}</label>
    <input type="password" id="anth-key" placeholder="sk-ant-…" />
    <label>OpenAI API key ${state.hasOpenAIKey ? "(saved)" : ""}</label>
    <input type="password" id="oai-key" placeholder="sk-…" />
    <p>LM Studio (OpenAI-compatible local endpoint): keep the provider set to
    <strong>LM Studio (local)</strong> in the toolbar and use Base URL
    <code>http://localhost:1234/v1</code>. LM Studio accepts any non-empty API key;
    if your server requires one, save it as the OpenAI key above.</p>
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
  if (!report) return `<div class="empty">Pick a repository and run a scan.</div>`;
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
    if (!report.aiReviewMd) {
      return `<div class="empty">AI Review stays empty until you choose an LLM provider. Heuristic-only runs never send code off this machine.</div>`;
    }
    return renderMarkdown(report.aiReviewMd);
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
    barWrap.hidden = false;
    const total = Number(p.total) || 0;
    const done = Number(p.done) || 0;
    if (p.event === "begin") progressStarted = Date.now();
    const pct = total ? Math.min(100, Math.round((done / total) * 100)) : (p.event === "stage" ? 100 : 8);
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

async function loadReportIfNeeded(state) {
  if (state.status === "running" || !state.hasReport) {
    reportCache = null;
    lastHasReport = false;
    return null;
  }
  if (reportCache && lastHasReport) return reportCache;
  try {
    reportCache = await getReport();
    lastHasReport = true;
  } catch {
    reportCache = null;
  }
  return reportCache;
}

async function refresh() {
  try {
    const state = await getState();
    paintStatus(state);
    const typing = document.activeElement && ["anth-key", "oai-key", "suppress-reason", "repo-label"].includes(document.activeElement.id);
    if (typing && currentView === "settings") return state;
    const report = state.status === "running" && currentView !== "settings" && currentView !== "recents"
      ? null
      : await loadReportIfNeeded(state);
    if (typing) return state;
    document.getElementById("main").innerHTML = showMissing(state) + renderMain(state, report);
    return state;
  } catch (err) {
    document.getElementById("main").innerHTML = `<div class="failed">${escapeHtml(err.message || String(err))}</div>`;
    return null;
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
    lastHasReport = false;
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
        ? (document.getElementById("base-url").value.trim() || "http://localhost:1234/v1")
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

refresh().finally(() => {
  const boot = document.getElementById("boot");
  if (boot) boot.remove();
});
setInterval(refresh, 800);
