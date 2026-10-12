let currentView = "exploitability";
let openRow = -1;

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function renderExploitability(rows) {
  if (!rows || !rows.length) {
    return `<div class="empty">No exploitability scores yet. Run a scan.</div>`;
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

function renderFindings(findings, filter) {
  const q = (filter || "").toLowerCase();
  const rows = (findings || []).filter((f) => JSON.stringify(f).toLowerCase().includes(q));
  return `<div class="filter"><input id="find-filter" placeholder="Filter findings" value="${escapeHtml(filter || "")}" /></div>
    ${rows.map((f) => {
      const loc = (f.locations && f.locations[0]) || {};
      return `<div class="list-row"><div>${escapeHtml(f.title || "")}<div class="muted">${(f.evidence || []).slice(0, 3).map(escapeHtml).join(" · ")}</div></div>
        <code>${escapeHtml((loc.file || "") + (loc.line ? ":" + loc.line : ""))}</code></div>`;
    }).join("")}`;
}

function renderPaths(paths) {
  if (!paths.length) return `<div class="empty">No attack paths.</div>`;
  return paths.map((p) => `<div class="list-row"><div><strong>${escapeHtml(p.name || "")}</strong>
    <div>${(p.steps || []).map((s) => escapeHtml((s.stage || "") + ": " + (s.detail || s.action || ""))).join("<br/>")}</div></div></div>`).join("");
}

function renderSurface(surfaces) {
  return (surfaces || []).map((s) => `<div class="list-row"><code>${escapeHtml(s.method || "")} ${escapeHtml(s.route || "")}</code>
    <span>${escapeHtml(s.file || "")}</span></div>`).join("") || `<div class="empty">No attack surface.</div>`;
}

function renderMain(state) {
  const r = state.report;
  if (state.status === "running") {
    const p = state.progress || {};
    return `<div class="running">Scanning… ${escapeHtml(p.label || p.event || "")} ${escapeHtml(p.current || "")}</div>`;
  }
  if (state.status === "failed") {
    return `<div class="failed">${escapeHtml(state.error || "Scan failed.")}</div>`;
  }
  if (!r) return `<div class="empty">Pick a repository and run a scan.</div>`;
  if (currentView === "overview") {
    return `<div class="prose">${escapeHtml(r.diagrams && r.diagrams.architecture || "No architecture summary.")}</div>`;
  }
  if (currentView === "findings") return renderFindings(r.findings, "");
  if (currentView === "exploitability") return renderExploitability(r.exploitability);
  if (currentView === "paths") return renderPaths(r.attackPaths || []);
  if (currentView === "surface") return renderSurface(r.attackSurfaces || []);
  if (currentView === "diagrams") return `<div class="prose">${escapeHtml((r.diagrams && r.diagrams.architecture) || "No diagram.")}</div>`;
  if (currentView === "review") return `<div class="prose">${escapeHtml(r.reviewMd || "")}</div>`;
  if (currentView === "ai-review") {
    if (!r.aiReviewMd) {
      return `<div class="empty">AI Review stays empty until you choose an LLM provider. Heuristic-only runs never send code off this machine.</div>`;
    }
    return `<div class="prose">${escapeHtml(r.aiReviewMd)}</div>`;
  }
  return "";
}

function paint(state) {
  const r = state.report;
  const n = r ? r.findingCount : 0;
  const status = document.getElementById("status-text");
  const delta = document.getElementById("delta");
  const watching = document.getElementById("watching");
  const run = document.getElementById("run");
  if (state.status === "running") {
    status.textContent = "Scanning…";
    run.textContent = "Cancel";
  } else if (state.status === "failed") {
    status.textContent = "Failed";
    run.textContent = "Run scan";
  } else {
    status.textContent = `Done — ${n} findings`;
    run.textContent = "Run scan";
  }
  if (r && (r.newCount || r.resolvedCount)) {
    delta.innerHTML = `<span class="new">+${r.newCount} new</span> · <span class="resolved">${r.resolvedCount} resolved</span>`;
  } else {
    delta.textContent = "";
  }
  watching.hidden = !state.watch;
  const repoMenu = document.getElementById("repo-menu");
  if (r && r.repoName && ![...repoMenu.options].some((o) => o.value === r.repoName)) {
    repoMenu.add(new Option(r.repoName, r.repoName, true, true));
  }
  document.getElementById("main").innerHTML = renderMain(state);
}

async function refresh() {
  const state = await getState();
  paint(state);
  return state;
}

document.getElementById("sidebar").addEventListener("click", (ev) => {
  const btn = ev.target.closest("button");
  if (!btn) return;
  currentView = btn.dataset.view;
  document.querySelectorAll(".sidebar button").forEach((b) => b.classList.toggle("active", b === btn));
  refresh();
});

document.getElementById("main").addEventListener("click", (ev) => {
  const row = ev.target.closest(".exploit-row");
  if (!row) return;
  const i = Number(row.dataset.i);
  openRow = openRow === i ? -1 : i;
  refresh();
});

document.getElementById("main").addEventListener("input", (ev) => {
  if (ev.target.id !== "find-filter") return;
  getState().then((state) => {
    document.getElementById("main").innerHTML = renderFindings(state.report.findings, ev.target.value);
  });
});

document.getElementById("run").addEventListener("click", async () => {
  const state = await getState();
  if (state.running) await post("/api/cancel", {});
  else {
    const repo = prompt("Repository path", state.repo || "");
    if (!repo) return;
    await post("/api/run", {
      repo,
      cve: document.getElementById("cve").checked,
      llm: document.getElementById("llm-menu").value,
      modules: document.getElementById("analyzers").value,
    });
  }
  refresh();
});

document.getElementById("watch").addEventListener("change", (ev) => {
  post("/api/watch", { enabled: ev.target.checked }).then(paint);
});

document.getElementById("llm-menu").addEventListener("change", (ev) => {
  if (ev.target.value !== "none") {
    alert("Enabling an LLM provider can send an evidence pack off this machine.");
  }
  post("/api/config", { llm: ev.target.value });
});

refresh();
setInterval(refresh, 800);
