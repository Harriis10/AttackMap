/* Lightweight offline Mermaid renderer for AttackMap diagrams.
   Handles flowchart node declarations and simple/labeled edges, rendering a
   clean vertical flow (node → arrow → node) without any network calls. */

function extractMermaidBlocks(md) {
  const blocks = [];
  const re = /```mermaid\r?\n([\s\S]*?)```/g;
  let m;
  while ((m = re.exec(md || ""))) blocks.push(m[1]);
  return blocks;
}

function _mlEscape(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function renderMermaidBlock(src) {
  const lines = (src || "").split("\n").map((l) => l.trim()).filter(Boolean);
  const nodes = {};
  const edges = [];
  const impact = new Set();

  for (const line of lines) {
    if (/^(flowchart|graph)\b/.test(line) || line.startsWith("classDef") || line.startsWith("%%")) continue;
    const cls = line.match(/^class\s+(\S+)\s+(\S+)/);
    if (cls) {
      if (cls[2] === "impact") impact.add(cls[1]);
      continue;
    }
    // Labeled / styled edges: A -- "label" --> B, A -.-> B, A ==> B, A --> B
    const edge = line.match(/^(\w+)\s*(?:--\s*"([^"]*)"\s*)?(?:-->|-.->|==>|---|-\.-)\s*(\w+)$/);
    if (edge && !line.includes("[")) {
      edges.push({ from: edge[1], label: edge[2] || "", to: edge[3] });
      continue;
    }
    // Node declaration: id["label"] or id["label"]:::cls
    const node = line.match(/^(\w+)\["(.*)"\]/);
    if (node) {
      nodes[node[1]] = node[2].replace(/<br\s*\/>/gi, " · ");
    }
  }

  // Order nodes by first appearance in edges, then declarations.
  const order = [];
  for (const e of edges) {
    if (!order.includes(e.from)) order.push(e.from);
    if (!order.includes(e.to)) order.push(e.to);
  }
  for (const id of Object.keys(nodes)) if (!order.includes(id)) order.push(id);

  if (!order.length) return `<div class="empty">Empty diagram.</div>`;

  const byId = (id) => nodes[id] || id;
  const parts = [];
  if (edges.length) {
    // Render as a sequence of hops with labels on the arrows.
    for (let idx = 0; idx < edges.length; idx++) {
      const e = edges[idx];
      const fromCls = impact.has(e.from) ? "m-node impact" : "m-node";
      parts.push(`<div class="m-row"><span class="${fromCls}">${_mlEscape(byId(e.from))}</span>
        <span class="m-arrow">${e.label ? `<span class="m-edge-label">${_mlEscape(e.label)}</span>` : ""}→</span>
        <span class="${impact.has(e.to) ? "m-node impact" : "m-node"}">${_mlEscape(byId(e.to))}</span></div>`);
    }
  } else {
    for (const id of order) {
      parts.push(`<div class="m-row"><span class="${impact.has(id) ? "m-node impact" : "m-node"}">${_mlEscape(byId(id))}</span></div>`);
    }
  }
  return `<div class="mermaid-wrap">${parts.join("")}</div>`;
}

function renderMermaidDocument(md) {
  if (!md) return `<div class="empty">No diagram.</div>`;
  const blocks = extractMermaidBlocks(md);
  if (!blocks.length) return renderMarkdown(md);
  const titles = [...md.matchAll(/^##\s+(.*)$/gm)].map((m) => m[1]);
  return blocks.map((b, i) =>
    `<h3 class="md-diagram-title">${_mlEscape(titles[i] || "Diagram")}</h3>${renderMermaidBlock(b)}`
  ).join("");
}
