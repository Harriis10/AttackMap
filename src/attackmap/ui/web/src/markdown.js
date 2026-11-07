/* Minimal but real Markdown renderer for the GUI (headings, bold/italic,
   lists incl. "- [HIGH]", tables, code fences, hr, links, paragraphs). */

function mdEscape(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function mdInline(src) {
  let out = mdEscape(src);
  out = out.replace(/`([^`]+)`/g, "<code>$1</code>");
  out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  out = out.replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
  out = out.replace(/(^|[^A-Za-z0-9_])_([^_\n]+)_(?![A-Za-z0-9_])/g, "$1<em>$2</em>");
  out = out.replace(/\\([_*[\]`])/g, "$1");
  out = out.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g,
    '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  return out;
}

function mdIsTableSep(line) {
  return /^\s*\|?(\s*:?-+:?\s*\|)+\s*$/.test(line);
}

function mdSplitRow(line) {
  const trimmed = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  return trimmed.split("|").map((c) => c.trim());
}

function renderMarkdown(src) {
  if (!src) return `<div class="empty">No review yet.</div>`;
  const mermaid = extractMermaidBlocks(src);
  let mi = 0;
  const work = src.replace(/```mermaid\r?\n[\s\S]*?```/g, () => `\n%%MERMAID_${mi++}%%\n`);

  const lines = work.replace(/\r\n/g, "\n").split("\n");
  const html = [];
  let i = 0;
  let para = [];
  let listType = null;
  let inCode = false;
  let codeLang = "";
  let codeBuf = [];

  const flushPara = () => {
    if (para.length) {
      html.push(`<p>${para.map(mdInline).join("<br/>")}</p>`);
      para = [];
    }
  };
  const flushList = () => {
    if (listType) {
      html.push(`</${listType}>`);
      listType = null;
    }
  };
  const flushCode = () => {
    html.push(`<pre class="code"><code>${mdEscape(codeBuf.join("\n"))}</code></pre>`);
    codeBuf = [];
  };

  while (i < lines.length) {
    const line = lines[i];
    const fence = line.match(/^```(\w*)\s*$/);
    if (fence) {
      if (inCode) {
        flushCode();
        inCode = false;
      } else {
        flushPara();
        flushList();
        inCode = true;
        codeLang = fence[1];
        codeBuf = [];
      }
      i++;
      continue;
    }
    if (inCode) {
      codeBuf.push(line);
      i++;
      continue;
    }

    const mer = line.match(/^%%MERMAID_(\d+)%%\s*$/);
    if (mer) {
      flushPara();
      flushList();
      html.push(renderMermaidBlock(mermaid[Number(mer[1])] || ""));
      i++;
      continue;
    }

    if (!line.trim()) {
      flushPara();
      flushList();
      i++;
      continue;
    }

    const head = line.match(/^(#{1,4})\s+(.*)$/);
    if (head) {
      flushPara();
      flushList();
      const level = head[1].length;
      html.push(`<h${level}>${mdInline(head[2])}</h${level}>`);
      i++;
      continue;
    }

    if (/^\s*(---+|\*\*\*+|___+)\s*$/.test(line)) {
      flushPara();
      flushList();
      html.push("<hr/>");
      i++;
      continue;
    }

    // Tables: header row, separator row, then body rows.
    if (line.includes("|") && i + 1 < lines.length && mdIsTableSep(lines[i + 1])) {
      flushPara();
      flushList();
      const headers = mdSplitRow(line);
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].includes("|") && lines[i].trim()) {
        rows.push(mdSplitRow(lines[i]));
        i++;
      }
      html.push(
        `<table class="md-table"><thead><tr>${headers.map((h) => `<th>${mdInline(h)}</th>`).join("")}</tr></thead>` +
        `<tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${mdInline(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>`
      );
      continue;
    }

    const ul = line.match(/^\s*[-*+]\s+(.*)$/);
    if (ul) {
      flushPara();
      if (listType !== "ul") {
        flushList();
        html.push("<ul>");
        listType = "ul";
      }
      html.push(`<li>${mdInline(ul[1])}</li>`);
      i++;
      continue;
    }

    const ol = line.match(/^\s*(\d+)\.\s+(.*)$/);
    if (ol) {
      flushPara();
      if (listType !== "ol") {
        flushList();
        html.push("<ol>");
        listType = "ol";
      }
      html.push(`<li>${mdInline(ol[2])}</li>`);
      i++;
      continue;
    }

    const quote = line.match(/^>\s?(.*)$/);
    if (quote) {
      flushPara();
      flushList();
      html.push(`<blockquote>${mdInline(quote[1])}</blockquote>`);
      i++;
      continue;
    }

    para.push(line);
    i++;
  }
  if (inCode) flushCode();
  flushPara();
  flushList();
  return `<div class="md">${html.join("\n")}</div>`;
}
