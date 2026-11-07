const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const fixture = require("../../desktop/windows/GraphExplorer.Web/synthetic-fixture.js");
const destination = path.resolve(process.argv[2] || path.join(__dirname, "../../.tmp/graph-explorer-fixtures"));
fs.mkdirSync(destination, { recursive: true });
const entries = [];
for (const [nodes, edges] of [[64, 96], [1000, 3000], [10000, 30000]]) {
  const name = `SYNTHETIC-fleet16-${nodes}-${edges}.json`, file = path.join(destination, name);
  const bytes = Buffer.from(JSON.stringify(fixture.create({ nodeCount: nodes, edgeCount: edges })) + "\n");
  fs.writeFileSync(file, bytes, { flag: "wx" });
  entries.push({ file: name, repositories: 16, nodes, edges, bytes: bytes.length, sha256: crypto.createHash("sha256").update(bytes).digest("hex"), synthetic: true });
}
fs.writeFileSync(path.join(destination, "manifest.json"), JSON.stringify({ kind: "synthetic-renderer-corpus", generator: "tools/graph-explorer/generate-fixtures.cjs", observed_scan: false, fixtures: entries }, null, 2) + "\n", { flag: "wx" });
process.stdout.write(JSON.stringify({ destination, fixtures: entries }, null, 2) + "\n");
