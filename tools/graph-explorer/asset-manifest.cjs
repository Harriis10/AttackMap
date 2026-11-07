const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const root = path.resolve(__dirname, "../../desktop/windows/GraphExplorer.Web");
const vendor = JSON.parse(fs.readFileSync(path.join(root, "vendor/manifest.json"), "utf8").replace(/^\uFEFF/, ""));
const names = ["index.html", "styles.css", "projection.js", "synthetic-fixture.js", "app.js", "vendor/manifest.json", ...vendor.packages.flatMap(item => [`vendor/${item.file}`, `vendor/${item.license_file}`])];
const manifest = { kind: "attackmap-offline-graph-assets", hash_algorithm: "sha256", files: names.sort().map(name => { const bytes = fs.readFileSync(path.join(root, name)); return { path: name, bytes: bytes.length, sha256: crypto.createHash("sha256").update(bytes).digest("hex") }; }) };
fs.writeFileSync(path.join(root, "asset-manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
process.stdout.write(JSON.stringify({ assets: manifest.files.length, sha256: crypto.createHash("sha256").update(fs.readFileSync(path.join(root, "asset-manifest.json"))).digest("hex") }) + "\n");
