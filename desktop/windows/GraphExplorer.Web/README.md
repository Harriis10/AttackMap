# Offline fleet graph candidate

WP043 isolated candidate, not product/release acceptance. All example data is explicitly synthetic. No Node.js, CDN, local server, network fetch, expand-collapse plugin, or AI call is required at runtime.

Open `index.html` directly for the labelled synthetic example or the file picker. Select the core-generated `fleet16-oracle.json` to exercise actual builder output. The page accepts the canonical `fleet_architecture` schema 1.0, including boolean `directed`, repository-qualified identity and a closed top-level evidence registry.

The full canonical document remains available in the keyboard list and JSON. Collapse is a view projection, with hidden internal edge counts. Compatible direct callsites aggregate with all underlying IDs; kind, directedness, resolution, basis, confidence, endpoint resolution and proxy legs remain separate. Proxy components stay visible. An aggregate overview chain is not a proven service path.

Grouped preset uses deterministic group-aware geometry. Compound fCoSE refines the same starting positions without randomization. It is synchronous, and has an explicit 350 visible node / 1000 displayed edge guard. Calling `stop`, adding a Promise or scheduling a timer would not provide preemptive cancellation. Current detail display limits are 1000 nodes / 3000 displayed edge groups; the full text/JSON remains available and omitted counts are shown. These are conservative implementation guards, not measured supported product bounds.

Pinned runtime closure is Cytoscape 3.34.4, fCoSE 2.2.0, cose-base 2.2.0 and layout-base 2.0.1, all MIT. `vendor/manifest.json` records official registry tarballs, verified SHA512 integrities, deployed SHA256 and license SHA256. Tarballs were extracted without lifecycle scripts. `asset-manifest.json` covers every mapped web asset. From the repository root, recompute it after changing deployed assets with `node tools/graph-explorer/asset-manifest.cjs`.

## Native bridge

The page exposes `window.AttackMapGraph`:

- `replaceGraph(graph, context, {synthetic:false})`, with host-owned `context.token` (nonempty opaque string); validated replacement is atomic.
- `clear()`, `select({node_ids,edge_ids,evidence_ids}, context)`, `theme("light"|"dark")`.
- `receive(message)` accepts `protocol:1`, `type:replaceGraph|clear|select|theme`, graph and context as applicable. Hosted messages require the exact `page_session` announced by `ready`; standalone callers may omit it.
- `setOptions({collapsedIds,query,kind,resolution,interRepoOnly,neighborhood,layout})`, `runLayout("preset"|"fcose")`, `snapshot()` for host QA.
- `canonicalJson()` returns the full reimportable graph with additive `export_metadata` containing host context, filters, coverage and limitations.
- `exportPng()` returns `Promise<{blob,metadata}>`. It captures the entire current overview projection, bounds dimensions to 8192 each and output to 32 MiB, and rejects stale layout/context completion. It does not claim to image canonical nodes omitted by an explicitly bounded detail view.

Outbound messages use `chrome.webview.postMessage` only when present, with `{protocol:1,type,page_session,context,...}`. Types are `ready`, `select`, `openEvidence`, `layoutState`, `export`. Selection/evidence messages include only validated canonical IDs. The host resolves source actions. Hosted export buttons send a request; the host chooses the destination. Standalone download includes an overview metadata sidecar. No path or command is accepted from a page message.

Hosted mode fits the desktop pane, hides standalone file/example actions, and explains that the selected Fleet run supplies the graph. It does not advertise PNG export. Graph replacement resets filters and text paging; changing the selection updates an active upstream/downstream neighborhood. Standalone mode starts empty until a file or the explicitly labelled synthetic example is selected.

Native JSON exports retain the host-verified canonical graph and append `export_metadata` with host-owned context/counts. Only bounded, known view settings are accepted from the page; they are labelled untrusted presentation state, and layout is labelled requested rather than executed. Page-supplied context, counts, coverage and limitations cannot replace canonical facts. The host exposes read-only `LayoutAcknowledgedContext`, cleared on replacement/clear/stop/process failure and set only after a current-context `rendered` or `complete` message. This is a message acknowledgment for QA, not pixel or visual proof.

`GraphWebView.cs` is candidate WinUI host source using the existing SDK and `AttackMap.GraphExplorer` core. Its isolated WinUI library build passed with zero warnings/errors; product integration and runtime acceptance remain separate. It validates canonical bytes before transmission, creates its own context token, checks actual message source + page session + context, restricts mapping to the hashed assets, denies external resource/navigation/window/download/permission actions, and queues native callbacks with a revision recheck. The window must call `Stop()` on the owning UI thread. Terminal hosts are not reusable. Hosted PNG is visibly disabled, and the native host rejects PNG requests with an explicit notice; no JSON is saved as PNG. Native export callbacks currently support JSON only. A qualified host-owned PNG export or the native SVG alternative requires integration.

## Focused checks and corpus

```powershell
# From repository root. The optional environment override selects another oracle directory.
node --test desktop/windows/GraphExplorer.Web/tests/bridge.test.cjs desktop/windows/GraphExplorer.Web/tests/projection.test.cjs
node tools/graph-explorer/generate-fixtures.cjs
```

Generator outputs labelled 16-group 64/96, 1000/3000 and 10000/30000 corpora with SHA256 under `.tmp/graph-explorer-fixtures`, or a supplied fresh output directory. It refuses to overwrite files. Tests prefer the durable core success/failure oracle under `docs/verification/windows-parity/WP043/fleet16-20261023/core`, then prior staging. Tests include aggregation parity and proxy legs, malformed identities/evidence, hostile ID characters, finite compound layout using the actual vendored headless fCoSE closure, stale selection rejection, unavailable-graphics text fallback and reimportable complete JSON. Headless checks are distinct from browser render/interaction/memory/cancellation measurements, visual review, keyboard/Narrator/200% checks, real scans and native integration.

For root browser QA, load a corpus through the file picker, then use the visible controls or the documented API. `snapshot()` returns counts, selected IDs, current positions and layout timing; `setOptions({collapsedIds:[],layout:'fcose'})` exercises the bounded fallback on large expanded detail. No automatic file access is performed by the page.

The separate qualification harness is `tools/graph-explorer/qualification.html`; serve the repository root on a local QA HTTP origin and open that path. Fixed harness controls fetch the durable core oracles or generated synthetic corpora and supply them through the public API, avoiding browser file chooser dependence. This harness is not a deployed product asset. Captured checks and browser measurements are under `docs/verification/windows-parity/WP043/fleet16-20261023/web`.
