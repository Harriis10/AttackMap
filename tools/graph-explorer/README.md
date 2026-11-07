# Graph candidate qualification tools

Run from the repository root:

```powershell
node tools/graph-explorer/generate-fixtures.cjs
```

This creates deterministic, explicitly SYNTHETIC 16-repository 64/96, 1000/3000 and 10000/30000 node/edge corpora under `.tmp/graph-explorer-fixtures`, with a SHA256 manifest. Supply another fresh output directory as the argument when needed. Existing files are never overwritten. No repository is scanned.

Serve the repository root through the root-owned local QA server, then open `/tools/graph-explorer/qualification.html`. The same-origin iframe displays `/desktop/windows/GraphExplorer.Web/index.html`. Buttons fetch the durable core success/failed oracles or generated corpora, then call the candidate's public API. The harness is separate from deployed assets and does not install a fixture autoloader in the product.

Controls record current fixture hash, graph counts, positions, synchronous layout timing, call-to-two-animation-frame settling observations, and optional browser JavaScript heap. These are not process working-set measurements or proof of all pixels painted. Large expanded detail records the bounded fCoSE→preset fallback explicitly. Results can be downloaded as JSON. Light/Dark, collapse/expand, comparison trials and compact graph focus remain visible controls.

`asset-manifest.cjs` regenerates the deployed asset SHA256 manifest only after deployed web assets change. Tests and this qualification harness are not mapped native runtime resources. Run focused tests with:

```powershell
node --test desktop/windows/GraphExplorer.Web/tests/bridge.test.cjs desktop/windows/GraphExplorer.Web/tests/projection.test.cjs
```

The default oracle location is `docs/verification/windows-parity/WP043/fleet16-20261023/core`, with prior staging as a fallback; `ATTACKMAP_GRAPH_CORE_ORACLE_DIR` overrides it. Native host compilation, visual/accessibility checks, offline enforcement and product packaging remain separately scoped evidence.
