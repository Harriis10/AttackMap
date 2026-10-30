# Cytoscape compound candidate evidence

Candidate source is durable under `desktop/windows/GraphExplorer.Web`. The separate harness and deterministic corpus generator are under `tools/graph-explorer`. No build outputs or large generated stress JSON are part of either source folder. Deployed assets match the qualified staging bytes; their manifest was preserved, not regenerated. All graphs used here are generated fixtures, not results of a new representative fleet scan.

## Verification scopes

| Evidence | Result and scope |
| --- | --- |
| `durable-node-test-results.txt` | 14 PASS, 0 FAIL/SKIP from the durable candidate; projection, aggregation, identity/evidence, fallback/bridge, current core oracles, SHA256 notices/assets and actual vendored headless fCoSE. |
| `node-test-results.txt` | Preserved original 14-test staged run. |
| `native-host-build-output.txt` | Preserved initial isolated WinUI WebView host library compile, 0 warnings/errors, before the bounded native metadata export addition. |
| `native-host-metadata-build-output.txt` | Current isolated WinUI host and test library build, 0 warnings/errors, including bounded export metadata, numeric-message exception guards, repeated asset checks and `LayoutAcknowledgedContext`. Both durable host copies are byte-identical to the compiled source. This is not a full product build or WebView runtime acceptance. |
| `host-export-test-output.txt` | 33 pure metadata checks PASS using the actual compiled host helper; canonical facts/identity preserved, UI coverage/context/counts cannot override them, unknown IDs/choices/fields, duplicates, oversized/control text rejected. No WinUI control constructed and no GUI launched. |
| `browser-measurements-01.json` | Preserved root-owned browser qualification output: 17 observations from Chrome 155 on Windows, local QA origin, 23 October 2026. Actual fixture loads/layout calls/positions and optional JS heap, synthetic data only. |
| `partial-index-tests/durable-pytest-results.txt` | 12 PASS from the durable proof location, importing its isolated staged Python module. |
| `partial-index-tests/pytest-results.txt` | Preserved original 12-test staged run. |
| `partial-index-tests/HANDOFF.md` | Summary binding semantics, publication ordering, tamper/missing/junction checks and explicit filesystem/size limitations. The staged module is proof material; root owns production integration. |

## Recorded browser observations

These are a small number of fixture observations from the preserved result file. Call durations include page API work and are not universal latency guarantees or p95 results. Settling via two animation frames is recorded separately; it does not prove every pixel was painted. JavaScript heap is not browser/native process working set.

| Current presentation | Recorded page calls |
| --- | --- |
| Core oracle, 40 canonical nodes / 34 canonical edges, collapsed to 17 nodes / 5 edge groups | Three grouped preset calls: 1.4–2.5 ms. Three actual bounded fCoSE calls: 9.5–24.5 ms. |
| 1000 nodes / 3000 edges, expanded, 1000 displayed nodes / 2165 edge groups | Expansion call about 1797.4 ms. Three grouped preset calls: 322.1–419.0 ms. Requests for fCoSE actually executed the explicit preset guard fallback (253.5–293.7 ms); this is not a successful fCoSE layout at that scale. |
| 10000 nodes / 30000 edges stress, expanded into the explicit bounded view | Canonical totals retained, 1000 displayed nodes / 230 edge groups. One expansion call about 1028.8 ms. This is bounded detail, not a fully drawn 10000-node graph. |

The recorded data does not measure native host integration, process working set, hostile input navigation enforcement, Narrator, 200% text, a clean portable installation, real 16-repository execution or release readiness. Hosted PNG is visibly unavailable and rejected by the native bridge. Standalone/browser PNG and complete JSON APIs are implemented; a native PNG integration claim is not made.

The hybrid host source at `desktop/windows/AttackMap.NativeSpike/Graphs/GraphWebView.cs` matches the sibling candidate host source. It exports host-owned canonical JSON with bounded UI-only settings under `export_metadata`. Supplied UI context/counts/coverage/limitations are ignored, and the host's graph context/counts remain authoritative. Read-only `LayoutAcknowledgedContext` records a validated current source/session/context layout message only; it is cleared at replacement/clear/stop/process failure. That acknowledgment is not visual/pixel proof. Existing selection/evidence/export event signatures are preserved, and native PNG remains disabled.

## Reproduction

From repository root:

```powershell
node --test desktop/windows/GraphExplorer.Web/tests/bridge.test.cjs desktop/windows/GraphExplorer.Web/tests/projection.test.cjs
node tools/graph-explorer/generate-fixtures.cjs
.\.venv\Scripts\python.exe -B -m pytest docs/verification/windows-parity/WP043/fleet16-20261023/web/partial-index-tests/test_partial_fleet_index.py -q -p no:cacheprovider --basetemp=<fresh own temp directory>
```

Tests prefer the durable core success/failure oracle in the neighboring `core` folder; prior staging is a fallback and `ATTACKMAP_GRAPH_CORE_ORACLE_DIR` may override it. Generator output goes to ignored `.tmp/graph-explorer-fixtures`, with explicit synthetic labels and SHA256; it refuses overwrite. Serve the repository root through a root-owned local QA HTTP server and open `/tools/graph-explorer/qualification.html` to load all allowlisted corpora without a browser file picker. No product fixture autoloader was added.

The isolated host build used `.tools/dotnet/dotnet.exe` SDK 8.0.426, Windows App SDK 2.4.0, transitive WebView2 1.0.3719.77, net8 Windows minimum 19041 and win-x64. It compiled as a framework-dependent class library because Windows App SDK self-contained is an executable-only setting. Original compile project/output remain in the coordination staging area; source-bound product integration belongs to root.

Durable `host-compile/GraphWebHost.csproj` and `host-export-tests/GraphWebExport.Tests.csproj` preserve the isolated compilation/test setup. Build with a caller-owned `.tmp` artifacts path, existing `.tools/nuget-packages` fallback and normal process permissions as needed; execute the built test DLL with the durable core oracle as its optional argument. These projects link the actual granted native host source and create no UI.

`hashes.json` binds these preserved proofs plus the durable source/tool files. Vendor tarball SHA512, deployed file SHA256 and MIT license SHA256 remain in `desktop/windows/GraphExplorer.Web/vendor/manifest.json`; all mapped web assets remain bound by its neighboring `asset-manifest.json`.
