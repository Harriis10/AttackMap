# Windows build development

Branch: **`codex/windows-build-development`**. Status as of **7 November 2026**.

Contribution source: [Mipam/AttackMap fork](https://github.com/Mipam/AttackMap).
Pull request target: `Harriis10/AttackMap:main`.

[Windows GUI screenshots with descriptions](docs/screenshots/windows-completed-scan-20261107/README.md)
show nine user-provided views of a completed Juice Shop scan: overview,
findings, architecture, inventory, reports, history, evidence and diagrams.

This branch contains development of the native Windows application, its
integration with the AttackMap engine, and a portable Windows distribution.
It is a development checkpoint with documented, bounded verification results;
overall product acceptance is governed by the
[active Windows roadmap](docs/roadmap-windows-parity-2026-10-20.md),
[TODO](docs/windows-parity-todo.md) and [backlog](docs/windows-parity-backlog.json).

## Comparison baseline and provenance

The target repository is [Harriis10/AttackMap](https://github.com/Harriis10/AttackMap).
During preparation, its `main` branch was at
[`611a37951a998be5e9f072ec2c575ab720b5ffa1`](https://github.com/Harriis10/AttackMap/commit/611a37951a998be5e9f072ec2c575ab720b5ffa1).
The saved implementation checkpoint used for comparison is
`2d232cb1a0f292ce93b54b07638b5bceb2b0b472`.

- The difference between these checkpoints comprises **104 commits**,
  **6,948 files**, **2,025,685 added** and **3,508 deleted lines**.
- **66 commits are inherited upstream history**, through the common baseline
  `01ded68d4e5dc0b18a48bf14f0532fc6115fa396`.
- **38 commits were created on the local Windows branch after that split**:
  implementation, integration, fixes and saved verification checkpoints.
- The local reference `origin/main` (`08ae704`) has another 41 commits that
  this branch does not contain. This checkpoint does not merge the latest upstream.

Most of the diff volume consists of documentation, fixtures and retained
verification results. It is not two million new lines of production code.
Together, `src/`, `schemas/`, `installer/`, `tools/` and `pyproject.toml` account
for 181 changed files (+48,692 / -2,982 lines). The Windows desktop, build tools
and installer subset contains 556 newly added files and overlaps that scope.
This overview and its documentation-index link are separate documentation
changes after the saved implementation checkpoint.

## What the changes add or modify

| Area | Resulting behavior and purpose | Main sources |
| --- | --- | --- |
| Native Windows application | A WinUI window with repository selection, scan start/cancel, and views for findings, architecture, inventory, reports, history, risk paths, evidence, diagrams, fleet runs and suppressions. | `desktop/windows/AttackMap.NativeSpike/MainWindow*`, `App.xaml.cs` |
| Shared engine and broker | CLI and desktop share analysis orchestration. Typed requests, events and run identities replace dependence on parsing human-readable CLI output. Capabilities define supported operations and schemas 1.0-1.5. | `src/attackmap/pipeline.py`, `scan_service.py`, `desktop_worker.py`, `desktop_actions.py`, `desktop_capabilities.py`, `schemas/`; native `EngineSession.cs`, `EngineProtocol.cs`, `DesktopActionRunner.cs` |
| Result publication and history | Manifests and checksums bind outputs to a specific engine, repository and generation. Completed generations are published atomically; failed or partial diagnostics are not presented as completed reports. History, compare, pin/prune and diagnostic workflows are included. | `src/attackmap/artifact_manifest.py`, `artifact_publisher.py`, `run_contract.py`, `desktop_*`; `HistoryComparisonView.cs`, `MainWindow.Workspaces.cs` |
| Scan options and analyzers | Save/restore preferences, select an explicit engine executable, profiles and modules, configure timeout, soft time budget, isolated processes, baseline and suppression policy. The catalog and execution ledger distinguish installation, provenance, applicability and actual analyzer execution. | `NativeScanOptions.cs`, `LocalSettings.cs`, `EngineCapabilities.cs`, `AnalyzerSelectionModel.cs`, `AnalyzerSelectionView.cs`; engine catalog, profiles and execution ledger |
| Captured inputs and process control | Snapshot/index/cache/SDK contracts stabilize analysis inputs and invalidation. Process supervision handles limits, failures, cancellation and cleanup. Isolated processes are not an OS security sandbox. | Snapshot, index, cache, SDK and execution modules in `src/attackmap/`; native launch/session services |
| Fleet and architectural relationships | Parallel child runs preserve each repository's identity and results. The model distinguishes namespace and Service/Ingress ownership, backend port/protocol and typed references. Observed HTTP links remain separate from candidates and declared messaging/datastore associations. | `src/attackmap/desktop_fleet.py`, `desktop_graph.py`, `contracts.py`, `config_scanner.py`; `desktop/windows/AttackMap.NativeSpike/Fleet/` |
| Graphs and evidence navigation | Shared graph projection, filters, expand/collapse, aggregation, layout and export. Native and WebView renderers have separate implementations. Selecting an element connects the graph to evidence from the corresponding generation. | `desktop/windows/GraphExplorer.*`, `MainWindow.FleetGraph.cs`, `FleetGraphEvidenceNavigation.cs` |
| Watch and suppressions | Explicitly enabled repository watching, coordinated repeat scans, and suppression rules with preview/change operations. | `desktop/windows/AttackMap.NativeSpike/Watch/`, `Suppression/`, `MainWindow.Workspaces.cs`; engine action routing |
| Exports | JSON and verified deterministic Markdown correspond to the selected report. HTML/PDF and selected SARIF projection are added. Export checks the manifest/artifact binding. | `ExportSelection.cs`, `ReviewExport.cs`, `ExportPrep/SelectedSarifProjection.cs`, `MainWindow.xaml.cs` |
| Optional AI | Provider/model and timeout configuration, metadata for the specific response, and separate loading of saved AI reviews. Displaying saved text does not start a new model request. Reference-format validity does not establish claim correctness or source-location validity. | `src/attackmap/desktop_ai.py`, `desktop_provider.py`, `provider_options.py`, `citations.py`, `llm_review.py`; `MainWindow.AiReview.cs`, `ProviderConfiguration.cs` |
| Source/frozen consistency | SARIF uses the same runtime version source as the CLI. Known AI reference formatting, including punctuation, is corrected while preserving the corresponding validation limitations. | `src/attackmap/sarif.py`, `citations.py` and focused tests |
| Windows distribution | PyInstaller engine, source/analyzer/toolchain inventories and bindings, SBOM and RequiredBundled verification. The native application can be built as an optimized Windows x64 Release with its own .NET runtime and bundled Python engine. The portable marker selects the bundled engine during restore even when an old engine path is saved. | `installer/`, `tools/generate_release_lock.py`, `generate_release_sbom.py`, `package_native_windows.ps1`; `AttackMap.NativeSpike.csproj`, `EngineCapabilities.cs` |

Inherited upstream history also introduced general taint/def-use analysis,
source/sink registries, taxonomy, supply-chain checks, expanded secrets/history
analysis and CI workflows. The Windows phase subsequently modifies some of
those files; these capabilities are therefore not all new Windows implementations.

## Documented verification and its scope

Production code was not changed while preparing the contribution. The results
below come from completed implementation-verification runs; the separate,
current full `pytest` result is reported in the pull request.

- **WP018 / shared pipeline:** the accepted DONE scope includes source/frozen
  format and serial/parallel parity, fleet16 with workers 1/2/4, fault/cleanup
  scenarios, an actual C# consumer and Automatic Juice Shop runs.
  [Verification record](docs/verification/windows-parity/WP018/closeout-20261106/README.md).
- **WP032 / configuration and relationships:** 609 Python tests PASS,
  source/frozen reference runs, and actual headless consumer and Juice Shop
  runs; the qualified scope is accepted as DONE.
  [Verification record](docs/verification/windows-parity/WP032/closeout-20261107/README.md).
- **User-operated Automatic + local AI:** an actual Juice Shop run completed
  both analysis and a model response in 421 seconds, with 18 findings and one
  path. It used the earlier engine whose SHA starts `e5de74f1`.
  [WP005 evidence](docs/verification/windows-parity/WP005/closeout-20261107/README.md).
- **Latest portable build:** 72 release tests PASS; 21 analyzers; five actual
  commands from the newly packaged engine: version, modules, capabilities,
  atomic broker scan and compare. All exited naturally with exit code 0.
  All 807 files in the ZIP and extracted application were verified. A headless
  check linked to production sources verified portable engine selection.
  [Build delivery record](docs/verification/windows-parity/RELEASE-PORTABLE-20261107/README.md).

The latest package was built from source commit `18c87db`; `2d232cb` added
delivery documentation. It contains .NET 8.0.32, Windows App SDK 2.4.0 and
engine 1.5.1 with SHA-256
`788572853653643fcab399c1ab8457071f32753d7d87594b9bc0f98bf29e387a`.
The archive has 118,353,499 bytes and SHA-256
`f6e962b417471f948a2ea5fa4c49e34d7948c1c7511843f16c18f53a2ccc2002`.

The portable archive and detailed raw evidence for the latest build are local
outputs in the ignored directories `dist/releases/` and
`artifacts/release-portable-20261107/`. The source branch contains the
implementation, build tools and tracked documentation; a separate GitHub
Release asset requires its own publication.

## Remaining acceptance gaps

The package is an unsigned development distribution. The supplied screenshots
document the displayed Windows workflows with an imported completed report.
Complete rendering, keyboard and Narrator checks, clean-host/installation
acceptance and deployment qualification remain separate.

Of the 44 active tasks, 9 are DONE, 5 IMPLEMENTED, 5 MANUAL_PENDING,
16 IN_PROGRESS, 7 OPEN and 2 DEFERRED. For example, WP005 remains MANUAL_PENDING,
WP022 IMPLEMENTED, and the full WP043/WP044 tasks IN_PROGRESS. Static declarations
do not prove runtime connectivity; a synthetic corpus is not a representative
production fleet. Accepted Windows M3 and the removal of Windows C26 remain intact.

## Viewing the diff

[GitHub comparison against main](https://github.com/Harriis10/AttackMap/compare/main...Mipam:codex%2Fwindows-build-development)
also includes the subsequent contribution-documentation commits. To inspect
the exact implementation diff before this overview was added, use these
commands in a clone:

```text
git diff --stat 611a37951a998be5e9f072ec2c575ab720b5ffa1 2d232cb1a0f292ce93b54b07638b5bceb2b0b472
git diff 611a37951a998be5e9f072ec2c575ab720b5ffa1 2d232cb1a0f292ce93b54b07638b5bceb2b0b472 -- src/attackmap schemas installer tools
git log --oneline 611a37951a998be5e9f072ec2c575ab720b5ffa1..codex/windows-build-development
```

GitHub may limit the displayed diff for a comparison this large. The complete
comparison is available through Git using the exact commits. A local
`artifacts/remote-windows-development-20261107/windows-development.patch`
was also prepared with a checksum and complete binary changes.
