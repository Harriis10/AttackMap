# Desktop platform inventory — 2026-10-15

AM019 / C16 evidence inventory. **Partial: source inventory completed; platform
support decision and runtime parity acceptance remain open.** “Present” below
means present in inspected source, not verified in a shipped app.

## Inspection identity and limits

- Core checkout: `C:\Projects\INPROGRESS\AttackMap`, HEAD
  `4366b40b52cccbb4095fb61b3a8f316b8b735132`, **dirty**. Inventory describes the
  preserved working tree, including existing M0 changes, rather than HEAD alone.
  Desktop changes already include server, launch, web assets, report freshness,
  exports, and tests; engine, CI, release docs, and other files are also dirty.
  Concurrent roadmap work can change this snapshot. No commit was created.
- Actual macOS repository: `mlaify/AttackMap-mac`, inspected read-only through
  connected GitHub at commit
  [`5f2e8b4d84f9dff06e0f87c69c861a434981bd6a`](https://github.com/mlaify/AttackMap-mac/commit/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a)
  (2026-10-12). The remote commit is immutable; a remote working-tree dirty
  status is not applicable. No local macOS checkout exists to certify clean.
  `git clone --depth 1 https://github.com/mlaify/AttackMap-mac.git
  .pytest_cache/desktop-inventory-mac` failed because the configured proxy was
  unreachable. GitHub connector file reads succeeded and were pinned to that SHA.
- Inspection host: Python `platform.platform()` reports
  `Windows-10-10.0.19045-SP0`, `platform.machine()` reports `AMD64`, Python
  `3.13.15`. CIM OS/CPU queries were denied; exact processor model is unverified.
  Existing integration records identify Windows 10 Pro, but this audit did not
  independently verify the edition. No macOS runtime/build test was performed.
- Read [roadmap C16](roadmap-2026-2028.md#c16-platform-inventory),
  [implementation tracker](implementation-todo.md),
  [historical Windows session](session-state-2026-10-13-windows-gui.md),
  [architecture review](architecture-review-2026-10-13.md), and
  [macOS plan](macos-gui-plan.md). Historical defects and plans are context,
  not proof that current code still has those defects or implements those plans.
- CodeGraph was used before local source exploration. No UI implementation,
  builds, live AI calls, external writes, or release publication occurred.

## Architecture and workflows

| Workflow / boundary | Windows working tree | macOS pinned source | Parity / acceptance gap |
| --- | --- | --- | --- |
| Desktop shell | Python pywebview on Windows, loopback HTML/JS; browser fallback | SwiftUI app, Foundation services, WKWebView diagrams | Intentionally different; Windows WinUI 3 is a proposed migration, not current implementation |
| Engine launch | Frozen-aware subprocess: EXE `analyze`; source Python `-m attackmap analyze` | Discovered installed CLI, `ProcessRunner` subprocess | Present; engine discovery/bundling intentionally differs |
| Folder selection | pywebview native bridge, typed path fallback, multiple folders | Native folder selection and fleet URLs | Present in source; clean-host native dialogs unverified |
| Single / fleet scan | Config forwards repositories/modules; JSON progress; fleet summary | `arguments` / `fleetArguments`; fleet summary decoding | Present; actual current-core macOS compatibility unverified |
| Cancel / terminal state | Running/cancelling state, worker cancel, run/workspace identity checks | Descendant SIGTERM then SIGKILL after default 3-second grace; explicit errors | Present; process-tree cleanup and latency on real hosts unverified |
| Current results | Per-run generation directory and atomic pointer; report identity in UI | Stable per-repo reports directory, baseline rotation | Different implementation; equivalent generation/freshness guarantees missing in inspected macOS launch path |
| Findings / suppressions | Findings and suppressed list; suppression endpoint/writer | Finding details, suppression service and export documented in actual repo | Present surfaces; adversarial writes and native UX acceptance need platform tests |
| Review surfaces | Overview, Findings, Exploitability, Paths, Surface, Diagrams, Review, AI Review | Corresponding native result models/views and AI artifact mode selection | Present; observed/inferred field rendering against latest report contract unverified |
| Inventory views | Dependencies, Secrets, CI workflows, Data flows, Analyzers | Scan decoder covers each corresponding collection | Present data surface; malformed section handling needs visible diagnostics |
| History / diff | Recents, previous promoted report baseline, diff | Recents documented; previous-report rotation, custom/none baseline choices in view model | Present; cross-version reopening and retention unverified |
| Export / reveal | Markdown/PDF export source and handlers; PDF requires located Edge/Chrome; Explorer reveal | JSON/SARIF/PR summary export and Finder reveal documented | Intentionally different formats; macOS PDF/Markdown parity unverified |
| Watch | First repository only; filename-blind Win32 notifications; active-run callback drops change | FSEvents file paths, ignore filtering, pending rescan; fleet explicitly disables watch | Present but limited; Windows filename filtering/pending dirty state missing, fleet coverage differs |
| Accessibility / themes / large reports | HTML/CSS renderer | SwiftUI native renderer | Unverified C24–C26; no manual assistive-technology or performance evidence from this audit |

Windows evidence: [launch](../src/attackmap/ui/launch.py),
[server](../src/attackmap/ui/server.py), [spawn](../src/attackmap/ui/spawn.py),
[output](../src/attackmap/ui/output.py), [watch](../src/attackmap/ui/watch.py),
[web app](../src/attackmap/ui/web/src/app.js), [report](../src/attackmap/ui/report.py).
macOS evidence at the pinned commit:
[ScanViewModel](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/ViewModels/ScanViewModel.swift),
[ProcessRunner](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/Services/ProcessRunner.swift),
[RepoWatcher](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/Services/RepoWatcher.swift),
[ScanOutputLocation](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/Services/ScanOutputLocation.swift).

## Engine options and schema assumptions

Both [Windows ScanConfig](../src/attackmap/ui/config.py) and
[macOS ScanConfig](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/Models/ScanConfig.swift)
emit `analyze`, repository paths, `--format all`, `--output`, and JSON progress.
Their option vocabulary covers CVE, recall, explicit analyzer modules,
`--no-suppress`, `--suppress-file`, baseline/diff/new-HIGH gate, PR summary,
review/hunt/hunt+verify/remediate/triage, provider/model/effort/fast mode, and
verify votes/lenses/rounds/budget. Fleet omits single-repository AI and baseline
options. Windows adds `--run-id`; macOS config has no corresponding run ID.

The configuration types are broader than the visible/executed workflow.
Windows `_start_scan_locked` forwards CVE, modules, mode, provider, model,
recall, no-suppress, automatic previous baseline and new-HIGH gate, but does
not forward config's effort, fast, custom suppression file, jury, custom baseline,
diff-output or PR-comment fields. Do not mark those end-to-end options complete
merely because `ScanConfig.cli_args()` supports them. macOS `ScanViewModel`
constructs the richer config, but execution remains runtime-unverified here.
Windows accepts an OpenAI-compatible base URL and free-text model; the inspected
macOS config uses model enums and has no base URL setting. Local LM Studio UI
parity is missing from that config (an inherited environment is not a UI feature).

Neither config is proof of complete parity with every current CLI option.
Options such as history-secret scanning and future engine additions require an
explicit CLI-help-to-desktop coverage check. Capability filtering can suppress
flags; the intended mode must not silently change when an engine lacks it.

Windows translates the snake-case monolithic engine report to camel-case
`GuiReport.as_json()` for the web client; it also accepts a fleet summary and
generation sidecars. macOS
[Report.swift](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/Models/Report.swift)
decodes the engine artifact directly using `CodingKeys`. Numerous `try?` decodes
default incompatible collections to empty, so a successful decode does not
prove the report was fully represented. Unknown auth defaults to `unknown`;
missing finding IDs can become random UUIDs. Windows masks secret evidence in
the UI projection; macOS secret views deliberately omit evidence values per
actual repo documentation. No proof was produced that macOS consumes current
working-tree review JSON 1.5.0, scoped evidence or generation metadata correctly.
AM009 must establish version policy, golden reports, and consumer tests.

## Credentials and distribution

Windows [secrets.py](../src/attackmap/ui/secrets.py) uses separate DPAPI blobs
under `%LOCALAPPDATA%\AttackMap`, with environment-key precedence. Outside
Windows, its protect/unprotect fallback is plaintext; this Python desktop shell
must not be advertised as macOS credential protection. Custom OpenAI endpoints
receive a saved key if present, otherwise a placeholder. Endpoint trust,
provider switching, secure-store failures, and inherited environment require
AM007/C07/C14 proof. Current server supplies a child overlay instead of the
historical permanent `os.environ` mutation.

macOS [Keychain.swift](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/AttackMap/Services/Keychain.swift)
stores provider accounts through Security APIs, prefers the data-protection
Keychain, and falls back to legacy Keychain on missing entitlement, with
migration on read. ScanViewModel adds the selected provider key only for AI
runs; ProcessRunner also inherits a process environment. Native secure-store
access, refusal/failure UX and redaction are runtime-unverified.

Windows distribution is PyInstaller onedir, console-enabled, native build
architecture (`target_arch=None`), bundled web assets, taint YAML, and 15 listed
official analyzer packages. [build wrapper](../installer/build-installer.bat)
delegates to the [spec](../installer/attackmap.spec); it requires prepared Python
dependencies. WebView2/pywebview are runtime requirements; browser fallback is
available. [CI](../.github/workflows/ci.yml) declares frozen build/smoke artifact
jobs, but configuration is not a passing release run. No signing/MSI/upgrade/
rollback acceptance is established here. Signing credential availability is
unverified; no credentials were inspected.

The actual macOS repo materially exceeds the historical plan:
[project.yml](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/project.yml)
declares macOS 15.0, Swift 6, version 0.2.3/build 5, hardened runtime, no App
Sandbox, and Developer ID release signing.
[package.sh](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/scripts/package.sh)
archives/exports, signs a DMG, notarizes/staples, and invokes signature/Gatekeeper
checks. [release workflow](https://github.com/mlaify/AttackMap-mac/blob/5f2e8b4d84f9dff06e0f87c69c861a434981bd6a/.github/workflows/release.yml)
uses `macos-15` and the `release` environment. Required secret names are
`MACOS_DEV_ID_CERT_P12`, `MACOS_CERT_PASSWORD`, `APPLE_TEAM_ID`, `NOTARY_KEY_P8`,
`NOTARY_KEY_ID`, `NOTARY_ISSUER_ID`. Their existence, environment protections,
certificate validity and successful release runs remain unverified. The engine
is externally installed, not bundled. README says 0.2.2/engine 0.4.31 and Homebrew
cask installation, while project.yml is 0.2.3 and docs/RELEASE.md says DMG-only:
documentation/distribution drift needs reconciliation, not an invented channel
guarantee. CPU slices of actual release binaries were not inspected.

## Support proposal and C16 acceptance gaps

These are **candidate targets, not a supported-platform declaration**.

| Candidate | Evidence / available verification | Required before claiming support |
| --- | --- | --- |
| Windows 11 x64 | No host verified in this audit; `windows-latest` CI declared | Named clean Windows 11 host, exact build/CPU; native UI/install/cancel/export/upgrade/uninstall |
| Windows 10 x64 | Current build 19045 AMD64 development host only | Decide maintenance scope explicitly; development tests do not establish clean-install support |
| Windows ARM64 | No host, native package or emulation proof | Defer unless a named ARM64 host and complete native/dependency acceptance exist |
| macOS 15+ arm64 | Source deployment floor 15; `macos-15` release runner declared | Record runner actual OS/CPU/Xcode and successful build, plus real interactive host lifecycle evidence |
| macOS 15+ x86_64 | Deployment floor alone gives no CPU proof | Named Intel Mac/runner, actual binary slices and engine dependencies; otherwise defer |
| Linux core CLI | Core CI declares ubuntu-latest | Separate core support from desktop scope; no Linux desktop support proposed |

No macOS hardware or interactive runner was available to this audit; a workflow
label does not establish its CPU architecture or availability to this session.
Do not infer a universal binary from a generic macOS archive destination.

To close AM019/C16: assign platform/release owners; ratify supported OS/CPU scope;
identify one usable host/runner for every claimed target; record exact build
identities and actual results; resolve option/contract drift; and exercise all
parity rows against current core. AM024/AM025 integration slices should test
missing/wrong engine, native dialogs, credential denial, launch, cancellation,
generation freshness and export before migration choices are finalized.
AM041/AM042 must supply signed clean-machine lifecycle and rollback evidence.
AM044 must close watch correctness gaps. The implementation tracker remains
authoritative for task status; this document does not close those gates.

Validation for this documentation-only change: pinned GitHub source reads,
local source/config inspection, host identity probe, and `git diff --check`.
Existing integration results are linked in the tracker rather than rerun or
represented as fresh platform acceptance. No remote AI provider was used.
