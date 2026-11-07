# WP043: strict UIA wrapper recovery and popup diagnostics

Date: 2026-10-31. This bounded checkpoint follows
[recovery provenance](../recovery-provenance-20261031/README.md).
WP043 remains **IN_PROGRESS**, rendering remains **FAILED**, and V01–V03 remain
blocked. This note grants no visual, package or release acceptance.

## Changes under verification

- `tools/capture_wp043_live.py` accepts a wrapped native safety error only when
  `ClientModalInspectionError` has API `UIAutomation`, stage
  `owned-target-recheck`, attempt 2, no confirmed modal, and a direct
  `NativeWindowSafetyError` cause from `uia-retry-before-descendants` or
  `uia-retry-after-descendants`. The original strict owned-target/blocker
  predicate still applies. Generic errors, arbitrary cause chains and external
  or mixed blockers remain fatal; retry limits are unchanged.
- The outer grid in `MainWindow.xaml` sets
  `KeyboardAcceleratorPlacementMode="Hidden"`. This is a targeted mitigation
  for the hypothesized automatic root accelerator tooltip observed as an owned
  popup during live-04. Actual suppression still requires a valid live run.
- `MainWindow.RenderDiagnostics.cs` records OverviewText metadata without its
  body text and OverviewPanel layout/scroll geometry. `MainWindow.xaml.cs`
  records `overviewCharacters` after report binding. These probes investigate
  the visibly blank Overview body; they do not establish its root cause.
- Focused tests cover the exact wrapper provenance, accepted owned recovery,
  rejected external/incorrect-PID errors, root XAML configuration and diagnostic
  metadata without report-body logging. Independent source review found no
  actionable defect in this recovery/XAML patch; it explicitly retained live
  visual review as a gate.

## Deterministic verification

Executed from the repository root using explicit elevated
`C:\Windows\System32\cmd.exe`, `login=false`:

```text
.venv\Scripts\python.exe -m pytest tests\test_wp043_live_capture.py -q --junitxml=docs\verification\windows-parity\WP043\popup-tooltip-recovery-20261031\harness-evidence-agent.xml
```

Result: **106 tests + 149 subtests PASS**, exit 0, 9.86 seconds.
[Fresh JUnit](harness-evidence-agent.xml) records the execution. These tests use
raw-API fakes; they do not establish real UIA behavior or pixels. No native
executable was launched by this documentation block.

SHA-256 recorded immediately after verification:

| File | SHA-256 |
| --- | --- |
| `tools/capture_wp043_live.py` | `2f04f1c6f9ed286c468a3e9c2a4cb7b6873583e36b3b15d8d595b51bdf647869` |
| `tests/test_wp043_live_capture.py` | `6ce1f3105884435e8b22550d67f5665d0b7fb7046758aa821fd0c47c13c38080` |
| `MainWindow.xaml` | `5e9cd51ada323d3d96266a93453e13b0d989b037a31d30b9f43f96082221b366` |
| `MainWindow.RenderDiagnostics.cs` | `fcae9cccbf18889e847e2208f53606aa339f023dcb549eefd8653c64304474bf` |
| `MainWindow.xaml.cs` | `cce09250357d8d7836635f4649548c7e68684f89ab27cce1ffdada6d335450ab` |
| `harness-evidence-agent.xml` | `6d821c709439f9439570f7b307666b1ceaa1fcdd27be3daf02911890b407f9c1` |

The three MainWindow files are under
`desktop/windows/AttackMap.NativeSpike/`. Recording their identity does not
assert that the C# implementation was executed by this Python suite.

## Invalid live candidates

The following retained raw run records are startup failures, not renderer tests:

| Run | Candidate | Captures / rounds | Raw result |
| --- | --- | --- | --- |
| [live-05](../../../../../artifacts/wp043-context-diagnostics-20261031/live-05/evidence.json) | Fresh non-self-contained Debug build | 0 / 0 | Timed out waiting for exactly one owned AttackMap window |
| [live-06](../../../../../artifacts/wp043-context-diagnostics-20261031/live-06/evidence.json) | Retained host with fresh DLL/XBF overlay | 0 / 0 | Same startup timeout |

Both records retain `manual_review: not-run`, `rendering_acceptance:
not-established`, `runId: null` and `closedCleanly: false`. These raw values are
preserved; they do not independently establish later process leakage.

During the overlay attempt the user observed a Windows bootstrap dialog asking
to install Windows App Runtime 2.x (MSIX package version >= 2.4.0.0). Root's build
diagnosis identified the non-self-contained DLL's WindowsAppSDK bootstrap
autoinitializer with `OnNoMatch_ShowUI`: copying that DLL into a retained
self-contained host did not produce a coherent candidate and caused the prompt.
This is a packaging failure, not proof that no compatible runtime exists anywhere
on the system; the package-registry inspection was inconclusive. The attempt
was stopped; no runtime installation was authorized or performed. Root then
checked the process list and found no `AttackMap.NativeSpike.exe` process. The
overlay is invalid for further verification and must not be reused as a valid
self-contained candidate. The user-visible dialog is session evidence; the raw
JSON records themselves establish only the startup timeouts.

live-05 executable SHA-256:
`d44ef4ecf076b3a81bc8d963ec9a1983e39900c613eeaae285e08ef65cd120bc`.
live-06 retained host SHA-256:
`0542f80d86327742899cd8453c53d69887fabceb6cd9e6981eab3d61945dcfb2`.
Both run records identify report SHA-256:
`860343835432b3267da81f4b4124925eeae94ea570ed972cb3c4b040875d581d`.
The retained host hash alone does not identify the overlaid DLL/XBF composition.

## Self-contained build and live-07

The [precompiled SDK task build](../../../../../artifacts/wp043-context-diagnostics-20261031/manifest-task-precompiled/README.md)
compiled the unchanged SDK-generated manifest task and selected it through
`UsingTask Override="true"`. The project-scoped self-contained build completed
**exit 0, 0 warnings, 0 errors** in 00:01:15.58; its complete output was copied
to `native-candidate-selfcontained-taskoverride`. Product source/configuration
was unchanged by this workaround. The ordinary SDK inline task still stalls
inside `RoslynCodeTaskFactory`; this diagnostic success does not resolve that
build-system issue or qualify a release.

The [live-07 raw record](../../../../../artifacts/wp043-context-diagnostics-20261031/live-07/evidence.json)
identifies that candidate and reached an owned window: PID **40344**, HWND
**138840**, runId **9d101901c68e497bae4df80699404306**. Window placement was
acknowledged. Before transient dismissal, `FrameSafetyError` rejected the
foreground **Terminal** (HWND 73830, PID 35952). The run retained **0 captures,
0 completed rounds**, `manual_review: not-run`, `rendering_acceptance:
not-established` and `closedCleanly: false`. Those raw values are preserved;
they establish neither visual acceptance nor subsequent process cleanup.
No Overview, tooltip suppression or five-round visual result was obtained.

The executable host hash matches live-06, but the fresh managed DLL hash is
`e38e244a9910707c1b3ee7d9fae3fe521a5e742652b77495e2441484793e03c7`
and `MainWindow.xbf` hash is
`3391267efde2f3f4418a7f1db7d8aede7dc79f217502e5f599046924a977328c`.
The build record confirms self-contained activation (`UndockedRegFreeWinRTCS`,
no `BootstrapCS` match); the rejected live-06 overlay remains invalid.

## Remaining gate

The later [live-10 checkpoint](../live10-fit-wrapping-20261031/README.md)
records deferred automatic Fit and Findings wrapping, a fresh diagnostic build
and 75 visually reviewed captures across five rounds. It improves this one
report/viewport observation without closing root cause or general acceptance.

The [live-08/live-09 follow-up](../live09-visual-review-20261031/README.md)
supersedes the earlier pending five-round capture step: live-08 had 10 captures
and 0 rounds before missing-engine diagram activation failed; live-09 explicitly
selected a retained frozen engine and completed 75 captures, 0 discarded,
5 rounds, 5 diagram activations and clean close. All 75 images were visually
reviewed (agents rounds 1–4, root round 5); no disappearing text or popup was
observed and Overview/detail were readable. The raw records are unchanged.

Harness `--engine`, timing/fail-fast verification has 110 unittest PASS in
reported session output and independent review. The later persisted pytest run
completed exit 0, **110 tests + 156 subtests PASS**, 29.75 seconds:
[fresh JUnit](harness-engine-activation.xml). The prior failed log is retained.
The single Dark 1600×1000 saved-report observation is not general acceptance:
small/clipped diagram, truncated Findings, unsupported offline fallback and
unverified scroll remain. Root cause is not proven. WP043 remains IN_PROGRESS,
global rendering FAILED; V01–V03, fresh common-source engine/package and release
qualification remain open.
