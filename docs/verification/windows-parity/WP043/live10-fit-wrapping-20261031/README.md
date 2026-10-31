# WP043: live-10 automatic Fit and Findings wrapping

Date: 2026-10-31. Bounded diagnostic checkpoint only: WP043 **IN_PROGRESS**,
general rendering **FAILED**, root cause unknown. No release acceptance.

## Build and source review

`GraphExplorerView` defers automatic Fit until viewport layout is available;
Findings uses Grid-based wrapping. Independent source review found no actionable
defect. The source-bound self-contained build used the unchanged precompiled
SDK manifest task override: **exit 0, 0 warnings/errors, 00:01:46.70** (coordinator
session output). Output: `native-candidate-fit-wrapping`. This is diagnostic
output, not a release-qualified build; ordinary inline SDK task recovery remains
open. No retained evidence was replaced by this note.

SHA-256 recorded from the current source and candidate:

| Source / candidate file | SHA-256 |
| --- | --- |
| `desktop/windows/GraphExplorer.NativeView/GraphExplorerView.cs` | `0423ad8c21ae31cdee23ffa1be52e59592e7c23b0a2aafc35ef345971070d06c` |
| `desktop/windows/AttackMap.NativeSpike/MainWindow.xaml` | `5d18931b0f75369c0fc47f3ce78e7101a7a892eedf361261c874c060677cf6df` |
| candidate `AttackMap.NativeSpike.exe` | `0542f80d86327742899cd8453c53d69887fabceb6cd9e6981eab3d61945dcfb2` |
| candidate `AttackMap.NativeSpike.dll` | `6a14cb9df6fa1674708cafb3fb829b0ba502598d1e16bf8bad8b1ba59faf130c` |
| candidate `MainWindow.xbf` | `0202a9e1503bc1d9edb1149e2f548b288bec44495ebf298d20bbfd45a9608120` |
| candidate `GraphExplorer.NativeView.dll` | `c72c2744f982b7c6eb63dca57fe8fd3cfc0ab581a2319d1f6e7ca6a4746ed601` |

## Live result and visual review

[Raw live-10 evidence](../../../../../artifacts/wp043-context-diagnostics-20261031/live-10/evidence.json):
**75 valid captures, 0 discarded, 5 complete rounds, 5 diagram activations,
closedCleanly=true**, runId `d974fba679e34e0f80797af1b631fa43`. PID **28972**
was absent on the follow-up process check. Raw `manual_review: not-run` and
`rendering_acceptance: not-established` are preserved; the review below is
separate session evidence.

All 75 images were visually reviewed: live07 agent reviewed rounds 1–2,
reviewer rounds 3–4, runner round 5; root additionally checked round-1/round-5
targets. No disappearing text or popup was observed. Compared with
[live-09](../live09-visual-review-20261031/README.md), the first two Findings
titles now wrap completely; long metadata retains ellipsis. The whole graph
fits in the viewport for this case. Labels remain small and zoom has not been
tested. Screenshots demonstrate **automatic Fit**, not manual Fit interaction.

## Boundaries

This covers one saved report, Dark theme and 1600×1000 only. The report SHA-256
is `860343835432b3267da81f4b4124925eeae94ea570ed972cb3c4b040875d581d`.
The explicit engine remains retained `ordinary-candidate-10/engine/attackmap.exe`,
SHA-256 `792184c584895bab68e4260447fe89543486ae228bd8ad85234ae3ca87ce8bba`;
it is not a fresh common-source frozen engine/package. Unsupported offline
diagram fallback and unverified scroll remain. A non-capture ordinary run,
manual keyboard/Narrator/zoom/scroll, other reports/themes/sizes, clean-host and
release gates remain open. This observation does not establish the disappearing
text root cause or close V01–V03/general rendering acceptance.
