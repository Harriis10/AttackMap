# Independent native analyzer visual review — 2026-10-23

**Scoped visual pass with viewport limitations.** All eight supplied PNGs were
independently opened through `view_image`. They are distinct, nonblank and
readable; no overlapping text, black capture or obscured primary control was
observed. Actual file hashes match all eight entries in `analyzer-smoke.json`.
See the [machine-readable review](python-django-native-visual-review.json) for
absolute capture paths, dimensions, hashes and per-image observations.

This is an AI review of in-process WinUI `RenderTargetBitmap` content. It is
not human visual, keyboard, Narrator, accessibility, popup-layer, OS appearance,
scaling or release acceptance. Nominal 1024×700 window captures contain
1008×661 content pixels; nominal 1600×1000 captures contain 1584×961 pixels.

## Reviewed material

All images originate from
`C:/Projects/INPROGRESS/AttackMap/.tmp/wp039-python-20261023/native-analyzers-final-01/`.

| Capture | Observed result |
| --- | --- |
| 1024x700-Light-Analyzers | Light selector, qualified profile expansion, experimental/opt-in markers and selection/applicability caveat readable. Inventory rows are below this captured viewport. |
| 1024x700-Dark-Analyzers | Dark counterpart readable with equivalent controls. No small-window inventory row is visible. |
| 1600x1000-Light-Analyzers | Selector and first selected ATProto plugin record visible, including package/analyzer versions and experimental/opt-in status. Source detail continues below the bounded list. |
| 1600x1000-Dark-Analyzers | Equivalent dark layout readable, with the inventory applicability/execution caveat visible. Further records require scrolling. |
| 1600x1000-Dark-Ledger | Selected report identity, explicit `node-atproto@1.0`, supplied-candidate scope and four succeeded/two skipped summary visible. Expanded `javascript-web` row shows recorded built-in origin, execution, timings, counts before merge and activity. |
| 1600x1000-Dark-Collision | Exactly one filtered `php-laminas` record. Effective built-in implementation/analyzer version is distinct from the nonselected shadowed plugin. Unknown core package version is honestly shown. |
| 1600x1000-Dark-Activity | Completed scan and unavailable stage total/ETA are explicit. Heading shows 221 updates and 21 earlier updates omitted; timestamped file activity is readable. |
| 1600x1000-Dark-DiscoveryFixture | A prominent fixture-only banner distinguishes six simulated failures/policy skips from actual inventory. Expanded panel and initial load/init/metadata rows readable. |

The collision screenshot does not show all selected module rows; the search
leaves one filtered record. The failure screenshot does not show all six
failure rows at once. The actual scan ledger is separate from current installed
inventory and explicitly warns that terminal completion does not prove full
coverage. These distinctions are visible, rather than inferred from a checked
profile selector.

## Runtime evidence and limits

The smoke result records a completed native scan of `C:/tmp/juice-shop` using
`node-atproto@1.0`. Its report hash independently matches
`0ab42550c71b075aa826b80fe673227b638ca287ec644224365cd4f6499a10d9`.
The actual report ledger confirms four succeeded, zero failed, two skipped and
zero not-started entries in `supplied_candidates` scope. The selected frozen
engine SHA-256 is
`6045194b77c0957166a6eb9fece45dbfd9c42441bb9e32cec6d040db6c419b05`.
The separate Python profile proof is the seventeen-case CLI oracle; these
native captures do not show a native Python-profile scan.

The retained activity model contains 200 entries and reports 21 omitted
updates, for 221 received updates. Only the visible part of that list was
reviewed. No independent scroll, keyboard or focus interaction was performed
by this reviewer. In particular, the small captures establish selector and
summary appearance, **not** inventory-detail/scroll usability at that size.
The larger inventory, ledger, activity and simulated-failure bodies also extend
below their bounded visible portions.

The discovery fixture is explicitly simulated and is not evidence that this
engine had six discovery failures. No source changes or rebuilds were performed
for this review. Wider manual UX/accessibility and platform acceptance gates
remain with the active plan.
