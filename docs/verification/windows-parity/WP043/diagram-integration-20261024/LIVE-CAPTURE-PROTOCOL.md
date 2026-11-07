# WP043 independent live-window capture protocol

## Scope and evidence limits

This protocol reproduces the real native-shell user journey against a retained report. It does not run an engine scan, call a provider, use coordinate-based navigation, capture through `RenderTargetBitmap`, or establish rendering acceptance. Only the integrator may launch the UI and perform manual review.

The runner requires the existing project `.venv`. Live UI Automation requires `pywinauto`; live screen capture requires Pillow. Missing dependencies produce `status = "not-run"`; the runner never substitutes unverified input or imaging implementations.

## Exact journey

1. Require `--native-only --theme dark --width 1600 --height 1000 --rounds 5`. Before launch, write exactly `{"theme":"dark"}` only to the isolated `LOCALAPPDATA/AttackMap/NativePreview/theme.json`. Never read or modify the personal theme file.
2. Resolve and hash the specified executable and retained report. Launch that executable with `--show-report <same-retained-report> --render-native-only --render-diagnostics <fresh-empty-diagnostics-directory>`.
3. Create a fresh local output path. Isolate `LOCALAPPDATA` and `WEBVIEW2_USER_DATA_FOLDER` beneath it. Reject UNC paths, reparse-point path components, existing output paths, duplicate capture names, and capture names containing traversal or path separators.
4. Find the visible top-level window by the launched PID, not by title alone. Require exactly one owned visible `AttackMap` window before sending input.
5. Restore the window if minimized, activate it, move/resize it to 1600×1000, and wait one second after restore/placement. Never resize a minimized window. Before traversal, require a new diagnostics snapshot with `rootTheme == "Dark"`, the expected nonempty report hash, and selected destination `Findings`.
6. Before every action and capture, require a live owned process, owned foreground HWND, visible non-minimized window, expected report hash in diagnostics, and no visible higher-Z-order window intersecting the target rectangle. Ignore cloaked windows; treat every other intersecting visible higher-Z-order window as an occluder.
7. Locate navigation items through UI Automation. Focus the exact item and send actual Enter through `SendInput`/pywinauto keyboard input. Wait for a new JSONL-sequence `navigation-after-turn` event whose run ID, report hash, navigation revision, selected label, and heading match the request. A key send without this acknowledgment is failed dispatch, not navigation.
8. In each of five rounds, traverse exactly `Overview`, `Findings`, `Architecture`, `Inventory`, `Reports`, `History`, `Scan options`, `Risk and paths`, `Evidence inventory`, `Diagrams`, `Fleet`, `Suppressions`, and `Settings`. Capture only after acknowledgment and a 500 ms post-layout delay.
9. Immediately after each Findings capture, select the first finding through UI Automation. Require a new `finding-selection` event bound to the same run ID, report hash, and Findings navigation revision, with `hasFinding == true`. Capture the existing inspector as `FindingDetail`; do not invent a new detail destination.
10. After the five rounds, separately exercise Ctrl+H and Ctrl+comma and require new History and Settings acknowledgments. Exercise F9/F10 only when the explicitly labeled `--diagnostic-interventions` run option is present. F9 requires both `f9-before-local-brush` and `f9-after-local-brush`; F10 requires both `f10-before-local-spacing` and `f10-after-local-spacing`. These events establish invocation/application only, not visual improvement.
11. Use `ImageGrab.grab(..., all_screens=True)` only after the safety checks. Recheck foreground and frame safety immediately before saving. Preserve every discarded capture with `discarded-invalid`, its reason, rectangle, byte count, and SHA-256; discarded frames do not count toward coverage.
12. Save `evidence.json`, `stdout.log`, `stderr.log`, the diagnostics JSONL, valid images, discarded images, and all capture metadata. Set `status = "independent-live-window-captured"` only after the complete protocol succeeds. Always retain `manual_review = "not-run"` and `rendering_acceptance = "not-established"` in runner evidence.
13. Close only the owned window and verify process exit. On timeout, kill only the owned process tree. On any failure, write partial evidence, preserve earlier valid and discarded captures, and perform no other process cleanup.

## Diagnostics binding

Every JSONL event must have top-level `runId` and `kind`; the reader assigns a monotonically increasing JSONL `sequence`. The `enabled` event establishes the UI run ID. Navigation and finding events must belong to that run and to the exact SHA-256 of the loaded retained report. An empty `displayedReadHash` before report load is never acknowledgment.

`navigation-after-turn` detail must include `rootTheme`, `selectedDestination`, `headingText`, `generation`, `displayedRun`, `displayedReadHash`, and `navigationRevision`, in addition to nested navigation/heading data. `finding-selection` detail must include `generation`, `displayedRun`, `displayedReadHash`, `navigationRevision`, `findingRevision`, and `hasFinding`.

## Integrator command

```powershell
& ./.venv/Scripts/python.exe tools/capture_wp043_live.py `
  --executable artifacts/diagram-integration-20261024/wp043-continuation-20261025/live-instrumented-baseline/AttackMap.NativeSpike.exe `
  --report artifacts/diagram-integration-20261024/source-render-audit-20261025/saved-generation/attackmap-report.json `
  --output artifacts/diagram-integration-20261024/wp043-continuation-20261025/live-baseline-01 `
  --native-only --theme dark --width 1600 --height 1000 --rounds 5
```

The integrator must inspect every valid image at native resolution and create separate manual-review evidence. If no anomaly appears, record `not-reproduced`, not `fixed`. A successful runner manifest alone never establishes manual review or rendering acceptance.
