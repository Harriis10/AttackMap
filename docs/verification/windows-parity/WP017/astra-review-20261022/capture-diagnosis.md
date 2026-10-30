# Review capture diagnosis — 2026-10-22

Read-only inspection while root's sequential model runs continue. No application, provider, GUI control, capture retry, build or source edit was performed. The PNG was viewed and its original bytes parsed with Python standard-library PNG chunk/zlib decoding; no image was edited. Pillow was unavailable, so no dependency was installed.

## Concrete finding

`WP017/astra-live-20261022/review/AI-mode.png` is **entirely transparent, not an opaque black capture**: 1424 x 720, 8-bit RGBA, noninterlaced, all PNG scanline filters zero and every decoded channel byte zero. Thus all 1,025,280 pixels are RGBA `(0,0,0,0)`. The viewer renders this as a black rectangle. File size is 4,105 bytes; SHA256 `e6eadbccae17abc2a18735b3366188c8e6b445d1dfc7e2ae16c9246861409c6a`, matching the native capture metadata. Metadata reports Light theme, scale 1, logical size 1424 x 720 and capture UTC `2026-10-22T12:16:04.1663293+00:00`.

This proves that the RenderTargetBitmap evidence contains no readable visual content. It does **not** prove that the actual window displayed a black/transparent page. Independent live-window observation is necessary to separate a capture/compositor/host anomaly from a real presentation defect. The successful HTTP/model/artifact/export evidence remains distinct; the visual gate fails.

`NativeCaptureProbe.cs:19-71` checks a loaded root, positive dimensions, two CompositionTarget frames, pixel-buffer length and bounded PNG encoding. It does not test for transparent/blank content. Its own scope warning (line 16) explicitly distinguishes RenderTargetBitmap from composition-backed displayed surfaces. `run_wp017_native_modes.collect` checks PNG signature and matching metadata hash; this is byte integrity, not visual acceptance. No acceptance boolean should be upgraded from that gate.

## Existing display-only recovery path

`MainWindow.ParitySmoke.cs:73-87` binds the selected completed AI artifact, exports its verified bytes, selects Reports, expands/brings the AI expander into view and invokes the probe. `MainWindow.Capture.cs:152-218` already supports loading the saved generation without scanning or calling an engine/provider:

```text
<same pinned AttackMap.NativeSpike.exe>
  --capture-smoke <absolute existing canonical report> <new existing empty capture directory>
  --capture-ai-mode review
```

Concrete Review report:

```text
C:\Projects\INPROGRESS\AttackMap\docs\verification\windows-parity\WP017\astra-live-20261022\review\reports\62feae910edd4843aef42f98e53fdd36\attackmap-report.json
```

Report SHA256 is `919619d6ffe6a8ccdf153f83d9b127ae06aa46c1b68351ee770565edbeb5b8c9`; bind its exact generation path and artifact manifest as well, because deterministic report bytes may match another run. Preserve original evidence; write supplemental captures separately.

The capture branch calls `LoadReport`, waits for parity binding, selects the requested saved mode, expands AI content, and visits only Reports. It produces four PNGs for requested 1024x700 / 1600x1000 and Light / Dark combinations, plus `capture-manifest.json` with `aiMode`, `selectedReportSha256`, expected/completed count 4 and `providerCalled=false`. It has no engine discovery, scan or provider call. The actual window is activated by `App.xaml.cs:19`. `MainWindow.xaml.cs:82-83` routes this flag through the capture branch, bypassing normal personal settings/provider/recent/placement restoration; theme loading is also excluded for capture flags. The corrected task-owned AppData hierarchy should still be supplied.

Do not use `--capture-reports-artifacts`: that separate branch deliberately substitutes synthetic artifact rows/text. Do not repeat `--parity-smoke --native-scan --ai-mode` to repair a screenshot: that would repeat the expensive model generation.

## Smallest next execution proposal (root owns approval and slot)

After the current five model runs finish, try **one** Review display-only capture using the same pinned package, corrected isolated environment and owned Windows Job on the verified interactive desktop/window host. Recheck package, report/generation manifest and selected artifact hashes before/after. Require no `capture-failure.json`, exact four capture records with safe fresh output paths, valid dimensions/scale/themes and hashes, nonblank/nontransparent pixels, then actually view the saved images. Reuse this path for the other completed mode generations only if Review produces usable evidence. No product rebuild is needed to try the existing branch.

This still uses the same RenderTargetBitmap API; its success is not guaranteed by the extra navigation dispatcher turn or size/theme loop. If it remains transparent, preserve the failure and independently inspect/capture the actual activated application window through an authorized live-window facility. Do not composite a background onto empty pixels or label metadata/control-state assertions as readable UI. External window capture must be bound to the same application process and saved generation; an arbitrary screenshot is insufficient. A source/capture implementation change, if ultimately needed, requires a separate lease and renewed product/source proof.

Current status: supplemental recovery proposed, not executed. Human visual/accessibility acceptance remains open.
