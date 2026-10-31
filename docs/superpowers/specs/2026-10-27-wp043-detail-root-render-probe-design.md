# WP043 Detail + root non-mutating render probe

Date: 2026-10-27
Status: Approved design; diagnostic only

## 2026-10-30 runtime correction after the source-only hardening

Live-30 proved that the intermediate Ctrl+Shift+F7 shortcut still opens the caret-browsing dialog; its quarantined screenshot and UIA IsDialog/IsModal records are retained. Candidate-10 replaces the key entirely: `VirtualKey.R` with Control|Menu|Shift, runner `CTRL+ALT+SHIFT+R` mapped to `^%+r`. F7 is not bound by this probe. No caret or text-selection setting is changed.

Live-31 observed five trigger acknowledgments without a modal rejection, four qualified complete pairs and a correctly rejected empty root in round 5. All 19 available target images were reviewed. This runtime evidence supersedes the earlier source-only shortcut assumption; it does not establish a rendering repair or complete five-round acceptance. Startup placement now follows the expected report-ready snapshot and requires observed outer-window geometry. Modal failures may retain a quarantined diagnostic-only screenshot under independent owned-window safety checks; it is never accepted as A/B.

## 2026-10-30 diagnostic hardening addendum

The user requested correction of the F7 collision and diagnostic image qualification after `detail-root-render-probe-live-28-retry-01`. That failed run displayed an in-client caret-browsing modal from the first B onward, and all four D/T artifacts were fully transparent. Its raw artifacts and negative rendering verdict remain preserved.

For new diagnostic candidates the trigger is **Ctrl+Alt+Shift+R**, not bare F7. The native opt-in accelerator and runner key mapping must agree; `Handled` remains synchronous before the asynchronous capture. Existing CLI mode, event names, strict run/report/navigation/finding/probe identity and direct Detail→root ordering stay intact. Production text selection and caret settings are not changed.

Read-only modal inspection must qualify client content before and after ordinary capture and before triggering the pair. A visible in-client ContentDialog/modal or an inspection failure fails the sample; it is not automatically dismissed, retried or accepted as missing glyphs. Actual ordinary outer-window dimensions must match the controlled 1600×1000 request; a mismatch is an environment failure rather than equivalent visual acceptance.

Both raw BGRA buffers and independently decoded bounded PNGs receive pixel-support metadata. Root qualification requires visible alpha support and visible pixel variation; a fully transparent or uniform root cannot serve as the scene control and fails before B. Rejected pair artifacts and bounded failure metadata remain available. PNG decoding errors also fail before B. Hidden RGB under zero alpha does not count as visible content, and alpha-only antialiasing of monochrome text must not be mistaken for a uniform raster.

A fully transparent **Detail alone remains an observable negative result** when the root is meaningful and modal-free: the approved D-blank/T-complete comparison must remain possible. Its quality classification is explicit; neither nonempty pixels nor a quality PASS establishes that the expected text is visible. Do not paint a diagnostic background, replace the capture target, add layout/settling operations, or reject an otherwise meaningful scene merely because expected glyphs are absent.

Focused fake/native source checks and an offline source-bound diagnostic build precede any new controlled live journey. These checks cannot establish current runtime modal isolation or a rendering repair; WP043/rendering/V01–V03 acceptance remains open.

## Purpose and boundary

Add an independent opt-in Ctrl+Alt+Shift+R observation that compares the live window with immediate RenderTargetBitmap (RTB) output for both the finding `Detail` and the current root visual tree. Its purpose is to distinguish target-dependent rasterization from live-presentation divergence in an anomalous WP043 round.

This is not a rendering repair, production workaround, composition-root-cause claim, promotion candidate, or V01/V02/V03 acceptance activity. Existing F8 behavior and all production UI behavior remain unchanged. No property mutations, `UpdateLayout`, explicit delay, frame settling, scrolling, theme changes, provider calls, new scans, packaging, or SDK changes are in scope.

## Sequence and components

For each of the five existing FindingDetail rounds, the runner performs:

1. **A:** the existing ordinary FindingDetail ImageGrab capture.
2. **D:** Ctrl+Alt+Shift+R triggers direct `RenderTargetBitmap.RenderAsync(Detail)` and PNG encoding.
3. **T:** the same modified-key invocation directly renders `(FrameworkElement)Content` to a second RTB and PNG.
4. **B:** after a valid completed pair acknowledgment and independent root quality qualification, the runner takes a second ordinary ImageGrab.

D and T occur consecutively inside one new `RenderDiagnosticsDetailRootRender` method. There is no inserted delay or layout operation between them. A and B remain external screen captures, so the four images are ordered observations rather than simultaneous snapshots.

Ctrl+Alt+Shift+R uses the CLI runner flag `--detail-root-render-probe`. It cannot be combined with F8 mode, diagnostic interventions, Detail spacing/brush probes, or PrintWindow comparison mode. Bare F7 is not a diagnostic trigger.

## Identity, evidence, and failure handling

One fresh `probeId` identifies the D/T pair. Started, completed, and failed events use `detail-root-render-capture-*` names and carry the current run ID, report hash, navigation revision, and finding revision. The completed event is emitted only after both PNG files are committed and contains their simple file names, dimensions, and rasterization scale.

The native method validates loaded, visible, nonzero-size Detail and root elements on the owning dispatcher, a selected finding, finite positive scale, bounded dimensions, bounded pixel buffers, and bounded encoded PNGs. PNG writes use unique temporary files, durable flushes, and non-overwriting atomic renames. A failure after D may leave the valid D artifact for diagnostics, but emits no completed pair acknowledgment.

The native method rechecks run/finding context and loaded state before encoding and before each commit. The runner rejects stale, mismatched, or failed acknowledgments; unsafe paths; invalid metadata; oversized files; and finding-revision changes across A/D/T/B. It validates both PNGs and records their paths, sizes, hashes, dimensions, and scale in a five-entry `detailRootRenderProbe` manifest collection. Any D/T failure fails the run without taking or claiming B. A/B capture names remain unique and identify their positions in the sequence.

## Interpretation and review

The run retains one ordinary five-round journey and targets visual review at all five A/D/T/B sets, including viewport-equivalent crops where necessary. Review records each image as complete, blank, or another explicitly described state; it does not infer glyph presence from UIA, dimensions, hashes, or successful encoding alone.

In an anomalous A-blank round:

- D complete with T blank supports target-dependent rasterization.
- D and T complete supports divergence of both RTB outputs from live presentation.
- D blank with T complete shows that local RTB is not a reliable live-presentation oracle.

These combinations narrow hypotheses but do not identify a WinUI, DWM, compositor, or glyph-cache root cause. If no anomaly reproduces, record `not-reproduced`; do not make a negative mechanism claim. Rendering acceptance remains failed unless separately established by complete visual acceptance.

## Focused verification

Use test-first changes in `tests/test_wp043_live_capture.py` and the existing fake backend:

- five complete A/D/T/B sequences, five modified-shortcut invocations, and both PNG manifests per round;
- fresh started/completed pair acknowledgment and rejection of stale or failed D/T events;
- rejection of report/navigation/finding mismatches and finding changes before B;
- incompatible CLI modes rejected before output creation;
- simple bounded PNG paths, dimensions, buffers, and files;
- no B capture after D or T failure;
- source gate proving direct Detail and root `RenderAsync`/`GetPixelsAsync` calls without `UpdateLayout`, `Task.Delay`, or UI property mutation;
- existing F8 triplet tests and the rest of the focused WP043 harness remain green.

Publish one offline diagnostic candidate with `dotnet publish --no-restore`, reuse the frozen engine, and record the managed DLL hash. Run exactly one serialized live capture with foreground/occlusion guards, then actually inspect all 20 targeted A/D/T/B images. Record evidence and remaining uncertainty without claiming repair or promotion.
