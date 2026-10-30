# WP043 Detail + root non-mutating render probe

Date: 2026-10-27
Status: Approved design; diagnostic only

## Purpose and boundary

Add an independent opt-in F7 observation that compares the live window with immediate RenderTargetBitmap (RTB) output for both the finding `Detail` and the current root visual tree. Its purpose is to distinguish target-dependent rasterization from live-presentation divergence in an anomalous WP043 round.

This is not a rendering repair, production workaround, composition-root-cause claim, promotion candidate, or V01/V02/V03 acceptance activity. Existing F8 behavior and all production UI behavior remain unchanged. No property mutations, `UpdateLayout`, explicit delay, frame settling, scrolling, theme changes, provider calls, new scans, packaging, or SDK changes are in scope.

## Sequence and components

For each of the five existing FindingDetail rounds, the runner performs:

1. **A:** the existing ordinary FindingDetail ImageGrab capture.
2. **D:** F7 triggers direct `RenderTargetBitmap.RenderAsync(Detail)` and PNG encoding.
3. **T:** the same F7 invocation directly renders `(FrameworkElement)Content` to a second RTB and PNG.
4. **B:** after a valid completed F7 acknowledgment, the runner takes a second ordinary ImageGrab.

D and T occur consecutively inside one new `RenderDiagnosticsDetailRootRender` method. There is no inserted delay or layout operation between them. A and B remain external screen captures, so the four images are ordered observations rather than simultaneous snapshots.

F7 uses the new CLI runner flag `--detail-root-render-probe`. It cannot be combined with F8 mode, diagnostic interventions, Detail spacing/brush probes, or PrintWindow comparison mode.

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

- five complete A/D/T/B sequences, five F7 invocations, and both PNG manifests per round;
- fresh started/completed pair acknowledgment and rejection of stale or failed D/T events;
- rejection of report/navigation/finding mismatches and finding changes before B;
- incompatible CLI modes rejected before output creation;
- simple bounded PNG paths, dimensions, buffers, and files;
- no B capture after D or T failure;
- source gate proving direct Detail and root `RenderAsync`/`GetPixelsAsync` calls without `UpdateLayout`, `Task.Delay`, or UI property mutation;
- existing F8 triplet tests and the rest of the focused WP043 harness remain green.

Publish one offline diagnostic candidate with `dotnet publish --no-restore`, reuse the frozen engine, and record the managed DLL hash. Run exactly one serialized live capture with foreground/occlusion guards, then actually inspect all 20 targeted A/D/T/B images. Record evidence and remaining uncertainty without claiming repair or promotion.
