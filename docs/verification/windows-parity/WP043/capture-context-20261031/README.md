# WP043 capture context and target-stage diagnostics — 2026-10-31

This is a bounded diagnostic correction, not a production text-rendering repair.
WP043 remains IN_PROGRESS, rendering acceptance FAILED, and V01–V03 blocked.
There is no release or five-round acceptance in this source/harness checkpoint.

## Current evidence and missing cause

The authoritative [30 October integration evidence](../../ROADMAP-BATCH-20261030/README.md)
retains the reviewed live31 distinction between live presentation and RTB output:
rounds 2–3 have absent live Detail body while Detail/root RTB contain the body;
round 4 has a transparent local RTB with meaningful root RTB; round 5 correctly
rejects an empty root before B. These are prior visual observations, not a new
visual review by this implementation block.

The fresh read-only [retained raster replay](../../../../../artifacts/wp043-context-diagnostics-20261031/retained-raster-replay.json)
independently decodes all ten retained D/T PNGs, including CRC validation, and
confirms Detail classifications nonuniform/nonuniform/nonuniform/empty/empty and
root classifications nonuniform/nonuniform/nonuniform/nonuniform/empty.
The retained trace contains zero SurfaceContentsLost, WebView2 ProcessFailed or
diagnostic-error events. That absence does not identify or exclude a compositor,
text-cache, GPU or other rendering mechanism. Existing trace metadata does not
record host visibility or per-target completion boundaries, so it cannot prove
why the fifth root is empty or where the local/root paths diverged.

## Smallest correction

`MainWindow.RenderDiagnostics.cs` previously checked generation and finding
revision during asynchronous RTB work, but read the navigation revision and report
identity again when emitting terminal events. Navigation, host visibility,
geometry or scale could change while the UI dispatcher yielded without producing
a specific invocation-bound context rejection. Separate F8 and pair flags also
allowed the two diagnostic captures to overlap.

The pair now preserves the invocation's report/run/navigation/finding identity;
checks selection identity, visible Findings, the same loaded XamlRoot, host/window
visibility, dimensions and scale after asynchronous boundaries and before file
commit; and reports `capture-context-changed` under the original ACK identity.
The observed current context is separate metadata, so the harness can consume a
specific failure instead of waiting for a terminal ACK under a different revision.
F8 and pair probes exclude each other.

Read-only target-stage events record before-render, after-render, after-pixels
and committed boundaries, total elapsed time and frame count, plus bounded host,
selection, geometry and scale state. They do not contain Detail/source body text.
Metadata reads degrade safely to an unavailable/error-type record during shutdown.
This instrumentation adds observation overhead; it does not establish that an
observed recovery is caused by RTB or that RTB matches live presentation.

Ctrl+Alt+Shift+R remains the pair shortcut; F7 is not bound. The existing immediate
Detail→root ordering, absence of explicit layout/frame settling/property changes,
native root variation gate, independent PNG validation and no-B-on-failure gate
remain intact. Transparent Detail remains admissible with a meaningful root.

## Verification and remaining gate

The focused Python fake-backend/source suite passed 69 tests plus 20 subtests.
The new scenario changes observed navigation/host state after started and proves
that an invocation-bound context failure stops the run with its precise reason,
retains failure metadata, performs one trigger and never releases B. Source
guards cover the new native context requirements and unchanged non-mutating path.
These checks do not execute WinUI pixels or prove native runtime acceptance.

Initial restricted test runs could not write inside Python-created temporary
directories (PermissionError, including a workspace-local retry). Their failed
JUnit reports are retained separately. The successful run used the same tests
with ordinary filesystem access; no test assertions were bypassed.

The diagnostic native project was published offline with .NET 8.0.426,
`--no-restore`, and the retained task-local package cache. Exact final source,
binary and engine identities, final commands and results are in
[`verification.json`](../../../../../artifacts/wp043-context-diagnostics-20261031/verification.json).
The adjacent engine is deliberately retained from candidate10; this is not a new
common-source core/native release.

The integrator must perform actual visual review of any new controlled native
run and record stage/host observations alongside A/D/T/B. Context qualification
and meaningful root pixels remain prerequisites, not evidence of expected glyph
presence. No repeated run should be used merely to obtain favorable pixels.
