# Triage-02 post-result abnormal exit — read-only diagnosis

2026-10-23, `/root/sol_gui_plan`. No product source change, GUI, provider/model,
build, test or reproduction was performed. CodeGraph preceded source inspection.
Only this new diagnosis was written; original runtime evidence is retained.

## Established boundary

Triage-02's native result reports `passed=true`, `failure=null`, completed scan,
completed selected Triage section, exact saved/exported artifact SHA256
`2ff740752d275bf22b60e81185c895a44dcb5ec1f6748a0378ba4e51b020e535`,
and generation `06a52eed4c6a4981a3b3a12b73cb07ae`. Root's transport observation
places HTTP200 completion at 2026-10-22 23:56:29 UTC. This review independently
read the native result/process files, not a new provider response.

Native capture metadata records `2026-10-22T23:56:39.9514035+00:00`.
The native PNG and result file were written at 23:56:39 UTC; process proof was
written at 23:56:40 UTC. PID19192 exited with **3221226107 / 0xC000027B** after
1035.930655 seconds, `timed_out=false`, actual ceiling4500,
`owned_job_assigned=true`, `owned_tree_cleanup_verified=true`.
Microsoft describes [0xC000027B as a stowed exception](https://learn.microsoft.com/en-us/shows/inside/c000027b).
That classification supplies no offending HRESULT, stack or source line here.

The harness correctly fails a nonzero native process even after a successful
pre-close result. Do not change it to accept this exit, relabel the entire journey
PASS or repeat the model request merely to investigate teardown. Saved transport,
artifact, native pre-close state and native process outcome are separate evidence.

## Source path and clues

| Site | Current source behavior | Implication / limit |
| --- | --- | --- |
| `MainWindow.ParitySmoke.cs:69–91` | Awaits RunSelectedRepository, report bindings, selected AI mode, manifest-bound artifact read/export and NativeCaptureProbe.Capture before assigning aiDisplay/modelCompleted. | Result construction was reached after these awaits returned. This is not evidence every XAML compositor/selection operation was quiescent. |
| `MainWindow.ParitySmoke.cs:102–106` | Main body catches Exception into failure. Finally writes parity-smoke.json, then an inner finally calls Close(). | Passed result immediately precedes Close. Close and Closed handlers are outside the body catch; a failure there can coexist with failure=null. This is the strongest concrete teardown boundary, not proof of the exact failing call. |
| `MainWindow.Parity.cs:62` | First Closed handler calls Diagrams.Stop and AiArtifacts.Stop. | Both methods invalidate epochs/state without touching XAML. Existing post-await stopped/revision checks reduce stale binding risk. No clear unguarded AI-selection continuation was found. |
| `MainWindow.Workspaces.cs:80` | Next Closed handler cancels scanAdmission, disposes repository/fleet watchers and disconnects fleet session. | Relevant disposal boundary, but this journey had watches off, no fleet run. RunSelectedRepository clears scanAdmission in its finally. A disposed non-null scan token is not supported by this successful path. |
| `MainWindow.xaml.cs:77` | Later Closed handler calls actionLifetime.Cancel, keyboardBindings.Dispose, engine.Disconnect. | keyboard binding disposal removes accelerators and flyout handlers from XAML during Closed and is not wrapped locally. This is a concrete inspect/instrument candidate, not a confirmed error. Cancellation follows earlier Closed handlers due registration order. |
| `EngineSession.cs:43–59` | Waits for worker exit, drains stderr, validates terminal/exit, awaits completed report import; finally sets worker=null when exited. | Normal successful engine work is already finished before export/capture/Close. A running engine stdin/disconnect race is lower priority than XAML teardown. This does not prove native window closure itself is safe. |
| `NativeCaptureProbe.cs:32–71,76–93` | Awaits two rendering frames, RenderAsync, pixel read, encoding, write and move. CompositionTarget.Rendering handler is removed in finally. | No obvious retained application Rendering subscription was found after Capture returns. The unused timeout task only resolves; it has no UI mutation callback. WinUI compositor/internal capture work may still differ from completed application awaits; a dump/reproduction is needed. |
| `App.xaml.cs:8–13` | UnhandledException attempts spike-error.txt in AppContext.BaseDirectory; does not set Handled. | The diagnostic destination is the immutable package, not caller output; no spike-error.txt was found beside this candidate app. Absence does not prove no managed exception occurred or identify a native-only exception. Do not create a sentinel there or change package bytes to test logging. |

Repository/fleet watcher disposal invalidates epochs and disposes timers/watchers;
queued shell notices check actionLifetime before UI updates. AiArtifacts workspace
and view guard stopped/revision both before and after asynchronous reads; Stop
does not clear XAML controls. These inspected protections weaken a simple claim
that a known stale artifact/read callback necessarily caused this failure.

## Same-candidate comparison

Both `inputs.json` files identify candidate `dev-20261022220136-08e1c566`, same
native EXE SHA256 `81ed7619e1ce5ebcbdc905f784a57d55234a2b03d416f46a77a0a57ef7e734fc`,
same seed and identical QA3600/4200/4500 budgets.

| Journey | Pre-close result | Capture | Process |
| --- | --- | --- | --- |
| Remediate | passed=true, failure=null, completed | SHA `1f0c146e382ec1edafd0cbf7f41e6ba9d1a9f1cf1d1f90330001b4e71475763c`, captured23:34:44UTC | PID30024, exit0,706.576992s,no timeout,owned cleanup verified |
| Triage-02 | passed=true, failure=null, completed | SHA `e6eadbccae17abc2a18735b3366188c8e6b445d1dfc7e2ae16c9246861409c6a`, captured23:56:39.951UTC | PID19192,0xC000027B,1035.930655s,no timeout,owned cleanup verified |

Triage's 4105-byte PNG hash exactly equals the previously established completely
transparent Review capture. Byte identity supports the same empty-image defect,
not a claim that the actual Triage window was transparent. Remediate's different
PNG and clean exit show the shared Close path does not fail deterministically on
every mode. They do not establish whether Triage content, timing, capture state,
focus, selection/expander animation or host conditions triggered this instance.

## Diagnostics attempted and missing

A bounded read-only Windows Application event query requested IDs1000,1001,1026
from23:56:25 through23:57:15UTC, converted to local timestamps. Windows returned
no matching records. stdout.log and stderr.log are empty. No stack, dump, stowed
exception payload or offending module was found by this review. No registry,
WER policy or system diagnostics configuration was changed.

## Smallest next evidence, owned by root

**Root's supplementary saved-generation result, received before this diagnosis
closed:** `WP023/astra-gui-20261022/sol-saved-triage-01/summary.json` reports
passed=true, mode=triage and capture_validation.passed=true with four frames.
This reviewer read that summary and its process proof: PID15984, exit0,
8.588447 seconds, no timeout, owned Job assignment and cleanup verified.
Root reports preserved inputs and actually viewing Large-Dark Reports with
completed status, correct provider/model and usage input93236/output9651.
That visual observation belongs to root; this reviewer did not open the new
supplementary images. It demonstrates saved Triage import/capture/automatic
close can succeed on this candidate and narrows the original problem further
toward the long live journey's particular UI state/timing. It does not establish
a deterministic teardown root cause or overturn the original process failure.

The following items are remaining/prospective diagnostic choices, not commands
executed by this reviewer. Root has released the source freeze for the separately
reviewed budget patch set and plans a full Triage journey on its later candidate;
the source observations above describe the frozen candidate inspected before
that unfreeze. Do not attribute a future successful run to a teardown repair
without isolating what changed.

1. Open/display/capture this exact saved canonical generation using the reviewed
   existing helper, isolated profile and same pinned package. No model call.
   **Completed by root as the supplementary result above.** Keep output new, bind selected Triage artifact, note actual window PID, inspect
   content, close normally, require exact exit/cleanup. This separates saved-report
   import/render/close from the completed live-workflow path. A clean helper run
   is supplementary recovery evidence; it cannot erase the original failed exit.
2. Compare capture-smoke's automatic Close with an ordinary --show-report window
   closed explicitly after settled observation. Root controls all interactive
   operations. Reuse saved artifacts; no expensive native scan/model retry.
3. If abnormal exit recurs, capture a per-process crash dump under a separately
   reviewed diagnostic lease and inspect stowed exception HRESULT/stack with
   matching package symbols. Prefer a bounded task-owned debugger/dump collector;
   do not introduce global WER registry policy or write inside immutable package.
4. If a source diagnostic change is justified, prepare a new candidate with
   caller-output timestamps around parity result-write/Close, each Closed handler,
   unload and App unhandled exception; record full exception without evidence or
   secrets. This requires root's source/build lease. Do not suppress exceptions,
   bypass Close, add arbitrary delays or call a timeout increase a proven repair.

Likely investigation area: **post-result XAML/window teardown or a queued UI
failure exposed during Close**. Confidence: boundary is strong; root cause is
unproven. Worker cleanup failure, provider timeout and harness timeout are not
supported by the retained process/result boundary.

## Retained proof pins

| File, relative to WP017 | SHA256 |
| --- | --- |
| sol-long-local-20261023-triage-02/triage/process.json | `75f566adadaf0eccde236e8495af470d974fd033828df7befa050bcb36c92d6f` |
| sol-long-local-20261023-triage-02/triage/parity-smoke.json | `6d061671cceade355e446a8ff8b433510b8bad4b1e6d46a90a642a91cd0f0cb8` |
| sol-long-local-20261023-triage-02/triage/inputs.json | `746c66b9acff1cf7fce48585ad51533bd9fb85b0d7999f2fe6fb6059267f1674` |
| sol-long-local-20261023-remediate/remediate/process.json | `5b3a921f4e522a8a358d23e4a331fc6ccaa29b3826a55e3dbd5af7c21788b01c` |
| sol-long-local-20261023-remediate/remediate/parity-smoke.json | `502b00080c92666e47397f6cac5d9fc010e23ced7660d537765d9848bad0e5c7` |
| sol-long-local-20261023-remediate/remediate/inputs.json | `6c92ab89824f9d3f6fa9ab50720185a6453bd843c988c9b2b2737e1184637b1a` |

This document does not accept Triage's native process, visual/accessibility gates,
WP017 or release. It records a completed pre-close model/artifact path followed by
an abnormal native exit and verified owned-process cleanup.
