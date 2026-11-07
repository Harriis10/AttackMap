# New budget-label preview — read-only plan

2026-10-23. Source inspected through CodeGraph before direct reads. No GUI,
provider, build or implementation performed. Root owns fresh freeze/publish and
the later actual preview. This plan accepts no visual or accessibility gate.

**Existing focused flag proves bottom-scroll bounds, but emits no screenshot.**
The full capture alternative emits screenshots of the initial Settings viewport;
it does not scroll to the new budget label. Neither existing path alone proves
that the changed label is legible at the small viewport.

## Existing focused scroll journey

Actual full-product argv, through the owned Job launcher after new candidate
qualification and manifest/source-lock pinning:

```text
NEW_CANDIDATE_APP --provider-scroll-smoke NEW_EXISTING_OUTPUT_DIR/result.json --viewport 1024 700
```

`MainWindow.xaml.cs:94–95,541–544` routes it to SmokeLoaded before personal
settings/provider restoration. `RunProviderScrollSmoke` validates a fresh absolute
.json path and existing unredirected parent, resizes, selects actual Settings,
waits dispatcher turns, programmatically scrolls `Provider.Content`'s ScrollViewer
to its bottom three times, records bounds and closes. It does not invoke Save,
Test connection, scan or any provider action. It requires no pointer coordinates.

The sole native output is the caller's `result.json`; there is **no PNG,
capture-manifest, pause-open option, mode/theme flag or budget-label measurement**.
Root's launcher additionally supplies stdout/stderr and owned process proofs.
Require exit0/no timeout/verified cleanup, unchanged pinned inputs,
`completed=true`, `failure=null`,
`result.bothActionsFullyVisibleAndEnabled=true`, two after-records for Save/Test,
`buttonActionsInvoked=providerRequestsInvoked=0`, and helper request count0.
Record actual root dimensions/scale, innerOffset and innerScrollableHeight.
It measures Save/Test intersection through realized ancestor viewports, not the
new label. Do not claim label visibility or keyboard/Narrator acceptance from it.

Historical reference only:
`RECONCILE-2026-10-21/provider-scroll-c/result.json` records the corresponding
1008×661,scale1 programmatic journey. Its process argv is exactly the same flag
shape, old candidate `integrated-20261021-c`, exit0. It supplies no new-candidate
acceptance and no captured label image.

## Existing full-capture alternative

Exact app argv, fresh existing empty phase folder, ordinary non-AI seed:

```text
NEW_CANDIDATE_APP --capture-smoke ABSOLUTE_CANONICAL_REPORT NEW_EXISTING_EMPTY_PHASE_DIR
```

Or use the existing source-pinned GUI owner, first without `--run` for preflight:

```powershell
& $taskPython -B $taskGui --app $taskApp --release-lock $taskLock --pinned-manifest $taskManifest --manifest-sha256 $taskPin --seed $taskSeed --output "$taskEvidence\sol-budgetcandidate-capture-01" --phase capture
& $taskPython -B $taskGui --app $taskApp --release-lock $taskLock --pinned-manifest $taskManifest --manifest-sha256 $taskPin --seed $taskSeed --output "$taskEvidence\sol-budgetcandidate-capture-01" --phase capture --run
```

Bindings are root's reviewed new candidate values from `sol-execution-plan.md`;
do not reuse the old candidate's pin. Current navigation produces56 PNGs: fourteen
views ×two sizes ×two themes, plus manifest and structure-row diagnostics.
Settings filenames may be localized `1024x700-Light-Nastavení.png` etc.; the
reviewed evidence-only alias preserves actual Settings coverage. Manifest requires
aiMode=null, providerCalled=false, exact selected report SHA, expected=completed
and correct capture count; shared guard checks hashes/pixels/actual viewport
pairs. Inspect actual images separately from pixel validation.

`CaptureLoaded` only selects each destination and captures its current initial
scroll position. The prior actual Settings small image stopped around Backend;
large image reached endpoint/model/credential. Calls and the changed total-time
label follow those fields, so no displayed label is established by those captures.
The --viewport option does not override CaptureLoaded's hardcoded size loops.
Combining --provider-scroll-smoke with --capture-smoke does not sequence them:
constructor branch precedence selects CaptureLoaded and bypasses the scroll
handler. Do not call either combination a focused label capture.

## Concrete visual gate and remaining choice

After full publish and pinned candidate qualification, root can run the focused
scroll proof as cheap non-provider evidence. Actual label acceptance still needs
an identified full-product Settings window scrolled so the time label and numeric
field are visible, then an actual image reviewed for wrapping, clipping and
overlap at small size (and the required theme/size matrix if closing that gate).
Verify default600 remains visible and the text accurately distinguishes3600
from explicit local7200; no Save/Test or model request is needed.

A demonstrated coordinate-free UI Automation ScrollPattern/focus facility could
perform that live-window scroll without pointer geometry; none was demonstrated
by this task. The existing focused flag has the programmatic scroll but closes
without capturing. A later focused capture hook would therefore require root's
separate source/build lease and new candidate; this plan does not implement it
or ask root to break the current freeze. A standalone WP015Preview can supply
supporting control-only material, but cannot replace actual full-product
integration acceptance. If no authorized observable scroll/capture path is
available, retain the label's visual gate as open instead of treating56 initial
screens or button-bound assertions as its preview.
