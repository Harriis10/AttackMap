# Frozen-candidate lifecycle and capture follow-up

2026-10-23, `/root/sol_gui_plan`, read-only code/evidence investigation. CodeGraph
was used before source inspection. Only this document was written; no source,
helper, package, GUI, model, test or build operation occurred. Root's active
Hunt+verify7200 session retains exclusive GUI/provider ownership.

## Scope and source binding

Current candidate `dev-20261023001948-7fa3eaff`, manifest SHA256
`3666fe473f69d362671cc67c235a4920ca63fcf1a64a0d8b1ae8ce14d22d61b6`.
Compared twelve inspected current source files against
`WP024/sol-long-budget-20261023/native-build/native-build.json`'s input hashes:
App.xaml.cs, MainWindow.xaml.cs, MainWindow.Parity.cs, MainWindow.Workspaces.cs,
MainWindow.ParitySmoke.cs, MainWindow.Capture.cs, NativeAccessibility.cs,
NativeCaptureProbe.cs, EngineSession.cs, AI/AiArtifactsView.cs,
Diagram/DiagramView.cs, MarkdownView.cs. **All twelve hashes match the frozen
build proof.** No binary decompilation or runtime trace was performed.

Earlier Triage-02's retained boundary and pins remain in
`WP017/sol-long-local-20261023-triage-02/triage-teardown-diagnosis.md`: native
passed result written immediately before Close, then0xC000027B; no harness
timeout, owned cleanup verified. A separate saved-Triage capture later exited0.
This follow-up does not reclassify that failed native journey or identify its
root cause. The new budget changes did not repair the inspected lifecycle code.

## Concrete lifecycle gaps found

1. **Report-import failure continuation lacks the close guard.**
   `MainWindow.xaml.cs:362–410` checks actionLifetime on successful asynchronous
   stages, but its catch only checks `current == generation` before assigning
   Status.Text. Closed cancels actionLifetime without incrementing generation.
   Thus this source sequence is possible: LoadReport captures current generation;
   an awaited adapter/read remains pending; window closes; read throws a caught
   IO/JSON/InvalidOperation exception; catch sees the same generation and writes
   to the closed XAML Status object. This is a concrete missing lifetime guard,
   not a reproduced failure. Whether the write throws and whether its caller
   catches that second exception depend on the actual close/import path.
   **Relevance to Triage-02 is limited:** parity awaits RunSelectedRepository,
   LoadReport and parityViewBinding before capture/result. No pending failed
   import was established at Triage's exit. Do not present this static gap as
   the demonstrated cause of its stowed exception.
2. **General UI event handlers remain enabled for closing notifications.**
   `ready` is set true in the constructor and is never reset. Navigate (line836)
   and NetworkOptionChanged (line162) check ready, but not the lifetime token or
   a closing flag, before reading/writing XAML controls. Provider.ConfigurationChanged
   remains subscribed. An already queued selection/configuration notification
   delivered during/after teardown can therefore enter these handlers. No trace
   establishes such a notification occurred in Triage; this is a candidate path
   to instrument, not proof a WinUI selection callback is necessarily emitted
   on Close.
3. **Closed cleanup ordering leaves the lifetime invalidation late.**
   Registration order is InitializeParityWorkspace → InitializeWorkspaceServices
   → constructor's final handler. Their Closed actions are respectively
   Diagrams.Stop/AiArtifacts.Stop; scanAdmission.Cancel/watch disposal/fleet
   disconnect; then actionLifetime.Cancel/keyboardBindings.Dispose/engine
   disconnect. The first two do not cancel the shared shell lifetime. Later
   actions also depend on earlier event handlers returning normally. The AI and
   diagram Stop functions only invalidate state and are deliberately free of
   XAML writes, so their implementations do not expose an obvious throw here.
   The order is a robustness concern; a causal timing window has not been measured.
4. **Keyboard disposal touches XAML in Window.Closed.**
   NativeAccessibility.Binding.Dispose removes accelerators from
   root.KeyboardAccelerators and unsubscribes root/flyout events. It runs in the
   late Closed handler without local diagnostic boundaries. If the root is no
   longer usable, an exception can prevent following engine.Disconnect. No
   HRESULT/stack proves such a failure occurred. Moving it blindly or suppressing
   its exceptions would not be a validated teardown repair.

The normal-startup-only AppWindow.Changed → CaptureWindowPlacement subscription
also lacks a closing guard/unsubscription and reads AppWindow.Presenter/XamlRoot.
However that subscription is not installed by --parity-smoke, so it is not an
explanation of the original Triage parity failure.

## Paths that already mitigate the suspected races

- EngineSession waits worker exit/stderr and validates terminal state, then awaits
  report import; successful finally clears worker before returning. Normal parity
  close occurs after that await chain, so an outstanding worker stdin operation
  is a weaker explanation than a post-result UI/native exception.
- RunSelectedRepository clears scanAdmission in finally before returning. A
  lingering disposed scanAdmission cancellation target is not supported by its
  successful parity path.
- AiArtifactsView.Stop and DiagramView.Stop set stopped/revision state without
  mutating XAML. Their asynchronous selection/read paths test stopped/revision
  before later display. parityViewBinding is awaited after report import and again
  before live AI selection. No unguarded AI artifact-load continuation was found.
- MarkdownView rendering is synchronous: Text → Render → clear/add XAML blocks.
  It contains no asynchronous work or own timer/dispatcher callback. Rendering
  creates selectable text nodes whose native XAML behavior is beyond this source
  inspection; the class alone does not demonstrate a late continuation race.
- NativeCaptureProbe removes its CompositionTarget.Rendering subscription in
  finally and awaits render/pixel/encoding/file operations before returning.
  There is no obvious retained application Rendering handler. A completed await
  does not establish every internal XAML/compositor operation is quiescent.

## Logging currently available

`App.xaml.cs:8–13` hooks Application.UnhandledException and attempts
`AppContext.BaseDirectory/spike-error.txt` containing HRESULT/message/exception.
It leaves Handled unchanged. This can still terminate the app as intended.
The path is inside the pinned immutable package and write failures for IO/access
are swallowed. It is not the caller-owned QA evidence directory; native/fail-fast
exceptions may also not reach this managed hook. Absence of that file is therefore
not proof that no exception occurred. No AppDomain.UnhandledException or
TaskScheduler.UnobservedTaskException sink was found in App.xaml.cs. The parity
result body catches exceptions, but its finally's Close lies outside that catch.

No new event-log query or dump collection was done during the current live run.
The earlier bounded Application1000/1001/1026 lookup found no matching records;
there is still no offending stack/HRESULT beyond the process stowed-exception code.

## Why the capture transition failures remain plausible without a UI defect

`MainWindow.Capture.cs:174–191` changes RequestedTheme and window size, switches
destinations, awaits one low-priority dispatcher TaskCompletionSource callback,
then UpdateLayout and capture. That TCS lacks RunContinuationsAsynchronously;
its awaiting continuation can resume inside SetResult's dispatcher callback.
NativeCaptureProbe subsequently waits two Rendering events, so it adds a frame
barrier, but neither mechanism observes NavigationView indicator/theme/entrance
transition completion or verifies each label's actual raster content.

This is a concrete **capture scheduling weakness**, not proof of an application
race: logical tree/layout readiness and two frame notifications can coexist with
intermediate composition/selection state. It is consistent with retained
Large-Dark Diagrams' blank toolbar/source text, FindingDetail's blank controls,
and blue nav accents at the preceding destination. It does not prove a common
cause for those images, the wholly transparent PNG, or0xC000027B. The shared
pixel guard correctly checks whole-image visibility/integrity; it cannot reject
a partially blank page whose sidebar/title still provide nonuniform pixels.

## Smallest useful tests and repair proposals, not implemented

1. After root releases the live slot, capture the same saved generation/view
   twice at an unchanged actual theme/viewport, with an explicit settled live
   window observation between attempts. No new model request. Compare actual
   screenshots and original pixel hashes, retaining both passes/failures. This
   tests transition sensitivity instead of guessing from control properties.
2. For a separately leased QA capture change, make the dispatcher continuation
   asynchronous, check enqueue success and apply a bounded wait; confirm actual
   requested theme/viewport and selected destination stay stable across rendering
   samples before capture. Add a second same-state observation where useful.
   This is a readiness contract, not an arbitrary long sleep. If native images
   remain incomplete, preserve failure and use authorized actual-window capture.
   Do not disable normal animations, paint substitute pixels or expand capture
   PASS to mean manual UI acceptance.
3. Small production hardening candidate: add the lifetime condition to
   LoadReport's error UI write, invalidate ready/lifetime at the earliest single
   closing boundary, and guard synchronous Navigate/NetworkOptionChanged against
   that terminal state. Keep cleanup actions observable and independent; do not
   swallow or mark native failures as success. Test a controlled delayed report
   read fault released after close, verifying zero UI writes after invalidation,
   no stale publish and successful worker cleanup. A normal task/fixture test
   without a WinUI window cannot prove COM teardown safety.
4. Before attributing a fix to0xC000027B, obtain caller-owned QA timestamps around
   result-write, Close and each cleanup handler, plus an actual crash dump if it
   recurs. An opt-in evidence-output diagnostic sink must validate a fresh local
   directory and avoid package mutation; record exception type/HRESULT/stack
   without turning exception handling into success. This needs a source/build
   lease and a newly qualified candidate, not edits during the current run.

Root's planned full Triage on the later candidate can establish whether the
abnormal exit repeats. A clean outcome is new runtime evidence; it is not proof
that budget or preview-label changes repaired a lifecycle race. Current verdict:
one concrete missing lifetime guard and capture scheduling weaknesses identified;
**no confirmed root cause** for the retained Triage-02 failure.
