# WP043 native snapshot context and navigation focus — 2026-10-31

This bounded harness change preserves the native-window evidence needed to
distinguish an identity, foreground, geometry or occlusion failure after a UIA
disappearance race. It does not attribute the live-03 blocker to a popup and
does not establish a rendering repair. No live capture was run in this block;
independent source/test review is required before any further live run.

Each native safety assessment now uses one `EnumWindows` result for both the
owned target and every higher-Z intersecting blocker. It records separate
identity, foreground, geometry and occlusion results, the numeric foreground
HWND before/after enumeration, target rectangles before/after, and each target
or blocker HWND, PID, title, native class, rectangle, Z order, visibility,
minimized and cloaked state. Native class comes directly from `GetClassNameW`;
an unavailable value remains null. A snapshot ID identifies each assessment.
UIA retry checks and failure-review checks use the same assessment. Failure
review retains the successful before-grab check and a structured failed
after-grab check when geometry or foreground changes.

Modal-inspection errors and their attempt records now retain an inspection
invocation ID, action phase, intended destination, diagnostics sequence,
attempt and known descendant count. Native recheck failures retain the full
structured target/blocker assessment as their cause. An unavailable count or
unobserved window identity remains unknown rather than being inferred.

Navigation candidates and focus use raw UIA calls. A direct `SetFocus` failure
is fatal. The intended item's direct `HasKeyboardFocus` property must be true
both after setting focus and immediately before global Enter. If a transient
dismissal loses that focus, the harness fails before sending Enter. The
pre-existing explicit owned-transient path remains bounded; external or mixed
occluders cannot enter it through a title substring. Confirmed client modals,
unknown UIA failures, and failed native rechecks during UIA inspection remain
fatal. No new popup-dismissal or occlusion-recovery action was added.

Focused tests cover same-snapshot target/blocker Z order, distinct geometry,
foreground and identity failures, external/mixed occluders during a stale UIA
retry, inspection context and descendant counts, raw SetFocus and keyboard
focus failures, lost focus after transient dismissal, and failure-review
before/after geometry. Existing modal recognition, fatal-error, transient and
capture tests remain in the complete harness run.

Exact final command, executed through elevated `C:\Windows\System32\cmd.exe`
with normal temporary-file access:

```text
C:\Projects\INPROGRESS\AttackMap\.venv\Scripts\python.exe -m pytest tests/test_wp043_live_capture.py -q -p no:cacheprovider --junitxml=docs/verification/windows-parity/WP043/context-snapshot-focus-20261031/harness-tests.xml
```

Exit code 0: **98 passed, 91 subtests passed in 6.28s**. The retained
[JUnit report](harness-tests.xml) contains 189 cases and zero failures, errors
or skips. The [verification record](verification.json) binds the tested source
and report hashes. `git diff --check` passed for the scoped files and evidence.
These deterministic checks use raw-API fakes; they do not execute a real UIA
provider, native rendering, live pixels, or LM Studio requests. Rendering
acceptance remains unestablished by this block.
