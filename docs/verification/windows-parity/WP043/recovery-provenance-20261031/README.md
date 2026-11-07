# WP043: recovery bound to the originating native safety error

Date: 2026-10-31. Scoped deterministic harness fix only; independent review is
still required before any new live capture. WP043, rendering acceptance and
V01–V03 remain open/blocked under the active plan.

Latest recursive-entry checkpoint: **102 tests + 142 subtests PASS** (244 JUnit
cases). A reviewer-confirmed remaining bypass was reproduced and fixed below.
The original checkpoint artifacts are preserved unchanged.

## Reproduced failure

The three recovery handlers previously accepted either a successfully dismissed
later transient **or** an original error naming only allowed owned transients.
A foreign/mixed blocker could disappear after its failing native snapshot, then
a different allowed owned transient could be dismissed. That later dismissal
incorrectly recovered the original unsafe frame/action.

The new regression matrix was executed before the fix. All 21 combinations of
three handlers and seven unsafe original conditions returned
`independent-live-window-captured`, violating the required fatal result.
[before-regression.xml](before-regression.xml) retains the 21 failed subtests.

## Scoped change

- `_owned_transient_only(error, target)` now qualifies the **original**
  `NativeWindowSafetyError` diagnostics: Win32 snapshot identity, original
  occlusion failure, live unique target HWND/PID, unchanged target rectangles,
  safe original foreground/geometry, and a non-empty blocker list containing
  only the explicit same-process `Hostitel místní nabídky` allowlist.
- Each navigation, before-grab and after-grab recovery handler requires that
  qualification before attempting any dismissal. A later successful close
  cannot authorize recovery from external/mixed, generic/unknown, changed
  identity/geometry/foreground, client-modal or UIA inspection errors.
- Dismissal retains the original target PID/HWND/rectangle and checks target,
  process and foreground before the close and while waiting for it. A new
  external/mixed blocker during recovery is fatal. Retry limits are unchanged.
- Valid original owned-transient recovery, including a transient that disappears
  before dismissal, remains supported and tested.

Only `tools/capture_wp043_live.py`, `tests/test_wp043_live_capture.py` and this
new evidence directory were changed for this scoped block. The two code files
already contained substantial uncommitted changes from earlier work; their
whole Git diff is not the incremental scope of this fix.

## Verification

Executed with explicit `C:\Windows\System32\cmd.exe`, `login=false`, elevated
execution and the repository Python environment:

```text
.venv\Scripts\python.exe -m pytest tests\test_wp043_live_capture.py -q --junitxml=docs\verification\windows-parity\WP043\recovery-provenance-20261031\harness.xml
```

Original checkpoint: **101 tests + 136 subtests PASS**, zero failures/errors/skips.
[harness.xml](harness.xml) records 237 JUnit cases; [verification.json](verification.json)
records command, result and source/artifact hashes. Scoped `git diff --check`
also passed.

New regression coverage:

- All three handlers reject original external, mixed, generic, incomplete-native,
  same-size position change, HWND change and foreground change failures, even
  after a later allowed transient appears. Original external/mixed blocker
  diagnostics are retained, and after-grab images remain discarded.
- All three handlers recover a valid original owned transient and complete 75
  fake captures, with one bounded dismissal each.
- All three handlers reject post-error target/foreground changes or a new
  external blocker before dismissal, plus target/foreground changes inside the
  close operation. None accepts a frame from those attempts.
- Existing owned-transient/retry-bound, confirmed modal, UIA inspection failure,
  snapshot provenance and focus tests remain passing in the full suite.

These are deterministic harness checks. No application/live capture, model HTTP
call, C# build, fleet validation or rendering review was performed in this block.

## Recursive recovery entry regression

Independent review found a further recurrence: a valid original owned transient
was dismissed, then the recursive entry precheck called dismissal with its
default `recovering=False`. A new external PID 777 blocker observed only by
that precheck could disappear before the full safety inspection. All three
handlers then incorrectly completed 75 fake captures.

The regression now returns an external or mixed blocker for exactly that one
enumeration, after the allowed close has cleared. Before the fix, all six
combinations (three handlers, external/mixed) failed the required fatal result;
[recursive-before-regression.xml](recursive-before-regression.xml) preserves
that reproduction.

The two recursive entry prechecks now pass `recovering=attempt > 0`, preserving
strict recovery through navigation and both capture-retry branches. A newly
observed external/mixed blocker is fatal even if it would disappear by the next
inspection. The six new cases require one allowed close, one fleeting blocker
observation, failed run evidence and zero accepted captures; an after-grab frame
remains discarded. Existing positive owned-transient cases still complete all
75 fake captures, and retry bounds are unchanged.

Executed with the same explicit elevated command shell and repository Python:

```text
.venv\Scripts\python.exe -m pytest tests\test_wp043_live_capture.py -q --junitxml=docs\verification\windows-parity\WP043\recovery-provenance-20261031\recursive-harness.xml
```

Result: **102 tests + 142 subtests PASS**, zero failures/errors/skips, 9.89 seconds.
[recursive-harness.xml](recursive-harness.xml) contains 244 JUnit cases;
[recursive-verification.json](recursive-verification.json) records both commands,
results and exact source/test/artifact hashes. Scoped `git diff --check` passed.
No live capture or model HTTP call was performed. Independent review remains the
next gate before a new live capture.

## Next gate

Independent review of these exact source/test hashes and the preserved pre-fix
reproduction. A new controlled live capture may proceed only after that review
approves the harness; it would be new evidence, not implied by these test passes.
